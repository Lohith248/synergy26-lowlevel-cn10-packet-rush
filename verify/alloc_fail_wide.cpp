// WIDE-POOL variant of tools/alloc_fail.cpp (r4 gate). Only the generators and the per-iteration wide_begin() differ.
// Covers: random rule sets of varying size and wildcard density, many priority ties,
// classify-after-update, real deletes of live IDs, deletes of missing IDs, same-ID replace
// (incl. moving to another index group), ID reuse after delete, re-initialize, partial batches.
#include "classifier.h"
#include "linear_classifier.h"
#include "io_utils.h"
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>
#include <string>
using namespace packet_rush;

static std::mt19937_64 rng;
static uint32_t U(uint32_t n) { return static_cast<uint32_t>(rng() % n); }
static bool coin(double p) { return std::uniform_real_distribution<double>(0, 1)(rng) < p; }

// Boundary mode (every 4th iteration): rule IDs count down from UINT32_MAX and many rules
// carry priority UINT32_MAX or UINT32_MAX - 1, so the largest legal rank is exercised.
static bool g_extreme = false;
[[maybe_unused]] static uint32_t idmap(uint32_t i) { return g_extreme ? UINT32_MAX - i : i; }

// WIDE pools: generators live in widegen.h (original narrow make_rule/make_packet removed).
#include "widegen.h"


// ---- Allocation-failure injection (this test binary only) -----------------------------
// Every global operator new counts down; when the countdown reaches zero it throws
// std::bad_alloc once. The classifier is then checked against its own verdicts from before
// the failed call (strong guarantee), and against the reference after a successful call.
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>
static long g_countdown = -1;  // -1 = disarmed
static long g_fired = 0;
static void* take(std::size_t n, std::size_t align) {
    if (g_countdown > 0 && --g_countdown == 0) { g_countdown = -1; ++g_fired; throw std::bad_alloc(); }
    if (n == 0) n = 1;
    void* p = align <= alignof(std::max_align_t) ? std::malloc(n) : std::aligned_alloc(align, (n + align - 1) / align * align);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new(std::size_t n) { return take(n, 0); }
void* operator new[](std::size_t n) { return take(n, 0); }
void* operator new(std::size_t n, std::align_val_t a) { return take(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return take(n, static_cast<std::size_t>(a)); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

static std::vector<Action> verdicts(OptimizedClassifier& c, const std::vector<Packet>& pk) {
    std::vector<Action> a(pk.size());
    c.classify_batch(pk.data(), pk.size(), a.data());
    for (size_t i = 0; i < pk.size(); ++i)
        if (c.classify(pk[i]) != a[i]) { std::printf("FAIL: single and batch disagree\n"); std::exit(1); }
    return a;
}

int main(int argc, char** argv) {
    const uint64_t iters = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 30;
    const uint64_t first = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0;  // wide variant: iteration offset (new seeds)
    long rejected[3] = {0, 0, 0}, committed[3] = {0, 0, 0};
    const char* names[3] = {"replace", "insert", "delete"};
    for (uint64_t it = first; it < first + iters; ++it) {
        rng.seed(5000 + it);
        g_extreme = it % 4 == 1;
        wide_begin(it);
        const double wc = std::vector<double>{0.0, 0.3, 0.65, 0.9}[it % 4];
        const uint32_t n = std::vector<uint32_t>{1, 50, 600, 3000}[(it / 4) % 4];
        std::vector<Rule> live;
        for (uint32_t i = 0; i < n; ++i) live.push_back(make_rule(idmap(i), wc, coin(0.5) ? 8 : 100000));
        OptimizedClassifier opt; LinearClassifier ref;
        opt.initialize(live); ref.initialize(live);
        uint32_t next_id = n;
        for (int step = 0; step < 60; ++step) {
            std::vector<Packet> pk(192);
            for (auto& p : pk) p = make_packet(live);
            const int kind = live.empty() ? 1 : static_cast<int>(U(3));
            Rule r{};
            uint32_t victim = 0;
            if (kind == 0) { victim = U(static_cast<uint32_t>(live.size())); r = make_rule(live[victim].rule_id, wc, 100000); }
            else if (kind == 1) r = make_rule(idmap(next_id++), wc, 100000);
            else victim = U(static_cast<uint32_t>(live.size()));
            const std::vector<Action> before = verdicts(opt, pk);
            for (long k = 1;; ++k) {
                g_countdown = k;
                bool threw = false;
                try {
                    if (kind == 2) opt.delete_rule(live[victim].rule_id); else opt.insert_rule(r);
                } catch (const std::bad_alloc&) { threw = true; }
                g_countdown = -1;
                if (!threw) break;
                ++rejected[kind];
                if (verdicts(opt, pk) != before) {
                    std::printf("FAIL: %s with allocation %ld failing changed a verdict (iter %llu step %d)\n",
                        names[kind], k, (unsigned long long)it, step);
                    return 1;
                }
            }
            ++committed[kind];
            if (kind == 2) { ref.delete_rule(live[victim].rule_id); live.erase(live.begin() + victim); }
            else { ref.insert_rule(r); if (kind == 0) live[victim] = r; else live.push_back(r); }
            const std::vector<Action> after = verdicts(opt, pk);
            for (size_t i = 0; i < pk.size(); ++i)
                if (after[i] != ref.classify(pk[i])) {
                    std::printf("FAIL: %s committed but verdict differs from reference (iter %llu step %d)\n",
                        names[kind], (unsigned long long)it, step);
                    return 1;
                }
        }
    }
    if (rejected[0] == 0 || rejected[1] == 0) { std::printf("FAIL: injection never fired\n"); return 1; }
    std::printf("OK: allocation failures injected=%ld; rejected replace=%ld insert=%ld delete=%ld; committed replace=%ld insert=%ld delete=%ld\n",
        g_fired, rejected[0], rejected[1], rejected[2], committed[0], committed[1], committed[2]);
}
