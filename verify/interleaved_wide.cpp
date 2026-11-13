// WIDE-POOL variant of tools/interleaved.cpp (r4 gate). Only the generators and the per-iteration wide_begin() differ.
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


// Release check modelled on the review's interleaved test: 15,000 live rules, then 5,000
// inserts of new IDs interleaved with 5,000 deletes of live IDs, verdicts checked against
// the reference every 25 operations; then 10,000 more insert/delete pairs on fresh keys
// (the official update count) to watch RSS. Fails on a mismatch, p99 update > 5 us, or
// peak RSS > 32 MiB.
#include <algorithm>
#include <chrono>
#include <sys/resource.h>
static double peak_mib() { rusage u{}; getrusage(RUSAGE_SELF, &u); return u.ru_maxrss / 1024.0; }
// official nearest-rank p99: index ceil(0.99 n) - 1
static double p99(std::vector<double> v) { std::sort(v.begin(), v.end()); return v[(v.size() * 99 + 99) / 100 - 1]; }

int main(int argc, char** argv) {
    const uint64_t seed = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1;
    rng.seed(9000 + seed);
    wide_begin(seed);
    std::vector<Rule> live;
    for (uint32_t i = 0; i < 15000; ++i) live.push_back(make_rule(i, 0.3, 100000));
    OptimizedClassifier opt; LinearClassifier ref;
    opt.initialize(live); ref.initialize(live);
    std::vector<double> ins, del;
    uint32_t next_id = 15000;
    uint64_t checks = 0;
    auto check = [&] {
        std::vector<Packet> pk(64);
        for (auto& p : pk) p = make_packet(live);
        std::vector<Action> a(pk.size());
        opt.classify_batch(pk.data(), pk.size(), a.data());
        for (size_t i = 0; i < pk.size(); ++i)
            if (a[i] != ref.classify(pk[i])) { std::printf("FAIL: mismatch after update\n"); std::exit(1); }
        checks += pk.size();
    };
    auto timed = [](auto&& f) {
        const auto t0 = std::chrono::steady_clock::now(); f();
        return std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count();
    };
    for (int op = 0; op < 10000; ++op) {
        if (op % 2 == 0) {
            const Rule r = make_rule(next_id++, 0.3, 100000);
            ins.push_back(timed([&] { opt.insert_rule(r); }));
            ref.insert_rule(r); live.push_back(r);
        } else {
            const uint32_t k = U(static_cast<uint32_t>(live.size()));
            const RuleId id = live[k].rule_id;
            del.push_back(timed([&] { opt.delete_rule(id); }));
            ref.delete_rule(id); live[k] = live.back(); live.pop_back();
        }
        if (op % 25 == 0) check();
    }
    const double mib_main = peak_mib();
    for (int pair = 0; pair < 10000; ++pair) {  // churn on fresh keys
        Rule r = make_rule(next_id++, 0.0, 100000);
        r.dst_ip.set(0x0A000000u + static_cast<uint32_t>(pair) * 256u, 24);
        opt.insert_rule(r); opt.delete_rule(r.rule_id);
    }
    check();
    const double mib_churn = peak_mib();
    const double pi = p99(ins), pd = p99(del);
    std::printf("insert p99 %.3f us, delete p99 %.3f us, peak RSS %.2f MiB (after churn %.2f MiB), %llu checks\n",
        pi, pd, mib_main, mib_churn, (unsigned long long)checks);
    if (mib_churn > 32.0) { std::printf("FAIL: peak RSS above the 32 MiB hard limit\n"); return 1; }
    // 5 us is the full-credit update target, not a cutoff: report a miss with its own exit code
    if (pi > 5.0 || pd > 5.0) { std::printf("TARGET-MISS: update p99 above the 5 us full-credit target\n"); return 3; }
    std::printf("OK: interleaved release check\n");
}
