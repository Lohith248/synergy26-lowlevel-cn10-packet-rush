// WIDE-POOL variant of tools/churn.cpp (r4 gate). Only the generators and the per-iteration wide_begin() differ.
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


// Heavy-churn memory check (review finding 3): `base` live rules (15,000 or 128), then 250,000 insert/delete
// pairs, each inserted rule pinned to a never-before-seen destination so it opens new hash keys
// and buckets. Verdicts are checked against the reference every 5,000 pairs. Fails if peak RSS
// reaches 32 MiB or the p99 of the 500,000 timed updates exceeds 5 us.
#include <algorithm>
#include <chrono>
#include <sys/resource.h>
static double peak_mib() { rusage u{}; getrusage(RUSAGE_SELF, &u); return u.ru_maxrss / 1024.0; }

int main(int argc, char** argv) {
    const uint64_t pairs = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 250000;
    const uint32_t base = argc > 2 ? static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 10)) : 15000;
    rng.seed(4242 + (argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0));
    wide_begin(0);
    std::vector<Rule> live;
    for (uint32_t i = 0; i < base; ++i) live.push_back(make_rule(i, 0.3, 100000));
    OptimizedClassifier opt; LinearClassifier ref;
    opt.initialize(live); ref.initialize(live);
    // Latency histogram in 10 ns bins up to 100 us (overflow in the last bin): fixed memory,
    // so the test's own bookkeeping doesn't grow with the pair count and skew peak RSS.
    std::vector<uint64_t> hist(10001, 0);
    double worst = 0;
    auto timed = [&](auto&& f) {
        const auto t0 = std::chrono::steady_clock::now(); f();
        const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count();
        worst = std::max(worst, us);
        ++hist[std::min<size_t>(10000, static_cast<size_t>(us * 100))];
    };
    uint64_t checks = 0;
    for (uint64_t k = 0; k < pairs; ++k) {
        Rule r = make_rule(static_cast<uint32_t>(100000 + k), 0.0, 100000);
        // fresh /24 (and so /16 every 256 pairs) on both addresses, and a rotating exact port,
        // so whichever dimensions the planner chose, the rule opens new hash keys
        r.dst_ip.set((static_cast<uint32_t>(k) << 8) | 1u, 32);
        r.src_ip.set(((static_cast<uint32_t>(k) * 2654435761u) & 0xFFFFFF00u) | 2u, 32);
        r.dst_port.low = r.dst_port.high = static_cast<uint16_t>(k);
        timed([&] { opt.insert_rule(r); });
        if (k % 5000 == 0) {
            ref.insert_rule(r);
            std::vector<Packet> pk(64);
            for (auto& p : pk) p = make_packet(live);
            pk[0].dst_ip = r.dst_ip.ip; pk[0].src_ip = r.src_ip.ip; pk[0].dst_port = r.dst_port.low;
            std::vector<Action> a(pk.size());
            opt.classify_batch(pk.data(), pk.size(), a.data());
            for (size_t i = 0; i < pk.size(); ++i)
                if (a[i] != ref.classify(pk[i])) { std::printf("FAIL: mismatch during churn (pair %llu)\n", (unsigned long long)k); return 1; }
            checks += pk.size();
            ref.delete_rule(r.rule_id);
        }
        timed([&] { opt.delete_rule(r.rule_id); });
    }
    const uint64_t rank = (2 * pairs * 99 + 99) / 100;  // nearest-rank p99
    uint64_t seen = 0; size_t bin = 0;
    while (bin < hist.size() && (seen += hist[bin]) < rank) ++bin;
    const double p99 = (bin + 1) / 100.0;  // upper edge of the bin
    const double mib = peak_mib();
    std::printf("churn: %llu pairs, update p99 %.3f us, max %.1f us, peak RSS %.2f MiB, %llu checks\n",
        (unsigned long long)pairs, p99, worst, mib, (unsigned long long)checks);
    if (mib >= 32.0) { std::printf("FAIL: peak RSS at or above the 32 MiB hard limit\n"); return 1; }
    if (p99 > 5.0) { std::printf("TARGET-MISS: update p99 above the 5 us full-credit target\n"); return 3; }
    std::printf("OK: churn release check\n");
}
