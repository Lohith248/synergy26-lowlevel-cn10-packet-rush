// WIDE-POOL variant of tools/fuzz.cpp (r4 gate): generators come from widegen.h, wide_begin() per iteration.
// Differential fuzzer: OptimizedClassifier vs the pack's LinearClassifier (golden oracle).
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

#define TR(x) ((void)0)
static std::mt19937_64 rng;
static uint32_t U(uint32_t n) { return static_cast<uint32_t>(rng() % n); }
static bool coin(double p) { return std::uniform_real_distribution<double>(0, 1)(rng) < p; }

// Boundary mode (every 4th iteration): rule IDs count down from UINT32_MAX and many rules
// carry priority UINT32_MAX or UINT32_MAX - 1, so the largest legal rank is exercised.
static bool g_extreme = false;
[[maybe_unused]] static uint32_t idmap(uint32_t i) { return g_extreme ? UINT32_MAX - i : i; }

// WIDE pools: generators live in widegen.h (original narrow make_rule/make_packet removed).
#include "widegen.h"

// Fixed reproducers for the maximum legal rank (priority = rule_id = UINT32_MAX): a lone
// match-all rule, the same rule behind 39 non-matching better-ranked rules, and both again
// when the rule arrives by insert_rule after initialize, and by same-ID replacement.
static uint64_t boundary_cases() {
    uint64_t checks = 0;
    Rule top{};
    top.rule_id = UINT32_MAX; top.priority = UINT32_MAX; top.action = Action::ACCEPT;
    std::vector<Rule> blockers;
    for (uint32_t i = 0; i < 39; ++i) {  // exact on dst_port 9999, which no probe packet uses
        Rule r{};
        r.rule_id = i; r.priority = i; r.action = Action::REJECT;
        r.dst_port.low = r.dst_port.high = 9999;
        r.vlan_id = {static_cast<uint16_t>(i % 3), false};
        blockers.push_back(r);
    }
    std::vector<std::vector<Rule>> sets{{top}, blockers};
    sets[1].push_back(top);
    for (int variant = 0; variant < 6; ++variant) {
        const std::vector<Rule>& set = sets[variant % 2];
        OptimizedClassifier opt; LinearClassifier ref;
        if (variant < 2) { opt.initialize(set); ref.initialize(set); }
        else {
            std::vector<Rule> rest(set.begin(), set.end() - 1);
            opt.initialize(rest); ref.initialize(rest);
            Rule first = set.back();
            if (variant >= 4) {  // arrive as a replacement of a different rule with the same ID
                first.action = Action::REDIRECT; first.priority = 5; first.dst_port.low = first.dst_port.high = 9999;
                opt.insert_rule(first); ref.insert_rule(first);
            }
            opt.insert_rule(set.back()); ref.insert_rule(set.back());
        }
        rng.seed(77 + variant);
        wide_begin(77 + variant);
        std::vector<Packet> pk(256);
        for (auto& p : pk) { p = make_packet({}); if (p.dst_port == 9999) p.dst_port = 9998; }  // 9999 belongs to the blockers
        std::vector<Action> a(pk.size());
        opt.classify_batch(pk.data(), pk.size(), a.data());
        for (size_t i = 0; i < pk.size(); ++i) {
            const Action e = ref.classify(pk[i]);
            if (e != Action::ACCEPT || a[i] != e || opt.classify(pk[i]) != e) {
                std::printf("MISMATCH boundary variant=%d pkt=%zu got=%d single=%d want=%d\n",
                    variant, i, (int)a[i], (int)opt.classify(pk[i]), (int)e);
                std::exit(1);
            }
        }
        checks += pk.size();
    }
    return checks;
}

int main(int argc, char** argv) {
    const uint64_t iters = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 200;
    const uint64_t first = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0;  // wide variant: iteration offset (new seeds)
    uint64_t checks = boundary_cases(), updates = 0;
    for (uint64_t it = first; it < first + iters; ++it) {
        rng.seed(1000 + it);
        g_extreme = it % 4 == 1;
        wide_begin(it);
        const double wc = std::vector<double>{0.0, 0.3, 0.65, 0.9, 1.0}[it % 5];
        const uint32_t n = std::vector<uint32_t>{0, 1, 50, 600, 3000}[(it / 5) % 5];
        const uint32_t prio_range = coin(0.5) ? 8 : 100000;  // many ties vs few
        std::vector<Rule> live;
        for (uint32_t i = 0; i < n; ++i) live.push_back(make_rule(idmap(i), wc, prio_range));
        OptimizedClassifier opt; LinearClassifier ref;
        opt.initialize(live); ref.initialize(live);
        TR(std::printf("INIT n=%zu\n", live.size()); for (auto& r : live) wrule(r));
        auto check = [&](int rounds) {
            std::vector<Packet> pk(static_cast<size_t>(rounds));
            for (auto& p : pk) p = make_packet(live);
            std::vector<Action> a(pk.size());
            size_t off = 0;
            while (off < pk.size()) {  // mixed batch sizes incl. partial / size 1
                size_t len = std::min<size_t>(pk.size() - off, 1 + U(64));
                opt.classify_batch(pk.data() + off, len, a.data() + off); off += len;
            }
            for (size_t i = 0; i < pk.size(); ++i) {
                Action e = ref.classify(pk[i]);
                if (a[i] != e || opt.classify(pk[i]) != e) {
                    std::printf("MISMATCH iter=%llu n=%u wc=%.2f pkt=%zu got=%d want=%d\n",
                        (unsigned long long)it, n, wc, i, (int)a[i], (int)e);
                    wdump(live, pk[i]);
                    std::exit(1);
                }
            }
            checks += pk.size();
        };
        check(256);
        uint32_t next_id = n;
        for (int step = 0; step < 300; ++step) {
            int op = static_cast<int>(U(10));
            if (op < 4) {                       // insert new or reuse a deleted id
                Rule r = make_rule(idmap(coin(0.2) ? U(next_id + 1) : next_id++), wc, prio_range);
                opt.insert_rule(r); ref.insert_rule(r);
                bool found = false;
                for (auto& x : live) if (x.rule_id == r.rule_id) { x = r; found = true; }
                if (!found) live.push_back(r);
            } else if (op < 6 && !live.empty()) {  // replace a live id with a different rule
                uint32_t k = U(static_cast<uint32_t>(live.size()));
                Rule r = make_rule(live[k].rule_id, wc, prio_range);
                opt.insert_rule(r); ref.insert_rule(r); live[k] = r;
            } else if (op < 9 && !live.empty()) {  // real delete
                uint32_t k = U(static_cast<uint32_t>(live.size()));
                opt.delete_rule(live[k].rule_id); ref.delete_rule(live[k].rule_id);
                live.erase(live.begin() + k);
            } else {                                // delete of a missing id
                opt.delete_rule(idmap(next_id + 7)); ref.delete_rule(idmap(next_id + 7));
            }
            ++updates;
            if (step % 10 == 0) check(64);
        }
        check(256);
        if (it % 7 == 3) { opt.initialize(live); ref.initialize(live); check(128); }  // re-init
    }
    std::printf("OK: %llu differential checks, %llu updates, %llu iterations\n",
        (unsigned long long)checks, (unsigned long long)updates, (unsigned long long)iters);
}
