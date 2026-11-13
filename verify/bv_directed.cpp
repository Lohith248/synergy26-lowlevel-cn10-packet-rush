// Directed tests for the bit-vector residual of r4 (the random fuzzers reach these cases only rarely):
//   A. the largest legal rank (priority = id = UINT32_MAX) as the only match, for residual sizes around the
//      256-rule block edge;
//   B. a replace that lands exactly when the delta fills (the merge rebuilds the filter), repeated for victims
//      held in the filter and in the delta;
//   D. port classes: ranges that start on, end on and cross a 1024-port block boundary, unnamed exact ports, named
//      (frequent exact) ports inside ranges, packets at boundary -1, 0, +1, on dst_port and src_port;
//   C. deletes until the dead-position compaction fires, then re-inserts under the same ids.
// Every answer is compared with the linear reference. Exit 0 and "OK:" on success.
#include "classifier.h"
#include "linear_classifier.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>
using namespace packet_rush;

// A rule that only constrains dst_port (and optionally vlan): wildcard IPs keep it out of every hash table.
static Rule mk(uint32_t id, uint32_t prio, uint16_t dport, Action a, int vlan = -1) {
    Rule r;
    r.rule_id = id; r.priority = prio; r.action = a;
    r.dst_port.low = r.dst_port.high = dport;
    if (vlan >= 0) { r.vlan_id.wildcard = false; r.vlan_id.value = static_cast<uint16_t>(vlan); }
    return r;
}
static Packet pk(uint16_t dport, uint16_t vlan = 7) {
    Packet p{};
    p.src_ip = 0x0A010203; p.dst_ip = 0x0B040506; p.src_port = 1234; p.dst_port = dport;
    p.packet_len = 100; p.region_id = 3; p.vlan_id = vlan; p.protocol = 6; p.tcp_flags = 0x10;
    p.ingress_iface = 1; p.dscp = 10; p.icmp_type = 0; p.ttl = 64;
    return p;
}
static int g_fail = 0;
static void same(OptimizedClassifier& o, LinearClassifier& l, const std::vector<uint16_t>& ports, const char* what) {
    for (uint16_t d : ports)
        for (uint16_t v : {7, 8}) {
            const Packet p = pk(d, v);
            Packet batch[3] = {p, p, p};
            Action out[3];
            o.classify_batch(batch, 3, out);
            if (out[0] != l.classify(p) || out[1] != out[0] || o.classify(p) != out[0]) {
                std::printf("FAIL: %s dport=%u vlan=%u got=%d want=%d\n", what, d, v, int(out[0]), int(l.classify(p)));
                ++g_fail;
            }
        }
}

int main() {
    // A. maximum rank as the only match.
    for (uint32_t n : {128u, 129u, 255u, 256u, 257u, 300u, 512u, 513u, 600u}) {
        std::vector<Rule> rules;
        std::vector<uint16_t> ports{5, 9999, 40000};
        for (uint32_t i = 0; i + 1 < n; ++i) {
            rules.push_back(mk(i, i / 3 + 1, static_cast<uint16_t>(1000 + i), Action::ACCEPT));
            ports.push_back(static_cast<uint16_t>(1000 + i));
        }
        rules.push_back(mk(UINT32_MAX, UINT32_MAX, 5, Action::REJECT));
        OptimizedClassifier o; LinearClassifier l;
        o.initialize(rules); l.initialize(rules);
        char w[64]; std::snprintf(w, sizeof w, "A n=%u", n);
        same(o, l, ports, w);
        o.delete_rule(UINT32_MAX); l.delete_rule(UINT32_MAX);  // and gone again
        same(o, l, ports, "A after delete");
        o.insert_rule(mk(UINT32_MAX, UINT32_MAX, 5, Action::REDIRECT)); l.insert_rule(mk(UINT32_MAX, UINT32_MAX, 5, Action::REDIRECT));
        same(o, l, ports, "A re-insert");
    }
    // B. replaces at the merge boundary.
    for (uint32_t start : {200u, 260u, 700u}) {
        std::vector<Rule> rules;
        std::vector<uint16_t> ports{9999, 4000, 4001, 4002};
        for (uint32_t i = 0; i < start; ++i) {
            rules.push_back(mk(i, (i * 7) % 50 + 1, static_cast<uint16_t>(2000 + i), Action::ACCEPT, i % 3 ? int(i % 11) : -1));
            ports.push_back(static_cast<uint16_t>(2000 + i));
        }
        OptimizedClassifier o; LinearClassifier l;
        o.initialize(rules); l.initialize(rules);
        uint32_t next = 10000;
        for (int round = 0; round < 6; ++round) {
            for (int j = 0; j < 80; ++j) {  // fill past the delta capacity; the victim of the replace is picked below
                const bool replace = (j % 20 == 19);
                const uint32_t id = replace ? uint32_t((round * 37 + j * 5) % start) : next++;  // BV-held or fresh ids
                const uint16_t port = replace ? uint16_t(4000 + (j % 3)) : uint16_t(3000 + (next % 900));
                const Rule r = mk(id, uint32_t((j * 13 + round) % 60), port, replace ? Action::DROP : Action::REJECT, replace ? int(j % 5) : -1);
                o.insert_rule(r); l.insert_rule(r);
                ports.push_back(port);
                if (replace || j % 16 == 0) same(o, l, ports, "B step");
            }
            // replace a rule that sits in the delta right now
            const uint32_t d = next - 1;
            const Rule r = mk(d, 0, 4001, Action::ACCEPT);
            o.insert_rule(r); l.insert_rule(r);
            same(o, l, ports, "B delta replace");
        }
        // C. delete most of the original rules (compaction), then bring some back differently.
        for (uint32_t i = 0; i < start; ++i) {
            if (i % 10 == 3) continue;
            o.delete_rule(i); l.delete_rule(i);
            if (i % 25 == 0) same(o, l, ports, "C delete");
        }
        same(o, l, ports, "C after deletes");
        for (uint32_t i = 0; i < start; i += 4) {
            const Rule r = mk(i, (i % 9) + 1, static_cast<uint16_t>(2000 + (i % 50)), Action::REDIRECT, int(i % 4));
            o.insert_rule(r); l.insert_rule(r);
        }
        same(o, l, ports, "C re-insert");
        for (int pass = 0; pass < 3; ++pass)
            for (uint32_t i = 0; i < start; ++i) {
                o.delete_rule(i); l.delete_rule(i);
                o.delete_rule(10000 + i); l.delete_rule(10000 + i);
            }
        same(o, l, ports, "C everything deleted");
    }
    // D. hybrid port classes (blocks of 65536/64 = 1024 ports, plus the most frequent exact ports as their own class).
    for (int side = 0; side < 2; ++side)
        for (uint32_t seed : {1u, 2u, 3u}) {
            std::vector<Rule> rules;
            std::vector<uint32_t> probe{0, 1, 65534, 65535};
            auto mkr = [&](uint32_t id, uint32_t lo, uint32_t hi) {
                static const Action acts[4] = {Action::ACCEPT, Action::DROP, Action::REJECT, Action::REDIRECT};
                Rule r = mk(id, (id * 2654435761u + seed) % 977 + 1, 0, acts[(id + seed) % 4]);
                r.dst_port.low = 0; r.dst_port.high = 65535;
                Range16& pr = side ? r.src_port : r.dst_port;
                pr.low = static_cast<uint16_t>(lo); pr.high = static_cast<uint16_t>(hi);
                probe.push_back(lo); probe.push_back(hi);
                if (lo) probe.push_back(lo - 1);
                if (hi < 65535) probe.push_back(hi + 1);
                return r;
            };
            uint32_t id = 1;
            for (uint32_t j = 1; j < 64; ++j) {
                const uint32_t b = j * 1024;
                rules.push_back(mkr(id++, b, b + 30 + seed));            // starts on the boundary
                rules.push_back(mkr(id++, b - 30 - seed, b));            // ends on the boundary
                rules.push_back(mkr(id++, b - 30 - seed, b - 1));        // ends just below it
                rules.push_back(mkr(id++, b - 20 - seed, b + 20 + seed)); // crosses it
                rules.push_back(mkr(id++, b + 200 + seed, b + 200 + seed)); // exact, unnamed
                rules.push_back(mkr(id++, b - 3, b + 2));
                probe.push_back(b - 1); probe.push_back(b); probe.push_back(b + 1);
            }
            for (uint32_t k = 0; k < 40; ++k)                              // frequent exact ports: named classes
                for (uint32_t c = 0; c < 4 + (k % 3); ++c) rules.push_back(mkr(id++, 5000 + 97 * k, 5000 + 97 * k));
            // A large filter exercises block classes; the third seed also exhausts named exact-port classes.
            for (uint32_t k = 0; k < 600; ++k) rules.push_back(mkr(id++, 20000 + 41 * k, 20001 + 41 * k));
            if (seed == 3)
                for (uint32_t k = 0; k < 300; ++k) rules.push_back(mkr(id++, 20000 + 101 * k, 20000 + 101 * k));
            rules.push_back(mkr(id++, 4900, 9000));                          // named ports inside a long range
            rules.push_back(mkr(id++, 0, 65535));                            // wildcard-like
            rules.push_back(mkr(id++, 1024, 2047));                          // exactly one block
            rules.push_back(mkr(id++, 2048, 4095));                          // two whole blocks
            OptimizedClassifier o; LinearClassifier l;
            o.initialize(rules); l.initialize(rules);
            std::sort(probe.begin(), probe.end());
            probe.erase(std::unique(probe.begin(), probe.end()), probe.end());
            for (uint32_t v : probe)
                for (int w = 0; w < 2; ++w) {
                    Packet p = pk(0, w ? 8 : 7);
                    (side ? p.src_port : p.dst_port) = static_cast<uint16_t>(v);
                    if (o.classify(p) != l.classify(p)) {
                        std::printf("FAIL: D side=%d seed=%u port=%u\n", side, seed, v);
                        ++g_fail;
                    }
                }
        }
    if (g_fail) { std::printf("FAIL: %d mismatches\n", g_fail); return 1; }
    std::printf("OK: bv directed tests\n");
}
