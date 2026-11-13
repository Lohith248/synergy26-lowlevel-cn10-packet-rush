// Packet Rush live demo: one readable packet flips ACCEPT -> DROP -> ACCEPT through live rule
// insert/delete, checked against the organiser's LinearClassifier at every step, then a
// 100000-packet differential run. Exit code 0 only if every comparison agreed.
//
// Usage: flip [--rules file.bin]      (no --rules: 1000 random rules built in code)
#include "classifier.h"
#include "classifier_interface.h"
#include "io_utils.h"
#include "linear_classifier.h"
#include "types.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace packet_rush;

namespace {

bool g_tty = false;
const char* kGreen = "\033[32;1m";
const char* kRed = "\033[31;1m";
const char* kReset = "\033[0m";

std::string paint(Action a) {
    const char* name = action_to_string(a);
    if (!g_tty) return name;
    if (a == Action::ACCEPT) return std::string(kGreen) + name + kReset;
    if (a == Action::DROP) return std::string(kRed) + name + kReset;
    return name;
}

[[noreturn]] void die(const char* msg) {
    std::fprintf(stderr, "%sFAIL: %s%s\n", g_tty ? kRed : "", msg, g_tty ? kReset : "");
    std::exit(1);
}

using Clock = std::chrono::steady_clock;
double us_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
}

// Rule matching every packet (all wildcards); callers narrow it.
Rule wildcard_rule(RuleId id, Priority prio, Action act) {
    Rule r;
    r.rule_id = id;
    r.priority = prio;
    r.action = act;
    r.src_ip.set(0, 0);
    r.dst_ip.set(0, 0);
    r.src_port = {0, 65535};
    r.dst_port = {0, 65535};
    r.protocol = {0, true};
    r.tcp_flags = {0, 0};
    r.region_id = {0, true};
    r.ingress_iface = {0, true};
    r.vlan_id = {0, true};
    r.dscp = {0, true};
    r.packet_len = {0, 65535};
    r.icmp_type = {0, true};
    r.ttl = {0, 255};
    return r;
}

// Random but valid rule: each field constrained with some probability.
Rule random_rule(std::mt19937& g, RuleId id) {
    auto chance = [&](unsigned pct) { return (g() % 100) < pct; };
    Rule r = wildcard_rule(id, 10 + g() % 100000, static_cast<Action>(g() % 4));
    if (chance(60)) r.src_ip.set(g(), 8 + static_cast<int32_t>(g() % 25));
    if (chance(70)) r.dst_ip.set(g(), 8 + static_cast<int32_t>(g() % 25));
    if (chance(30)) {
        uint16_t a = static_cast<uint16_t>(g()), b = static_cast<uint16_t>(g());
        r.src_port = {std::min(a, b), std::max(a, b)};
    }
    if (chance(50)) {
        uint16_t a = static_cast<uint16_t>(g());
        r.dst_port = {a, static_cast<uint16_t>(std::min<uint32_t>(65535, a + g() % 2000))};
    }
    if (chance(60)) r.protocol = {static_cast<uint8_t>(chance(70) ? 6 : (chance(50) ? 17 : 1)), false};
    if (chance(15)) {
        uint8_t m = static_cast<uint8_t>(1u << (g() % 5));
        r.tcp_flags = {static_cast<uint8_t>(g() & m), m};
    }
    if (chance(20)) r.region_id = {static_cast<uint16_t>(g() % 8), false};
    if (chance(15)) r.ingress_iface = {static_cast<uint8_t>(g() % 8), false};
    if (chance(20)) r.vlan_id = {static_cast<uint16_t>(g() % 4096), false};
    if (chance(10)) r.dscp = {static_cast<uint8_t>(g() % 64), false};
    if (chance(15)) {
        uint32_t a = 20 + g() % 1500;
        r.packet_len = {static_cast<uint16_t>(a), static_cast<uint16_t>(a + g() % 2000)};
    }
    if (chance(5)) r.icmp_type = {static_cast<uint8_t>(g() % 16), false};
    if (chance(10)) {
        uint8_t a = static_cast<uint8_t>(g()), b = static_cast<uint8_t>(g());
        r.ttl = {std::min(a, b), std::max(a, b)};
    }
    return r;
}

uint32_t in_range(std::mt19937& g, uint32_t lo, uint32_t hi) {
    return lo + static_cast<uint32_t>(g() % (static_cast<uint64_t>(hi - lo) + 1));
}

Packet random_packet(std::mt19937& g) {
    Packet p;
    std::memset(&p, 0, sizeof p);
    p.src_ip = g();
    p.dst_ip = g();
    p.src_port = static_cast<uint16_t>(g());
    p.dst_port = static_cast<uint16_t>(g());
    p.packet_len = static_cast<uint16_t>(in_range(g, 20, 65535));
    p.region_id = static_cast<uint16_t>(g() % 8);
    p.vlan_id = static_cast<uint16_t>(g() % 4096);
    p.protocol = static_cast<uint8_t>((g() & 3) ? 6 : 17);
    p.tcp_flags = static_cast<uint8_t>(g());
    p.ingress_iface = static_cast<uint8_t>(g() % 8);
    p.dscp = static_cast<uint8_t>(g() % 64);
    p.icmp_type = static_cast<uint8_t>(g() % 16);
    p.ttl = static_cast<uint8_t>(g());
    return p;
}

// Packet drawn from inside a rule's match region (may still be shadowed by a better rule).
Packet packet_for_rule(std::mt19937& g, const Rule& r) {
    Packet p = random_packet(g);
    p.src_ip = (g() & ~r.src_ip.mask) | r.src_ip.ip;
    p.dst_ip = (g() & ~r.dst_ip.mask) | r.dst_ip.ip;
    p.src_port = static_cast<uint16_t>(in_range(g, r.src_port.low, r.src_port.high));
    p.dst_port = static_cast<uint16_t>(in_range(g, r.dst_port.low, r.dst_port.high));
    if (!r.protocol.wildcard) p.protocol = r.protocol.value;
    p.tcp_flags = static_cast<uint8_t>((p.tcp_flags & ~r.tcp_flags.mask) | (r.tcp_flags.value & r.tcp_flags.mask));
    if (!r.region_id.wildcard) p.region_id = r.region_id.value;
    if (!r.ingress_iface.wildcard) p.ingress_iface = r.ingress_iface.value;
    if (!r.vlan_id.wildcard) p.vlan_id = r.vlan_id.value;
    if (!r.dscp.wildcard) p.dscp = r.dscp.value;
    p.packet_len = static_cast<uint16_t>(in_range(g, r.packet_len.low, r.packet_len.high));
    if (!r.icmp_type.wildcard) p.icmp_type = r.icmp_type.value;
    p.ttl = static_cast<uint8_t>(in_range(g, r.ttl.low, r.ttl.high));
    return p;
}

std::string describe(const Packet& p) {
    char buf[240];
    std::snprintf(buf, sizeof buf, "%s:%u -> %s:%u proto %u flags 0x%02X region %u vlan %u iface %u dscp %u ttl %u len %u",
                  ip_to_string(p.src_ip).c_str(), p.src_port, ip_to_string(p.dst_ip).c_str(), p.dst_port, p.protocol,
                  p.tcp_flags, p.region_id, p.vlan_id, p.ingress_iface, p.dscp, p.ttl, p.packet_len);
    return buf;
}

struct Engines {
    OptimizedClassifier ours;
    LinearClassifier base;
};

// Classify with both engines; die loudly on disagreement. Returns the verdict.
Action verdict(Engines& e, const Packet& p, const char* step) {
    Action a = e.ours.classify(p);
    Action b = e.base.classify(p);
    if (a != b) {
        std::fprintf(stderr, "step %s: ours=%s baseline=%s\n", step, action_to_string(a), action_to_string(b));
        die("engine disagrees with the organiser baseline");
    }
    return a;
}

void expect(Action got, Action want, const char* step) {
    if (got != want) {
        std::fprintf(stderr, "step %s: expected %s, got %s\n", step, action_to_string(want), action_to_string(got));
        die("unexpected verdict");
    }
}

}  // namespace

int main(int argc, char** argv) {
    g_tty = isatty(STDOUT_FILENO) != 0;
    std::string rules_path;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--rules") == 0 && i + 1 < argc) {
            rules_path = argv[++i];
        } else {
            std::fprintf(stderr, "usage: %s [--rules file.bin]\n", argv[0]);
            return 2;
        }
    }
    std::mt19937 g(12345);

    // a. rule set + both engines
    std::vector<Rule> rules;
    if (!rules_path.empty()) {
        if (!load_rules_binary(rules_path, rules)) die("could not load rules file");
    } else {
        for (RuleId i = 1; i <= 1000; ++i) rules.push_back(random_rule(g, i));
    }
    Engines e;
    e.ours.initialize(rules);
    e.base.initialize(rules);
    std::printf("[a] rules: %zu (%s); engines ready: %s + %s\n", rules.size(),
                rules_path.empty() ? "random, built in code" : rules_path.c_str(), e.ours.name(), e.base.name());

    // b. fixed packet; make ACCEPT its verdict
    Packet pkt;
    std::memset(&pkt, 0, sizeof pkt);
    pkt.src_ip = string_to_ip("10.1.2.3");
    pkt.dst_ip = string_to_ip("192.168.7.9");
    pkt.src_port = 51000;
    pkt.dst_port = 443;
    pkt.protocol = 6;
    pkt.tcp_flags = 0x02;  // SYN
    pkt.region_id = 3;
    pkt.vlan_id = 100;
    pkt.ingress_iface = 2;
    pkt.dscp = 0;
    pkt.ttl = 64;
    pkt.packet_len = 1500;
    std::printf("[b] packet: %s (TCP SYN)\n", describe(pkt).c_str());

    Priority best = UINT32_MAX;
    RuleId max_id = 0;
    for (const Rule& r : rules) {
        max_id = std::max(max_id, r.rule_id);
        if (r.matches(pkt)) best = std::min(best, r.priority);
    }
    Priority accept_prio = 1000;
    if (best != UINT32_MAX) {
        if (best < 2) die("existing rules leave no priority slot below this packet's best match");
        accept_prio = best - 1;
        std::printf("    best existing match has priority %u (lower number wins), so the ACCEPT rule gets priority %u\n", best,
                    accept_prio);
    } else {
        std::printf("    no existing rule matches (default verdict is DROP); the ACCEPT rule gets priority %u\n", accept_prio);
    }
    const Priority drop_prio = accept_prio - 1;  // strictly better (lower) than the ACCEPT rule
    const RuleId accept_id = max_id + 1, drop_id = max_id + 2;

    Rule acc = wildcard_rule(accept_id, accept_prio, Action::ACCEPT);
    acc.src_ip.set(pkt.src_ip, 32);
    acc.dst_ip.set(pkt.dst_ip, 32);
    acc.src_port = {pkt.src_port, pkt.src_port};
    acc.dst_port = {pkt.dst_port, pkt.dst_port};
    acc.protocol = {pkt.protocol, false};
    acc.tcp_flags = {pkt.tcp_flags, 0xFF};
    acc.region_id = {pkt.region_id, false};
    acc.ingress_iface = {pkt.ingress_iface, false};
    acc.vlan_id = {pkt.vlan_id, false};
    acc.dscp = {pkt.dscp, false};
    acc.packet_len = {pkt.packet_len, pkt.packet_len};
    acc.icmp_type = {pkt.icmp_type, false};
    acc.ttl = {pkt.ttl, pkt.ttl};
    e.ours.insert_rule(acc);
    e.base.insert_rule(acc);
    Action v = verdict(e, pkt, "b");
    expect(v, Action::ACCEPT, "b");
    std::printf("[b] verdict: %s  (rule %u: exact-match ACCEPT, priority %u)   baseline agrees\n", paint(v).c_str(), accept_id,
                accept_prio);

    // c. live insert of a better-priority DROP on the destination /24
    Rule drop = wildcard_rule(drop_id, drop_prio, Action::DROP);
    drop.dst_ip.set(pkt.dst_ip, 24);
    auto t0 = Clock::now();
    e.ours.insert_rule(drop);
    double ins_us = us_since(t0);
    e.base.insert_rule(drop);
    v = verdict(e, pkt, "c");
    expect(v, Action::DROP, "c");
    std::printf("[c] insert rule %u (DROP dst %s/24, priority %u): verdict: %s (insert took %.2f us)   baseline agrees\n", drop_id,
                ip_to_string(pkt.dst_ip & 0xFFFFFF00U).c_str(), drop_prio, paint(v).c_str(), ins_us);

    // d. live delete
    t0 = Clock::now();
    e.ours.delete_rule(drop_id);
    double del_us = us_since(t0);
    e.base.delete_rule(drop_id);
    v = verdict(e, pkt, "d");
    expect(v, Action::ACCEPT, "d");
    std::printf("[d] delete rule %u: verdict: %s (delete took %.2f us)   baseline agrees\n", drop_id, paint(v).c_str(), del_us);

    // f. differential run (step e, baseline agreement, is checked inside every step above)
    std::vector<Rule> live = rules;
    live.push_back(acc);  // the engines' current rule set (the DROP rule is deleted again)
    constexpr size_t kN = 100000, kBatch = 64;
    std::vector<Packet> pkts(kN);
    for (size_t i = 0; i < kN; ++i) {
        pkts[i] = (i & 1) ? packet_for_rule(g, live[g() % live.size()]) : random_packet(g);
    }
    std::vector<Action> out_ours(kN), out_base(kN);
    t0 = Clock::now();
    for (size_t i = 0; i < kN; i += kBatch) e.ours.classify_batch(&pkts[i], std::min(kBatch, kN - i), &out_ours[i]);
    double secs = us_since(t0) / 1e6;
    for (size_t i = 0; i < kN; i += kBatch) e.base.classify_batch(&pkts[i], std::min(kBatch, kN - i), &out_base[i]);
    size_t diffs = 0, accepts = 0;
    for (size_t i = 0; i < kN; ++i) {
        diffs += out_ours[i] != out_base[i];
        accepts += out_base[i] == Action::ACCEPT;
    }
    if (diffs != 0) {
        std::fprintf(stderr, "%zu differences in %zu packets\n", diffs, kN);
        die("differential check failed");
    }
    std::printf("[f] %zu packets: 0 differences (half crafted to hit rules, batches of 64; %zu ACCEPT, %zu other)\n", kN, accepts,
                kN - accepts);
    std::printf("    ours: %.2f Mpps over this run (this machine, not a benchmark)\n", static_cast<double>(kN) / secs / 1e6);
    std::printf("%sRESULT: all checks passed%s\n", g_tty ? kGreen : "", g_tty ? kReset : "");
    return 0;
}
