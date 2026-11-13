// widegen.h -- WIDE-pool rule and packet generators for the r4 gate (replaces the narrow
// make_rule/make_packet that fuzz.cpp, alloc_fail.cpp, interleaved.cpp and churn.cpp each carry).
//
// Include AFTER rng, U(), coin(), g_extreme and idmap() are defined, in place of the
// "Small value pools" block. Call wide_begin(seed) once per iteration (right after rng.seed):
// it draws a PROFILE (value domains, pool sizes, interval-boundary counts, IP structure,
// rule-shape mix) so that different iterations stress different class-map regimes:
//   * vlan / region: small, 0..4095, 4096..65535, edge-heavy (near 255/256/4095/4096/65535)
//   * IP: all 256 top bytes, nested /8 /16 /24 sharing, every bit (incl. bits 24-29), all prefix lengths
//   * ports / packet_len / ttl: exact-only, few ranges, hundreds of distinct boundaries (>255 intervals)
//     and >62 distinct exact ports, skewed picks so a few values are hot and many are rare
//   * dscp over 0..255 (>= 64), tcp flags many distinct (value,mask) incl. value bits outside the mask
//   * proto / iface / icmp over 0..255
//   * rule shapes: catch-all, near-catch-all, residual-heavy (short IP prefixes, other fields wildcard),
//     clones of earlier rules (identical match, different id/priority), priority 0 and priority ties
// Packets share the rule pools, are steered to match a chosen rule on every field, and half of
// the steered ones are then moved just OUTSIDE one field (off-by-one range edge, flipped prefix bit,
// flipped exact bit, flipped mask bit) so each class-map edge is probed.
#pragma once
#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

struct WDom { int kind = 1; uint32_t maxv = 255; uint32_t clamp = 256; };
// kinds: 0 small(0..7)  1 uniform(0..maxv)  2 edge-heavy  3 mixed  4 "valid" (0..min(maxv,clamp-1))  5 near-clamp
static uint32_t wdom_gen(const WDom& d, int kind = -1) {
    if (kind < 0) kind = d.kind;
    switch (kind) {
        case 0: return U(std::min<uint32_t>(d.maxv + 1, 8));
        case 1: return U(d.maxv + 1);
        case 2: {
            static const uint32_t e[] = {0, 1, 2, 62, 63, 64, 65, 126, 127, 128, 129, 254, 255, 256, 257, 1023, 1024,
                                         4094, 4095, 4096, 4097, 8191, 8192, 32767, 32768, 65534, 65535};
            const uint32_t v = e[U(static_cast<uint32_t>(sizeof e / sizeof *e))];
            return v > d.maxv ? d.maxv - std::min<uint32_t>(U(3), d.maxv) : v;
        }
        case 3: { static const int ks[] = {0, 1, 2, 4, 5}; return wdom_gen(d, ks[U(5)]); }
        case 4: return U(std::min<uint32_t>(d.maxv, d.clamp - 1) + 1);
        default: {  // near-clamp: clamp-3 .. clamp+3 (and the top value)
            if (coin(0.15)) return d.maxv;
            const uint32_t v = d.clamp - 3 + U(7);
            return v > d.maxv ? d.maxv : v;
        }
    }
}
struct WPool {
    WDom d; std::vector<uint32_t> v; double fresh = 0.06;  // P(rule value drawn fresh from the domain instead of the pool)
    void build(const WDom& dom, uint32_t n) { d = dom; v.resize(n); for (auto& x : v) x = wdom_gen(d); }
    uint32_t rule_val() const {  // skewed: a few hot values, many rare ones
        if (v.empty() || coin(fresh)) return wdom_gen(d);
        const uint32_t n = static_cast<uint32_t>(v.size());
        return coin(0.5) ? v[U(n)] : v[(U(n) * U(n)) / n];
    }
    uint32_t pkt_val() const {
        if (v.empty() || coin(0.3)) return coin(0.5) ? U(d.maxv + 1) : wdom_gen(d);
        return v[U(static_cast<uint32_t>(v.size()))];
    }
};
static WDom wrdom(uint32_t maxv, uint32_t clamp) {
    WDom d; d.maxv = maxv; d.clamp = clamp;
    const uint32_t r = U(100);
    d.kind = r < 12 ? 0 : r < 38 ? 1 : r < 52 ? 2 : r < 78 ? 3 : r < 90 ? 4 : 5;
    return d;
}
static uint32_t wpick_n() { static const uint32_t s[] = {1, 2, 3, 8, 40, 300}; return s[U(6)]; }

struct WProf {
    WPool vlan, region, iface, proto, icmp, dscp, sport, dport, plen, ttl;
    double exact_p[4] = {0.5, 0.5, 0.5, 0.5};  // sport dport plen ttl: P(exact) for a non-wildcard rule field
    std::vector<uint32_t> tops, sec, thr, ippool;
    int len_mode = 0;
    std::vector<std::pair<uint8_t, uint8_t>> flagpool;
    double p_catch = 0, p_near = 0, p_resid = 0, p_clone = 0, p_steer = 0.6, p_miss = 0.5;
    int prio_mode = 0;  // 0 caller's prio_range, 1 tiny ties incl. 0, 2 huge range
    std::vector<Rule> recent;
};
static WProf g_w;

static uint32_t wip_fresh() {
    if (g_w.ippool.empty() || coin(0.05)) return static_cast<uint32_t>(rng());
    return g_w.ippool[U(static_cast<uint32_t>(g_w.ippool.size()))];
}
static void wide_begin(uint64_t seed) {
    (void)seed;
    WProf& w = g_w; w = WProf{};
    w.vlan.build(wrdom(65535, 4096), wpick_n());
    w.region.build(wrdom(65535, 256), wpick_n());
    w.iface.build(wrdom(255, 256), wpick_n());
    w.proto.build(wrdom(255, 256), wpick_n());
    w.icmp.build(wrdom(255, 256), wpick_n());
    w.dscp.build(wrdom(255, 64), wpick_n());
    static const uint32_t bsz[] = {2, 5, 30, 62, 63, 70, 200, 700};
    static const double exs[] = {0.0, 0.3, 0.7, 1.0};
    w.sport.build(wrdom(65535, 256), bsz[U(8)]);
    w.dport.build(wrdom(65535, 256), bsz[U(8)]);
    w.plen.build(wrdom(65535, 256), bsz[U(8)]);
    w.ttl.build(wrdom(255, 256), std::min<uint32_t>(bsz[U(8)], 256));
    for (double& e : w.exact_p) e = exs[U(4)];
    // "spread" profiles: uniform domain, thousands of pool values, many fresh draws -> hundreds of distinct
    // exact values / interval boundaries (more than 255 elementary intervals once there are enough rules)
    for (WPool* p : {&w.sport, &w.dport, &w.plen, &w.ttl})
        if (coin(0.3)) { WDom dd = p->d; dd.kind = 1; p->build(dd, 2500); p->fresh = 0.3; }
    // IP structure: T top bytes x S2 second bytes x S3 third bytes, free low byte
    static const uint32_t T[] = {1, 2, 4, 16, 256}, S2[] = {1, 2, 4, 64}, S3[] = {1, 3, 40};
    const uint32_t t = T[U(5)], s2 = S2[U(4)], s3 = S3[U(3)];
    for (uint32_t i = 0; i < t; ++i) w.tops.push_back(t == 256 ? i : (coin(0.3) ? U(4) : U(256)));
    for (uint32_t i = 0; i < s2; ++i) w.sec.push_back(coin(0.3) ? U(4) : U(256));
    for (uint32_t i = 0; i < s3; ++i) w.thr.push_back(coin(0.3) ? U(4) : U(256));
    static const uint32_t ipn[] = {4, 32, 300, 1500};
    const uint32_t nip = ipn[U(4)];
    for (uint32_t i = 0; i < nip; ++i)
        w.ippool.push_back((w.tops[U(t)] << 24) | (w.sec[U(s2)] << 16) | (w.thr[U(s3)] << 8) | U(256));
    w.len_mode = static_cast<int>(U(4));
    const uint32_t nf = std::vector<uint32_t>{2, 8, 40, 200}[U(4)];
    for (uint32_t i = 0; i < nf; ++i) {
        uint8_t mask;
        switch (U(7)) {
            case 0: mask = 0xFF; break;
            case 1: mask = static_cast<uint8_t>(1u << U(8)); break;
            case 2: mask = static_cast<uint8_t>(U(256)); break;
            case 3: mask = static_cast<uint8_t>(U(256) & U(256)); break;
            case 4: { static const uint8_t m[] = {0x02, 0x12, 0x10, 0x29, 0x3F, 0x17, 0xC0}; mask = m[U(7)]; break; }
            case 5: mask = static_cast<uint8_t>(1 + U(255)); break;
            default: mask = 0; break;
        }
        uint8_t val = static_cast<uint8_t>(U(256));
        if (coin(0.4)) val &= mask;  // else value bits outside the mask are kept on purpose
        w.flagpool.push_back({val, mask});
    }
    static const double pc[] = {0.0, 0.0, 0.01, 0.05, 0.2}, pn[] = {0.0, 0.0, 0.05, 0.15, 0.4},
                        pr[] = {0.0, 0.0, 0.1, 0.4, 0.8}, pl[] = {0.0, 0.0, 0.05, 0.2};
    w.p_catch = pc[U(5)]; w.p_near = pn[U(5)]; w.p_resid = pr[U(5)]; w.p_clone = pl[U(4)];
    w.p_steer = coin(0.5) ? 0.6 : 0.9; w.p_miss = coin(0.5) ? 0.5 : 0.2;
    w.prio_mode = coin(0.6) ? 0 : (coin(0.7) ? 1 : 2);
}

// ---- rule fields ---------------------------------------------------------------------------
static int wlen() {
    switch (g_w.len_mode) {
        case 0: return static_cast<int>(U(33));
        case 1: { static const int c[] = {8, 16, 24, 32, 12, 20, 28, 0}; return c[U(8)]; }
        case 2: return static_cast<int>(U(17));
        default: return static_cast<int>(17 + U(16));
    }
}
// mode: 0 wildcard, 1 normal, 2 short (1..15)
static void w_ip(Prefix32& p, int mode) {
    const uint32_t ip = wip_fresh();
    p.set(ip, mode == 0 ? 0 : mode == 2 ? static_cast<int32_t>(1 + U(15)) : wlen());
}
static void w_range(WPool& pool, double exact_p, bool wild, uint32_t wlo, uint32_t hi_lim, uint32_t& lo, uint32_t& hi) {
    if (wild) { lo = wlo; hi = hi_lim; return; }
    if (coin(exact_p)) { lo = hi = pool.rule_val(); return; }
    uint32_t a = pool.rule_val(), b = pool.rule_val();
    if (a > b) std::swap(a, b);
    if (coin(0.12)) b = hi_lim; else if (coin(0.12)) a = std::min(a, wlo);  // always a valid range (low <= high): the engines drop invalid rules, the baseline does not
    lo = a; hi = b;
}
static void w_exact8(ExactOrWildcard8& f, const WPool& p, bool wild) { f.wildcard = wild; f.value = static_cast<uint8_t>(wild ? U(256) : p.rule_val()); }
static void w_exact16(ExactOrWildcard16& f, const WPool& p, bool wild) { f.wildcard = wild; f.value = static_cast<uint16_t>(wild ? U(65536) : p.rule_val()); }
static void w_flags(Masked8& f, bool wild) {
    if (wild) { f.value = static_cast<uint8_t>(U(256)); f.mask = 0; return; }
    if (coin(0.85)) { auto pr = g_w.flagpool[U(static_cast<uint32_t>(g_w.flagpool.size()))]; f.value = pr.first; f.mask = pr.second; }
    else { f.value = static_cast<uint8_t>(U(256)); f.mask = static_cast<uint8_t>(U(256)); }
}
// field indices: 0 src_ip 1 dst_ip 2 src_port 3 dst_port 4 proto 5 flags 6 region 7 iface 8 vlan 9 dscp 10 plen 11 icmp 12 ttl
// wild[f] true = wildcard; ipmode[0..1] 0/1/2
static void w_fields(Rule& r, const bool (&wild)[13], const int (&ipm)[2]) {
    w_ip(r.src_ip, ipm[0]); w_ip(r.dst_ip, ipm[1]);
    uint32_t lo, hi;
    w_range(g_w.sport, g_w.exact_p[0], wild[2], 0, 65535, lo, hi); r.src_port.low = uint16_t(lo); r.src_port.high = uint16_t(hi);
    w_range(g_w.dport, g_w.exact_p[1], wild[3], 0, 65535, lo, hi); r.dst_port.low = uint16_t(lo); r.dst_port.high = uint16_t(hi);
    w_exact8(r.protocol, g_w.proto, wild[4]);
    w_flags(r.tcp_flags, wild[5]);
    w_exact16(r.region_id, g_w.region, wild[6]);
    w_exact8(r.ingress_iface, g_w.iface, wild[7]);
    w_exact16(r.vlan_id, g_w.vlan, wild[8]);
    w_exact8(r.dscp, g_w.dscp, wild[9]);
    w_range(g_w.plen, g_w.exact_p[2], wild[10], coin(0.7) ? 20 : 0, 65535, lo, hi); r.packet_len.low = uint16_t(lo); r.packet_len.high = uint16_t(hi);
    w_exact8(r.icmp_type, g_w.icmp, wild[11]);
    w_range(g_w.ttl, g_w.exact_p[3], wild[12], 0, 255, lo, hi); r.ttl.low = uint8_t(lo); r.ttl.high = uint8_t(hi);
}
static Rule make_rule(uint32_t id, double wc, uint32_t prio_range) {
    Rule r{};
    bool wild[13]; int ipm[2] = {1, 1};
    const double x = std::uniform_real_distribution<double>(0, 1)(rng);
    if (!g_w.recent.empty() && x < g_w.p_clone) {  // identical match, new identity
        r = g_w.recent[U(static_cast<uint32_t>(g_w.recent.size()))];
    } else {
        for (bool& b : wild) b = coin(wc);
        if (x < g_w.p_clone + g_w.p_catch) {
            for (bool& b : wild) b = true;
            ipm[0] = ipm[1] = 0;
        }
        else if (x < g_w.p_clone + g_w.p_catch + g_w.p_near) {
            for (bool& b : wild) b = true;
            ipm[0] = ipm[1] = 0;
            const uint32_t f = U(13);
            if (f < 2) ipm[f] = 1; else wild[f] = false;
        } else if (x < g_w.p_clone + g_w.p_catch + g_w.p_near + g_w.p_resid) {
            for (int f = 2; f < 13; ++f) wild[f] = true;  // everything IP-hash-friendly is wildcard
            ipm[0] = coin(0.8) ? 2 : 0; ipm[1] = coin(0.8) ? 2 : 0;
            for (uint32_t k = U(3); k > 0; --k) { static const int ff[] = {4, 5, 6, 7, 8, 9, 10, 11, 12}; wild[ff[U(9)]] = false; }
        } else {
            for (int k = 0; k < 2; ++k) ipm[k] = wild[k] ? 0 : 1;
        }
        w_fields(r, wild, ipm);
    }
    r.rule_id = id;
    switch (g_w.prio_mode) {
        case 0: r.priority = 1 + U(prio_range); break;
        case 1: r.priority = U(4); break;
        default: r.priority = 1 + U(0xFFFFFFF0u); break;
    }
    if (g_extreme && coin(0.35)) r.priority = coin(0.7) ? UINT32_MAX : UINT32_MAX - 1;
    r.action = static_cast<Action>(U(4));
    if (g_w.recent.size() < 64) g_w.recent.push_back(r); else if (coin(0.05)) g_w.recent[U(64)] = r;
    return r;
}

// ---- packets -------------------------------------------------------------------------------
static uint32_t wpip() { uint32_t ip = wip_fresh(); if (coin(0.25)) ip ^= 1u << U(32); return ip; }
static Packet make_packet(const std::vector<Rule>& rules) {
    Packet p{};
    p.src_ip = wpip(); p.dst_ip = wpip();
    p.src_port = uint16_t(g_w.sport.pkt_val()); p.dst_port = uint16_t(g_w.dport.pkt_val());
    p.packet_len = uint16_t(std::max<uint32_t>(20, g_w.plen.pkt_val()));
    p.region_id = uint16_t(g_w.region.pkt_val()); p.vlan_id = uint16_t(g_w.vlan.pkt_val());
    p.protocol = uint8_t(g_w.proto.pkt_val()); p.ingress_iface = uint8_t(g_w.iface.pkt_val());
    p.dscp = uint8_t(g_w.dscp.pkt_val()); p.icmp_type = uint8_t(g_w.icmp.pkt_val());
    p.ttl = uint8_t(g_w.ttl.pkt_val()); p.tcp_flags = uint8_t(coin(0.5) ? U(256) : g_w.flagpool[U(uint32_t(g_w.flagpool.size()))].first);
    if (rules.empty() || !coin(g_w.p_steer)) return p;
    const Rule& r = rules[U(static_cast<uint32_t>(rules.size()))];
    auto in16 = [](uint32_t lo, uint32_t hi) { return coin(0.3) ? lo : coin(0.4) ? hi : lo + U(hi - lo + 1); };
    p.src_ip = r.src_ip.ip | (p.src_ip & ~r.src_ip.mask);  // len 0: mask 0, ip 0 -> unchanged
    p.dst_ip = r.dst_ip.ip | (p.dst_ip & ~r.dst_ip.mask);
    p.src_port = uint16_t(in16(r.src_port.low, r.src_port.high));
    p.dst_port = uint16_t(in16(r.dst_port.low, r.dst_port.high));
    p.packet_len = uint16_t(std::max<uint32_t>(20, in16(r.packet_len.low, r.packet_len.high)));
    p.ttl = uint8_t(in16(r.ttl.low, r.ttl.high));
    if (!r.protocol.wildcard) p.protocol = r.protocol.value;
    if (!r.region_id.wildcard) p.region_id = r.region_id.value;
    if (!r.ingress_iface.wildcard) p.ingress_iface = r.ingress_iface.value;
    if (!r.vlan_id.wildcard) p.vlan_id = r.vlan_id.value;
    if (!r.dscp.wildcard) p.dscp = r.dscp.value;
    if (!r.icmp_type.wildcard) p.icmp_type = r.icmp_type.value;
    p.tcp_flags = static_cast<uint8_t>((p.tcp_flags & ~r.tcp_flags.mask) | (r.tcp_flags.value & r.tcp_flags.mask));
    // just outside [lo,hi] within [minv,maxv] (or cur if the range is the whole domain)
    auto out = [](uint32_t lo, uint32_t hi, uint32_t minv, uint32_t maxv, uint32_t cur) -> uint32_t {
        if (lo > minv && (hi >= maxv || coin(0.5))) return lo - 1;
        return hi < maxv ? hi + 1 : cur;
    };
    if (coin(g_w.p_miss)) {  // move ONE field just outside the rule
        switch (U(13)) {
            case 0: if (r.src_ip.prefix_len) p.src_ip ^= 1u << (32 - r.src_ip.prefix_len); break;
            case 1: if (r.dst_ip.prefix_len) p.dst_ip ^= 1u << (32 - r.dst_ip.prefix_len); break;
            case 2: p.src_port = uint16_t(out(r.src_port.low, r.src_port.high, 0, 65535, p.src_port)); break;
            case 3: p.dst_port = uint16_t(out(r.dst_port.low, r.dst_port.high, 0, 65535, p.dst_port)); break;
            case 4: if (!r.protocol.wildcard) p.protocol ^= uint8_t(1u << U(8)); break;
            case 5: if (r.tcp_flags.mask) { uint8_t m = r.tcp_flags.mask; uint8_t b; do b = uint8_t(1u << U(8)); while (!(m & b)); p.tcp_flags ^= b; } break;
            case 6: if (!r.region_id.wildcard) p.region_id ^= uint16_t(1u << U(16)); break;
            case 7: if (!r.ingress_iface.wildcard) p.ingress_iface ^= uint8_t(1u << U(8)); break;
            case 8: if (!r.vlan_id.wildcard) p.vlan_id = coin(0.5) ? uint16_t(r.vlan_id.value ^ (1u << U(16))) : uint16_t(r.vlan_id.value + 1); break;
            case 9: if (!r.dscp.wildcard) p.dscp = coin(0.5) ? uint8_t(r.dscp.value ^ (1u << U(8))) : uint8_t(r.dscp.value + 1); break;
            case 10: p.packet_len = uint16_t(out(r.packet_len.low, r.packet_len.high, 20, 65535, p.packet_len)); break;
            case 11: if (!r.icmp_type.wildcard) p.icmp_type ^= uint8_t(1u << U(8)); break;
            default: p.ttl = uint8_t(out(r.ttl.low, r.ttl.high, 0, 255, p.ttl)); break;
        }
    }
    return p;
}

// make_packet needs non-empty pools even before the first wide_begin() (e.g. boundary cases).
static const int g_wide_init = (wide_begin(0), 0);

// Failure aid: print a rule / the live rule set and the offending packet.
[[maybe_unused]] static void wrule(const Rule& r, const Packet* p = nullptr) {
    std::printf("  rule id=%u prio=%u act=%d src=%08x/%d dst=%08x/%d sp=%u-%u dp=%u-%u len=%u-%u ttl=%u-%u proto=%u%s flags=%02x/%02x region=%u%s vlan=%u%s iface=%u%s dscp=%u%s icmp=%u%s%s\n",
        r.rule_id, r.priority, int(r.action), r.src_ip.ip, r.src_ip.prefix_len, r.dst_ip.ip, r.dst_ip.prefix_len,
        r.src_port.low, r.src_port.high, r.dst_port.low, r.dst_port.high, r.packet_len.low, r.packet_len.high, r.ttl.low, r.ttl.high,
        r.protocol.value, r.protocol.wildcard ? "*" : "", r.tcp_flags.value, r.tcp_flags.mask, r.region_id.value, r.region_id.wildcard ? "*" : "",
        r.vlan_id.value, r.vlan_id.wildcard ? "*" : "", r.ingress_iface.value, r.ingress_iface.wildcard ? "*" : "",
        r.dscp.value, r.dscp.wildcard ? "*" : "", r.icmp_type.value, r.icmp_type.wildcard ? "*" : "",
        p ? (r.matches(*p) ? "  [MATCHES]" : "  [no match]") : "");
}
[[maybe_unused]] static void wdump(const std::vector<Rule>& rules, const Packet& p) {
    std::printf("  packet src=%08x dst=%08x sp=%u dp=%u len=%u region=%u vlan=%u proto=%u flags=%02x iface=%u dscp=%u icmp=%u ttl=%u\n",
        p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.packet_len, p.region_id, p.vlan_id, p.protocol, p.tcp_flags,
        p.ingress_iface, p.dscp, p.icmp_type, p.ttl);
    std::printf("  %zu live rules%s\n", rules.size(), rules.size() > 8 ? " (showing matching ones)" : "");
    size_t shown = 0;
    for (const Rule& r : rules) {
        if (rules.size() > 8 && !r.matches(p)) continue;
        if (++shown > 12) break;
        wrule(r, &p);
    }
}
