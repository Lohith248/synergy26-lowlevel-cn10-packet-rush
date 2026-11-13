// Packet classifier (first match by priority, then rule id). Single thread, no dependencies beyond the standard
// library and x86 intrinsics. Design:
//
//  1. Hash tuple tables. A planner picks up to R1_MAX_TABLES key shapes (up to 3 dimensions each: IP prefix
//     /8, /16, /24, exact port, protocol, region, vlan, interface, dscp, icmp type). A rule goes to the first table
//     whose key it fully determines; a bucket is the rank-sorted run of rules sharing a key. Lookup = hash (CRC32
//     and a multiply with SSE4.2, else multiply/xor-shift), SIMD tag match in a 4-slot group, then the bucket's
//     records in rank order until one matches or cannot beat the best so far (the first record without a branch).
//  2. Residual. Rules no table fits are held in a bit-vector filter (BitRes) once there are R4_BV_MIN or more of
//     them, otherwise in a lane-major SIMD sweep. BitRes keeps, per field, a value -> class map and one bitmap
//     row per class over the rank-sorted rules; a packet ANDs its 13 rows block by block and verifies the
//     surviving bits with the full rule check, lowest rank first. Each row is a superset of the rules that can
//     match its class, so the survivors are a superset of the matches: the filter is exact.
//  3. Catch-all dominance: a rule that matches every packet bounds the search (anything ranked behind it never wins).
//  4. Updates: inserts go to a small sorted delta swept with every query and merged (or rebuilt, for BitRes) when
//     full; deletes tombstone in place. A rebuild builds the new index on the side and swaps it in only on success,
//     so an allocation failure (std::bad_alloc) leaves the previous state untouched.
//  5. The table path uses chunks of 8 packets: presence tests, a flat probe list, a flat bucket list, residual.
//     Hash-indexed presence bits skip known misses; stale bits after deletes only cost speed. Unnamed ports use
//     block classes and frequent exact ports have their own classes, keeping the residual rows selective.
//     Table-less batches keep the 64-packet sweep. Memory accesses of many packets overlap. The packet's comparison vectors are built with byte shuffles.
//     Branches that depend on data were removed where the hardware counters showed mispredictions.
//  Correctness never depends on the planner: any plan returns the linear-scan answer; the plan only changes speed.
//  Packets shorter than the catch-all's packet_len lower bound (including malformed ones, packet_len < 20) are not
//  covered by the dominance cut and take an exact full scan.
#include "classifier.h"

#include <immintrin.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstring>
#include <new>
#if defined(R1_STATS) || defined(R3_STATS)
#include <cstdio>
#endif

namespace packet_rush {
namespace {

constexpr uint8_t kNoDim = 14;      // dimension index of a constant zero
constexpr uint8_t kDims = 14;       // real key dimensions
constexpr uint8_t kResidual = 0xFE;
constexpr uint8_t kDormant = 0xFF;  // ranked behind the catch-all: never wins, not indexed
constexpr uint8_t kCatchAll = 0xFD;
#ifndef R1_MAX_TABLES
#define R1_MAX_TABLES 16
#endif
constexpr size_t kMaxTables = R1_MAX_TABLES;
#ifndef R3_BATCH
#define R3_BATCH 64
#endif
constexpr size_t kBatch = R3_BATCH;
// Packets per pipelined chunk on the table path (hash+prefetch, probe, scan). Small chunks keep the outstanding
// prefetches within what the core can track and the per-chunk state in L1; measured 4-9% faster than 64 on s02/s03.
#ifndef R4_CHUNK
#define R4_CHUNK 8
#endif
constexpr size_t kChunk = R4_CHUNK;
#ifndef R7_BM_LOG
#define R7_BM_LOG 2
#endif
constexpr size_t kPlanSample = 2048;
constexpr uint32_t kLanes = 26;     // sweep lanes: 8 lo, 8 ~hi, 5 masked values, 5 masks

// Test hook: the release gate builds its fuzzers and planted-bug variants with -DCN10_FORCE_HEAD=<n> (a knob of an
// older engine). Here it selects a test profile in which hash tables and the bit-vector both occur at fuzz-sized
// rule sets (r3-sized planner costs, bit-vector from 4 residual rules). With the shipped constants a few hundred
// rules build no table, so the table paths would go unexercised. The shipped build never defines it.
#ifdef CN10_FORCE_HEAD
#ifndef R1_PROBE_COST
#define R1_PROBE_COST 23.0
#endif
#ifndef R3_PROBE_BIG
#define R3_PROBE_BIG 23.0
#endif
#ifndef R1_BUCKET_COST
#define R1_BUCKET_COST 3.0
#endif
#ifndef R4_BV_MIN
#define R4_BV_MIN 4
#endif
#endif

// Planner costs, in units of the per-packet cost of one rule in the bit-vector residual (about 0.01 ns). Tuned on
// the lab host; a table is built only when the rules it takes out of the residual repay its probe and bucket scan.
#ifndef R1_PROBE_COST
#define R1_PROBE_COST 800.0
#endif
#ifndef R1_BUCKET_COST
#define R1_BUCKET_COST 200.0
#endif
#ifndef R1_COLLISION
#define R1_COLLISION 400.0
#endif
#ifndef R3_PROBE_BIG
#define R3_PROBE_BIG 800.0
#endif
#ifndef R3_BIG_RULES
#define R3_BIG_RULES 4096
#endif
// Hash + tag probe. ponytail: two-step model (tables in L1 vs spilling to L2/L3), cut at R3_BIG_RULES live
// rules; a footprint-based estimate would be the upgrade.
double probe_cost(size_t live) { return live > R3_BIG_RULES ? R3_PROBE_BIG : R1_PROBE_COST; }
constexpr double kBucketCost = R1_BUCKET_COST;    // one record fetched and checked
constexpr double kCollisionLimit = R1_COLLISION;  // max mean bucket size a rule may share

using Dims = std::array<uint8_t, 3>;

uint32_t round16(uint32_t n) { return (n + 15) & ~15u; }

// ---------- rule helpers ----------

uint64_t rank_of(const Rule& r) { return (uint64_t{r.priority} << 32) | r.rule_id; }

uint64_t rec_rank(const RuleRec& r) {
    uint32_t prio, id;
    std::memcpy(&prio, r.val + 9, 4);
    std::memcpy(&id, r.msk + 9, 4);
    return (uint64_t{prio} << 32) | id;
}

bool rule_valid(const Rule& r) {
    return r.src_ip.prefix_len <= 32 && r.dst_ip.prefix_len <= 32 && r.src_port.low <= r.src_port.high &&
           r.dst_port.low <= r.dst_port.high && r.packet_len.low <= r.packet_len.high &&
           r.ttl.low <= r.ttl.high && static_cast<uint8_t>(r.action) <= 3;
}

// Mask regenerated from prefix_len; host bits cleared (spec: supplied masks are discarded).
Rule normalized(const Rule& in) {
    Rule r = in;
    r.src_ip.set(in.src_ip.ip, in.src_ip.prefix_len);
    r.dst_ip.set(in.dst_ip.ip, in.dst_ip.prefix_len);
    return r;
}

// Matches every packet with packet_len >= r.packet_len.low (<= 20, the spec's minimum).
// Packets below that bound (out of spec, but sent by the gate fuzzer) take the exact slow path.
bool is_catchall(const Rule& r) {
    return r.src_ip.prefix_len == 0 && r.dst_ip.prefix_len == 0 && r.src_port.low == 0 &&
           r.src_port.high == 65535 && r.dst_port.low == 0 && r.dst_port.high == 65535 &&
           r.packet_len.low <= 20 && r.packet_len.high == 65535 && r.ttl.low == 0 && r.ttl.high == 255 &&
           r.protocol.wildcard && r.tcp_flags.mask == 0 && r.region_id.wildcard && r.ingress_iface.wildcard &&
           r.vlan_id.wildcard && r.dscp.wildcard && r.icmp_type.wildcard;
}

void put_byte(RuleRec& rec, int i, bool wild, uint8_t v) {
    rec.val[i] = wild ? 0 : v;
    rec.msk[i] = wild ? 0 : 0xFF;
}

RuleRec make_rec(const Rule& r) {
    RuleRec rec{};
    const uint32_t s_lo = r.src_ip.ip, s_hi = r.src_ip.ip | ~r.src_ip.mask;
    const uint32_t d_lo = r.dst_ip.ip, d_hi = r.dst_ip.ip | ~r.dst_ip.mask;
    const uint16_t lo[8] = {uint16_t(s_lo >> 16), uint16_t(s_lo), uint16_t(d_lo >> 16), uint16_t(d_lo),
                            r.src_port.low, r.dst_port.low, r.packet_len.low, r.ttl.low};
    const uint16_t hi[8] = {uint16_t(s_hi >> 16), uint16_t(s_hi), uint16_t(d_hi >> 16), uint16_t(d_hi),
                            r.src_port.high, r.dst_port.high, r.packet_len.high, r.ttl.high};
    for (int i = 0; i < 8; ++i) {
        rec.lo[i] = lo[i];
        rec.nhi[i] = static_cast<uint16_t>(~hi[i]);
    }
    put_byte(rec, 0, r.protocol.wildcard, r.protocol.value);
    put_byte(rec, 1, r.ingress_iface.wildcard, r.ingress_iface.value);
    put_byte(rec, 2, r.dscp.wildcard, r.dscp.value);
    put_byte(rec, 3, r.icmp_type.wildcard, r.icmp_type.value);
    rec.val[4] = r.tcp_flags.value & r.tcp_flags.mask;
    rec.msk[4] = r.tcp_flags.mask;
    put_byte(rec, 5, r.region_id.wildcard, uint8_t(r.region_id.value));
    put_byte(rec, 6, r.region_id.wildcard, uint8_t(r.region_id.value >> 8));
    put_byte(rec, 7, r.vlan_id.wildcard, uint8_t(r.vlan_id.value));
    put_byte(rec, 8, r.vlan_id.wildcard, uint8_t(r.vlan_id.value >> 8));
    std::memcpy(rec.val + 9, &r.priority, 4);
    rec.val[13] = static_cast<uint8_t>(r.action);
    std::memcpy(rec.msk + 9, &r.rule_id, 4);
    return rec;
}

// ---------- key dimensions ----------
// 0-2 src /8 /16 /24, 3-5 dst /8 /16 /24, 6 sport, 7 dport, 8 proto, 9 region, 10 vlan,
// 11 iface, 12 dscp, 13 icmp, 14 constant zero.

void packet_dims(const Packet& p, uint32_t F[16]) {
    F[0] = p.src_ip >> 24; F[1] = p.src_ip >> 16; F[2] = p.src_ip >> 8;
    F[3] = p.dst_ip >> 24; F[4] = p.dst_ip >> 16; F[5] = p.dst_ip >> 8;
    F[6] = p.src_port; F[7] = p.dst_port; F[8] = p.protocol; F[9] = p.region_id;
    F[10] = p.vlan_id; F[11] = p.ingress_iface; F[12] = p.dscp; F[13] = p.icmp_type;
    F[14] = 0; F[15] = 0;
}

// For every dimension the rule specifies, the record's lower bounds equal the value any
// matching packet carries there, so one function places rules and probes packets.
void rec_dims(const RuleRec& r, uint32_t F[16]) {
    Packet p{};
    p.src_ip = (uint32_t{r.lo[0]} << 16) | r.lo[1];
    p.dst_ip = (uint32_t{r.lo[2]} << 16) | r.lo[3];
    p.src_port = r.lo[4];
    p.dst_port = r.lo[5];
    p.protocol = r.val[0];
    p.ingress_iface = r.val[1];
    p.dscp = r.val[2];
    p.icmp_type = r.val[3];
    p.region_id = static_cast<uint16_t>(r.val[5] | (r.val[6] << 8));
    p.vlan_id = static_cast<uint16_t>(r.val[7] | (r.val[8] << 8));
    packet_dims(p, F);
}

uint16_t fit_mask(const Rule& r) {
    const int s = r.src_ip.prefix_len, d = r.dst_ip.prefix_len;
    uint16_t m = 1u << kNoDim;
    m |= (s >= 8) << 0 | (s >= 16) << 1 | (s >= 24) << 2;
    m |= (d >= 8) << 3 | (d >= 16) << 4 | (d >= 24) << 5;
    m |= (r.src_port.low == r.src_port.high) << 6 | (r.dst_port.low == r.dst_port.high) << 7;
    m |= (!r.protocol.wildcard) << 8 | (!r.region_id.wildcard) << 9 | (!r.vlan_id.wildcard) << 10;
    m |= (!r.ingress_iface.wildcard) << 11 | (!r.dscp.wildcard) << 12 | (!r.icmp_type.wildcard) << 13;
    return m;
}

uint16_t need_mask(const uint8_t* d) { return uint16_t((1u << d[0]) | (1u << d[1]) | (1u << d[2])); }

uint64_t key64(const uint8_t* d, const uint32_t* F) {
    uint64_t h = F[d[0]] * 0x9E3779B97F4A7C15ull + F[d[1]] * 0xC2B2AE3D27D4EB4Full + F[d[2]] * 0x165667B19E3779F9ull;
    h ^= h >> 29;
    return h * 0xBF58476D1CE4E5B9ull;
}

// ---------- SIMD single-rule check (candidates from tables) ----------

struct PacketVec {
#if defined(__AVX2__)
    __m256i x;
#else
    __m128i x0, x1;
#endif
    __m128i p;
};

#if defined(__SSSE3__)
// Packet layout (24 bytes, little endian): src_ip 0-3, dst_ip 4-7, sport 8-9, dport 10-11, plen 12-13, region 14-15,
// vlan 16-17, proto 18, flags 19, iface 20, dscp 21, icmp 22, ttl 23. Two 16-byte loads (bytes 0-15 and 8-23)
// and byte shuffles build the vectors; -1 selects zero.
static_assert(sizeof(Packet) == 24 && offsetof(Packet, ttl) == 23 && offsetof(Packet, region_id) == 14 &&
                  offsetof(Packet, protocol) == 18 && offsetof(Packet, icmp_type) == 22,
              "packet layout");
inline __m128i pkt_lo(const Packet& k) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(&k)); }
inline __m128i pkt_hi(const Packet& k) {
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(reinterpret_cast<const char*>(&k) + 8));
}
#endif

PacketVec make_vec(const Packet& k) {
#if defined(__SSSE3__)
    const __m128i lo = pkt_lo(k), hi = pkt_hi(k);
    const __m128i v = _mm_or_si128(_mm_shuffle_epi8(lo, _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 8, 9, 10, 11, 12, 13, -1, -1)),
                                   _mm_shuffle_epi8(hi, _mm_setr_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                                                      -1, -1, 15, -1)));
    const __m128i nv = _mm_xor_si128(v, _mm_set1_epi32(-1));
    PacketVec pv;
#if defined(__AVX2__)
    pv.x = _mm256_set_m128i(nv, v);
#else
    pv.x0 = v;
    pv.x1 = nv;
#endif
    pv.p = _mm_shuffle_epi8(hi, _mm_setr_epi8(10, 12, 13, 14, 11, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1));
    return pv;
#else
    const __m128i v = _mm_setr_epi16(short(k.src_ip >> 16), short(k.src_ip), short(k.dst_ip >> 16), short(k.dst_ip),
                                     short(k.src_port), short(k.dst_port), short(k.packet_len), short(k.ttl));
    const __m128i nv = _mm_xor_si128(v, _mm_set1_epi32(-1));
    PacketVec pv;
#if defined(__AVX2__)
    pv.x = _mm256_set_m128i(nv, v);
#else
    pv.x0 = v;
    pv.x1 = nv;
#endif
    pv.p = _mm_setr_epi8(char(k.protocol), char(k.ingress_iface), char(k.dscp), char(k.icmp_type), char(k.tcp_flags),
                         char(k.region_id), char(k.region_id >> 8), char(k.vlan_id), char(k.vlan_id >> 8), 0, 0, 0, 0,
                         0, 0, 0);
    return pv;
#endif
}

// lo <= v and ~hi <= ~v on all 16 lanes (saturating subtract is zero), and the nine masked bytes equal.
inline bool rec_matches(const RuleRec& r, const PacketVec& pv) {
    const auto* base = reinterpret_cast<const __m128i*>(&r);
#if defined(__AVX2__)
    const __m256i d = _mm256_subs_epu16(_mm256_load_si256(reinterpret_cast<const __m256i*>(&r)), pv.x);
    const bool ranges = _mm256_testz_si256(d, d);
#else
    const __m128i d = _mm_or_si128(_mm_subs_epu16(_mm_load_si128(base), pv.x0),
                                   _mm_subs_epu16(_mm_load_si128(base + 1), pv.x1));
    const bool ranges = _mm_movemask_epi8(_mm_cmpeq_epi8(d, _mm_setzero_si128())) == 0xFFFF;
#endif
    const __m128i eq = _mm_cmpeq_epi8(_mm_and_si128(pv.p, _mm_load_si128(base + 3)), _mm_load_si128(base + 2));
    const bool bytes = (_mm_movemask_epi8(eq) & 0x1FF) == 0x1FF;
    return ranges & bytes;
}

// ---------- residual sweep (lane-major, 16 rules per step) ----------

void sweep_values(const RuleRec& r, uint16_t out[kLanes]) {
    for (int i = 0; i < 8; ++i) {
        out[i] = r.lo[i];
        out[8 + i] = r.nhi[i];
    }
    const uint8_t* src[2] = {r.val, r.msk};
    for (int s = 0; s < 2; ++s) {
        const uint8_t* b = src[s];
        uint16_t* o = out + 16 + 5 * s;
        o[0] = uint16_t(b[0] | (b[1] << 8));  // protocol | iface
        o[1] = uint16_t(b[2] | (b[3] << 8));  // dscp | icmp
        o[2] = b[4];                          // tcp flags
        o[3] = uint16_t(b[5] | (b[6] << 8));  // region
        o[4] = uint16_t(b[7] | (b[8] << 8));  // vlan
    }
}

// The packet's sweep lanes (layout of sweep_values()); lanes 0-15 are the vector's range half.
inline void vec_lanes(const PacketVec& pv, const Packet& k, uint16_t px[24]) {
#if defined(__AVX2__)
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(px), pv.x);
#else
    _mm_storeu_si128(reinterpret_cast<__m128i*>(px), pv.x0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(px + 8), pv.x1);
#endif
#if defined(__SSSE3__)
    // px[16..23]: proto | iface << 8, dscp | icmp << 8, flags, region, vlan, then zeros.
    _mm_storeu_si128(reinterpret_cast<__m128i*>(px + 16),
                     _mm_shuffle_epi8(pkt_hi(k), _mm_setr_epi8(10, 12, 13, 14, 11, -1, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1)));
#else
    px[16] = uint16_t(k.protocol | (k.ingress_iface << 8));
    px[17] = uint16_t(k.dscp | (k.icmp_type << 8));
    px[18] = k.tcp_flags;
    px[19] = k.region_id;
    px[20] = k.vlan_id;
#endif
}

// Padding never matches through lane 0 when that lane is swept; when it is not, a padding entry may match,
// and sweep_search() ignores it (it can never be taken: a catch-all may start `best` at the maximum rank).
void sweep_pad(Sweep& s) {
    for (uint32_t i = s.n; i < round16(s.n); ++i) {
        s.lanes[i] = 0xFFFF;
        s.lanes[8 * s.cap + i] = 0xFFFF;
        s.rank[i] = ~uint64_t{0};
        s.action[i] = 0;
    }
}

uint32_t sweep_active(const uint16_t v[kLanes]) {
    uint32_t a = 0;
    for (uint32_t k = 0; k < 16; ++k) a |= uint32_t(v[k] != 0) << k;
    for (uint32_t m = 0; m < 5; ++m) a |= uint32_t((v[16 + m] | v[21 + m]) != 0) << (16 + m);
    return a;
}

void sweep_alloc(Sweep& s, uint32_t cap) {
    s.n = 0;
    s.active = 0;
    s.cap = std::max<uint32_t>(16, round16(cap));
    s.lanes.assign(size_t(kLanes) * s.cap, 0);
    s.rank.assign(s.cap, 0);
    s.action.assign(s.cap, 0);
}

void sweep_write(Sweep& s, uint32_t i, const RuleRec& r) {
    uint16_t v[kLanes];
    sweep_values(r, v);
    s.active |= sweep_active(v);
    for (uint32_t k = 0; k < kLanes; ++k) s.lanes[size_t(k) * s.cap + i] = v[k];
    s.rank[i] = rec_rank(r);
    s.action[i] = r.val[13];
}

uint32_t sweep_lower(const Sweep& s, uint64_t rank) {
    return uint32_t(std::lower_bound(s.rank.begin(), s.rank.begin() + s.n, rank) - s.rank.begin());
}

// Requires cap >= round16(n + 1).
void sweep_insert(Sweep& s, const RuleRec& r) {
    const uint32_t pos = sweep_lower(s, rec_rank(r));
    const uint32_t tail = s.n - pos;
    for (uint32_t k = 0; k < kLanes; ++k) {
        uint16_t* lane = s.lanes.data() + size_t(k) * s.cap;
        std::memmove(lane + pos + 1, lane + pos, tail * sizeof(uint16_t));
    }
    std::memmove(s.rank.data() + pos + 1, s.rank.data() + pos, tail * sizeof(uint64_t));
    std::memmove(s.action.data() + pos + 1, s.action.data() + pos, tail);
    sweep_write(s, pos, r);
    ++s.n;
    sweep_pad(s);
}

void sweep_erase(Sweep& s, uint64_t rank) {
    const uint32_t pos = sweep_lower(s, rank);
    if (pos >= s.n || s.rank[pos] != rank) return;
    const uint32_t tail = s.n - pos - 1;
    for (uint32_t k = 0; k < kLanes; ++k) {
        uint16_t* lane = s.lanes.data() + size_t(k) * s.cap;
        std::memmove(lane + pos, lane + pos + 1, tail * sizeof(uint16_t));
    }
    std::memmove(s.rank.data() + pos, s.rank.data() + pos + 1, tail * sizeof(uint64_t));
    std::memmove(s.action.data() + pos, s.action.data() + pos + 1, tail);
    --s.n;
    sweep_pad(s);
}

#ifndef R3_DELTA
#define R3_DELTA 64
#endif
constexpr uint32_t kDelta = R3_DELTA;  // residual inserts buffered before a merge (a floor: see delta_cap_for)
constexpr uint32_t kDeltaMax = 512;
constexpr uint8_t kDead = 0x80;        // action flag of a tombstone

// Deletes from the big residual sweep in O(log n): the entry stays in rank order but can never match (lanes
// 0 and 8, swept from now on, both 0xFFFF need the source IP's top half to be both 0xFFFF and 0).
bool sweep_kill(Sweep& s, uint64_t rank) {
    for (uint32_t pos = sweep_lower(s, rank); pos < s.n && s.rank[pos] == rank; ++pos) {
        if (s.action[pos] & kDead) continue;
        s.lanes[pos] = 0xFFFF;
        s.lanes[8 * size_t(s.cap) + pos] = 0xFFFF;
        s.action[pos] |= kDead;
        s.active |= 1u | 1u << 8;
        ++s.dead;
        return true;
    }
    return false;
}

// The live entries of a and b, in rank order, into d (allocated and empty, cap >= their count): no allocation.
void sweep_merge(Sweep& d, const Sweep& a, const Sweep& b) {
    auto copy = [&d](const Sweep& s, uint32_t k) {
        uint16_t v[kLanes];
        for (uint32_t l = 0; l < kLanes; ++l) v[l] = s.lanes[size_t(l) * s.cap + k];
        d.active |= sweep_active(v);
        for (uint32_t l = 0; l < kLanes; ++l) d.lanes[size_t(l) * d.cap + d.n] = v[l];
        d.rank[d.n] = s.rank[k];
        d.action[d.n] = s.action[k];
        ++d.n;
    };
    uint32_t i = 0, j = 0;
    while (i < a.n || j < b.n) {
        if (i < a.n && (a.action[i] & kDead)) { ++i; continue; }
        if (j < b.n && (b.action[j] & kDead)) { ++j; continue; }
        if (j >= b.n || (i < a.n && a.rank[i] < b.rank[j])) copy(a, i++); else copy(b, j++);
    }
    sweep_pad(d);
}

// Bit 2i (and 2i+1) set when entry b+i matches; entries are rank-sorted.
inline uint32_t sweep_block(const uint16_t* L, size_t cap, uint32_t b, const uint16_t* px, uint32_t act) {
#if defined(__AVX2__)
    __m256i acc = _mm256_setzero_si256();
    for (int k = 0; k < 16; ++k) {
        if (!(act >> k & 1)) continue;
        const __m256i lane = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(L + k * cap + b));
        acc = _mm256_or_si256(acc, _mm256_subs_epu16(lane, _mm256_set1_epi16(short(px[k]))));
    }
    for (int m = 0; m < 5; ++m) {
        if (!(act >> (16 + m) & 1)) continue;
        const __m256i val = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(L + (16 + m) * cap + b));
        const __m256i msk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(L + (21 + m) * cap + b));
        acc = _mm256_or_si256(acc, _mm256_xor_si256(_mm256_and_si256(_mm256_set1_epi16(short(px[16 + m])), msk), val));
    }
    return uint32_t(_mm256_movemask_epi8(_mm256_cmpeq_epi16(acc, _mm256_setzero_si256())));
#else
    uint32_t bits = 0;
    for (int half = 0; half < 2; ++half) {
        const uint32_t o = b + 8 * half;
        __m128i acc = _mm_setzero_si128();
        for (int k = 0; k < 16; ++k) {
            if (!(act >> k & 1)) continue;
            const __m128i lane = _mm_loadu_si128(reinterpret_cast<const __m128i*>(L + k * cap + o));
            acc = _mm_or_si128(acc, _mm_subs_epu16(lane, _mm_set1_epi16(short(px[k]))));
        }
        for (int m = 0; m < 5; ++m) {
            if (!(act >> (16 + m) & 1)) continue;
            const __m128i val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(L + (16 + m) * cap + o));
            const __m128i msk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(L + (21 + m) * cap + o));
            acc = _mm_or_si128(acc, _mm_xor_si128(_mm_and_si128(_mm_set1_epi16(short(px[16 + m])), msk), val));
        }
        bits |= uint32_t(_mm_movemask_epi8(_mm_cmpeq_epi16(acc, _mm_setzero_si128()))) << (16 * half);
    }
    return bits;
#endif
}

// First match in rank order wins; stops once a block starts behind `best`.
inline void sweep_search(const Sweep& s, const uint16_t* px, uint64_t& best, uint8_t& act) {
    for (uint32_t b = 0; b < s.n; b += 16) {
        if (s.rank[b] > best) return;
        const uint32_t bits = sweep_block(s.lanes.data(), s.cap, b, px, s.active);
        if (bits) {
            const uint32_t i = b + uint32_t(__builtin_ctz(bits)) / 2;
            if (i < s.n && s.rank[i] <= best) {  // a padding bit is lowest only if no real entry matched
                best = s.rank[i];
                act = s.action[i];
            }
            return;
        }
    }
}

// ---------- bit-vector residual ----------
// Per field, a value->class map (one byte per value) and one row per class. A row is a superset of the rules that
// can match any value of its class, so the AND of a packet's rows is a superset of its matching rules, and every
// survivor is confirmed by rec_matches(). Positions are rank-sorted, so the first confirmed survivor is the best.

enum : uint32_t { BF_SIP, BF_DIP, BF_SPORT, BF_DPORT, BF_PLEN, BF_TTL, BF_PROTO, BF_IFACE, BF_DSCP, BF_ICMP,
                  BF_FLAGS, BF_REGION, BF_VLAN };
static_assert(BF_VLAN + 1 == kBvFields, "field list");
// Map sizes: the value domain, clamped for dscp (64), region and vlan (4096); the clamp slot is the "high" class.
// (region and vlan keep their maps in map16 instead: offsets 0 and 4097.)
constexpr uint32_t kBvMapSize[kBvFields] = {256, 256, 65536, 65536, 65536, 256, 256, 256, 65, 256, 256, 0, 0};
constexpr uint32_t kNone32 = 0xFFFFFFFFu;
// Offsets of the one-byte maps in BitRes::maps (fixed by kBvMapSize; bv_build_flat assigns the same values).
constexpr uint32_t bv_moff(uint32_t f) {
    uint32_t o = 0;
    for (uint32_t g = 0; g < f; ++g) o += kBvMapSize[g];
    return o;
}

#ifndef R4_ROW_BUDGET
#define R4_ROW_BUDGET (6u << 20)  // bytes of rows a build may use; classes per field shrink to fit
#endif
#ifndef R4_BV_MIN
#define R4_BV_MIN 128  // residual rules at which the bit-vector replaces the sweep
#endif
constexpr uint32_t kBvMin = R4_BV_MIN;

inline void bit_set(uint64_t* row, uint32_t i) { row[i >> 6] |= uint64_t{1} << (i & 63); }
inline uint64_t* bv_row(BitRes& B, uint32_t r) { return B.rows[size_t(r) * B.W].w; }

// Appends `ncls` zeroed rows; returns the first row's index.
uint32_t bv_append(BitRes& B, uint32_t ncls, uint32_t& nrows) {
    const uint32_t r0 = nrows;
    nrows += ncls;
    B.rows.resize(size_t(nrows) * B.W);
    return r0;
}

// Range field over [0, D): classes are the elementary intervals between the rules' bounds. Rows come from the
// previous row by toggling the rules that start or end at the boundary. With more than `cap` intervals the
// domain is cut into 2^shift-wide blocks instead (rows then hold every rule overlapping the block), unless
// !coarse_ok, which returns kNone32. Returns the class count (0: no rule constrains the field, so it is not used).
uint32_t bv_interval_field(BitRes& B, uint32_t f, uint32_t D, const std::vector<uint32_t>& lo,
                           const std::vector<uint32_t>& hi, uint32_t cap, uint32_t& nrows, bool coarse_ok) {
    const uint32_t n = B.n, W = B.W;
    bool constrained = false;
    for (uint32_t i = 0; i < n && !constrained; ++i) constrained = lo[i] != 0 || hi[i] != D - 1;
    if (!constrained) return 0;
    std::vector<uint32_t> starts{0};
    for (uint32_t i = 0; i < n; ++i) {
        starts.push_back(lo[i]);
        if (hi[i] + 1 < D) starts.push_back(hi[i] + 1);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    uint32_t shift = 0, Dc = D;
    std::vector<uint32_t> clo, chi;
    const std::vector<uint32_t>* L = &lo;
    const std::vector<uint32_t>* H = &hi;
    if (starts.size() > cap) {
        if (!coarse_ok) return kNone32;
        while (((D - 1) >> shift) + 1 > cap) ++shift;
        Dc = ((D - 1) >> shift) + 1;
        starts.resize(Dc);
        for (uint32_t u = 0; u < Dc; ++u) starts[u] = u;
        clo.resize(n);
        chi.resize(n);
        for (uint32_t i = 0; i < n; ++i) {
            clo[i] = lo[i] >> shift;
            chi[i] = hi[i] >> shift;
        }
        L = &clo;
        H = &chi;
    }
    const uint32_t m = uint32_t(starts.size());
    uint8_t* map = B.maps.data() + B.moff[f];
    for (uint32_t v = 0, j = 0; v < D; ++v) {
        const uint32_t u = v >> shift;
        while (j + 1 < m && starts[j + 1] <= u) ++j;
        map[v] = uint8_t(j);
    }
    auto cls_of = [&](uint32_t u) {
        return uint32_t(std::upper_bound(starts.begin(), starts.end(), u) - starts.begin()) - 1;
    };
    std::vector<std::pair<uint32_t, uint32_t>> ev;  // (class where the rule's bit toggles, rule)
    ev.reserve(2 * size_t(n));
    for (uint32_t i = 0; i < n; ++i) {
        ev.push_back({cls_of((*L)[i]), i});
        if ((*H)[i] + 1 < Dc) ev.push_back({cls_of((*H)[i] + 1), i});
    }
    std::sort(ev.begin(), ev.end());
    B.base[f] = bv_append(B, m, nrows);
    size_t e = 0;
    for (uint32_t j = 0; j < m; ++j) {
        uint64_t* r = bv_row(B, B.base[f] + j);
        if (j) std::memcpy(r, r - size_t(W) * 4, size_t(W) * sizeof(BvBlk));
        for (; e < ev.size() && ev[e].first == j; ++e) r[ev[e].second >> 6] ^= uint64_t{1} << (ev[e].second & 63);
    }
    return m;
}

#ifndef R7_PORT_BLOCKS
#define R7_PORT_BLOCKS 64  // classes that cut the unnamed ports into equal blocks (rounded down to a power of two)
#endif
// Port field with too many intervals: hybrid classes. Classes 0..NB-1 are blocks of 65536/NB ports (an unnamed port
// maps to port >> shift); the next classes are the most frequent exact ports, one each. A block's row holds each
// rule that admits at least one unnamed port inside the block; a named port's row holds each rule whose range
// contains it. Every row is a superset of the rules matching any port of its class.
uint32_t bv_port_named_field(BitRes& B, uint32_t f, const std::vector<uint32_t>& lo, const std::vector<uint32_t>& hi,
                             uint32_t cap, uint32_t& nrows) {
    const uint32_t n = B.n;
    std::vector<std::pair<uint32_t, uint32_t>> vc;  // (UINT32_MAX - count, port)
    {
        std::vector<uint32_t> exact;
        for (uint32_t i = 0; i < n; ++i)
            if (lo[i] == hi[i]) exact.push_back(lo[i]);
        std::sort(exact.begin(), exact.end());
        for (size_t i = 0; i < exact.size();) {
            size_t j = i;
            while (j < exact.size() && exact[j] == exact[i]) ++j;
            vc.push_back({kNone32 - uint32_t(j - i), exact[i]});
            i = j;
        }
    }
    std::sort(vc.begin(), vc.end());
    // ponytail: four-block filters keep the compact unnamed row; splitting it costs more cache misses than it
    // saves checks. Retune this build-time threshold with paired runs if the record/filter layout changes.
    uint32_t NB = 1;
    while (B.W > 4 && NB * 2 <= R7_PORT_BLOCKS && NB * 2 <= cap / 2 && NB * 2 + vc.size() <= cap) NB *= 2;
    // Preserve the exact-port classes before spending spare classes on blocks: evicting named ports hurts
    // high-cardinality and correlated-service sets more than blocks help them.
    uint32_t shift = 16;
    for (uint32_t t = NB; t > 1; t >>= 1) --shift;
    const uint32_t bw = 1u << shift;
    if (vc.size() > cap - NB) vc.resize(cap - NB);
    std::vector<uint32_t> named;
    for (const auto& x : vc) named.push_back(x.second);
    std::sort(named.begin(), named.end());
    uint8_t* map = B.maps.data() + B.moff[f];
    for (uint32_t port = 0; port < 65536; ++port) map[port] = uint8_t(port >> shift);
    for (size_t k = 0; k < named.size(); ++k) map[named[k]] = uint8_t(NB + k);
    const uint32_t ncls = NB + uint32_t(named.size());
    B.base[f] = bv_append(B, ncls, nrows);
    std::vector<uint32_t> free_blk(NB);  // does block j hold an unnamed port at all?
    for (uint32_t j = 0; j < NB; ++j) {
        const uint32_t s0 = j * bw, e0 = s0 + bw - 1;
        const uint32_t in = uint32_t(std::upper_bound(named.begin(), named.end(), e0) -
                                     std::lower_bound(named.begin(), named.end(), s0));
        free_blk[j] = in < bw;
    }
    auto unnamed_in = [&](uint32_t s0, uint32_t e0) {  // overlap [s0, e0] holds an unnamed port
        const uint32_t in = uint32_t(std::upper_bound(named.begin(), named.end(), e0) -
                                     std::lower_bound(named.begin(), named.end(), s0));
        return in < e0 - s0 + 1;
    };
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t jl = lo[i] >> shift, jh = hi[i] >> shift;
        for (uint32_t j = jl; j <= jh; ++j) {
            const uint32_t s0 = std::max(lo[i], j * bw), e0 = std::min(hi[i], j * bw + bw - 1);
            const bool full = s0 == j * bw && e0 == j * bw + bw - 1;
            if (full ? free_blk[j] != 0 : unnamed_in(s0, e0)) bit_set(bv_row(B, B.base[f] + j), i);
        }
        const size_t ka = size_t(std::lower_bound(named.begin(), named.end(), lo[i]) - named.begin());
        const size_t kb = size_t(std::upper_bound(named.begin(), named.end(), hi[i]) - named.begin());
        for (size_t k = ka; k < kb; ++k) bit_set(bv_row(B, B.base[f] + NB + uint32_t(k)), i);
    }
    return ncls;
}

// Exact-or-wildcard field (val[i] = kNone32 for a wildcard). Values >= L share class 1 (row: wildcard rules and
// rules naming a value >= L); named values below L get a class each; the rest share class 0.
template <class M>
uint32_t bv_exact_field(BitRes& B, M* map, uint32_t f, uint32_t L, const std::vector<uint32_t>& val, uint32_t cap,
                        uint32_t& nrows) {
    const uint32_t n = B.n, W = B.W;
    std::vector<uint32_t> cnt(L, 0);
    uint32_t constrained = 0;
    for (uint32_t i = 0; i < n; ++i)
        if (val[i] != kNone32) {
            ++constrained;
            if (val[i] < L) ++cnt[val[i]];
        }
    if (!constrained) return 0;
    std::vector<std::pair<uint32_t, uint32_t>> vc;
    for (uint32_t v = 0; v < L; ++v)
        if (cnt[v]) vc.push_back({kNone32 - cnt[v], v});
    std::sort(vc.begin(), vc.end());
    if (vc.size() > cap - 2) vc.resize(cap - 2);
    std::vector<M> cls_of(L, 0);
    for (size_t k = 0; k < vc.size(); ++k) cls_of[vc[k].second] = M(2 + k);
    for (uint32_t v = 0; v < L; ++v) map[v] = cls_of[v];
    map[L] = 1;
    const uint32_t ncls = 2 + uint32_t(vc.size());
    B.base[f] = bv_append(B, ncls, nrows);
    std::vector<uint64_t> wild(size_t(W) * 4, 0);
    for (uint32_t i = 0; i < n; ++i)
        if (val[i] == kNone32) bit_set(wild.data(), i);
    for (uint32_t c = 0; c < ncls; ++c) std::memcpy(bv_row(B, B.base[f] + c), wild.data(), size_t(W) * sizeof(BvBlk));
    for (uint32_t i = 0; i < n; ++i) {
        if (val[i] == kNone32) continue;
        bit_set(bv_row(B, B.base[f] + (val[i] >= L ? 1u : cls_of[val[i]])), i);
    }
    return ncls;
}

// TCP flags: 256 candidate rows (one per flag byte), identical rows merged into one class.
uint32_t bv_flags_field(BitRes& B, const std::vector<RuleRec>& R, uint32_t& nrows) {
    const uint32_t n = B.n, W = B.W;
    bool constrained = false;
    for (uint32_t i = 0; i < n && !constrained; ++i) constrained = R[i].msk[4] != 0;
    if (!constrained) return 0;
    const uint32_t r0 = bv_append(B, 256, nrows);
    std::vector<uint64_t> wild(size_t(W) * 4, 0);
    for (uint32_t i = 0; i < n; ++i)
        if (R[i].msk[4] == 0) bit_set(wild.data(), i);
    for (uint32_t c = 0; c < 256; ++c) std::memcpy(bv_row(B, r0 + c), wild.data(), size_t(W) * sizeof(BvBlk));
    for (uint32_t i = 0; i < n; ++i) {
        const uint8_t m = R[i].msk[4], v = R[i].val[4];
        if (m == 0) continue;
        for (uint32_t c = 0; c < 256; ++c)
            if ((c & m) == v) bit_set(bv_row(B, r0 + c), i);
    }
    const size_t words = size_t(W) * 4;
    std::vector<uint64_t> hash(256);
    for (uint32_t c = 0; c < 256; ++c) {
        const uint64_t* r = bv_row(B, r0 + c);
        uint64_t h = 0x9E3779B97F4A7C15ull;
        for (size_t k = 0; k < words; ++k) h = (h ^ r[k]) * 0xFF51AFD7ED558CCDull, h ^= h >> 32;
        hash[c] = h;
    }
    std::vector<uint32_t> rep;  // representative candidate row of each class
    uint8_t* map = B.maps.data() + B.moff[BF_FLAGS];
    for (uint32_t c = 0; c < 256; ++c) {
        uint32_t k = 0;
        for (; k < rep.size(); ++k)
            if (hash[rep[k]] == hash[c] && std::memcmp(bv_row(B, r0 + rep[k]), bv_row(B, r0 + c), words * 8) == 0) break;
        if (k == rep.size()) rep.push_back(c);
        map[c] = uint8_t(k);
    }
    for (uint32_t k = 0; k < rep.size(); ++k)  // rep[k] >= k, so moving down never clobbers a pending source
        if (rep[k] != k) std::memcpy(bv_row(B, r0 + k), bv_row(B, r0 + rep[k]), words * 8);
    nrows = r0 + uint32_t(rep.size());
    B.rows.resize(size_t(nrows) * W);
    B.base[BF_FLAGS] = r0;
    return uint32_t(rep.size());
}

// R: the rules, sorted by rank, at least one. May throw std::bad_alloc.
BitRes bv_build(const std::vector<RuleRec>& R) {
    BitRes B;
    const uint32_t n = uint32_t(R.size());
    B.n = n;
    B.W = (n + 255) / 256;
    const uint32_t W = B.W;
    B.recs = R;
    B.rank.resize(n);
    for (uint32_t i = 0; i < n; ++i) B.rank[i] = rec_rank(R[i]);
    B.first.resize(W);
    for (uint32_t b = 0; b < W; ++b) B.first[b] = B.rank[size_t(b) * 256];
    B.ones.assign(W, BvBlk{});
    for (uint32_t i = 0; i < n; ++i) bit_set(B.ones[i >> 8].w, i & 255);
    B.alive = B.ones;
    uint32_t off = 0;
    for (uint32_t f = 0; f < kBvFields; ++f) {
        B.moff[f] = off;
        off += kBvMapSize[f];
    }
    B.maps.assign(off, 0);
    B.map16.assign(2 * 4097, 0);
    B.moff[BF_REGION] = 0;
    B.moff[BF_VLAN] = 4097;
    for (uint32_t f = 0; f < BF_REGION; ++f)
        if (B.moff[f] != bv_moff(f)) __builtin_trap();  // the query side uses the constants
    // Classes per field: what the row budget allows, up to 256 (one-byte maps) or, for region and vlan, 4096.
    const uint32_t cap16 = std::clamp<uint32_t>(std::max(1u, R4_ROW_BUDGET / (W * uint32_t(sizeof(BvBlk)))) / kBvFields, 8u, 4096u);
    const uint32_t cap = std::min(cap16, 256u);
    B.rows.reserve((size_t(kBvFields) * cap16 + 256) * W);  // address space only: pages are touched as rows are written
    uint32_t nrows = 0;
    uint32_t ncls[kBvFields] = {};
    uint32_t named_from[kBvFields] = {};  // first class that stands for real values (exact fields skip 0 and 1)
    std::vector<uint32_t> a(n), b(n);
    auto range_field = [&](uint32_t f, uint32_t D, int lane, bool ports) {
        for (uint32_t i = 0; i < n; ++i) {
            a[i] = R[i].lo[lane] >> (D == 256 && lane < 4 ? 8 : 0);
            b[i] = uint16_t(~R[i].nhi[lane]) >> (D == 256 && lane < 4 ? 8 : 0);
        }
        ncls[f] = bv_interval_field(B, f, D, a, b, cap, nrows, !ports);
        if (ncls[f] == kNone32) ncls[f] = bv_port_named_field(B, f, a, b, cap, nrows);  // ports with too many intervals
    };
    range_field(BF_SIP, 256, 0, false);
    range_field(BF_DIP, 256, 2, false);
    range_field(BF_SPORT, 65536, 4, true);
    range_field(BF_DPORT, 65536, 5, true);
    range_field(BF_PLEN, 65536, 6, false);
    range_field(BF_TTL, 256, 7, false);
    auto exact_field = [&](uint32_t f, uint32_t L, auto get) {
        for (uint32_t i = 0; i < n; ++i) a[i] = get(R[i]);
        if (f == BF_REGION || f == BF_VLAN) ncls[f] = bv_exact_field(B, B.map16.data() + B.moff[f], f, L, a, cap16, nrows);
        else ncls[f] = bv_exact_field(B, B.maps.data() + B.moff[f], f, L, a, cap, nrows);
        named_from[f] = 2;
    };
    exact_field(BF_PROTO, 255, [](const RuleRec& r) { return r.msk[0] ? uint32_t(r.val[0]) : kNone32; });
    exact_field(BF_IFACE, 255, [](const RuleRec& r) { return r.msk[1] ? uint32_t(r.val[1]) : kNone32; });
    exact_field(BF_DSCP, 64, [](const RuleRec& r) { return r.msk[2] ? uint32_t(r.val[2]) : kNone32; });
    exact_field(BF_ICMP, 255, [](const RuleRec& r) { return r.msk[3] ? uint32_t(r.val[3]) : kNone32; });
    exact_field(BF_REGION, 4096,
                [](const RuleRec& r) { return r.msk[5] ? uint32_t(r.val[5] | (r.val[6] << 8)) : kNone32; });
    exact_field(BF_VLAN, 4096,
                [](const RuleRec& r) { return r.msk[7] ? uint32_t(r.val[7] | (r.val[8] << 8)) : kNone32; });
    ncls[BF_FLAGS] = bv_flags_field(B, R, nrows);
    // Fields in order of selectivity: mean row density over the classes that stand for real values.
    std::vector<std::pair<double, uint32_t>> dens;
    for (uint32_t f = 0; f < kBvFields; ++f) {
        if (!ncls[f]) continue;
        const uint32_t c0 = named_from[f] < ncls[f] ? named_from[f] : 0;
        double sum = 0;
        for (uint32_t c = c0; c < ncls[f]; ++c) {
            const uint64_t* r = bv_row(B, B.base[f] + c);
            for (size_t k = 0; k < size_t(W) * 4; ++k) sum += __builtin_popcountll(r[k]);
        }
        dens.push_back({sum / double(ncls[f] - c0) / double(n), f});
    }
    std::sort(dens.begin(), dens.end());
#ifdef R1_STATS
    {
        static const char* const names[kBvFields] = {"sip", "dip", "sport", "dport", "plen", "ttl", "proto", "iface",
                                                     "dscp", "icmp", "flags", "region", "vlan"};
        std::fprintf(stderr, "  bv: n=%u W=%u rows=%u cap=%u fields:", n, W, nrows, cap);
        for (const auto& d : dens) std::fprintf(stderr, " %s(%u cls, %.3f)", names[d.second], ncls[d.second], d.first);
        std::fprintf(stderr, "\n");
    }
#endif
#ifdef R4_DROP
    while (!dens.empty() && dens.back().first > R4_DROP) dens.pop_back();  // experiment: skip unselective fields
#endif
    B.nact = uint32_t(dens.size());
    for (uint32_t k = 0; k < B.nact; ++k) B.order[k] = uint8_t(dens[k].second);
    // Fields no rule constrains read class 0 of a single all-ones row, in the slots after the active ones, so a
    // query writes each field's row straight to its slot.
    uint32_t used = 0;
    for (uint32_t k = 0; k < B.nact; ++k) used |= 1u << B.order[k];
    uint32_t slot = B.nact, ones_row = kNone32;
    for (uint32_t k = 0; k < B.nact; ++k) B.pos[B.order[k]] = uint8_t(k);
    for (uint32_t f = 0; f < kBvFields; ++f) {
        if (used >> f & 1) continue;
        if (ones_row == kNone32) {
            ones_row = bv_append(B, 1, nrows);
            std::memcpy(bv_row(B, ones_row), B.ones.data(), size_t(W) * sizeof(BvBlk));
        }
        B.base[f] = ones_row;
        B.pos[f] = uint8_t(slot++);
    }
    return B;
}

// The row of each field's class for packet p, in selectivity order; unused slots point at the all-ones row.
inline void bv_rows(const BitRes& B, const Packet& p, const BvBlk** out) {
    const uint8_t* m8 = B.maps.data();
    const uint16_t* m16 = B.map16.data();
    const BvBlk* rows = B.rows.data();
    const size_t W = B.W;
    auto put = [&](uint32_t f, uint32_t cls) { out[B.pos[f]] = rows + (size_t(B.base[f]) + cls) * W; };
    put(BF_SIP, m8[bv_moff(BF_SIP) + (p.src_ip >> 24)]);
    put(BF_DIP, m8[bv_moff(BF_DIP) + (p.dst_ip >> 24)]);
    put(BF_SPORT, m8[bv_moff(BF_SPORT) + p.src_port]);
    put(BF_DPORT, m8[bv_moff(BF_DPORT) + p.dst_port]);
    put(BF_PLEN, m8[bv_moff(BF_PLEN) + p.packet_len]);
    put(BF_TTL, m8[bv_moff(BF_TTL) + p.ttl]);
    put(BF_PROTO, m8[bv_moff(BF_PROTO) + p.protocol]);
    put(BF_IFACE, m8[bv_moff(BF_IFACE) + p.ingress_iface]);
    put(BF_DSCP, m8[bv_moff(BF_DSCP) + std::min<uint32_t>(p.dscp, 64)]);
    put(BF_ICMP, m8[bv_moff(BF_ICMP) + p.icmp_type]);
    put(BF_FLAGS, m8[bv_moff(BF_FLAGS) + p.tcp_flags]);
    put(BF_REGION, m16[0 + std::min<uint32_t>(p.region_id, 4096)]);
    put(BF_VLAN, m16[4097 + std::min<uint32_t>(p.vlan_id, 4096)]);
}

#ifndef R4_STAGE
#define R4_STAGE 5  // rows ANDed before the early all-zero test (0: no test)
#endif

// First confirmed rule in rank order that ranks at or before `best` wins; blocks that start behind `best` are skipped.
#ifdef R3_STATS
static unsigned long long g_bvc;  // filter candidates reaching the full record check
#endif
inline void bv_search(const BitRes& B, const BvBlk* const* rp, const PacketVec& pv, uint64_t& best, uint8_t& act) {
    const uint32_t W = B.W;
    for (uint32_t b = 0; b < W; ++b) {
        if (B.first[b] > best) return;
        alignas(32) uint64_t w[4];
#if defined(__AVX2__)
        __m256i acc = _mm256_load_si256(reinterpret_cast<const __m256i*>(rp[0] + b));
        for (uint32_t k = 1; k < R4_STAGE; ++k)
            acc = _mm256_and_si256(acc, _mm256_load_si256(reinterpret_cast<const __m256i*>(rp[k] + b)));
        if (R4_STAGE && _mm256_testz_si256(acc, acc)) continue;
        for (uint32_t k = R4_STAGE ? R4_STAGE : 1; k < kBvFields; ++k)
            acc = _mm256_and_si256(acc, _mm256_load_si256(reinterpret_cast<const __m256i*>(rp[k] + b)));
        if (B.dead) acc = _mm256_and_si256(acc, _mm256_load_si256(reinterpret_cast<const __m256i*>(&B.alive[b])));
        if (_mm256_testz_si256(acc, acc)) continue;
        _mm256_store_si256(reinterpret_cast<__m256i*>(w), acc);
        // Visit only the non-zero words (one mask, not four data-dependent branches).
        uint32_t nzw = ~uint32_t(_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(acc, _mm256_setzero_si256())))) & 15u;
#else
        __m128i a0 = _mm_load_si128(reinterpret_cast<const __m128i*>(rp[0] + b));
        __m128i a1 = _mm_load_si128(reinterpret_cast<const __m128i*>(rp[0] + b) + 1);
        for (uint32_t k = 1; k < kBvFields; ++k) {
            a0 = _mm_and_si128(a0, _mm_load_si128(reinterpret_cast<const __m128i*>(rp[k] + b)));
            a1 = _mm_and_si128(a1, _mm_load_si128(reinterpret_cast<const __m128i*>(rp[k] + b) + 1));
        }
        if (B.dead) {
            a0 = _mm_and_si128(a0, _mm_load_si128(reinterpret_cast<const __m128i*>(&B.alive[b])));
            a1 = _mm_and_si128(a1, _mm_load_si128(reinterpret_cast<const __m128i*>(&B.alive[b]) + 1));
        }
        _mm_store_si128(reinterpret_cast<__m128i*>(w), a0);
        _mm_store_si128(reinterpret_cast<__m128i*>(w) + 1, a1);
        if (!(w[0] | w[1] | w[2] | w[3])) continue;
        uint32_t nzw = uint32_t(w[0] != 0) | uint32_t(w[1] != 0) << 1 | uint32_t(w[2] != 0) << 2 | uint32_t(w[3] != 0) << 3;
#endif
        for (; nzw; nzw &= nzw - 1) {
            const uint32_t q = uint32_t(__builtin_ctz(nzw));
            for (uint64_t x = w[q]; x; x &= x - 1) {
                const size_t i = size_t(b) * 256 + q * 64 + size_t(__builtin_ctzll(x));
                const uint64_t rk = B.rank[i];
                if (rk > best) return;
#ifdef R3_STATS
                ++g_bvc;
#endif
                if (rec_matches(B.recs[i], pv)) {
                    best = rk;
                    act = B.recs[i].val[13];
                    return;
                }
            }
        }
    }
}

// Position of the rule with this rank, or n.
uint32_t bv_find(const BitRes& B, uint64_t rank) {
    const auto it = std::lower_bound(B.rank.begin(), B.rank.end(), rank);
    return it != B.rank.end() && *it == rank ? uint32_t(it - B.rank.begin()) : B.n;
}

// Removes the rule: its position never survives again. Returns false if it was not there (or already removed).
bool bv_kill(BitRes& B, uint64_t rank) {
    const uint32_t i = bv_find(B, rank);
    if (i >= B.n || !(B.alive[i >> 8].w[(i >> 6) & 3] >> (i & 63) & 1)) return false;
    B.alive[i >> 8].w[(i >> 6) & 3] &= ~(uint64_t{1} << (i & 63));
    ++B.dead;
    return true;
}

// ---------- bucket table ----------

constexpr uint32_t kCnt = 0x0FFFFFFFu;  // BSlot::n record count
constexpr uint32_t kOvf = 0x80000000u;  // BSlot::n of slot 0: the group spilled

// Slot count for `keys` distinct keys at load <= 0.5 (with headroom for growth).
uint32_t capacity_for(uint32_t keys) {
    uint32_t want = std::max<uint32_t>(16, 2 * (keys + keys / 4 + 1)), cap = 16;
    while (cap < want) cap <<= 1;
    return cap;
}

#ifndef R1_CRC
#define R1_CRC 1
#endif
#if R1_CRC && defined(__SSE4_2__)
// Three CRC32 steps and a multiply (so the top bits, which pick the home group, depend on every input bit).
inline uint32_t key_h(const uint8_t* d, const uint32_t* F) {
    const uint32_t c = _mm_crc32_u32(_mm_crc32_u32(_mm_crc32_u32(0x9E3779B9u, F[d[0]]), F[d[1]]), F[d[2]]);
    return (c * 0x85EBCA77u) | 1u;  // never 0
}
#else
uint32_t key_h(const uint8_t* d, const uint32_t* F) { return uint32_t(key64(d, F) >> 32) | 1u; }  // never 0
#endif
uint32_t rec_key(const TupleTable& t, const RuleRec& rec) {
    uint32_t F[16];
    rec_dims(rec, F);
    return key_h(t.dim, F);
}
uint32_t home_of(const TupleTable& t, uint32_t h) { return h >> t.gshift; }
uint32_t rec_prio(const RuleRec& r) {
    uint32_t p;
    std::memcpy(&p, r.val + 9, 4);
    return p;
}
uint32_t bucket_room(uint32_t n) { return n <= 1 ? 1u : std::bit_ceil(n); }
bool bucket_full(uint32_t n) { return (n & (n - 1)) == 0; }  // n is a power of two: room == n
uint32_t slot_n(const BSlot& s) { return s.n & kCnt; }
void set_n(BSlot& s, uint32_t n) { s.n = (s.n & ~kCnt) | n; }

int log2_cap(uint32_t cap) {
    int bits = 0;
    while ((1u << bits) < cap) ++bits;
    return bits;
}

uint32_t table_slots(const TupleTable& t) { return uint32_t(t.groups.size()) * 4; }

void table_init(TupleTable& t, uint32_t cap) {
    const uint32_t g = cap / 4;
    t.gshift = uint32_t(32 - log2_cap(g));
    t.gmask = g - 1;
    t.count = 0;
    t.used = 0;
    t.spilled = 0;
    t.groups.assign(g, BGroup{});
    // Presence bitmap: R7_BM_LOG extra bits of resolution per slot, 2^12..2^22 bits. A bit is set when a key is
    // created and never cleared, so a clear bit proves the table has no such key.
    int lb = log2_cap(cap) + R7_BM_LOG;
    lb = std::clamp(lb, 12, 22);
    t.bm_shift = uint32_t(32 - lb);
    t.bm.assign(size_t(1) << (lb - 6), 0);
    t.arena.clear();
}

// Follows the overflow chain from the home group.
const BSlot* table_find(const TupleTable& t, uint32_t h) {
    for (uint32_t g = home_of(t, h);; g = (g + 1) & t.gmask) {
        const BGroup& G = t.groups[g];
        for (const BSlot& s : G.s)
            if (s.tag == h) return &s;
        if (!(G.s[0].n & kOvf)) return nullptr;
    }
}
BSlot* table_find(TupleTable& t, uint32_t h) {
    return const_cast<BSlot*>(table_find(static_cast<const TupleTable&>(t), h));
}

// A free slot for a new key, marking every full group passed as spilled. Requires a free slot somewhere.
BSlot& table_claim(std::vector<BGroup>& groups, uint32_t gmask, uint32_t home, uint32_t& spilled) {
    for (uint32_t g = home;; g = (g + 1) & gmask) {
        BGroup& G = groups[g];
        for (BSlot& s : G.s)
            if (!s.tag) return s;
        if (!(G.s[0].n & kOvf)) {
            G.s[0].n |= kOvf;
            ++spilled;
        }
    }
}

// First position in b[0, n) whose rank is not below rk.
uint32_t bucket_lower(const RuleRec* b, uint32_t n, uint64_t rk) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        const uint32_t mid = (lo + hi) / 2;
        if (rec_rank(b[mid]) < rk) lo = mid + 1; else hi = mid;
    }
    return lo;
}

// Arena records an insert into bucket s (null: new bucket) may append. Generous: a replace may first
// shrink the same bucket to a power of two, which then relocates on the insert.
size_t put_need(const BSlot* s) { return s ? 2 * size_t(slot_n(*s)) : 2; }

// Adds rec to its bucket. Allocates only when the arena lacks room; the commit path of an update has
// made sure it has room (put_need) and a free slot, so it cannot throw there.
void table_put(TupleTable& t, const RuleRec& rec) {
    const uint32_t h = rec_key(t, rec);
    BSlot* sp = table_find(t, h);
    if (!sp) {
        sp = &table_claim(t.groups, t.gmask, home_of(t, h), t.spilled);
        sp->tag = h;
        {
            const uint32_t bi = h >> t.bm_shift;
            t.bm[bi >> 6] |= uint64_t{1} << (bi & 63);
        }
        sp->off = uint32_t(t.arena.size());
        set_n(*sp, 0);
        t.arena.resize(t.arena.size() + 1);
        ++t.used;
    } else if (bucket_full(slot_n(*sp))) {  // relocate to the arena's end with double room
        const uint32_t n = slot_n(*sp), no = uint32_t(t.arena.size());
        t.arena.resize(t.arena.size() + 2 * size_t(n));
        std::copy_n(t.arena.begin() + sp->off, n, t.arena.begin() + no);
        sp->off = no;
    }
    BSlot& s = *sp;
    const uint32_t n = slot_n(s);
    RuleRec* b = t.arena.data() + s.off;
    const uint32_t pos = bucket_lower(b, n, rec_rank(rec));
    std::memmove(static_cast<void*>(b + pos + 1), b + pos, size_t(n - pos) * sizeof(RuleRec));
    b[pos] = rec;
    set_n(s, n + 1);
    s.first_prio = rec_prio(b[0]);
    ++t.count;
}

// Records the live buckets occupy after a repack.
size_t arena_live(const TupleTable& t) {
    size_t live = 0;
    for (const BGroup& G : t.groups)
        for (const BSlot& s : G.s)
            if (s.tag) live += bucket_room(slot_n(s));
    return live;
}

// Copies every bucket into `na` (empty, with capacity >= arena_live): no allocation, no holes.
void arena_repack(TupleTable& t, std::vector<RuleRec>&& na) {
    for (BGroup& G : t.groups)
        for (BSlot& s : G.s) {
            if (!s.tag) continue;
            const uint32_t off = uint32_t(na.size()), n = slot_n(s);
            na.insert(na.end(), t.arena.begin() + s.off, t.arena.begin() + s.off + n);
            na.resize(off + bucket_room(n));
            s.off = off;
        }
    t.arena.swap(na);
}

void table_erase(TupleTable& t, const RuleRec& rec) {
    BSlot* sp = table_find(t, rec_key(t, rec));
    if (!sp) return;
    BSlot& s = *sp;
    const uint32_t n = slot_n(s);
    RuleRec* b = t.arena.data() + s.off;
    const uint64_t rk = rec_rank(rec);
    const uint32_t pos = bucket_lower(b, n, rk);
    if (pos >= n || rec_rank(b[pos]) != rk) return;
    std::memmove(static_cast<void*>(b + pos), b + pos + 1, size_t(n - pos - 1) * sizeof(RuleRec));
    set_n(s, n - 1);
    --t.count;
    if (n == 1) {  // empty: free the slot (the group's overflow bit stays)
        s.tag = 0;
        s.first_prio = ~uint32_t{0};
        s.off = 0;
        --t.used;
    } else {
        s.first_prio = rec_prio(b[0]);
    }
}

// Rehash into a pre-allocated, zeroed group array: no allocation. Clears stale overflow bits.
void table_rehash(TupleTable& t, std::vector<BGroup>&& ng) {
    const uint32_t g = uint32_t(ng.size());
    const uint32_t gshift = uint32_t(32 - log2_cap(g)), gmask = g - 1;
    uint32_t spilled = 0;
    for (const BGroup& G : t.groups)
        for (const BSlot& s : G.s) {
            if (!s.tag) continue;
            BSlot& d = table_claim(ng, gmask, s.tag >> gshift, spilled);
            const uint32_t keep = d.n & kOvf;
            d = s;
            d.n = (s.n & kCnt) | keep;
        }
    t.groups.swap(ng);
    t.gshift = gshift;
    t.gmask = gmask;
    t.spilled = spilled;
}

// Grow at load 1/2, or rebuild in place once 1/8 of the groups carry stale overflow bits.
bool table_needs_rehash(const TupleTable& t, bool new_key) {
    return (new_key && (t.used + 1) * 2 > table_slots(t)) || t.spilled * 8 > t.groups.size();
}
uint32_t rehash_groups(const TupleTable& t, bool new_key) {
    const uint32_t g = uint32_t(t.groups.size());
    return (new_key && (t.used + 1) * 2 > table_slots(t)) ? 2 * g : g;
}

uint8_t first_fit(const std::vector<TupleTable>& tables, uint16_t fit) {
    for (size_t t = 0; t < tables.size(); ++t) {
        const uint16_t need = need_mask(tables[t].dim);
        if ((fit & need) == need) return static_cast<uint8_t>(t);
    }
    return kResidual;
}

// ---------- planner ----------

bool dims_ok(const Dims& d) {
    int src = 0, dst = 0;
    for (uint8_t x : d) {
        src += x <= 2;
        dst += x >= 3 && x <= 5;
    }
    return src <= 1 && dst <= 1;
}

struct PlanRule {
    uint16_t fit;
    uint32_t F[16];
};

// Deterministic generator for planning packets.
struct Lcg {
    uint64_t s = 0x2545F4914F6CDD1Dull;
    uint32_t next() {
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        return uint32_t(s >> 32);
    }
};

// A planning packet built from the rules alone (never from traffic): `aim` (if set) fixes
// every field it specifies; other fields copy a randomly chosen rule's field (or are random
// where that rule is wildcarded too).
// Values the rules pin on each exact field (protocol, iface, dscp, icmp, region, vlan). Real traffic mostly
// carries values some rule names, so a field the aimed rule leaves open is drawn from here.
struct Pinned {
    std::vector<uint16_t> v[6];
};
Pinned pinned_values(const std::vector<const Rule*>& all) {
    Pinned pv;
    for (const Rule* r : all) {
        if (!r->protocol.wildcard) pv.v[0].push_back(r->protocol.value);
        if (!r->ingress_iface.wildcard) pv.v[1].push_back(r->ingress_iface.value);
        if (!r->dscp.wildcard) pv.v[2].push_back(r->dscp.value);
        if (!r->icmp_type.wildcard) pv.v[3].push_back(r->icmp_type.value);
        if (!r->region_id.wildcard) pv.v[4].push_back(r->region_id.value);
        if (!r->vlan_id.wildcard) pv.v[5].push_back(r->vlan_id.value);
    }
    return pv;
}

Packet synth_packet(const Rule* aim, const std::vector<const Rule*>& all, const Pinned& pin, Lcg& g) {
    auto pick = [&]() -> const Rule& { return *all[g.next() % all.size()]; };
    auto ip = [&](Prefix32 Rule::*f) {
        const Prefix32& x = (aim && (aim->*f).prefix_len) ? aim->*f : pick().*f;
        return x.ip | (g.next() & ~x.mask);
    };
    auto range16 = [&](Range16 Rule::*f, uint16_t full_lo) {
        const Range16* x = aim ? &(aim->*f) : nullptr;
        if (!x || (x->low <= full_lo && x->high == 65535)) x = &(pick().*f);
        return uint16_t(x->low + g.next() % (uint32_t(x->high) - x->low + 1));
    };
    auto open_value = [&](int field, uint32_t dom) -> uint32_t {
        const std::vector<uint16_t>& v = pin.v[field];
        if (!v.empty() && g.next() % 10 != 0) return v[g.next() % v.size()];
        return g.next() % dom;
    };
    auto exact8 = [&](ExactOrWildcard8 Rule::*f, int field, uint32_t dom) {
        if (aim && !(aim->*f).wildcard) return (aim->*f).value;
        return uint8_t(open_value(field, dom));
    };
    auto exact16 = [&](ExactOrWildcard16 Rule::*f, int field, uint32_t dom) {
        if (aim && !(aim->*f).wildcard) return (aim->*f).value;
        return uint16_t(open_value(field, dom));
    };
    Packet p{};
    p.src_ip = ip(&Rule::src_ip);
    p.dst_ip = ip(&Rule::dst_ip);
    p.src_port = range16(&Rule::src_port, 0);
    p.dst_port = range16(&Rule::dst_port, 0);
    p.packet_len = range16(&Rule::packet_len, 20);
    p.protocol = exact8(&Rule::protocol, 0, 256);
    p.ingress_iface = exact8(&Rule::ingress_iface, 1, 256);
    p.dscp = exact8(&Rule::dscp, 2, 64);
    p.icmp_type = exact8(&Rule::icmp_type, 3, 256);
    p.region_id = exact16(&Rule::region_id, 4, 65536);
    p.vlan_id = exact16(&Rule::vlan_id, 5, 4096);
    const Masked8 fl = aim ? aim->tcp_flags : Masked8{};
    p.tcp_flags = uint8_t((g.next() & ~fl.mask) | (fl.value & fl.mask));
    const Range8 tt = aim ? aim->ttl : Range8{};
    p.ttl = uint8_t(tt.low + g.next() % (uint32_t(tt.high) - tt.low + 1));
    return p;
}

constexpr size_t kPlanPackets = 1024;

// Estimated per-packet saving of a table over the sampled unassigned rules: rules leaving
// the residual sweep, minus one probe, minus the records the planning packets would fetch
// (tag matches = rules sharing the packet's key).
double table_gain(const Dims& d, const std::vector<const PlanRule*>& sample, double p, double probe,
                  const std::vector<std::array<uint32_t, 16>>& probes, std::vector<uint64_t>& keys) {
    const uint16_t need = need_mask(d.data());
    keys.clear();
    for (const PlanRule* r : sample)
        if ((r->fit & need) == need) keys.push_back(key64(d.data(), r->F));
    if (keys.empty()) return -1e300;
    std::sort(keys.begin(), keys.end());
    double pairs = 0;
    for (size_t i = 0; i < keys.size();) {
        size_t j = i;
        while (j < keys.size() && keys[j] == keys[i]) ++j;
        pairs += double(j - i) * double(j - i - 1);
        i = j;
    }
    const double fit = keys.size() / p;
    const double sumsq = fit + pairs / (p * p);
    if (sumsq / fit > kCollisionLimit) return -1e300;  // TupleMerge-style collision limit
    double hits = 0;
    for (const auto& F : probes) {
        const auto range = std::equal_range(keys.begin(), keys.end(), key64(d.data(), F.data()));
        hits += double(range.second - range.first);
    }
    const double fetched = hits / double(probes.size()) / p;
    // Weighted set cover: per-packet cost per covered rule, against 1 unit per residual rule.
    return 1.0 - (probe + kBucketCost * fetched) / fit;
}

std::vector<Dims> plan_tables(const std::vector<PlanRule>& rules, const std::vector<const Rule*>& src) {
    std::vector<Dims> plan;
    if (rules.empty()) return plan;
    const double probe = probe_cost(rules.size());
    std::vector<const PlanRule*> left;
    for (const PlanRule& r : rules) left.push_back(&r);
    std::vector<uint64_t> keys;
    std::vector<std::array<uint32_t, 16>> probes(kPlanPackets);
    Lcg g;
    const Pinned pin = pinned_values(src);
    for (auto& F : probes) {
        const bool aimed = g.next() % 10 < 7;
        const Rule* aim = aimed ? src[g.next() % src.size()] : nullptr;
        packet_dims(synth_packet(aim, src, pin, g), F.data());
    }
    while (plan.size() < kMaxTables && !left.empty()) {
        const size_t step = std::max<size_t>(1, left.size() / kPlanSample);
        std::vector<const PlanRule*> sample;
        for (size_t i = 0; i < left.size(); i += step) sample.push_back(left[i]);
        const double p = double(sample.size()) / double(left.size());

        std::vector<std::pair<double, Dims>> scored;
        for (uint8_t a = 0; a < kDims; ++a)
            for (uint8_t b = a; b < kDims; ++b) {
                const Dims d{a, b == a ? kNoDim : b, kNoDim};
                if (dims_ok(d)) scored.push_back({table_gain(d, sample, p, probe, probes, keys), d});
            }
        std::sort(scored.begin(), scored.end(), [](auto& x, auto& y) { return x.first > y.first; });
        const size_t top = std::min<size_t>(6, scored.size());
        for (size_t i = 0; i < top; ++i) {
            if (scored[i].second[1] == kNoDim) continue;
            for (uint8_t c = 0; c < kDims; ++c) {
                Dims d = scored[i].second;
                if (c == d[0] || c == d[1]) continue;
                d[2] = c;
                if (dims_ok(d)) scored.push_back({table_gain(d, sample, p, probe, probes, keys), d});
            }
        }
        const auto best = std::max_element(scored.begin(), scored.end(),
                                           [](auto& x, auto& y) { return x.first < y.first; });
        if (best == scored.end() || best->first <= 0) break;
        plan.push_back(best->second);
        const uint16_t need = need_mask(best->second.data());
        left.erase(std::remove_if(left.begin(), left.end(), [&](const PlanRule* r) { return (r->fit & need) == need; }),
                   left.end());
    }
    return plan;
}

// Touches a vector's spare capacity (construct, then drop) so later growth inside it takes no first-touch
// page faults during a timed update. No allocation: the capacity is already there.
template <class V>
void prefault(V& v) {
    const size_t n = v.size();
    v.resize(v.capacity());
    v.resize(n);
}

// ---------- id map (open addressing, value = id << 32 | index + 1, 0 = empty) ----------

uint32_t id_home(uint32_t id, size_t cap) { return uint32_t((id * 0x9E3779B97F4A7C15ull) >> 32) & uint32_t(cap - 1); }

long idmap_find(const std::vector<uint64_t>& m, uint32_t id) {
    if (m.empty()) return -1;
    for (uint32_t j = id_home(id, m.size());; j = (j + 1) & uint32_t(m.size() - 1)) {
        if (m[j] == 0) return -1;
        if (uint32_t(m[j] >> 32) == id) return long(j);
    }
}

void idmap_put(std::vector<uint64_t>& m, uint32_t id, size_t index) {
    uint32_t j = id_home(id, m.size());
    while (m[j] != 0) j = (j + 1) & uint32_t(m.size() - 1);
    m[j] = (uint64_t{id} << 32) | (index + 1);
}

void idmap_erase_at(std::vector<uint64_t>& m, uint32_t i) {
    const uint32_t mask = uint32_t(m.size() - 1);
    uint32_t j = i;
    for (;;) {
        j = (j + 1) & mask;
        if (m[j] == 0) break;
        const uint32_t k = id_home(uint32_t(m[j] >> 32), m.size());
        const bool stays = (i <= j) ? (i < k && k <= j) : (i < k || k <= j);
        if (!stays) {
            m[i] = m[j];
            i = j;
        }
    }
    m[i] = 0;
}

std::vector<uint64_t> idmap_build(const std::vector<OptimizedClassifier::Entry>& entries, size_t room) {
    size_t cap = 16;
    while (cap < 2 * room) cap <<= 1;
    std::vector<uint64_t> m(cap, 0);
    for (size_t i = 0; i < entries.size(); ++i) idmap_put(m, entries[i].rule.rule_id, i);
    return m;
}

size_t store_index(uint64_t slot_value) { return size_t(slot_value & 0xFFFFFFFFu) - 1; }

// ---------- index maintenance ----------

void index_remove(OptimizedClassifier::Index& ix, const OptimizedClassifier::Entry& e) {
    if (e.where < kMaxTables) {
        table_erase(ix.tables[e.where], make_rec(e.rule));
    } else if (e.where == kResidual) {
        const uint64_t rk = rank_of(e.rule);
        const uint32_t p = sweep_lower(ix.delta, rk);
        if (p < ix.delta.n && ix.delta.rank[p] == rk) sweep_erase(ix.delta, rk);
        else if (ix.use_bv) bv_kill(ix.bv, rk);
        else sweep_kill(ix.residual, rk);
    }
}

// Folds the delta into the residual sweep. `m` is allocated and empty with room for both.
void residual_merge(OptimizedClassifier::Index& ix, Sweep& m) {
    sweep_merge(m, ix.residual, ix.delta);
    ix.residual = std::move(m);
    ix.delta.n = 0;
}
size_t merge_room(const OptimizedClassifier::Index& ix) {
    const size_t live = ix.residual.n - ix.residual.dead + ix.delta.n;
    return live + live / 4 + 16;
}
// Delta capacity for a residual of `n` rules held in a bit-vector. A merge rebuilds the whole filter (about 1 us
// per rule), so it must stay below 1% of the inserts a p99 sees: capacity grows with the filter.
uint32_t delta_cap_for(size_t n, bool bv) {
    if (!bv) return kDelta;
    return std::clamp<uint32_t>(round16(uint32_t(n / 64)), kDelta, kDeltaMax);
}
// Live residual rules (including the delta's), rank-sorted, without the entry at `skip` (-1: none), plus `extra`.
std::vector<RuleRec> residual_recs(const std::vector<OptimizedClassifier::Entry>& store, long skip,
                                   const RuleRec* extra) {
    std::vector<RuleRec> v;
    for (size_t i = 0; i < store.size(); ++i)
        if (store[i].where == kResidual && long(i) != skip) v.push_back(make_rec(store[i].rule));
    if (extra) v.push_back(*extra);
    std::sort(v.begin(), v.end(), [](const RuleRec& a, const RuleRec& b) { return rec_rank(a) < rec_rank(b); });
    return v;
}

}  // namespace

OptimizedClassifier::OptimizedClassifier() = default;
OptimizedClassifier::~OptimizedClassifier() = default;

// Builds a complete index for `entries` on the side; commits (index_ and every entry's
// `where`) only after all allocation succeeded.
void OptimizedClassifier::rebuild_from(std::vector<Entry>& entries) {
    Index nx;
    long cat = -1;
    for (size_t i = 0; i < entries.size(); ++i)
        if (is_catchall(entries[i].rule) && (cat < 0 || rank_of(entries[i].rule) < rank_of(entries[size_t(cat)].rule)))
            cat = long(i);
    if (cat >= 0) {
        const Rule& c = entries[size_t(cat)].rule;
        nx.has_cat = true;
        nx.cat_rank = rank_of(c);
        nx.cat_action = static_cast<uint8_t>(c.action);
        nx.cat_len_low = c.packet_len.low;
    }
    std::vector<uint8_t> where(entries.size(), kDormant);
    std::vector<PlanRule> live;
    std::vector<const Rule*> live_rules;
    std::vector<size_t> live_pos;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (long(i) == cat) {
            where[i] = kCatchAll;
            continue;
        }
        if (nx.has_cat && rank_of(entries[i].rule) > nx.cat_rank) continue;
        PlanRule pr;
        pr.fit = fit_mask(entries[i].rule);
        rec_dims(make_rec(entries[i].rule), pr.F);
        live.push_back(pr);
        live_rules.push_back(&entries[i].rule);
        live_pos.push_back(i);
    }
    const std::vector<Dims> plan = plan_tables(live, live_rules);
    nx.tables.resize(plan.size());
    for (size_t t = 0; t < plan.size(); ++t) std::copy(plan[t].begin(), plan[t].end(), nx.tables[t].dim);

    std::vector<uint32_t> counts(plan.size(), 0);
    std::vector<size_t> res_pos;
    for (size_t k = 0; k < live.size(); ++k) {
        const uint8_t w = first_fit(nx.tables, live[k].fit);
        where[live_pos[k]] = w;
        if (w == kResidual) res_pos.push_back(live_pos[k]); else ++counts[w];
    }
    std::vector<size_t> by_rank(live_pos);
    std::sort(by_rank.begin(), by_rank.end(),
              [&](size_t a, size_t b) { return rank_of(entries[a].rule) < rank_of(entries[b].rule); });
    {
        std::vector<std::vector<uint64_t>> keys(plan.size());
        for (size_t i : live_pos)
            if (where[i] != kResidual) keys[where[i]].push_back(rec_key(nx.tables[where[i]], make_rec(entries[i].rule)));
        for (size_t t = 0; t < plan.size(); ++t) {
            std::sort(keys[t].begin(), keys[t].end());
            table_init(nx.tables[t], capacity_for(uint32_t(std::unique(keys[t].begin(), keys[t].end()) - keys[t].begin())));
        }
    }
    for (size_t t = 0; t < plan.size(); ++t) nx.tables[t].arena.reserve(2 * size_t(counts[t]) + 16);
    for (size_t i : by_rank)
        if (where[i] != kResidual) table_put(nx.tables[where[i]], make_rec(entries[i].rule));
    for (TupleTable& t : nx.tables) {  // drop relocation holes; keep room for updates
        const size_t live = arena_live(t);
        std::vector<RuleRec> na;
        na.reserve(live + live / 4 + 64);
        prefault(na);
        arena_repack(t, std::move(na));
    }
    std::sort(res_pos.begin(), res_pos.end(),
              [&](size_t a, size_t b) { return rank_of(entries[a].rule) < rank_of(entries[b].rule); });
    if (res_pos.size() >= kBvMin) {
        std::vector<RuleRec> rr;
        rr.reserve(res_pos.size());
        for (size_t i : res_pos) rr.push_back(make_rec(entries[i].rule));
        nx.bv = bv_build(rr);
        nx.use_bv = true;
    } else {
        sweep_alloc(nx.residual, uint32_t(res_pos.size() + res_pos.size() / 4 + 16));
        for (size_t i : res_pos) sweep_write(nx.residual, nx.residual.n++, make_rec(entries[i].rule));
        sweep_pad(nx.residual);
    }
    sweep_alloc(nx.delta, delta_cap_for(res_pos.size(), nx.use_bv));
#ifdef R1_STATS
    std::fprintf(stderr, "rebuild: %zu entries, %zu live, cat=%d residual=%u\n", entries.size(), live.size(),
                 int(nx.has_cat), nx.residual.n);
    {
        int act = 0;
        for (uint32_t k = 0; k < kLanes; ++k) {
            bool any = false;
            for (uint32_t i = 0; i < nx.residual.n; ++i) {
                const uint16_t v = nx.residual.lanes[size_t(k) * nx.residual.cap + i];
                any |= v != 0;
            }
            if (k >= 16 && k < 21) continue;  // value lanes follow their masks
            act += any;
            std::fprintf(stderr, "%d", int(any));
        }
        std::fprintf(stderr, "  active lanes %d of 21\n", act);
    }
    for (const TupleTable& t : nx.tables) {
        std::fprintf(stderr, "  table dims %d %d %d rules %u buckets %u cap %u\n", t.dim[0], t.dim[1],
                     t.dim[2], t.count, t.used, table_slots(t));
    }
#endif
    index_ = std::move(nx);  // commit: nothing below allocates
    for (size_t i = 0; i < entries.size(); ++i) entries[i].where = where[i];
}

void OptimizedClassifier::initialize(const std::vector<Rule>& rules) {
    std::vector<Entry> entries;
    entries.reserve(rules.size() + rules.size() / 4 + 16);
    prefault(entries);
    size_t cap = 16;
    while (cap < 2 * entries.capacity()) cap <<= 1;
    std::vector<uint64_t> map(cap, 0);
    for (const Rule& in : rules) {
        if (!rule_valid(in)) continue;
        const Rule r = normalized(in);
        const long slot = idmap_find(map, r.rule_id);
        if (slot >= 0) {  // duplicate id: the later rule replaces the earlier one
            entries[store_index(map[size_t(slot)])].rule = r;
            continue;
        }
        entries.push_back({r, kDormant});
        idmap_put(map, r.rule_id, entries.size() - 1);
    }
    rebuild_from(entries);
    store_.swap(entries);
    idmap_.swap(map);
    idmap_count_ = uint32_t(store_.size());
    warm_up();
}

void OptimizedClassifier::place_new(const Rule& r, long pos) {
    Index& ix = index_;
    const bool fresh = pos < 0;
    uint8_t dest = kDormant;
    if (!(ix.has_cat && rank_of(r) > ix.cat_rank)) dest = first_fit(ix.tables, fit_mask(r));

    // Phase 1: every allocation the commit needs.
    std::vector<uint64_t> grown_map;
    if (fresh) {
        if ((idmap_count_ + 1) * 2 > idmap_.size()) grown_map = idmap_build(store_, store_.size() * 2 + 16);
        if (store_.size() == store_.capacity()) {
            store_.reserve(std::max<size_t>(16, store_.capacity() * 2));
            prefault(store_);
        }
    }
    std::vector<BGroup> grown_groups;
    std::vector<RuleRec> repacked;
    Sweep grown_sweep;
    BitRes grown_bv;
    Sweep grown_delta;
    bool grow_table = false, grow_sweep = false, grow_bv = false, repack = false;
    const RuleRec rec = make_rec(r);
    if (dest < kMaxTables) {
        TupleTable& t = ix.tables[dest];
        const BSlot* cur = table_find(t, rec_key(t, rec));
        if (table_needs_rehash(t, !cur)) {
            grown_groups.assign(rehash_groups(t, !cur), BGroup{});
            grow_table = true;
        }
        const size_t need = put_need(cur);
        if (t.arena.size() + need > t.arena.capacity()) {
            const size_t live = arena_live(t) + need;
            repacked.reserve(2 * live + 64);
            prefault(repacked);
            repack = true;
        }
    } else if (dest == kResidual && ix.delta.n + 1 > ix.delta.cap) {
        const size_t live = (ix.use_bv ? ix.bv.n - ix.bv.dead : ix.residual.n - ix.residual.dead) + ix.delta.n + 1;
        if (ix.use_bv || live >= kBvMin) {  // fold the delta (and this rule) into a fresh bit-vector
            grown_bv = bv_build(residual_recs(store_, pos, &rec));
            sweep_alloc(grown_delta, delta_cap_for(grown_bv.n, true));
            grow_bv = true;
        } else {
            sweep_alloc(grown_sweep, uint32_t(merge_room(ix)));
            grow_sweep = true;
        }
    }

    // Phase 2: commit without allocating.
    if (grow_table) table_rehash(ix.tables[dest], std::move(grown_groups));
    if (repack) arena_repack(ix.tables[dest], std::move(repacked));
    if (grow_sweep) residual_merge(ix, grown_sweep);
    const bool old_in_bv = grow_bv && !fresh && store_[size_t(pos)].where == kResidual;  // not in the new filter
    if (grow_bv) {
        ix.bv = std::move(grown_bv);
        ix.use_bv = true;
        ix.residual.n = 0;
        ix.residual.dead = 0;
        ix.delta = std::move(grown_delta);
    }
    if (!grown_map.empty()) idmap_.swap(grown_map);
    if (!fresh && !old_in_bv) index_remove(ix, store_[size_t(pos)]);
    if (dest < kMaxTables) table_put(ix.tables[dest], rec);
    else if (dest == kResidual && !grow_bv) sweep_insert(ix.delta, rec);
    if (fresh) {
        store_.push_back({r, dest});
        idmap_put(idmap_, r.rule_id, store_.size() - 1);
        ++idmap_count_;
    } else {
        store_[size_t(pos)] = {r, dest};
    }
}

void OptimizedClassifier::insert_rule(const Rule& in) {
    if (!rule_valid(in)) return;  // rejected: state untouched
    const Rule r = normalized(in);
    const long slot = idmap_find(idmap_, r.rule_id);
    const long pos = slot < 0 ? -1 : long(store_index(idmap_[size_t(slot)]));
    if (pos >= 0 && store_[size_t(pos)].where == kCatchAll) {
        // The bound itself changes: rebuild everything on the side.
        std::vector<Entry> next = store_;
        next[size_t(pos)].rule = r;
        rebuild_from(next);
        store_.swap(next);
        return;
    }
    place_new(r, pos);
}

void OptimizedClassifier::delete_rule(uint32_t rule_id) {
    const long slot = idmap_find(idmap_, rule_id);
    if (slot < 0) return;
    const size_t pos = store_index(idmap_[size_t(slot)]);
    if (store_[pos].where == kCatchAll) {
        std::vector<Entry> next = store_;
        next[pos] = next.back();
        next.pop_back();
        std::vector<uint64_t> map = idmap_build(next, std::max(next.size(), idmap_.size() / 2));
        rebuild_from(next);
        store_.swap(next);
        idmap_.swap(map);
        idmap_count_ = uint32_t(store_.size());
        return;
    }
    index_remove(index_, store_[pos]);
    if (index_.use_bv) {
        if (index_.bv.dead * 2 > index_.bv.n && index_.bv.n >= 64) {  // drop deleted positions
            try {
                const std::vector<RuleRec> rr = residual_recs(store_, long(pos), nullptr);
                BitRes nb;
                if (!rr.empty()) nb = bv_build(rr);
                index_.bv = std::move(nb);
                index_.use_bv = !rr.empty();
                index_.delta.n = 0;  // the filter now holds the delta's rules too
            } catch (const std::bad_alloc&) {  // optional: the dead positions just stay
            }
        }
    } else if (index_.residual.dead * 2 > index_.residual.n && index_.residual.n >= 64) {  // drop tombstones
        try {
            Sweep m;
            sweep_alloc(m, uint32_t(merge_room(index_)));
            residual_merge(index_, m);
        } catch (const std::bad_alloc&) {  // optional: the tombstones just stay
        }
    }
    idmap_erase_at(idmap_, uint32_t(slot));
    const size_t last = store_.size() - 1;
    if (pos != last) {
        store_[pos] = store_[last];
        const long moved = idmap_find(idmap_, store_[pos].rule.rule_id);
        idmap_[size_t(moved)] = (uint64_t{store_[pos].rule.rule_id} << 32) | (pos + 1);
    }
    store_.pop_back();
    --idmap_count_;
}

namespace {

// Exact answer over every live rule, dormant ones included (out-of-spec short packets).
Action scan_all(const std::vector<OptimizedClassifier::Entry>& store, const Packet& p) {
    uint64_t best = ~uint64_t{0};
    Action act = Action::DROP;
    for (const auto& e : store)
        if (e.rule.matches(p) && rank_of(e.rule) <= best) {
            best = rank_of(e.rule);
            act = e.rule.action;
        }
    return act;
}

#ifdef R3_PROF
#include <x86intrin.h>
static unsigned long long g_ph[8], g_last, g_n;
struct ProfDump { ~ProfDump() { std::fprintf(stderr, "cycles/pkt p1 %.0f p2 %.0f buckets %.0f bv %.0f rest %.0f\n", double(g_ph[1])/g_n, double(g_ph[2])/g_n, double(g_ph[4])/g_n, double(g_ph[5])/g_n, double(g_ph[3])/g_n); } } g_dump;
#define PROF_T(k) do { unsigned long long t_ = __rdtsc(); if (k == 0) { g_last = t_; g_n += n; } else { g_ph[k] += t_ - g_last; g_last = t_; } } while (0)
#else
#define PROF_T(k) ((void)0)
#endif

#ifdef R3_STATS
static unsigned long long g_chk, g_bk, g_pk;
struct StatDump { ~StatDump() { std::fprintf(stderr, "checks/pkt %.2f buckets/pkt %.2f bvcand/pkt %.3f\n", double(g_chk)/g_pk, double(g_bk)/g_pk, double(g_bvc)/g_pk); } } g_sd;
#endif
struct Probe {
    PacketVec vec;
    uint16_t px[24];
    uint64_t best;
    uint8_t act;
    bool short_pkt;
};
struct Item {      // a (packet, table) pair whose presence bit is set
    uint32_t h;
    uint32_t pt;   // packet << 4 | table
};
static_assert(kMaxTables <= 16, "table number must fit in 4 bits");
struct BkEnt {     // a non-empty bucket that can beat the catch-all
    const RuleRec* r;
    uint32_t cnt;
    uint32_t pkt;
};

// Sweep only, for an index without tables (e.g. a dominance cut left a handful of rules).
void sweep_chunk(const OptimizedClassifier::Index& ix, const std::vector<OptimizedClassifier::Entry>& store,
                 const Packet* pk, size_t n, Action* out) {
    const uint64_t start_rank = ix.has_cat ? ix.cat_rank : ~uint64_t{0};
    const uint8_t start_action = ix.has_cat ? ix.cat_action : 0;
    for (size_t i = 0; i < n; ++i) {
        if (pk[i].packet_len < ix.cat_len_low) {
            out[i] = scan_all(store, pk[i]);
            continue;
        }
        const PacketVec v = make_vec(pk[i]);
        uint16_t px[24];
        vec_lanes(v, pk[i], px);
        uint64_t best = start_rank;
        uint8_t act = start_action;
        if (ix.use_bv) {
            const BvBlk* rp[kBvFields];
            bv_rows(ix.bv, pk[i], rp);
            bv_search(ix.bv, rp, v, best, act);
        } else {
            sweep_search(ix.residual, px, best, act);
        }
        if (ix.delta.n) sweep_search(ix.delta, px, best, act);
        out[i] = static_cast<Action>(act);
    }
}

// Pass A hashes every packet into every table and tests the table's key-presence bit; only pairs whose bit is
// set (a superset of the tables that hold the key) are listed, and only their home group is prefetched.
// Pass B resolves each listed bucket, keeping those whose best rule can beat the catch-all, and prefetches
// their first records. Pass C scans each kept bucket in rank order, stopping at the first rule that either
// cannot beat the best or matches. Pass D runs the residual filter, which skips blocks ranked behind the best.
void classify_chunk(const OptimizedClassifier::Index& ix, const std::vector<OptimizedClassifier::Entry>& store,
                    const Packet* pk, size_t n, Action* out) {
    const size_t T = ix.tables.size();
    const uint64_t start_rank = ix.has_cat ? ix.cat_rank : ~uint64_t{0};
    const uint8_t start_action = ix.has_cat ? ix.cat_action : 0;
    Probe pr[kChunk];
    Item item[kChunk * kMaxTables + 1];
    BkEnt bk[kChunk * kMaxTables + 1];
    size_t ni = 0, nbk = 0;
    static const char kDummy[64] = {};
    PROF_T(0);
    for (size_t i = 0; i < n; ++i) {
        Probe& q = pr[i];
        q.short_pkt = pk[i].packet_len < ix.cat_len_low;  // cat_len_low is 0 when there is no bound
        q.best = start_rank;
        q.act = start_action;
        q.vec = make_vec(pk[i]);
        vec_lanes(q.vec, pk[i], q.px);
        uint32_t F[16];
        packet_dims(pk[i], F);
        const uint32_t live = uint32_t(q.short_pkt) - 1u;  // all ones unless the packet takes the full scan
        for (size_t t = 0; t < T; ++t) {
            const TupleTable& tb = ix.tables[t];
            const uint32_t h = key_h(tb.dim, F);
            const uint32_t bi = h >> tb.bm_shift;
            const uint32_t bit = uint32_t(tb.bm[bi >> 6] >> (bi & 63)) & 1u & live;
            item[ni] = {h, uint32_t(i << 4 | t)};
            ni += bit;
            // Prefetch the home group only for a set bit; a clear bit prefetches a resident dummy line.
            const uintptr_t mk = uintptr_t(0) - uintptr_t(bit);
            const uintptr_t ga = reinterpret_cast<uintptr_t>(&tb.groups[home_of(tb, h)]);
            const uintptr_t da = reinterpret_cast<uintptr_t>(kDummy);
            _mm_prefetch(reinterpret_cast<const char*>((ga & mk) | (da & ~mk)), _MM_HINT_T0);
        }
    }
    PROF_T(1);
    const uint32_t best_prio = uint32_t(start_rank >> 32);
    for (size_t j = 0; j < ni; ++j) {
        const uint32_t h = item[j].h;
        const TupleTable& tb = ix.tables[item[j].pt & 15u];
        const BGroup& G = tb.groups[home_of(tb, h)];
        // Branchless: tag-match mask, first set bit (4 = none), conditional append. Written as a mask
        // because GCC turns a ternary select chain into compare-and-jump.
#if defined(__AVX2__) && !defined(R1_NO_SIMD_TAG)
        const __m256i hv = _mm256_set1_epi32(int(h));
        const uint32_t m0 = uint32_t(_mm256_movemask_ps(_mm256_castsi256_ps(
            _mm256_cmpeq_epi32(_mm256_load_si256(reinterpret_cast<const __m256i*>(&G.s[0])), hv))));
        const uint32_t m1 = uint32_t(_mm256_movemask_ps(_mm256_castsi256_ps(
            _mm256_cmpeq_epi32(_mm256_load_si256(reinterpret_cast<const __m256i*>(&G.s[2])), hv))));
        // Tags are lane 0 of each 16-byte slot: bits 0 and 4 of each mask.
        const uint32_t m = (m0 & 1u) | ((m0 >> 3) & 2u) | ((m1 & 1u) << 2) | ((m1 >> 1) & 8u);
#else
        const uint32_t m = uint32_t(G.s[0].tag == h) | uint32_t(G.s[1].tag == h) << 1 |
                           uint32_t(G.s[2].tag == h) << 2 | uint32_t(G.s[3].tag == h) << 3;
#endif
        uint32_t k = uint32_t(__builtin_ctz(m | 16u));
        const BSlot* s = &G.s[k & 3];
        const bool slow = (k == 4) & ((G.s[0].n & kOvf) != 0);  // one rare branch, not two
        if (__builtin_expect(slow, 0)) {  // key may sit in a later group
            s = table_find(tb, h);
            k = 4u * uint32_t(s == nullptr);
            if (!s) s = &G.s[0];
        }
        const bool take = (k < 4) & (s->first_prio <= best_prio);
        const RuleRec* r = tb.arena.data() + s->off;
        bk[nbk] = {r, slot_n(*s), item[j].pt >> 4};
        nbk += take;
        const char* rc = reinterpret_cast<const char*>(r);
        _mm_prefetch(rc, _MM_HINT_T0);
        _mm_prefetch(rc + 64 * uint32_t(slot_n(*s) > 1), _MM_HINT_T0);
    }
    PROF_T(2);
    for (size_t e = 0; e < nbk; ++e) {
        Probe& q = pr[bk[e].pkt];
        const RuleRec* r = bk[e].r;
        const uint32_t cnt = bk[e].cnt;
        uint64_t best = q.best;
        uint8_t act = q.act;
#ifdef R3_STATS
        ++g_bk;
#endif
#ifndef R1_BRANCHY_BUCKET
        // Most buckets hold one rule: test the first record without a branch (masked select of best and
        // action); scan the rest only when it neither matched nor ranks behind `best`.
        if (__builtin_expect(cnt == 0, 0)) continue;
        const uint64_t rk0 = rec_rank(r[0]);
        const bool in0 = rk0 <= best;  // inclusive: the max legal rank still wins
        const bool hit0 = in0 & rec_matches(r[0], q.vec);
        const uint64_t m0 = uint64_t(0) - uint64_t(hit0);
        best = (rk0 & m0) | (best & ~m0);
        act = uint8_t((r[0].val[13] & uint8_t(m0)) | (act & ~uint8_t(m0)));
        q.best = best;
        q.act = act;
        if (__builtin_expect(hit0 | !in0 | (cnt == 1), 1)) continue;
        for (uint32_t k = 1; k < cnt; ++k) {
#else
        for (uint32_t k = 0; k < cnt; ++k) {
#endif
            const uint64_t rk = rec_rank(r[k]);
#ifdef R3_STATS
            ++g_chk;
#endif
            if (rk > best) break;  // inclusive: the max legal rank still wins
            if (rec_matches(r[k], q.vec)) {
                best = rk;
                act = r[k].val[13];
                break;
            }
        }
        q.best = best;
        q.act = act;
    }
    PROF_T(4);
    for (size_t i = 0; i < n; ++i) {
        const Probe& q = pr[i];
#ifdef R3_STATS
        ++g_pk;
#endif
        if (q.short_pkt) {
            out[i] = scan_all(store, pk[i]);
            continue;
        }
        uint64_t best = q.best;
        uint8_t act = q.act;
        // Last: skips blocks ranked behind `best`. The rows are looked up here, and only if a block can still win
        // (they sit in L2; prefetching them earlier cost more instructions than it saved).
        if (ix.use_bv) {
            if (ix.bv.W && ix.bv.first[0] <= best) {
                const BvBlk* rp[kBvFields];
                bv_rows(ix.bv, pk[i], rp);
                bv_search(ix.bv, rp, q.vec, best, act);
            }
        }
        else sweep_search(ix.residual, q.px, best, act);
        PROF_T(5);
        if (ix.delta.n) sweep_search(ix.delta, q.px, best, act);
        out[i] = static_cast<Action>(act);
    }
    PROF_T(3);
}

}  // namespace

// Pays the cold-start costs (instruction cache, first-touch stack pages, index lines evicted by the build's
// temporaries) at initialize() instead of in the first timed batch: one read pass over the index, then a few
// batches of synthetic packets. Results are discarded; nothing is cached by packet.
void OptimizedClassifier::warm_up() {
    uint64_t sum = 0;
    auto touch = [&sum](const void* p, size_t bytes) {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        for (size_t i = 0; i < bytes; i += 64) sum += b[i];
    };
    for (const TupleTable& t : index_.tables) {
        touch(t.groups.data(), t.groups.size() * sizeof(BGroup));
        touch(t.arena.data(), t.arena.size() * sizeof(RuleRec));
    }
    for (const TupleTable& t : index_.tables) touch(t.bm.data(), t.bm.size() * sizeof(uint64_t));
    touch(index_.bv.rows.data(), index_.bv.rows.size() * sizeof(BvBlk));
    touch(index_.bv.recs.data(), index_.bv.recs.size() * sizeof(RuleRec));
    touch(index_.bv.maps.data(), index_.bv.maps.size());
    touch(index_.bv.map16.data(), index_.bv.map16.size() * 2);
    for (const Sweep* s : {&index_.residual, &index_.delta}) {
        touch(s->lanes.data(), s->lanes.size() * sizeof(uint16_t));
        touch(s->rank.data(), s->rank.size() * sizeof(uint64_t));
    }
    std::vector<const Rule*> all;
    all.reserve(store_.size());
    for (const Entry& e : store_) all.push_back(&e.rule);
    if (all.empty()) return;
    const Pinned pin = pinned_values(all);
    Lcg g;
    constexpr size_t kWarm = 4 * kBatch;
    std::vector<Packet> pk(kWarm);
    for (Packet& p : pk) p = synth_packet(g.next() % 10 < 7 ? all[g.next() % all.size()] : nullptr, all, pin, g);
    std::vector<Action> out(kWarm);
    for (int rep = 0; rep < 2; ++rep) classify_batch(pk.data(), pk.size(), out.data());
    for (Action a : out) sum += static_cast<uint64_t>(a);
    asm volatile("" : : "r"(sum));  // keep the reads
}

Action OptimizedClassifier::classify(const Packet& packet) {
    Action a;
    classify_batch(&packet, 1, &a);
    return a;
}

void OptimizedClassifier::classify_batch(const Packet* packets, size_t count, Action* out_actions) {
    if (index_.tables.empty()) return sweep_chunk(index_, store_, packets, count, out_actions);
    for (size_t i = 0; i < count; i += kChunk)
        classify_chunk(index_, store_, packets + i, std::min(kChunk, count - i), out_actions + i);
}

}  // namespace packet_rush
