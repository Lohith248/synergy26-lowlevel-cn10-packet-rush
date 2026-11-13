#pragma once
// Hash tuple tables of 64-byte rule records, a bit-vector (or lane-major sweep) residual and a full-catch-all
// dominance cut. The design is described at the top of classifier.cpp.

#include "classifier_interface.h"
#include <cstdint>
#include <vector>

namespace packet_rush {

// One rule in one cache line. Bytes 0-31: eight u16 lower bounds then eight complemented
// upper bounds (src/dst IP halves, ports, length, TTL). Bytes 32-63: nine masked byte
// equalities (protocol, iface, dscp, icmp, tcp flags, region, vlan) plus rank and action.
struct alignas(64) RuleRec {
    uint16_t lo[8];
    uint16_t nhi[8];
    uint8_t val[16];  // [0..8] values, [9..12] priority, [13] action
    uint8_t msk[16];  // [0..8] masks,  [9..12] rule id
};
static_assert(sizeof(RuleRec) == 64, "RuleRec must be one cache line");

// Bucket table: groups of four slots (one cache line), probed group by group from the home group (the
// 32-bit tag's top bits, so the tag alone identifies a bucket; tag == 0 marks an empty slot). A bucket is a
// rank-sorted run of records in the table's arena, with room for at least bit_ceil(count). The slot caches
// the best record's priority so a lookup can skip the bucket without touching its records.
struct alignas(16) BSlot {
    uint32_t tag = 0;
    uint32_t first_prio = ~uint32_t{0};
    uint32_t off = 0;  // first record in the arena
    uint32_t n = 0;    // bits 0-27: records; bit 31 of slot 0: some key homed here sits in a later group
};
struct alignas(64) BGroup {
    BSlot s[4];
};

struct TupleTable {
    uint8_t dim[3] = {0, 0, 0};  // key dimensions; kNoDim pads unused ones
    uint32_t gshift = 30;        // 32 - log2(groups)
    uint32_t gmask = 3;          // groups - 1
    uint32_t count = 0;          // rules
    uint32_t used = 0;           // occupied slots (buckets)
    uint32_t spilled = 0;        // groups with the overflow bit set
    std::vector<BGroup> groups;
    std::vector<uint64_t> bm;    // key-presence bitmap indexed by h >> bm_shift: a superset of the live keys
    uint32_t bm_shift = 20;
    std::vector<RuleRec> arena;  // buckets, contiguous; holes are reclaimed by a repack
};

// Rank-sorted rules stored lane-major (26 u16 lanes, `cap` entries each) so one SIMD op
// tests one field of 16 rules. Entries in [n, round16(n)) are padding that ranks last with action 0.
struct Sweep {
    uint32_t n = 0, cap = 0;
    uint32_t active = 0;  // lanes some entry constrains (bit k: lane k; bit 16+m: masked pair m); only grows
    uint32_t dead = 0;    // tombstones (deleted entries that never match), dropped by the next merge
    std::vector<uint16_t> lanes;
    std::vector<uint64_t> rank;
    std::vector<uint8_t> action;
};

// Bit-vector filter over a rank-sorted rule set (the residual that no hash table covers). For each of 13 fields
// the packet's value picks a class, and each class owns one bitmap row (one bit per rule, 256 rules per block)
// holding every rule that can match some value of that class. AND-ing the rows leaves a superset of the matching
// rules; the survivors are confirmed with the full rule check, lowest rank first.
struct alignas(32) BvBlk {
    uint64_t w[4];
};
constexpr uint32_t kBvFields = 13;
struct BitRes {
    uint32_t n = 0;     // rules; position order is rank order
    uint32_t W = 0;     // 256-rule blocks
    uint32_t dead = 0;  // deleted positions (cleared in `alive`)
    uint32_t nact = 0;  // fields some rule constrains: order[0..nact) lists them, most selective first
    uint32_t moff[kBvFields] = {};  // field -> offset of its value->class map in `maps`
    uint32_t base[kBvFields] = {};  // field -> first row index of its classes
    uint8_t order[kBvFields] = {};
    uint8_t pos[kBvFields] = {};    // field -> its slot in a packet's row list (inverse of order; unused fields last)
    std::vector<RuleRec> recs;     // the rules, for the final check
    std::vector<uint64_t> rank;
    std::vector<uint64_t> first;   // rank of the first rule of each block
    std::vector<BvBlk> rows;       // all class rows, W blocks each
    std::vector<BvBlk> ones;       // W blocks: bit i set for every position i < n (stands in for unused fields)
    std::vector<BvBlk> alive;      // same, minus deleted positions
    std::vector<uint8_t> maps;     // value -> class, per field (up to 256 classes)
    std::vector<uint16_t> map16;   // region and vlan: value -> class (more classes; vlan names hundreds of values)
};

class OptimizedClassifier : public IPacketClassifier {
public:
    OptimizedClassifier();
    ~OptimizedClassifier() override;

    void initialize(const std::vector<Rule>& rules) override;
    Action classify(const Packet& packet) override;
    void classify_batch(const Packet* packets, size_t count, Action* out_actions) override;
    void insert_rule(const Rule& rule) override;
    void delete_rule(uint32_t rule_id) override;

    const char* name() const override { return "RewriteR1"; }

    // Search index: everything a rebuild replaces in one swap.
    struct Index {
        std::vector<TupleTable> tables;
        Sweep residual;            // rules no table fits, when they are few (deletes leave tombstones)
        BitRes bv;                 // ...or this filter when they are many (use_bv)
        bool use_bv = false;
        Sweep delta;               // recent residual inserts, merged into the residual when full
        bool has_cat = false;      // a full catch-all bounds every packet...
        uint64_t cat_rank = 0;
        uint8_t cat_action = 0;
        uint16_t cat_len_low = 0;  // ...whose packet_len is at least this
    };
    struct Entry {
        Rule rule;
        uint8_t where;  // table number, or kResidual / kDormant / kCatchAll
    };

private:
    std::vector<Entry> store_;     // every live rule, dense
    std::vector<uint64_t> idmap_;  // open addressing: id << 32 | (store index + 1)
    uint32_t idmap_count_ = 0;
    Index index_;

    void rebuild_from(std::vector<Entry>& entries);
    void place_new(const Rule& rule, long old_pos);
    void warm_up();
};

} // namespace packet_rush
