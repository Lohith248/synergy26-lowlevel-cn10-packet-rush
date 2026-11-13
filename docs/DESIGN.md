# Design and exactness argument

## Semantics
A rule matches a packet when all 13 field predicates hold (IP prefixes, port and length ranges, TTL range, exact or
wildcard protocol/iface/dscp/icmp/region/vlan, masked tcp flags). The answer is the action of the matching rule with the
lowest rank, `rank = priority << 32 | rule_id` (all 64-bit values are legal, including `~0`), or the default when no rule
matches. Rules with an invalid shape are rejected and leave state untouched; a duplicate id replaces the earlier rule.

## Structure
1. **Tuple tables.** A planner picks up to 16 key shapes of up to 3 dimensions (source/destination /8,/16,/24, exact
   ports, protocol, region, vlan, iface, dscp, icmp). A rule goes to the first table whose key it fully fixes. A bucket
   is the rank-sorted run of rules sharing a key (64-byte records in an arena). Lookup: hash (CRC32 with SSE4.2), SIMD 32-bit tag compare in a
   4-slot group (branchless select), then scan the bucket until the record rank exceeds the best match so far.
   Only the tag identifies a bucket, but every record is confirmed by the full 13-field check, so a collision costs time
   only.
2. **Residual.** Rules no table fits go to a bit-vector filter (`BitRes`) when there are 128 or more, otherwise to a
   lane-major SIMD sweep. For each of 13 fields the filter holds a value-to-class map and one bitmap row per class over
   the rank-sorted rules (256 rules per block). A packet ANDs the 13 rows block by block, stops at the first block whose
   best possible rank cannot beat the current best, and verifies each surviving bit with the full check, lowest rank first.
3. **Catch-all dominance.** A rule that matches every packet with `packet_len >= L` bounds the search for such packets:
   rules ranked behind it can never win and are not indexed. Packets with `packet_len < L` (including malformed
   `packet_len < 20`) take an exact full scan.
4. **Batches.** The table path handles 8 packets in four passes: packet vectors and presence-tested probe list, group lookups and bucket list, full record checks, then residual and delta. Flat lists preserve packet association. The table-less 64-packet sweep is unchanged.

## Why the filter is exact
Each class row is built as a *superset*: it contains every rule whose predicate on that field accepts at least one value
of the class (ranges are cut into elementary intervals or coarse blocks, never narrowed). A rule that matches a packet
accepts the packet's value in every field, so its bit is set in every row the packet selects; it survives the AND. The
survivors therefore include all matching rules plus possibly non-matching ones, and the full check removes the latter.
Taking the lowest-rank confirmed survivor gives the linear-scan answer. The planner affects speed only: any plan, and
any residual representation, yields the same verdicts. The release receipts record mutation coverage.

## Updates
- **Insert/replace.** Phase 1 allocates everything the change needs (table growth, a new filter when the delta is full)
  and may throw `std::bad_alloc`; the previous index is untouched when it does. Phase 2 commits with no allocation.
- **Delta.** Residual inserts go to a small rank-sorted delta swept with every query. When it fills, the filter is
  rebuilt on the side (about 1 us per rule) and swapped in; the delta capacity grows with the filter (up to 512) so
  rebuilds stay under 1% of inserts.
- **Delete.** Table rules are erased in place; filter rules are tombstoned by clearing an `alive` bit; the filter is
  rebuilt when more than half its positions are dead. Deleting the catch-all rebuilds everything on the side.

## Performance model
The planner scores candidate tables by the expected per-packet cost removed from the residual (probe cost, bucket scan,
collision limit) against the residual's modelled cost, using synthetic packets pinned to rule values. Costs were tuned
on the lab host (`R1_PROBE_COST=800`, `R1_BUCKET_COST=200`, in units of one filter-rule test).

## Known limits
Residual-heavy rule sets of disjoint wildcard shapes are filter-bound (about 14 Mpps on the s03 shape). The 6 MiB row
budget lowers class resolution for very large residuals, which costs speed, not correctness.

## Presence bitmaps

Each table allocates a zeroed hash-indexed bitmap with 2^12 to 2^22 bits. Creating a key sets its bit before the key becomes visible. Deletes leave bits set, and rehash preserves hashes and the bitmap. A rebuild starts a new bitmap. Every live key therefore has a set bit: a clear bit proves absence, and skipping that table cannot lose a match. Stale bits and hash collisions cost time only. Bitmap allocation happens alongside group allocation, outside the update commit path. Warm-up touches the bitmap too.

## Port classes

Unnamed ports map to equal blocks, and frequent exact ports receive individual classes in the existing one-byte map. A block row includes a rule when its range overlaps an unnamed port in that block. A named row includes a rule when its range contains that port. Every matching rule survives either row, preserving the filter's superset argument.

Filters with at most four blocks retain one unnamed class. Larger filters use up to 64 block classes, bounded by the row budget and the space remaining after exact-port classes. This build-side policy avoids extra cache misses on small filters and avoids displacing useful named ports. The cutoff is a measured heuristic; changing the layout requires new paired measurements. It never changes answers.
