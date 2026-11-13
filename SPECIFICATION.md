# NEXUSNET INCIDENT DISPATCH: PACKET RUSH MASTER SPECIFICATION
**Classification**: Official Competition Specification (Canonical Benchmark Contract)  
**Version**: 2.0.0 (Frozen Specification)  
**Target Architecture**: x86_64 Linux / C++20  
**Incident Reference**: `NX-2026-9941` (Severity: SEV-1 Outage)

---

## 1. The Operational Crisis

Following the commissioning of the high-density **Melbourne Hyperscale Core Exchange**, tier-1 carrier **NexusNet** activated its 400 Gbps multi-region backbone switching fabric. Connecting enterprise interconnects, cloud transit paths, and critical customer services, NexusNet's ingress edge switches are encountering an unprecedented traffic surge exceeding tens of millions of packets per second.

Rapid multi-tenant expansion and synchronized DDoS mitigation policies have swollen the active firewall database to tens of thousands of rules containing nested CIDR prefixes, overlapping port intervals, VLAN tags, and real-time ACL mutations.

The legacy sequential packet classification engine has collapsed into **severe classification bottlenecks and ingress queue saturation**:
- Packets are queuing rapidly in edge ring buffers.
- Classification latency has spiked from microseconds to milliseconds.
- Legitimate traffic is suffering drops across edge peering links.

### The Mission
Design, implement, and benchmark a next-generation packet classification engine in **C++20**. Your engine must correctly classify packets against NexusNet's multi-dimensional **13-tuple header space** at line-rate speed (target: **25.0 Million packets/sec**), low batch latency (P99 batch latency $\le 2.5\ \mu\text{s}$ across 64-packet batches), within a strict **32.0 MiB** memory footprint, supporting sub-5 microsecond dynamic updates.

---

## 2. Packet Architecture (24-Byte 13-Tuple)

Every network packet processed by the NexusNet data plane is represented by a compact 24-byte structure aligned to an 8-byte boundary:

```cpp
struct alignas(8) Packet {
    uint32_t src_ip;        // IPv4 source address in host byte order
    uint32_t dst_ip;        // IPv4 destination address in host byte order
    uint16_t src_port;      // Layer 4 source port (0..65535)
    uint16_t dst_port;      // Layer 4 destination port (0..65535)
    uint16_t packet_len;    // Total IPv4 packet length in bytes (20..65535)
    uint16_t region_id;     // Datacenter geographic region ID (0..65535)
    uint16_t vlan_id;       // 802.1Q Virtual LAN identifier (0..4095)
    uint8_t  protocol;      // IP Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
    uint8_t  tcp_flags;     // Bitmask: SYN(0x02), ACK(0x10), FIN(0x01), RST(0x04)
    uint8_t  ingress_iface; // Physical/virtual ingress interface ID (0..255)
    uint8_t  dscp;          // Differentiated Services Code Point (0..63)
    uint8_t  icmp_type;     // ICMP message type (0..255)
    uint8_t  ttl;           // IP Time to Live (0..255)
};
static_assert(sizeof(Packet) == 24, "Packet must be exactly 24 bytes");
```

- **Packet Field Validity Guarantee**: The benchmark harness guarantees that all incoming `Packet` instances passed to `classify` or `classify_batch` are structurally valid: `packet_len` is within $[20, 65535]$, `vlan_id` is within $[0, 4095]$, and `dscp` is within $[0, 63]$. The classifier is not required to perform ingress sanity checks or reject malformed packets; all evaluation packets satisfy these domain constraints.

---

## 3. Formal Matching Contract (13 Predicates)

### Rule Identification & Ordering Types
Rules and priorities are formally typed as unsigned 32-bit integers:
```cpp
using RuleId   = uint32_t; // Globally unique among active rules (0..UINT32_MAX)
using Priority = uint32_t; // Numerical precedence: lower value = higher priority
```
- **Rule ID Lifecycle & Reuse**: `RuleId` values are globally unique among currently active rules. A `RuleId` may be reused after its previous rule has been successfully deleted.

### The Strict Conjunction Contract
A filtering rule matches an incoming packet **if and only if all 13 field predicates evaluate to true simultaneously (strict logical conjunction)**:

$$\text{Match}(\text{rule}, \text{pkt}) \iff \bigwedge_{i=1}^{13} \text{Predicate}_i(\text{rule}_i, \text{pkt}_i)$$

If any single predicate evaluates to false, the rule does not match the packet. The 13 individual matching predicates are defined as follows:

| Field Name | Type | Matching Logic / Formal Predicate | Neutral / Wildcard Condition |
| :--- | :--- | :--- | :--- |
| `src_ip` | CIDR `/0`–`/32` | `(pkt.src_ip & rule.src_ip.mask) == (rule.src_ip.ip & rule.src_ip.mask)` | `rule.src_ip.prefix_len == 0` |
| `dst_ip` | CIDR `/0`–`/32` | `(pkt.dst_ip & rule.dst_ip.mask) == (rule.dst_ip.ip & rule.dst_ip.mask)` | `rule.dst_ip.prefix_len == 0` |
| `src_port` | Closed Range | `pkt.src_port >= rule.src_port.low && pkt.src_port <= rule.src_port.high` | `low == 0 && high == 65535` |
| `dst_port` | Closed Range | `pkt.dst_port >= rule.dst_port.low && pkt.dst_port <= rule.dst_port.high` | `low == 0 && high == 65535` |
| `packet_len` | Closed Range | `pkt.packet_len >= rule.packet_len.low && pkt.packet_len <= rule.packet_len.high` | `low == 20 && high == 65535` |
| `region_id` | Exact / Flag | `rule.region_id.wildcard || pkt.region_id == rule.region_id.value` | `rule.region_id.wildcard == true` |
| `vlan_id` | Exact / Flag | `rule.vlan_id.wildcard || pkt.vlan_id == rule.vlan_id.value` | `rule.vlan_id.wildcard == true` |
| `protocol` | Exact / Flag | `rule.protocol.wildcard || pkt.protocol == rule.protocol.value` | `rule.protocol.wildcard == true` |
| `tcp_flags` | Bitmask / Val | `(pkt.tcp_flags & rule.tcp_flags.mask) == (rule.tcp_flags.value & rule.tcp_flags.mask)` | `rule.tcp_flags.mask == 0x00` |
| `ingress_iface`| Exact / Flag | `rule.ingress_iface.wildcard || pkt.ingress_iface == rule.ingress_iface.value` | `rule.ingress_iface.wildcard == true` |
| `dscp` | Exact / Flag | `rule.dscp.wildcard || pkt.dscp == rule.dscp.value` | `rule.dscp.wildcard == true` |
| `icmp_type` | Exact / Flag | `rule.icmp_type.wildcard || pkt.icmp_type == rule.icmp_type.value` | `rule.icmp_type.wildcard == true` *(Type 0 is valid)* |
| `ttl` | Closed Range | `pkt.ttl >= rule.ttl.low && pkt.ttl <= rule.ttl.high` | `low == 0 && high == 255` |

### Validation & Ingestion Semantics
- **CIDR Prefix Validation & Deterministic Mask Generation**: Input prefix lengths are represented as signed integers (`int32_t`). Valid prefix lengths must satisfy $0 \le \text{prefix\_len} \le 32$. Inputs outside this range ($< 0$ or $> 32$) are rejected prior to type conversion to `uint8_t`, preventing silent unsigned wrap-around. The subnet bitmask must be deterministically generated from the validated `prefix_len` ($L$) using `uint32_t` unsigned arithmetic:
  - $L = 0 \implies \text{mask} = 0\text{x}00000000\text{U}$
  - $L = 32 \implies \text{mask} = 0\text{xFFFFFFFF}\text{U}$
  - $1 \le L < 32 \implies \text{mask} = \text{static\_cast}<\text{uint32\_t}>(\sim((\text{uint32\_t}\{1\} \ll (32 - L)) - \text{uint32\_t}\{1\}))$  
  Independently supplied bitmasks are discarded to prevent disagreement between prefix length and mask. Valid rules normalize host bits: `rule.ip &= rule.mask`.
- **Closed Interval Validation**: Valid intervals require $\text{low} \le \text{high}$. If a rule supplies $\text{low} > \text{high}$ on any range field (`src_port`, `dst_port`, `packet_len`, `ttl`), the rule is invalid and must be strictly rejected upon insertion.
- **Transactional State Preservation**: A rejected insertion leaves the entire classifier state completely unmodified and intact. This guarantee strictly covers:
  1. Primary rule storage and database.
  2. Search indices, tries, and dimension trees.
  3. Priority queues and total-ordering structures.
  4. Auxiliary hash tables, pre-filtered bitmaps, and cache buffers.
  Even when attempting to overwrite an existing `rule_id`, a failed insertion leaves the preceding active rule and all associated indexing structures untouched.
- **Packet Length Definition**: `packet_len` specifies the total IPv4 packet length, including the IPv4 header and payload, excluding Ethernet framing (valid range: 20..65535 bytes).
- **TCP Flags Semantics**: The `tcp_flags` bitmask matching operates on all 8 bits ($0\text{x}00$–$0\text{xFF}$), supporting all standard TCP control flags including CWR ($0\text{x}80$), ECE ($0\text{x}40$), URG ($0\text{x}20$), ACK ($0\text{x}10$), PSH ($0\text{x}08$), RST ($0\text{x}04$), SYN ($0\text{x}02$), and FIN ($0\text{x}01$).
- **ICMP Matching Independence**: `icmp_type` matching is evaluated strictly as an ordinary 8-bit integer field independently of the packet's `protocol` field. The classifier must not apply implicit protocol gating (such as checking whether `protocol == 1` before evaluating `icmp_type`); the predicate evaluates purely on `pkt.icmp_type` against `rule.icmp_type`. ICMP Type 0 (Echo Reply) is a valid, operational message type and is never treated as a wildcard unless `wildcard == true`.

---

## 4. Priority Resolution & Global Lexicographical Ordering

Let $\mathcal{R}$ denote the set of all active rules in the classifier, and let $\mathcal{M}(p) = \{ r \in \mathcal{R} \mid M(r, p) \}$ represent the candidate set of rules matching packet $p$ across all 13 dimensions.

The classification decision is governed by exact mathematical contracts:

1. **Empty Candidate Set Fallback**: If $\mathcal{M}(p) = \emptyset$, no active rules match the packet. The classifier must return **`Action::DROP`**.
2. **Lexicographical Minimization**: If $\mathcal{M}(p) \ne \emptyset$, the winning rule $r^*$ is the unique element in $\mathcal{M}(p)$ that minimizes the pair $(\text{priority}, \text{rule\_id})$ in lexicographical order:
   $$r^* = \arg\min_{r \in \mathcal{M}(p)} (\text{priority}_r, \, \text{rule\_id}_r)$$
3. **Action Exclusivity**: The engine must return strictly the discrete action associated with the globally winning rule:
   $$\text{ResultAction}(p) = \text{action}_{r^*}$$
   Engines must never combine, accumulate, merge, or chain actions across multiple matching candidates.
4. **Global Ordering Invariant**: Indexing structures (such as multi-field tries, hash tables, or coordinate trees) must never return a locally preferred candidate from a specific sub-tree or bucket without ensuring it globally dominates all other potential matches across the entire rule set.
5. **Numerical Priority & Tie-Breaking Rules**:
   - **Lower Numerical Priority Wins**: A rule with `priority = 10` strictly takes precedence over a rule with `priority = 50`.
   - **Deterministic Tie-Breaker**: If two matching rules possess identical numerical priority, the rule with the **lower numerical `rule_id`** wins.
6. **Supported Actions**: Rules evaluate to `Action::ACCEPT` (1), `Action::DROP` (0), `Action::REJECT` (2), or `Action::REDIRECT` (3).

---

## 5. The Official Benchmark Contract

To ensure fair, mathematically defensible algorithmic evaluation and eliminate hardware variance:

- **Controlled Execution Environment**:
  All submissions are evaluated inside an identical, isolated container environment on bare-metal hardware (Ubuntu 24.04 LTS x86_64, standard glibc runtime, identical compiler toolchain).
- **Execution Topology & Concurrency Contract**:
  - The benchmark harness is **strictly single-threaded and synchronous**.
  - Pinned to a single isolated physical x86_64 CPU core (`taskset -c` / `pthread_setaffinity_np`) with fixed CPU clock frequency (no dynamic frequency scaling / thermal throttling).
  - Classification and update loops execute strictly on one thread. Background helper threads, detached processes, asynchronous worker pools, or offloaded coprocessors are prohibited. Intra-thread SIMD vectorization (AVX2, AVX-512) is explicitly permitted.
- **Process-Wide Peak Memory Limit ($M$)**:
  - Metric: Process-wide Peak Resident Set Size (`ru_maxrss`) via `getrusage(RUSAGE_SELF, ...)`.
  - Target: **$M \le 32.0\text{ MiB}$** (where $1\text{ MiB} = 1,048,576\text{ bytes}$, so $32.0\text{ MiB} = 33,554,432\text{ bytes}$, or $32,768\text{ KiB}$).
  - Accounting Scope: Kernel high-water mark measured across the complete process lifetime from launch through initialization, all classification batches, updates, and shutdown. It accounts for the complete executable process, stack, glibc allocator arenas, rule storage, and all internal indexing structures.
  - Scoring: $S_M = 20.0 \times \min(1.0, 32.0 / M)$.
- **Authoritative Timing Source**:
  - Timing is measured exclusively using **`std::chrono::steady_clock`** (monotonic, steady clock unaffected by NTP or system clock adjustments).
- **Throughput ($T$) & Batching Contract**:
  - Standard batch size: $B = 64$ packets via `classify_batch(const Packet* in, size_t count, Action* out)`.
  - For $N$ total packets, the total number of batches is $K = \lceil N / 64 \rceil$.
  - Batches $1$ through $K - 1$ contain exactly 64 packets. If $N \pmod{64} \ne 0$, the final batch $K$ contains the remaining $N \pmod{64}$ packets (a partial batch).
  - Throughput calculation:
    $$T = \frac{N}{t_{\text{total}}} \times 10^{-6} \quad (\text{Mpps})$$
    where $t_{\text{total}}$ is the total elapsed time from the start of batch 1 to the return of batch $K$. Throughput strictly counts actual packets processed ($N$), not rounded batch multiples. Target: **25.0 Mpps** (40 points).
- **P99 Batch Latency ($L_{\text{batch}}$) & Nearest-Rank Convention**:
  - Measured across all complete 64-packet batches ($\tau_k$ in $\mu\text{s}$, excluding any final partial batch $< 64$ packets).
  - Sorted ascending: $\tau_{(1)} \le \tau_{(2)} \le \dots \le \tau_{(M)}$.
  - Defined by the standard **nearest-rank percentile**:
    $$L_{\text{batch}} = \tau_{(r)}, \quad r = \lceil 0.99 \times M \rceil$$
  - Target: **$L_{\text{batch}} \le 2.5\ \mu\text{s}$** per 64-packet batch (25 points).
  - **Metric Relationship**: At $25.0\text{ Mpps}$, a 64-packet batch has an average amortized duration of $\frac{64}{25\times 10^6}\text{ seconds} = 2.56\ \mu\text{s}$. The P99 batch latency target ($\le 2.5\ \mu\text{s}$) is an independent, separate tail-latency requirement under the same workload. Completing 99% of batches in $\le 2.5\ \mu\text{s}$ does not automatically guarantee $25.0\text{ Mpps}$ throughput, nor does achieving 25.0 Mpps average throughput guarantee low tail latency.

---

## 6. Dynamic Update Semantics & Transactional Contract

NexusNet requires dynamic rule updates without table rebuild stalls:

```cpp
virtual void insert_rule(const Rule& rule) = 0;
virtual void delete_rule(uint32_t rule_id) = 0;
```

### Operational Semantics:
- **Rule ID Uniqueness**: Rule IDs are unsigned 32-bit integers (`RuleId`, valid range: `0` to `UINT32_MAX`). Rule IDs must be globally unique across all active rules in the classifier database.
- **Explicit Single-Threaded Interleaving**:
  - Scenario 05 executes on a single pinned CPU thread:
    ```
    Interleaved Loop:
      1. classify_batch(64 packets)
      2. Execute mutation operation(s): insert_rule() or delete_rule()
    ```
  - No concurrent calls to `classify`, `classify_batch`, or update methods are performed or tested.
- **Sequential Visibility**: Updates must be fully committed and visible to the engine before the subsequent classification call begins. Readers never observe torn or partially rebuilt indices.
- **Transactional Failure & Rollback Semantics**:
  - Updates that fail validation (prefix lengths outside $0 \le \text{prefix\_len} \le 32$, malformed intervals $\text{low} > \text{high}$, or memory exhaustion) are rejected transactionally.
  - A failed update leaves the entire classifier state (rule storage, lookup tables, indices, priority structures, auxiliary buffers) completely unchanged.
  - For rule replacement (inserting an existing `rule_id`): the prior rule and its full indexed state remain active and unchanged unless the replacement is successfully and completely committed.
- **Update Latency SLA & Statistically Robust Workload**:
  - Each individual mutation operation is timed independently via `std::chrono::steady_clock`: $u_i = t_{\text{end}} - t_{\text{start}}$.
  - In Scenario 05, updates are evaluated across a statistically robust workload of $\ge 10,000$ operations (4 interleaved cycles of 2,500 operations: 5,000 insertions, 5,000 deletions), ensuring the nearest-rank 99th percentile ($r = 9,900$) is determined by the 100th-slowest operation rather than small-sample noise.
  - Target P99 update latency: **$U \le 5.0\ \mu\text{s}$** (15 points).

---

## 7. Workload Generation & Benchmark Scenarios

The evaluation suite tests classifiers across five distinct workload profiles designed to prevent naive single-field partitioning:

| Scenario | Weight | Active Rules / Packets | Workload Characteristics & Architectural Stress |
| :--- | :---: | :---: | :--- |
| **`01_correctness_small`** | 15% | 1,000 / 5,000 | Boundary condition verification: CIDR `/0` and `/32`, ICMP Type 0 discrimination, empty interval rejection, default DROP fallback. |
| **`02_scalability_medium`** | 20% | 15,000 / 20,000 | Cache hierarchy pressure: L2/L3 cache footprint boundaries, testing sublinear lookup scaling across heterogeneous fields. |
| **`03_performance_large`** | 25% | 40,000 / 30,000 | Line-rate stress testing: Sustained throughput stress test evaluating SIMD vectorization, prefetching, and batch pipeline efficiency. |
| **`04_adversarial_skew`** | 20% | 20,000 / 20,000 | Anti-partitioning stress: 65%+ dense wildcards, nested CIDRs, overlapping port ranges, and identical priorities requiring deep tie-breaker resolution. |
| **`05_dynamic_heavy`** | 20% | 15,000 + 10,000 ops / 20,000 | Dynamic mutations: 10,000 insert/delete operations (4 cycles of 2,500 ops: 5,000 inserts, 5,000 deletes) measuring incremental update latency. |

---

## 8. Multi-Dimensional 100-Point Scoring Model

$$S = S_T + S_L + S_M + S_U$$

| Dimension | Max Points | Production Target | Mathematical Scoring Formula |
| :--- | :---: | :---: | :--- |
| **Throughput ($T$)** | 40 pts | $25.0\text{ Mpps}$ | $S_T = 40 \times \min\left(1.0, \frac{T}{25.0}\right)$ |
| **P99 Batch Latency ($L$)** | 25 pts | $2.5\ \mu\text{s}$ (64 pkts) | $S_L = 25 \times \min\left(1.0, \frac{2.5}{L}\right)$ |
| **Memory Efficiency ($M$)** | 20 pts | $32.0\text{ MiB}$ | $S_M = 20 \times \min\left(1.0, \frac{32.0}{M}\right)$ |
| **Dynamic Updates ($U$)** | 15 pts | $5.0\ \mu\text{s}$ | $S_U = 15 \times \min\left(1.0, \frac{5.0}{U}\right)$ |

$$\text{Final Weighted Score} = \sum_{i=1}^{5} w_i \times S_i$$

### Zero-Tolerance Correctness Mandate:
Any mismatched packet action against the golden baseline, runtime crash (SIGSEGV/SIGABRT), timeout (>120 seconds), or memory violation results in **0.0 points** for that scenario. Correctness must be 100%.

---

## 9. Submission Interface (C++20)

Participants implement the pure virtual interface defined in `include/classifier_interface.h`:

```cpp
class IPacketClassifier {
public:
    virtual ~IPacketClassifier() = default;

    virtual void initialize(const std::vector<Rule>& rules) = 0;
    virtual Action classify(const Packet& packet) = 0;
    virtual void classify_batch(const Packet* packets, size_t count, Action* out_actions) {
        for (size_t i = 0; i < count; ++i) out_actions[i] = classify(packets[i]);
    }
    virtual void insert_rule(const Rule& rule) = 0;
    virtual void delete_rule(uint32_t rule_id) = 0;

    virtual const char* name() const = 0;
};
```

All modifications are confined to `starter/classifier.h` and `starter/classifier.cpp`.

---
*NexusNet Global Infrastructure Council — Incident Response Taskforce NX-2026-9941.*
