# PACKET RUSH: EVALUATION MATRIX & RULES
## Systems Engineering Hackathon — Official Competition Rules, Benchmark Contract & Scoring Model
**Classification**: Official Competition Rules & Scoring Model (Derived from Canonical Specification v2.0.0)  
**Incident Reference**: `NX-2026-9941`  
**Target Architecture**: x86_64 Linux / C++20

---

## 1. Multi-Dimensional 100-Point Scoring Model

To prevent submissions that sacrifice memory bounds or update capabilities for raw lookup speed, evaluation is governed by a 100-point balanced model:

$$S = S_T + S_L + S_M + S_U$$

| Dimension | Max Points | Production Target | Mathematical Scoring Formula |
| :--- | :---: | :---: | :--- |
| **Throughput ($T$)** | 40 pts | $25.0\text{ Mpps}$ | $S_T = 40 \times \min\left(1.0, \frac{T}{25.0}\right)$ |
| **P99 Batch Latency ($L$)** | 25 pts | $2.5\ \mu\text{s}$ (64 pkts) | $S_L = 25 \times \min\left(1.0, \frac{2.5}{L}\right)$ |
| **Memory Efficiency ($M$)** | 20 pts | $32.0\text{ MiB}$ | $S_M = 20 \times \min\left(1.0, \frac{32.0}{M}\right)$ |
| **Dynamic Updates ($U$)** | 15 pts | $5.0\ \mu\text{s}$ | $S_U = 15 \times \min\left(1.0, \frac{5.0}{U}\right)$ |

$$\text{Final Weighted Score} = \sum_{i=1}^{5} w_i \times S_i$$

### Zero-Tolerance Correctness Mandate
- Classification correctness against the golden reference baseline is an absolute requirement.
- **Packet Field Validity**: The benchmark harness guarantees that all incoming `Packet` instances passed to `classify` or `classify_batch` are structurally valid: `packet_len` is within $[20, 65535]$, `vlan_id` is within $[0, 4095]$, and `dscp` is within $[0, 63]$. Classifiers do not need to validate packets on ingress.
- A rule matches an incoming packet if and only if **all 13 field predicates evaluate to true simultaneously (strict logical conjunction)**. The winning rule is resolved via global lexicographical minimization: $r^* = \arg\min_{r \in \mathcal{M}(p)} (\text{priority}_r, \text{rule\_id}_r)$. If $\mathcal{M}(p) = \emptyset$, return `Action::DROP`. If multiple rules match, return exclusively the single discrete action of the winning rule $r^*$.
- Any output action mismatch immediately awards **0.0 points** for that scenario.
- Memory violations (SIGSEGV), process aborts (SIGABRT), timeouts (>120 seconds), or non-deterministic outputs result in scenario failure.

---

## 2. The Official Benchmark Execution Contract

To ensure fair, mathematically defensible algorithmic evaluation and eliminate hardware variance:

- **Controlled Execution Environment**:
  All submissions are evaluated inside an identical, isolated container environment on bare-metal hardware (Ubuntu 24.04 LTS x86_64, standard glibc runtime, identical compiler toolchain).
- **Execution Topology & Concurrency Contract**:
  - The benchmark harness is **strictly single-threaded and synchronous**.
  - Pinned to a single isolated physical x86_64 CPU core (`taskset -c` / `pthread_setaffinity_np`) with fixed CPU clock frequency (no dynamic frequency scaling / thermal throttling).
  - Classification and update loops execute strictly on one thread. Background helper threads, detached processes, asynchronous worker pools, or offloaded coprocessors are prohibited. Intra-thread SIMD vectorization (AVX2, AVX-512) is explicitly permitted.
- **Process-Wide Peak Memory Limit ($M$)**:
  - Metric: Process-wide Peak Resident Set Size (`ru_maxrss` via `getrusage`).
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

## 3. Dynamic Update Semantics & Transactional Contract

NexusNet requires dynamic rule updates without table rebuild stalls:

- **Rule Identification & Types**:
  ```cpp
  using RuleId   = uint32_t; // Globally unique among active rules (0..UINT32_MAX)
  using Priority = uint32_t; // Numerical precedence: lower value = higher priority
  ```
  A `RuleId` may be reused after its previous rule has been successfully deleted.
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

## 4. Evaluation Workload Scenarios

The evaluation suite tests classifiers across five distinct workload profiles designed to prevent naive single-field partitioning:

| Scenario | Weight | Active Rules / Packets | Workload Characteristics & Architectural Stress |
| :--- | :---: | :---: | :--- |
| **`01_correctness_small`** | 15% | 1,000 / 5,000 | Boundary condition verification: CIDR `/0` and `/32`, ICMP Type 0 discrimination, empty interval rejection, default DROP fallback. |
| **`02_scalability_medium`** | 20% | 15,000 / 20,000 | Cache hierarchy pressure: L2/L3 cache footprint boundaries, testing sublinear lookup scaling across heterogeneous fields. |
| **`03_performance_large`** | 25% | 40,000 / 30,000 | Line-rate stress testing: Sustained throughput stress test evaluating SIMD vectorization, prefetching, and batch pipeline efficiency. |
| **`04_adversarial_skew`** | 20% | 20,000 / 20,000 | Anti-partitioning stress: 65%+ dense wildcards, nested CIDRs, overlapping port ranges, and identical priorities requiring deep tie-breaker resolution. |
| **`05_dynamic_heavy`** | 20% | 15,000 + 10,000 ops / 20,000 | Dynamic mutations: 10,000 insert/delete operations (4 cycles of 2,500 ops: 5,000 inserts, 5,000 deletes) measuring incremental update latency. |

---

## 5. Submission Interface & Regulations

1. **Compiler Flags**: Submissions are compiled using:
   ```bash
   g++ -O3 -std=c++20 -march=native -Wall -Wextra
   ```
2. **Batching & Vectorization**: Batch classification via `classify_batch` is explicitly allowed and encouraged. AVX2, AVX-512, cache prefetching (`__builtin_prefetch`), and memory alignment are permitted.
3. **Artifacts**: All modifications must be contained within `starter/classifier.h` and `starter/classifier.cpp`.
4. **Disallowed Behaviors**:
   - Spawning detached background threads or worker pools during classification.
   - Performing file or network I/O during classification or update routines.
   - Modifying the benchmark harness or timing logic.
