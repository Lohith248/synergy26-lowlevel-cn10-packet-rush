# PACKET RUSH: OPERATION DATA SHIELD
## Systems Engineering Hackathon — Problem Statement & Technical Challenge
**Classification**: Official Competition Problem Statement (Derived from Canonical Specification v2.0.0)  
**Incident Reference**: `NX-2026-9941` (Severity: SEV-1 Critical Outage)  
**Target Architecture**: x86_64 Linux / C++20

---

## 1. The Incident Narrative

Following the commissioning of the high-density **Melbourne Hyperscale Core Exchange**, tier-1 telecommunications provider **NexusNet** activated its 400 Gbps multi-region backbone switching fabric. Connecting millions of concurrent users, cloud transit paths, and mission-critical enterprise services, NexusNet's ingress edge switches are experiencing an unprecedented flood of traffic exceeding tens of millions of packets per second.

Rapid multi-tenant expansion and synchronized DDoS mitigation policies have swollen the active firewall database to tens of thousands of filtering rules containing nested CIDR prefixes, overlapping port intervals, VLAN tags, and real-time ACL mutations.

The legacy sequential rule-matching architecture has completely collapsed into **severe classification bottlenecks and ingress queue saturation**:
- Packets are accumulating rapidly in edge ring buffers.
- Classification latency has spiked from microseconds to hundreds of milliseconds.
- Legitimate users and enterprise workloads are suffering packet drops across core transit links.

### The Mission
Design, implement, and benchmark the fastest, most memory-efficient, and reliably updateable packet classification engine in **C++20**. Your engine must correctly classify incoming packets against NexusNet's filtering policies across a multi-dimensional **13-tuple header space** at line-rate speed (target: **25.0 Million packets/sec**), low batch latency (P99 batch latency $\le 2.5\ \mu\text{s}$ across 64-packet batches), within a strict **32.0 MiB** memory footprint, supporting sub-5 microsecond dynamic updates.

---

## 2. Technical Architecture: 24-Byte 13-Tuple Packet

Standard 5-tuple algorithms fail under real-world conditions due to dimensionality explosion. NexusNet's data plane enforces policies across **13 distinct packet attributes**. Every incoming packet is represented by an ultra-compact 24-byte 8-byte-aligned structure:

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

### Validation & Transactional State Preservation
- **CIDR Prefix Validation & Deterministic Mask Generation**: Input prefix lengths are signed integers (`int32_t`). Valid prefix lengths must satisfy $0 \le \text{prefix\_len} \le 32$. Inputs outside this range ($< 0$ or $> 32$) are rejected prior to conversion to `uint8_t`, preventing unsigned wrap-around. The subnet bitmask is deterministically generated from the validated `prefix_len` ($L$) using `uint32_t` unsigned arithmetic:
  - $L = 0 \implies \text{mask} = 0\text{x}00000000\text{U}$
  - $L = 32 \implies \text{mask} = 0\text{xFFFFFFFF}\text{U}$
  - $1 \le L < 32 \implies \text{mask} = \text{static\_cast}<\text{uint32\_t}>(\sim((\text{uint32\_t}\{1\} \ll (32 - L)) - \text{uint32\_t}\{1\}))$  
  Independently supplied bitmasks are discarded to prevent disagreement between prefix length and mask. Valid rules normalize host bits: `rule.ip &= rule.mask`.
- **Closed Interval Validation**: Valid intervals require $\text{low} \le \text{high}$. If a rule supplies $\text{low} > \text{high}$ on any range field (`src_port`, `dst_port`, `packet_len`, `ttl`), the rule is invalid and must be strictly rejected upon insertion.
- **Transactional State Preservation**: A rejected insertion leaves the entire classifier state completely unmodified and intact (including rule storage, search indices, priority structures, and auxiliary tables). Even when attempting to replace an existing `rule_id`, the preceding active rule remains untouched.
- **Packet Length Definition**: `packet_len` specifies the total IPv4 packet length, including the IPv4 header and payload, excluding Ethernet framing (valid range: 20..65535 bytes).
- **TCP Flags Semantics**: The `tcp_flags` bitmask matching operates on all 8 bits ($0\text{x}00$–$0\text{xFF}$), supporting all standard TCP control flags including CWR ($0\text{x}80$), ECE ($0\text{x}40$), URG ($0\text{x}20$), ACK ($0\text{x}10$), PSH ($0\text{x}08$), RST ($0\text{x}04$), SYN ($0\text{x}02$), and FIN ($0\text{x}01$).
- **ICMP Matching Independence**: `icmp_type` matching is evaluated strictly as an ordinary 8-bit integer field independently of the packet's `protocol` field. The classifier must not apply implicit protocol gating (such as checking whether `protocol == 1` before evaluating `icmp_type`); the predicate evaluates purely on `pkt.icmp_type` against `rule.icmp_type`. ICMP Type 0 (Echo Reply) is a valid, operational message type and is never treated as a wildcard unless `wildcard == true`.

---

## 4. Priority Resolution & Global Lexicographical Ordering

Let $\mathcal{R}$ denote the set of all active rules, and let $\mathcal{M}(p) = \{ r \in \mathcal{R} \mid M(r, p) \}$ represent the candidate set of rules matching packet $p$ across all 13 dimensions.

1. **Empty Candidate Set Fallback**: If $\mathcal{M}(p) = \emptyset$, no rules match. The classifier must return **`Action::DROP`**.
2. **Lexicographical Minimization**: If $\mathcal{M}(p) \ne \emptyset$, the winning rule $r^*$ is the unique element minimizing $(\text{priority}, \text{rule\_id})$:
   $$r^* = \arg\min_{r \in \mathcal{M}(p)} (\text{priority}_r, \, \text{rule\_id}_r)$$
3. **Action Exclusivity**: The engine must return strictly the discrete action associated with the globally winning rule:
   $$\text{ResultAction}(p) = \text{action}_{r^*}$$
   Engines must never combine, accumulate, merge, or chain actions across multiple matching candidates.
4. **Global Ordering Invariant**: Indexing structures must never return a locally preferred candidate from a specific sub-tree or bucket without ensuring it globally dominates all other potential matches across the entire rule set.
5. **Numerical Priority & Tie-Breaking Rules**:
   - **Lower Numerical Priority Wins**: A rule with `priority = 10` strictly takes precedence over a rule with `priority = 50`.
   - **Deterministic Tie-Breaker**: If two matching rules possess identical numerical priority, the rule with the **lower numerical `rule_id`** wins.
6. **Supported Actions**: Rules evaluate to `Action::ACCEPT` (1), `Action::DROP` (0), `Action::REJECT` (2), or `Action::REDIRECT` (3).
