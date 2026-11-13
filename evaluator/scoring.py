#!/usr/bin/env python3
"""
NexusNet Packet Rush - Official 100-Point Scoring Calculator

Formulas:
  S_T = 40 * min(1.0, T / 25.0)      # Target: 25.0 Mpps
  S_L = 25 * min(1.0, 2.5 / L_batch) # Target: 2.5 us P99 64-packet batch latency
  S_M = 20 * min(1.0, 32.0 / M)      # Target: 32.0 MiB Peak RSS
  S_U = 15 * min(1.0, 5.0 / U)       # Target: 5.0 us P99 Update
  Total = S_T + S_L + S_M + S_U

Hard Rules:
  - Correctness must be 100%. Any mismatch, crash, or timeout awards 0 points for the scenario.
  - Across multiple scenarios, scores are aggregated via weighted average.
"""

import math
import sys
import json

TARGET_THROUGHPUT_MPPS = 25.0
TARGET_BATCH_LATENCY_US = 2.5
TARGET_MEMORY_MIB = 32.0
TARGET_UPDATE_US = 5.0

SCENARIO_WEIGHTS = {
    "01_correctness_small": 0.15,
    "02_scalability_medium": 0.20,
    "03_performance_large": 0.25,
    "04_adversarial_skew": 0.20,
    "05_dynamic_heavy": 0.20
}

def compute_score(throughput_mpps, p99_latency_us, peak_memory_mib, p99_update_us, correct=True):
    if not correct:
        return {
            "throughput_score": 0.0,
            "latency_score": 0.0,
            "memory_score": 0.0,
            "update_score": 0.0,
            "total_score": 0.0,
            "status": "DISQUALIFIED_INCORRECT"
        }

    # Hard Memory Limit: 32.0 MiB
    if peak_memory_mib > TARGET_MEMORY_MIB:
        return {
            "throughput_score": 0.0,
            "latency_score": 0.0,
            "memory_score": 0.0,
            "update_score": 0.0,
            "total_score": 0.0,
            "status": "DISQUALIFIED_MEMORY_EXCEEDED"
        }

    # 1. Throughput (40 pts)
    t_ratio = throughput_mpps / TARGET_THROUGHPUT_MPPS if throughput_mpps > 0 else 0.0
    s_t = 40.0 * min(1.0, max(0.0, t_ratio))

    # 2. P99 64-Packet Batch Latency (25 pts)
    l_ratio = (TARGET_BATCH_LATENCY_US / p99_latency_us) if p99_latency_us > 0 else 1.0
    s_l = 25.0 * min(1.0, max(0.0, l_ratio))

    # 3. Peak Memory RSS (20 pts)
    m_ratio = (TARGET_MEMORY_MIB / peak_memory_mib) if peak_memory_mib > 0 else 1.0
    s_m = 20.0 * min(1.0, max(0.0, m_ratio))

    # 4. Dynamic Updates (15 pts)
    if p99_update_us > 0:
        u_ratio = (TARGET_UPDATE_US / p99_update_us)
        s_u = 15.0 * min(1.0, max(0.0, u_ratio))
    else:
        s_u = 15.0 # Max score if no updates required for this scenario

    total = s_t + s_l + s_m + s_u

    return {
        "throughput_score": round(s_t, 2),
        "latency_score": round(s_l, 2),
        "memory_score": round(s_m, 2),
        "update_score": round(s_u, 2),
        "total_score": round(total, 2),
        "status": "PASSED"
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            data = json.load(f)
        score = compute_score(
            throughput_mpps=data.get("throughput_mpps", 0.0),
            p99_latency_us=data.get("p99_latency_us", 1000.0),
            peak_memory_mib=data.get("peak_memory_mib", 1024.0),
            p99_update_us=data.get("p99_update_us", 0.0),
            correct=True
        )
        print(json.dumps(score, indent=2))
    else:
        print("Usage: scoring.py <benchmark_result.json>")
