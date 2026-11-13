#!/usr/bin/env python3
"""
Test 1: Exact Match Verification
Tests exact matching across all 13 fields without wildcards.
"""

import subprocess
import os
import sys

def run_test():
    gen_script = os.path.join(os.path.dirname(__file__), "../generator/generate.py")
    test_dir = "/tmp/packet_rush_test_exact"
    os.makedirs(test_dir, exist_ok=True)

    print("--- [Test 1: Exact Match] ---")
    # Generate 500 rules with 0.0 wildcard rate (strictly exact fields)
    subprocess.run([
        sys.executable, gen_script,
        "--rules", "500",
        "--packets", "2000",
        "--wildcard-rate", "0.0",
        "--out", test_dir,
        "--prefix", "exact"
    ], check=True)

    bench = os.path.join(os.path.dirname(__file__), "../benchmark_starter")
    gt_bin = os.path.join(test_dir, "gt.bin")
    opt_bin = os.path.join(test_dir, "opt.bin")

    # Run baseline
    subprocess.run([
        bench,
        "--rules", f"{test_dir}/exact_rules.bin",
        "--packets", f"{test_dir}/exact_packets.bin",
        "--mode", "baseline",
        "--dump-actions", gt_bin
    ], check=True)

    # Run optimized
    subprocess.run([
        bench,
        "--rules", f"{test_dir}/exact_rules.bin",
        "--packets", f"{test_dir}/exact_packets.bin",
        "--mode", "optimized",
        "--dump-actions", opt_bin
    ], check=True)

    correctness_script = os.path.join(os.path.dirname(__file__), "../evaluator/correctness.py")
    res = subprocess.run([sys.executable, correctness_script, gt_bin, opt_bin])
    assert res.returncode == 0, "Exact match test failed!"
    print(">>> Test 1 Passed.\n")

if __name__ == "__main__":
    run_test()
