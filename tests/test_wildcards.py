#!/usr/bin/env python3
"""
Test 3: Heavy Wildcard & Prefix Evaluation
Tests edge cases with dense wildcards (60%+), default routes (/0 CIDR), and port spans.
"""

import subprocess
import os
import sys

def run_test():
    gen_script = os.path.join(os.path.dirname(__file__), "../generator/generate.py")
    test_dir = "/tmp/packet_rush_test_wildcard"
    os.makedirs(test_dir, exist_ok=True)

    print("--- [Test 3: Dense Wildcard Matching] ---")
    subprocess.run([
        sys.executable, gen_script,
        "--rules", "800",
        "--packets", "2500",
        "--wildcard-rate", "0.65",
        "--out", test_dir,
        "--prefix", "wildcards"
    ], check=True)

    bench = os.path.join(os.path.dirname(__file__), "../benchmark_starter")
    gt_bin = os.path.join(test_dir, "gt.bin")
    opt_bin = os.path.join(test_dir, "opt.bin")

    subprocess.run([
        bench,
        "--rules", f"{test_dir}/wildcards_rules.bin",
        "--packets", f"{test_dir}/wildcards_packets.bin",
        "--mode", "baseline",
        "--dump-actions", gt_bin
    ], check=True)

    subprocess.run([
        bench,
        "--rules", f"{test_dir}/wildcards_rules.bin",
        "--packets", f"{test_dir}/wildcards_packets.bin",
        "--mode", "optimized",
        "--dump-actions", opt_bin
    ], check=True)

    correctness_script = os.path.join(os.path.dirname(__file__), "../evaluator/correctness.py")
    res = subprocess.run([sys.executable, correctness_script, gt_bin, opt_bin])
    assert res.returncode == 0, "Wildcard matching test failed!"
    print(">>> Test 3 Passed.\n")

if __name__ == "__main__":
    run_test()
