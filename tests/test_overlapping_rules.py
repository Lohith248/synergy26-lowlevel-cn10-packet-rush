#!/usr/bin/env python3
"""
Test 2: Overlapping Rules and Priority Semantics
Tests that:
 1. Lower numerical priority strictly overrides higher numerical priority.
 2. In equal priority ties, lower rule_id strictly wins.
"""

import subprocess
import os
import sys

def run_test():
    gen_script = os.path.join(os.path.dirname(__file__), "../generator/generate.py")
    test_dir = "/tmp/packet_rush_test_overlapping"
    os.makedirs(test_dir, exist_ok=True)

    print("--- [Test 2: Overlapping Rules & Priority Ties] ---")
    subprocess.run([
        sys.executable, gen_script,
        "--rules", "1000",
        "--packets", "3000",
        "--wildcard-rate", "0.4",
        "--out", test_dir,
        "--prefix", "overlap"
    ], check=True)

    bench = os.path.join(os.path.dirname(__file__), "../benchmark_starter")
    gt_bin = os.path.join(test_dir, "gt.bin")
    opt_bin = os.path.join(test_dir, "opt.bin")

    subprocess.run([
        bench,
        "--rules", f"{test_dir}/overlap_rules.bin",
        "--packets", f"{test_dir}/overlap_packets.bin",
        "--mode", "baseline",
        "--dump-actions", gt_bin
    ], check=True)

    subprocess.run([
        bench,
        "--rules", f"{test_dir}/overlap_rules.bin",
        "--packets", f"{test_dir}/overlap_packets.bin",
        "--mode", "optimized",
        "--dump-actions", opt_bin
    ], check=True)

    correctness_script = os.path.join(os.path.dirname(__file__), "../evaluator/correctness.py")
    res = subprocess.run([sys.executable, correctness_script, gt_bin, opt_bin])
    assert res.returncode == 0, "Overlapping rules priority test failed!"
    print(">>> Test 2 Passed.\n")

if __name__ == "__main__":
    run_test()
