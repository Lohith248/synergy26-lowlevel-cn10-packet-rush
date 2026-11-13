#!/usr/bin/env python3
"""
Test 4: Dynamic Rule Updates Verification
Tests dynamic insert_rule() and delete_rule() operations while packets are in flight.
"""

import subprocess
import os
import sys

def run_test():
    gen_script = os.path.join(os.path.dirname(__file__), "../generator/generate.py")
    test_dir = "/tmp/packet_rush_test_dynamic"
    os.makedirs(test_dir, exist_ok=True)

    print("--- [Test 4: Dynamic Updates] ---")
    subprocess.run([
        sys.executable, gen_script,
        "--rules", "500",
        "--packets", "1000",
        "--updates", "200",
        "--out", test_dir,
        "--prefix", "dyn"
    ], check=True)

    bench = os.path.join(os.path.dirname(__file__), "../benchmark_starter")
    out_json = os.path.join(test_dir, "dyn_result.json")

    subprocess.run([
        bench,
        "--rules", f"{test_dir}/dyn_rules.bin",
        "--packets", f"{test_dir}/dyn_packets.bin",
        "--updates", f"{test_dir}/dyn_updates.bin",
        "--mode", "optimized",
        "--output", out_json
    ], check=True)

    scoring_script = os.path.join(os.path.dirname(__file__), "../evaluator/scoring.py")
    res = subprocess.run([sys.executable, scoring_script, out_json])
    assert res.returncode == 0, "Dynamic updates test failed!"
    print(">>> Test 4 Passed.\n")

if __name__ == "__main__":
    run_test()
