#!/usr/bin/env python3
"""
NexusNet Packet Rush - Correctness Verification Utility
Compares output binary action dumps between baseline and participant implementations.
"""

import sys
import os

ACTION_MAP = {0: "DROP", 1: "ACCEPT", 2: "REJECT", 3: "REDIRECT"}

def verify_actions(ground_truth_path, participant_path):
    if not os.path.exists(ground_truth_path):
        print(f"Error: Ground truth file '{ground_truth_path}' does not exist.")
        return False
    if not os.path.exists(participant_path):
        print(f"Error: Participant output file '{participant_path}' does not exist.")
        return False

    with open(ground_truth_path, "rb") as f:
        gt = f.read()
    with open(participant_path, "rb") as f:
        part = f.read()

    if len(gt) != len(part):
        print(f"[FAIL] Output size mismatch! Expected {len(gt)} packets, got {len(part)}.")
        return False

    total = len(gt)
    mismatches = 0
    max_reported = 10

    for i in range(total):
        if gt[i] != part[i]:
            mismatches += 1
            if mismatches <= max_reported:
                print(f"  [Mismatch @ Packet {i}]: Expected {ACTION_MAP.get(gt[i], gt[i])} ({gt[i]}), got {ACTION_MAP.get(part[i], part[i])} ({part[i]})")

    if mismatches > 0:
        print(f"[FAIL] {mismatches} / {total} packets mismatched ({100.0 * (total - mismatches) / total:.2f}% accuracy).")
        return False

    print(f"[SUCCESS] All {total} packets classified correctly (100.00% match).")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: correctness.py <ground_truth.bin> <participant_output.bin>")
        sys.exit(1)
    passed = verify_actions(sys.argv[1], sys.argv[2])
    sys.exit(0 if passed else 1)
