# PACKET RUSH — Systems Engineering Hackathon Starter Pack

Welcome to the **Packet Rush** starter pack. This repository contains all necessary reference implementations, build scripts, dataset generators, benchmark runners, and verification test suites to develop and benchmark your submission.

---

## Directory Structure

```
starter_pack/
├── include/
│   ├── types.h                  # Core 24-byte Packet and Rule structures
│   ├── classifier_interface.h   # IPacketClassifier virtual interface
│   └── io_utils.h               # High-speed binary & JSON I/O
├── starter/
│   ├── classifier.h             # Your custom classifier declarations
│   └── classifier.cpp           # Your implementation goes here
├── baseline/
│   ├── linear_classifier.h      # Golden reference linear classifier
│   └── linear_classifier.cpp
├── data/
│   ├── sample_rules.bin         # Public sample rules (binary)
│   ├── sample_packets.bin       # Public sample packets (binary)
│   ├── sample_updates.bin       # Public sample dynamic updates
│   ├── sample_rules.json        # Human-readable sample rules
│   └── sample_packets.json      # Human-readable sample packets
├── generator/
│   └── generate.py              # Synthetic dataset generator
├── evaluator/
│   ├── benchmark.cpp            # Official latency, throughput & memory harness
│   ├── correctness.py          # Strict correctness comparator
│   └── scoring.py              # Official 100-point scoring formula
├── tests/
│   ├── test_exact_match.py
│   ├── test_overlapping_rules.py
│   ├── test_wildcards.py
│   └── test_dynamic_updates.py
├── Makefile
├── CMakeLists.txt
├── Dockerfile
└── SPECIFICATION.md
```

---

## Quickstart

### 1. Build the Benchmark Harness
```bash
make
```

### 2. Run the Baseline Benchmark
```bash
./benchmark_baseline \
  --rules data/sample_rules.bin \
  --packets data/sample_packets.bin \
  --updates data/sample_updates.bin \
  --mode baseline \
  --output baseline_result.json
```

### 3. Check Baseline Score
```bash
python3 evaluator/scoring.py baseline_result.json
```

### 4. Run the Full Test Suite
```bash
python3 tests/test_exact_match.py
python3 tests/test_overlapping_rules.py
python3 tests/test_wildcards.py
python3 tests/test_dynamic_updates.py
```

---

## Developing Your Submission

All your changes should be contained within `starter/classifier.h` and `starter/classifier.cpp`. You are free to allocate additional helper structures, headers, or internal classes.

To test your optimized engine:
```bash
./benchmark_starter \
  --rules data/sample_rules.bin \
  --packets data/sample_packets.bin \
  --updates data/sample_updates.bin \
  --mode optimized \
  --output starter_result.json

python3 evaluator/scoring.py starter_result.json
```

Good luck engineers. Every packet counts.
