# Benchmarks and receipts (entry R7)

R7 is compared with the previous version R6 on a lab host, an i9-12900K, CPU 4. The stock gate, architecture builds, and paired runs use g++ 13.4, `-O3 -std=c++20`, and either `-march=native` or `-march=x86-64-v3`. The host was shared with other workloads, so every comparison uses alternating paired runs. Each main cell contains 40 alternating A/B pairs. Every run's verdict bytes match the linear reference before aggregation.

The local weighted proxy improves in all eight main cells by 3.16 to 5.43 points. R7's proxy is 83.01 to 85.71. These are local measurements, not a judge prediction.
Across both builds and four seeds, per-scenario geometric mean throughput gains are s02 +20.7%, s03 +22.3%, s05 +20.5%.

Mean of the four native per-seed median Mpps, measured in the same paired runs:

| scenario | R6 | R7 |
|---|---:|---:|
| s01 | 33.98 | 34.56 |
| s02 | 16.77 | 20.00 |
| s03 | 11.48 | 13.95 |
| s04 | 60.31 | 60.24 |
| s05 | 16.83 | 20.16 |


The complete paired medians and ranges are in `receipts/combined/report.txt`, with each raw observation in `runs.jsonl`. The initial 10 pairs are preserved in `receipts/main/`; a 30-pair confirmation repeats every main cell and is preserved in `receipts/confirm/`. The pooled 40-pair sample resolves noise on the unchanged sweep path. The result evaluator is `verify/check_acceptance.py`. Its machine-readable verdict is `receipts/acceptance.json`.

## Acceptance evidence

- g++ 13.4 compiles all eight architecture targets with `-Werror`. The full stock gate passes and catches all 15 original planted bugs. See `receipts/acceptance_chain.log` and `receipts/release_gate.log`.
- The g++ 11.4 300-iteration wide gate passes all 20 configurations, including allocation-failure injection and sanitizers. See `receipts/wide_gate.log` and `receipts/wide_gate/log/`.
- All three new bitmap/probe mutations and both new port mutations are caught. See `receipts/mutations_presence_bitmap.log` and `receipts/mutations_bitvector.log`.
- Seeds 7, 42, 1001, and 2026 pass in native and x86-64-v3 builds. No scenario's accepted median batch time exceeds the 3% regression limit. Both holdout seeds, 11 and 23, have positive weighted deltas. See `receipts/combined/` and `receipts/holdout/`.
- Development families d1-d8 show no slowdown beyond paired noise. The 40-family replay has 240/240 reference-identical runs, with another 24/24 on the four size-edge fixtures. See `receipts/families/`, `receipts/robustness.log`, and `receipts/robustness/runs.jsonl`.
- Peak candidate RSS is 24.51 MiB on s03 and 29.70 MiB at 60,000 rules. The maximum all-operation update p99 is 0.800 us across 48 update-tail runs. See `receipts/update_tail.log` and `receipts/robustness/runs.jsonl`.

## Changes and limits

Presence bitmaps remove known-empty probes. Flat probe and bucket lists remove per-packet bucket bookkeeping. Hybrid port classes reduce false filter candidates. Small filters retain the compact unnamed row; exact-port classes are preserved before spare classes are spent on blocks. The original fixed-block v12 failed s01 and d1/d2 acceptance, so it is not packaged.

The requested `nbk += 1` mutation preserves classification answers because extra buckets still receive the full record check. The wrong-packet-association mutation replaces it for correctness testing. Legacy BV tests include duplicate cases insensitive under individual planner profiles; both profiles' raw reports are retained. No surviving new correctness mutation is accepted.

The planner is unchanged from R6. AVX-512 targets compile but cannot execute on this host. No AMD run of R7 is claimed.
