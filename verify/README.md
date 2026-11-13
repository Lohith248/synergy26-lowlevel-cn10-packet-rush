# Verification tools (Linux)

All tools build against this repository's `include/` and `baseline/` and compare our classifier with the organiser's
`LinearClassifier` packet by packet.

| tool | what it does | run |
|---|---|---|
| `run_wide.sh` | 20 configurations: differential fuzzing at x86-64/v2/v3/native, forced-table profiles, allocation-failure injection, interleaved updates, churn, ASAN+UBSAN | `bash verify/run_wide.sh starter 200` |
| `bv_directed.cpp` | directed filter cases: maximum rank, merges, deletes, port-block boundaries, named ports inside ranges | built by `mut4.sh`, or compile like `fuzz_wide.cpp` |
| `mut4.sh` + `mutants_*.txt` | plants each listed bug with `sed`, rebuilds, and checks that a test catches it | `XF=-DCN10_FORCE_HEAD=64 bash verify/mut4.sh starter verify/mutants_presence_bitmap.txt` |
| `check_acceptance.py` | re-evaluates the numerical acceptance rules from the raw receipts | `python3 verify/check_acceptance.py receipts` |

`mutants_release_gate.txt` lists the 15 planted bugs used by the release gate (results in `receipts/release_gate.log`).
`CN10_FORCE_HEAD` is a test-only build profile that makes tables and the filter appear at fuzz sizes; the submitted
build never defines it.
