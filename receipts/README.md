# Receipts: the raw evidence behind every number

These are unedited outputs from the test and benchmark runs on the lab machine (Intel i9-12900K, one pinned core,
g++ 13.4). Nothing here was hand-written except this index. To re-check every acceptance rule from these files:

```bash
python3 verify/check_acceptance.py receipts     # prints the summary; "accepted": true
```

## Correctness

| file | what it shows |
|---|---|
| `release_gate.log` | Full release gate: differential fuzzing at 4 CPU levels, allocation-failure injection, interleaved updates, churn, ASAN/UBSAN, and the 15 planted bugs, each caught. Ends with `GATE PASSED`. |
| `wide_gate.log`, `wide_gate/` | Wide differential gate: 20 configurations with fresh seeds and sanitizers, 20/20 OK, with one log per configuration. |
| `mutations_presence_bitmap.log` | Bugs planted in the R7 presence-bitmap code; every one is caught. |
| `mutations_bitvector.log`, `mutations_bitvector_tables.log` | Bugs planted in the bit-vector filter and port classes, without and with the forced-table test profile. |
| `robustness.log`, `robustness/` | 40 extra rule-set families (1 to 60,000 rules, wildcard rate 0 to 1.0, priority ties) plus size edges: 264/264 identical to the reference, with peak memory for each. |
| `package_check.txt` | The README build steps, the sample benchmark against the baseline and the live demo, run with g++ 13.4. |
| `repo_check.txt` | This repository from a fresh copy: `scripts/run_scenarios.sh`, `make test`, the demo and the prebuilt binaries. |

## Performance (paired runs: previous version "A" = R6, entry "B" = R7, alternating order on the same core)

| folder or file | what it shows |
|---|---|
| `main/`, `confirm/`, `combined/` | Seeds 7, 42, 1001 and 2026, native and x86-64-v3 builds: the first 10 pairs per cell, a 30-pair confirmation, and the pooled 40 pairs. `report.txt` has the medians; `runs.jsonl` has every run. |
| `holdout/` | Seeds 11 and 23, never used for tuning. |
| `families/` | Development rule-set families d1 to d8. |
| `screening/`, `screening_families/`, `screening_counters.txt` | Early screening runs and hardware-counter readings taken while the change was being developed. |
| `update_tail.log`, `update_tail/` | Insert/delete latency, p99 over all operations, 48 cells (2 seeds x 2 builds x 4 modes x 3 repeats). |
| `*.log` next to a folder | The console output of that run. |
| `acceptance_chain.log` | The whole acceptance run in order, with the source hashes and the `-Werror` builds for 8 CPU targets. |
| `acceptance.json` | Output of `verify/check_acceptance.py`: every rule and whether it passed. |
| `source.sha256` | Hashes of the two submitted files that all of the above refer to. |

Labels you will see inside the raw logs: `v13` is the entry R7 and `v9` is the previous version R6 (our internal
build numbers). Paths beginning with `~/lab/` are the lab machine's working folders.
