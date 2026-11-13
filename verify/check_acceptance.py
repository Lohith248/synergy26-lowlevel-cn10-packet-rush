"""Re-checks the acceptance rules for R7 against the raw, unmodified receipts in this repository.

Usage: python3 verify/check_acceptance.py receipts
The paired runner already checks verdict bytes and RSS on every timed run.
"""
from collections import defaultdict
import json
from math import exp, log
from pathlib import Path
import re
from statistics import median
import sys

root = Path(sys.argv[1])
failures = []


def check(ok, message):
    if not ok:
        failures.append(message)


def load(name, expected):
    rows = [json.loads(line) for line in (root / name / "runs.jsonl").read_text().splitlines()]
    check(len(rows) == expected, f"{name}: expected {expected} rows, got {len(rows)}")
    return rows


weights = dict(zip(("s01", "s02", "s03", "s04", "s05"), (.15, .2, .25, .2, .2)))


def score(row):
    latency = min(1, 2.5 / row["p99_batch_us"]) if row["p99_batch_us"] else 1
    update = min(1, 5 / row["p99_update_us"]) if row["p99_update_us"] else 1
    return 40 * min(1, row["mpps"] / 25) + 25 * latency + 20 + 15 * update


def paired(rows):
    groups = defaultdict(dict)
    for row in rows:
        groups[row["build"], row["seed"], row["scenario"], row["run"]][row["engine"]] = row
    check(all(set(pair) == {"A", "B"} for pair in groups.values()), "unpaired rows")
    return groups


combined = (root / "combined/runs.jsonl").exists()
main = load("combined", 3200) if combined else load("main", 800)
holdout = load("holdout", 200)
fam = load("families", 160)
summary = {"main_pairs_per_cell": 40 if combined else 10}
for name, rows in (("main", main), ("holdout", holdout), ("fam", fam)):
    by_cell = defaultdict(list)
    proxy = defaultdict(lambda: [0.0, 0.0])
    for (build, seed, scenario, run), pair in paired(rows).items():
        a, b = pair["A"], pair["B"]
        by_cell[build, seed, scenario].append((a, b))
        if scenario in weights:
            p = proxy[build, seed, run]
            p[0] += weights[scenario] * score(a)
            p[1] += weights[scenario] * score(b)
    cells = []
    geomeans = defaultdict(list)
    for (build, seed, scenario), pairs in sorted(by_cell.items()):
        batch = median(b["median_batch_us"] for a, b in pairs) / median(a["median_batch_us"] for a, b in pairs)
        ratio = median(b["mpps"] for a, b in pairs) / median(a["mpps"] for a, b in pairs)
        deltas = [b["median_batch_us"] / a["median_batch_us"] - 1 for a, b in pairs]
        if name == "main":
            check(batch <= 1.03, f"{build}/{seed}/{scenario}: median batch {100*(batch-1):+.2f}%")
            geomeans[scenario].append(ratio)
        if name == "fam":
            check(not (median(deltas) > .03 and min(deltas) > 0), f"{scenario}: family slower beyond paired noise")
        cells.append(dict(build=build, seed=seed, scenario=scenario, mpps_ratio=ratio,
                          median_batch_ratio=batch, paired_batch_delta=median(deltas),
                          paired_batch_range=[min(deltas), max(deltas)],
                          mpps_A=median(a["mpps"] for a, b in pairs), mpps_B=median(b["mpps"] for a, b in pairs)))
    weighted = defaultdict(list)
    for (build, seed, run), (a, b) in proxy.items():
        weighted[build, seed].append((a, b))
    scores = []
    for (build, seed), values in sorted(weighted.items()):
        delta = median(b-a for a, b in values)
        check(delta > 0, f"{name}/{build}/{seed}: weighted delta {delta:+.3f}")
        scores.append(dict(build=build, seed=seed, A=median(a for a, b in values),
                           B=median(b for a, b in values), delta=delta))
    summary[name] = dict(cells=cells, weighted=scores)
    if name == "main":
        gm = {s: exp(sum(map(log, values))/len(values)) for s, values in geomeans.items()}
        summary["geomean_ratios"] = gm
        for s in ("s02", "s03", "s05"):
            check(gm[s] >= 1.04, f"{s}: geomean gain below 4%")

summary["s03_peak_rss_mib"] = max(r["peak_rss_mib"] for r in main if r["engine"] == "B" and r["scenario"] == "s03")
check(summary["s03_peak_rss_mib"] <= 26, "s03 RSS exceeds 26 MiB")
tails = [float(x) for x in re.findall(r"p99_all=([0-9.]+)", (root / "update_tail.log").read_text())]
check(len(tails) == 48, f"expected 48 update-tail results, got {len(tails)}")
summary["update_tail_max_us"] = max(tails)
check(max(tails) < 2.5, "update tail p99 >= 2.5 us")
gate = (root / "release_gate.log").read_text()
check("GATE PASSED\n" in gate, "stock gate did not pass")
check(len(re.findall(r"planted bug \d+ caught", gate)) == 15, "stock mutants not 15/15")
check("WIDE SUMMARY: 20 OK, 0 WARN, 0 FAIL" in (root / "wide_gate.log").read_text(), "wide gate not 20/20")
bm = (root / "mutations_presence_bitmap.log").read_text()
check(bm.count("CAUGHT") == 3 and "BUILDFAIL" not in bm, "bitmap mutations not 3/3")
bv = (root / "mutations_bitvector.log").read_text()
for number in (10, 11):
    check(re.search(rf"mutant {number} .*CAUGHT", bv) is not None, f"port mutant {number} not caught")
robust = load("robustness", 264)
check(all(r["verdict"] == "MATCH" for r in robust), "robust verdict mismatch")
rss60 = max(r["peak_rss_mib"] for r in robust if r["dataset"] == "T2a" and r["engine"] == "B")
summary["60k_peak_rss_mib"] = rss60
check(rss60 < 32, "60k RSS >= 32 MiB")
package_check = (root / "package_check.txt").read_text()
check("README build and sample verdicts PASSED" in package_check, "README build/sample check did not pass")
check("RESULT: all checks passed" in package_check, "live demo did not pass")
summary["failures"] = failures
summary["accepted"] = not failures
print(json.dumps(summary, indent=2))
sys.exit(bool(failures))
