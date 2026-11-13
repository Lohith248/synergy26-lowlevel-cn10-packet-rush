#!/usr/bin/env bash
# run_scenarios.sh [SEED]  -- one command: generate the five official scenario shapes, build with the judge's
# flags, run the organiser's benchmark for our classifier and for the linear baseline, require identical verdicts,
# and score each scenario with the organiser's formula (evaluator/scoring.py).
#   SEED  generator seed (default 42). CPU=<n> pins the timed runs to one core (recommended: an idle P-core).
#   BIN=<path> uses a prebuilt benchmark binary (e.g. bin/benchmark_x86-64-v3) instead of building.
# Exit 0 only if every scenario's verdicts equal the baseline's.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$root"
seed=${1:-42}; data="data/seed$seed"; out="out/seed$seed"; mkdir -p "$data" "$out"
pin=(); [ -n "${CPU:-}" ] && pin=(taskset -c "$CPU")
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32;1m'; R=$'\033[31;1m'; D=$'\033[2m'; N=$'\033[0m'; else B= G= R= D= N=; fi

echo "${B}Packet Rush CN10 -- scenario run, seed $seed${N}"
# name rules packets extra-generator-args   (shapes from the organiser's rules document, section 4)
scen=("s01 1000 5000" "s02 15000 20000" "s03 40000 30000 --wildcard-rate 0.3" "s04 20000 20000 --wildcard-rate 0.65" "s05 15000 20000 --updates 10000")
for s in "${scen[@]}"; do
  set -- $s; name=$1 nr=$2 np=$3; shift 3
  [ -s "$data/${name}_rules.bin" ] || python3 generator/generate.py --seed "$seed" --out "$data" --rules "$nr" --packets "$np" --prefix "$name" "$@" > /dev/null
done
echo "${D}[1/3] datasets ready in $data${N}"

if [ -n "${BIN:-}" ]; then bench="$BIN"; echo "${D}[2/3] using prebuilt $bench${N}"
else
  make -s benchmark_starter > "$out/build.log" 2>&1 || { cat "$out/build.log"; exit 1; }
  bench=./benchmark_starter
  echo "${D}[2/3] built with: $(sed -n 's/^CXXFLAGS ?= //p' Makefile) ($(${CXX:-g++} --version | head -1))${N}"
fi

echo "${D}[3/3] running (baseline = organiser's linear classifier; ours = starter/classifier.cpp)${N}"
ok=1
for s in "${scen[@]}"; do
  set -- $s; name=$1; upd=(); [ -s "$data/${name}_updates.bin" ] && upd=(--updates "$data/${name}_updates.bin")
  args=(--rules "$data/${name}_rules.bin" --packets "$data/${name}_packets.bin" "${upd[@]}")
  [ -s "$out/${name}_base.act" ] || "$bench" "${args[@]}" --mode baseline --output "$out/${name}_base.json" --dump-actions "$out/${name}_base.act" > /dev/null
  "${pin[@]}" "$bench" "${args[@]}" --mode optimized --output "$out/${name}.json" --dump-actions "$out/${name}.act" > /dev/null
  if cmp -s "$out/${name}.act" "$out/${name}_base.act"; then echo MATCH > "$out/${name}.verdict"; else echo MISMATCH > "$out/${name}.verdict"; ok=0; fi
done

python3 - "$out" "$G" "$R" "$B" "$N" <<'PY'
import json, os, sys
sys.path.insert(0, "evaluator"); from scoring import compute_score
out, G, R, B, N = sys.argv[1:]
names = {"s01": "correctness_small", "s02": "scalability_medium", "s03": "performance_large",
         "s04": "adversarial_skew", "s05": "dynamic_heavy"}
weight = {"s01": .15, "s02": .20, "s03": .25, "s04": .20, "s05": .20}
print(f"\n{B}{'scenario':<22}{'weight':>7}{'Mpps':>9}{'p99 batch us':>14}{'RSS MiB':>9}{'update p99 us':>15}{'score':>8}  verdicts{N}")
total = 0.0
for s in names:
    d = json.load(open(f"{out}/{s}.json")); v = open(f"{out}/{s}.verdict").read().strip()
    sc = compute_score(d.get("throughput_mpps", 0), d.get("p99_latency_us", 1e3), d.get("peak_memory_mib", 1e3),
                       d.get("p99_update_us", 0), correct=(v == "MATCH"))["total_score"]
    total += weight[s] * sc
    col = G if v == "MATCH" else R
    print(f"{s+' '+names[s]:<22}{weight[s]:>7.2f}{d.get('throughput_mpps',0):>9.2f}{d.get('p99_latency_us',0):>14.3f}"
          f"{d.get('peak_memory_mib',0):>9.2f}{d.get('p99_update_us',0):>15.3f}{sc:>8.2f}  {col}{v} vs baseline{N}")
print(f"{B}weighted score (organiser formula, this machine): {total:.2f} / 100{N}")
PY
[ $ok = 1 ] && echo "${G}RESULT: every verdict identical to the baseline${N}" || { echo "${R}RESULT: verdict mismatch${N}"; exit 1; }
