#!/usr/bin/env bash
# run_wide.sh SRC_DIR [ITERS]   -- Linux. Wide-pool differential gate for an engine.
#   SRC_DIR  directory with classifier.h + classifier.cpp (relative or absolute)
#   ITERS    fuzz iterations per configuration (default 200; alloc-fail uses ITERS/5, min 30)
# Environment (all optional):
#   CXX     compiler (default g++)
#   KIT     directory with include/ and baseline/ (default: this repository)
#   CPUS    taskset list for every job (default: all CPUs)      JOBS  parallel jobs (default 6)
#   FIRST   first iteration number (default 0; use a new value for fresh seeds)
#   OUT     output dir (default out/wide-<time>)
# Builds fuzz_wide for -march x86-64, x86-64-v2, x86-64-v3, native (-O2 -Wall -Wextra -Werror), native with
# -DCN10_FORCE_HEAD=0/64 (ignored by engines without the knob), alloc_fail_wide, interleaved_wide x3 seeds,
# churn_wide, and a -O1 ASAN+UBSAN fuzz_wide plus UBSAN alloc_fail_wide.  A run whose CPU lacks the ISA level
# is reported COMPILED-ONLY.  One line per run:  OK|FAIL|WARN|COMPILED-ONLY  label  seconds  last output line.
# Exit 0 if no FAIL.  WARN = interleaved/churn update-latency TARGET-MISS (exit 3), not a correctness failure.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=$(cd "${1:?usage: run_wide.sh SRC_DIR [ITERS]}" && pwd)
ITERS=${2:-200}; AF=$(( ITERS / 5 )); [ $AF -lt 30 ] && AF=30   # alloc-fail needs ~30 iterations before every injection kind has fired
CXX=${CXX:-g++}
K=${KIT:-$(cd "$HERE/.." && pwd)}   # repo root: include/ and baseline/
CPUS=${CPUS:-0-$(( $(nproc) - 1 ))}; JOBS=${JOBS:-6}; FIRST=${FIRST:-0}
OUT=${OUT:-$K/out/wide-$(date +%Y%m%d-%H%M%S)}; mkdir -p "$OUT/bin" "$OUT/log"
[ -s "$SRC/classifier.cpp" ] && [ -s "$SRC/classifier.h" ] || { echo "FAIL: missing $SRC/classifier.{h,cpp}"; exit 1; }
echo "engine: $SRC  cpp sha256 $(sha256sum "$SRC/classifier.cpp" | cut -c1-16)  $($CXX --version | head -1)  iters=$ITERS first=$FIRST cpus=$CPUS"
cpuflags=" $(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2) "
has() { for f in "$@"; do [[ $cpuflags == *" $f "* ]] || return 1; done; }
can_run() { case $1 in
  x86-64|native) return 0 ;;
  x86-64-v2) has sse4_1 sse4_2 ssse3 popcnt ;;
  x86-64-v3) has sse4_1 sse4_2 ssse3 popcnt avx avx2 bmi1 bmi2 fma movbe ;;
esac; }
INC=(-I"$K/include" -I"$K/baseline" -I"$SRC" -I"$HERE")
build() {  # build <name> <test> <flags...>
  local n=$1 t=$2; shift 2
  nice taskset -c "$CPUS" "$CXX" -std=c++20 -Wall -Wextra -Werror "$@" "${INC[@]}" "$HERE/$t.cpp" \
      "$K/baseline/linear_classifier.cpp" "$SRC/classifier.cpp" -o "$OUT/bin/$n" > "$OUT/log/$n.build" 2>&1 \
    && echo "built $n" || { echo "BUILDFAIL $n"; cat "$OUT/log/$n.build" | head -20; }
}
# ---- plan: name | march-level | test | build flags | run args --------------------------------------
declare -a NAMES BLD RUNARGS LEVEL
add() { NAMES+=("$1"); LEVEL+=("$2"); BLD+=("$3 $4"); RUNARGS+=("$5"); }   # $3=test $4=flags
for lvl in x86-64 x86-64-v2 x86-64-v3 native; do
  add "fuzz[$lvl]" $lvl fuzz_wide "-O2 -march=$lvl" "$ITERS $FIRST"
done
add "fuzz[native head0]"  native fuzz_wide "-O2 -march=native -DCN10_FORCE_HEAD=0"  "$ITERS $FIRST"
add "fuzz[native head64]" native fuzz_wide "-O2 -march=native -DCN10_FORCE_HEAD=64" "$ITERS $FIRST"
# Tables and the bit-vector together on small sets: r3-sized planner costs make hash tables worthwhile at fuzz size,
# and R4_BV_MIN=4 puts any residual of 4+ rules into the bit-vector (the defaults give one or the other, never both).
BVT="-DR4_BV_MIN=4 -DR1_PROBE_COST=23.0 -DR3_PROBE_BIG=23.0 -DR1_BUCKET_COST=3.0"
add "fuzz[native tables+bv]" native fuzz_wide "-O2 -march=native $BVT" "$ITERS $FIRST"
add "alloc-fail[tables+bv]"  native alloc_fail_wide "-O2 -march=native $BVT" "$AF $FIRST"
add "interleaved[tables+bv]" native interleaved_wide "-O3 -march=native $BVT" "1"
add "bv_directed[native]" native bv_directed "-O2 -march=native" ""
add "bv_directed[tables+bv]" native bv_directed "-O2 -march=native $BVT" ""
add "alloc-fail[native]"  native alloc_fail_wide "-O2 -march=native" "$AF $FIRST"
add "alloc-fail[native head64]" native alloc_fail_wide "-O2 -march=native -DCN10_FORCE_HEAD=64" "$AF $FIRST"
for s in 1 2 3; do add "interleaved[seed$s]" native interleaved_wide "-O3 -march=native" "$s"; done
add "churn[base15000]" native churn_wide "-O3 -march=native" "40000 15000 1"
add "churn[base128]"   native churn_wide "-O3 -march=native" "40000 128 2"
SAN="-O1 -g -march=native -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
add "asan+ubsan fuzz"  native fuzz_wide "$SAN -DCN10_FORCE_HEAD=8" "$(( ITERS / 3 + 1 )) $FIRST"
add "ubsan alloc-fail" native alloc_fail_wide "-O1 -g -march=native -fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -Wno-error=mismatched-new-delete -DCN10_FORCE_HEAD=64" "$AF $FIRST"

run_one() {  # run_one idx
  local i=$1 n="${NAMES[$1]}" bn="b$1" t0 rc=0 out
  local tag; tag=$(echo "$n" | tr -c 'A-Za-z0-9_.-' '_')
  read -r test flags <<<"${BLD[$i]}"
  build "$bn" "$test" $flags > "$OUT/log/$bn.bl" 2>&1 || true
  if [ ! -x "$OUT/bin/$bn" ]; then echo "FAIL|$n|0|BUILD FAILED (see $OUT/log/$bn.build)" > "$OUT/log/$tag.res"; return; fi
  if ! can_run "${LEVEL[$i]}"; then echo "COMPILED-ONLY|$n|0|cpu lacks ${LEVEL[$i]}" > "$OUT/log/$tag.res"; return; fi
  t0=$(date +%s)
  out=$(ASAN_OPTIONS=detect_leaks=0 nice taskset -c "$CPUS" timeout 3000 "$OUT/bin/$bn" ${RUNARGS[$i]} 2>&1) || rc=$?
  printf '%s\n' "$out" > "$OUT/log/$tag.out"
  local last; last=$(printf '%s\n' "$out" | tail -1 | cut -c1-110); local dt=$(( $(date +%s) - t0 ))
  local st=FAIL
  if [ $rc -eq 0 ] && [[ $last == OK:* ]]; then st=OK
  elif [ $rc -eq 3 ]; then st=WARN; fi
  [ $st = FAIL ] && last="rc=$rc $(printf '%s\n' "$out" | grep -m1 -E 'MISMATCH|FAIL|ERROR|runtime error' | cut -c1-100) | $last"
  echo "$st|$n|$dt|$last" > "$OUT/log/$tag.res"
}
# Run with at most JOBS concurrent children (build + run per job).
running=0
for i in "${!NAMES[@]}"; do
  run_one "$i" &
  running=$((running + 1))
  if [ $running -ge "$JOBS" ]; then wait -n; running=$((running - 1)); fi
done
wait
fail=0; ok=0; warn=0
for f in "$OUT"/log/*.res; do
  IFS='|' read -r st n dt last < "$f"
  printf '%-13s %-26s %5ss  %s\n' "$st" "$n" "$dt" "$last"
  case $st in FAIL) fail=$((fail+1)) ;; OK) ok=$((ok+1)) ;; WARN) warn=$((warn+1)) ;; esac
done
echo "WIDE SUMMARY: $ok OK, $warn WARN, $fail FAIL   (logs: $OUT)"
[ $fail -eq 0 ]
