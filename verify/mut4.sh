#!/usr/bin/env bash
# mut4.sh SRC_DIR MUTFILE : Linux. Lines 'test|args|sed-expr'. Builds the wide test with the bug planted and runs it with args.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); SRC=$(cd "$1" && pwd); MUT=$2
CXX=${CXX:-g++}
K=${KIT:-$(cd "$HERE/.." && pwd)}; CPUS=${CPUS:-0-$(( $(nproc) - 1 ))}; W=$K/out/mut4-$(date +%H%M%S)-$$; mkdir -p $W
one() { local i=$1 test=$2 args=$3 expr=$4 d=$W/m$1; mkdir -p $d; cp $SRC/classifier.h $d/
  sed "$expr" $SRC/classifier.cpp > $d/classifier.cpp
  if cmp -s $d/classifier.cpp $SRC/classifier.cpp; then echo "mutant $i DID NOT APPLY: ${expr:0:80}"; return; fi
  nice taskset -c $CPUS $CXX -std=c++20 -Wall -Wextra -O2 -march=native ${XF:-} -I$K/include -I$K/baseline -I$d -I$HERE $HERE/$test.cpp $K/baseline/linear_classifier.cpp $d/classifier.cpp -o $d/t 2> $d/build.log || { echo "mutant $i BUILDFAIL: $(grep -m1 error $d/build.log | cut -c1-100)"; return; }
  local out; out=$(nice taskset -c $CPUS timeout 1200 $d/t $args 2>&1 | grep -E 'MISMATCH|FAIL|OK:|TARGET' | head -1)
  if [[ $out == *"OK:"* || $out == *TARGET* ]]; then echo "mutant $i [$test $args] MISSED   | ${expr:0:70}"; else echo "mutant $i [$test $args] CAUGHT ${out:0:50} | ${expr:0:50}"; fi; }
i=0; n=0
while IFS='|' read -r test args expr; do [ -z "$test" ] && continue; i=$((i+1)); one $i "$test" "$args" "$expr" > $W/res$i 2>&1 & n=$((n+1)); [ $((n % ${JOBS:-6})) -eq 0 ] && wait; done < $MUT
wait; cat $W/res* | sort -V
