#!/usr/bin/env bash
# Build and run the Packet Rush flip demo. Usage: run_demo.sh [kit_root]
# kit_root = the organiser's starter_pack directory (default: this repository).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kit="$(cd "${1:-$here/..}" && pwd)"
out="${TMPDIR:-/tmp}/flip_demo_bin"
g++ -O3 -std=c++20 -march=native -Wall -Wextra -Wno-psabi ${DEMO_WERROR:-} \
    -I"$kit/include" -I"$kit/baseline" -I"$here/../starter" \
    -o "$out" "$here/flip.cpp" "$kit/baseline/linear_classifier.cpp" "$here/../starter/classifier.cpp"
"$out" --rules "$kit/data/sample_rules.bin"
