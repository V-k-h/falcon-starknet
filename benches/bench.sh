#!/usr/bin/env bash
# Falcon-512 Cairo verifier — per-component benchmark harness.
# Runs the snforge suite with resource profiling and tabulates steps + L2 gas.
#
# Usage:  benches/bench.sh            # table to stdout
#         benches/bench.sh > benches/RESULTS.md
set -euo pipefail
cd "$(dirname "$0")/../packages/falcon"

echo "# Falcon-512 Cairo verifier — benchmarks"
echo
echo "Measured with \`snforge test --detailed-resources\` (scarb 2.12.1). Hash-to-point"
echo "uses **standard SHAKE256** (pure-Cairo Keccak-f[1600]); the NTT is the codegen'd"
echo "n=512 unrolled transform; verify is the hint-based core."
echo
printf '| Component | Steps | L2 gas |\n'
printf '|---|--:|--:|\n'

snforge test --detailed-resources 2>/dev/null | awk '
  /\[PASS\]/ {
    split($2, a, "::"); name = a[3];
    if (match($0, /l2_gas: ~[0-9]+/)) gas = substr($0, RSTART + 9, RLENGTH - 9); else gas = "?";
    have = 1;
  }
  /steps:/ && have {
    printf "| %s | %s | %s |\n", name, $2, gas;
    have = 0;
  }
'
echo
echo "_Note: hash_to_point dominates — standard SHAKE256 in pure Cairo is ~3.7M steps"
echo "(~10 Keccak-f[1600] permutations). SNIP-32 (keccak_f1600 syscall) would collapse this._"
