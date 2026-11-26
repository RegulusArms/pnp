#!/usr/bin/env bash
# Measures this machine's hardware random sources with NIST's SP 800-90B entropy assessment (docs/entropy.md).
#
#   make build/pnp-test
#   tests/entropy/assess.sh build/pnp-test OUT [BYTES]
#
# Dumps BYTES (default 1000000, the least the assessment accepts) of raw output from each usable source
# (/dev/hwrng, RDSEED) with the test build's PNP_TEST_DUMP hook, into OUT/<source>.bin, then runs NIST's
# non-IID estimators on each (8 bits per sample) if ea_non_iid is in PATH or EA_NON_IID names it, writing
# OUT/<source>.txt. Without it, the dumps are left for you to assess elsewhere. Building ea_non_iid
# (C++, not part of pnp, so pnp itself stays libc only):
#   sudo apt install g++ make libbz2-dev libdivsufsort-dev libjsoncpp-dev libssl-dev libmpfr-dev libgmp-dev
#   git clone https://github.com/usnistgov/SP800-90B_EntropyAssessment && make -C SP800-90B_EntropyAssessment/cpp non_iid
#
# What to look for: the "min(H_original, 8 X H_bitstring)" line, in bits per byte. pnp's health tests assume each
# source gives at least 4 bits per byte (src/rng.h); a measured value well above 4 says that assumption is
# conservative for this machine. Reading /dev/hwrng needs the pnp group (README, "Installing").
set -euo pipefail
PNP="$(realpath "$1")"
OUT="$2"
BYTES="${3:-1000000}"
EA="${EA_NON_IID:-$(command -v ea_non_iid || true)}"
mkdir -p "$OUT"
unset PNP_TEST_HWRNG PNP_TEST_NO_RDSEED # the real sources
for src in hwrng rdseed; do
    if ! PNP_TEST_DUMP=$src PNP_TEST_DUMP_BYTES=$BYTES "$PNP" >"$OUT/$src.bin"; then
        echo "$src: not usable here, skipped"
        rm -f "$OUT/$src.bin"
        continue
    fi
    echo "$src: $BYTES raw bytes in $OUT/$src.bin"
    if [[ -n "$EA" ]]; then
        "$EA" -a -v "$OUT/$src.bin" 8 >"$OUT/$src.txt" 2>&1
        echo "$src: $(grep -E 'min\(H_original' "$OUT/$src.txt" | tail -1)"
    fi
done
[[ -n "$EA" ]] || echo "ea_non_iid not found: assess the .bin files with it (see the top of this script)"
{
    echo "machine: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
    echo "hwrng driver: $(cat /sys/class/misc/hw_random/rng_current 2>/dev/null || echo none)"
    echo "kernel: $(uname -r)"
    echo "date: $(date -u +%F)"
} >"$OUT/machine.txt"
cat "$OUT/machine.txt"
