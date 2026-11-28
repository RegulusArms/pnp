#!/usr/bin/env bash
# Seeds for the fuzz harnesses (tests/fuzz/): valid files of every kind, made with the test build, plus a few edge
# cases, so fuzzing starts from inputs that get deep into each parser.
#   tests/fuzz/seeds.sh build/pnp-test OUT     makes OUT/header, OUT/keys, OUT/passfile, OUT/verify
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PNP="$(realpath "$1")"
OUT="$(realpath -m "$2")"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"/{header,keys,passfile,verify,group,kill,courier}
head -c $((4 << 20)) /dev/urandom >"$W/rng"
export PNP_TEST_HWRNG="$W/rng" PNP_TEST_NO_RDSEED=1 PNP_TEST_VM=
printf 'pw\n' >"$W/pass"
P8=(--protect --kdf-memory 8 --passphrase-file "$W/pass")

# real files: small ones (the verify harness gives each file at most 65535 bytes)
cd "$W"
for size in 0 1 7 8 9 100 1000; do
    head -c "$size" /dev/urandom >"f$size"
done
# format 3 containers, kept small with --size (the default is at least 1 MiB), in both key forms
"$PNP" -q --size 16 f0 && "$PNP" -q --size 300 f100 && "$PNP" -q --size 23 --shares 3 f7 &&
    "$PNP" -q --size 64 "${P8[@]}" f9 && "$PNP" -q --size 40 --key-form padded --shares 2 "${P8[@]}" f8 &&
    "$PNP" -q --size 1100 --shares 16 f1000 && "$PNP" -q --size 200 --key-form padded -o p100.pnp f100
for f in f0.pnp f0.pnp.key f100.pnp f100.pnp.key f7.pnp f7.pnp.key.1 f9.pnp.key f8.pnp.key.2 f1000.pnp.key.16 \
    p100.pnp.key; do
    cp "$f" "$OUT/header/$f"
done
# format 2
mkdir v2 && cp f0 f100 f7 f9 v2/ && (cd v2 && "$PNP" -q --format 2 f0 && "$PNP" -q --format 2 f100 &&
    "$PNP" -q --format 2 --shares 3 f7 && "$PNP" -q --format 2 "${P8[@]}" f9)
for f in f0.pnp f0.pnp.key f100.pnp f100.pnp.key f7.pnp.key.1 f9.pnp.key; do
    cp "v2/$f" "$OUT/header/v2-$f"
done
# the old format (001): a ciphertext and key with no MAC
printf 'PNPCT001%016d' 0 >"$OUT/header/v1.pnp" && printf 'abc' >>"$OUT/header/v1.pnp"
printf 'PNPKY001%016d' 0 >"$OUT/header/v1.pnp.key" && printf 'xyz' >>"$OUT/header/v1.pnp.key"
cp "$OUT/header/v1.pnp" "$OUT/header/v1-short" && truncate -s 20 "$OUT/header/v1-short"

# verify: [u16 length, bytes] for the ciphertext, then each key file
put() { printf "\\x$(printf %02x $(($1 & 255)))\\x$(printf %02x $(($1 >> 8)))"; }
pack() { local f; for f in "$@"; do put "$(stat -c %s "$f")"; cat "$f"; done; }
pack f0.pnp f0.pnp.key >"$OUT/verify/whole-empty"
pack f100.pnp f100.pnp.key >"$OUT/verify/whole"
pack f7.pnp f7.pnp.key.1 f7.pnp.key.2 f7.pnp.key.3 >"$OUT/verify/shares"
pack f7.pnp f7.pnp.key.3 f7.pnp.key.1 >"$OUT/verify/shares-missing"
pack f9.pnp f9.pnp.key >"$OUT/verify/protected"
pack f100.pnp f0.pnp.key >"$OUT/verify/mismatch"
pack "$OUT/header/v1.pnp" "$OUT/header/v1.pnp.key" >"$OUT/verify/v1"
pack p100.pnp p100.pnp.key >"$OUT/verify/padded"
pack f8.pnp f8.pnp.key.1 f8.pnp.key.2 >"$OUT/verify/padded-shares-protected"
pack v2/f100.pnp v2/f100.pnp.key >"$OUT/verify/v2-whole"
pack v2/f7.pnp v2/f7.pnp.key.1 v2/f7.pnp.key.2 v2/f7.pnp.key.3 >"$OUT/verify/v2-shares"
pack v2/f100.pnp f100.pnp.key >"$OUT/verify/v2-v3-mismatch"
# a key whose range points past the container's end (offset = n), and one whose length overflows offset + length
cp f100.pnp.key past.key && printf '\054\001\000\000\000\000\000\000' | dd of=past.key bs=1 seek=24 conv=notrunc status=none
cp f100.pnp.key over.key && printf '\377\377\377\377\377\377\377\377' | dd of=over.key bs=1 seek=32 conv=notrunc status=none
pack f100.pnp past.key >"$OUT/verify/range-past-end"
pack f100.pnp over.key >"$OUT/verify/range-length-overflow"

# keys: arrows (both forms), Page Up/Down, Home/End, a long number, a lone Esc, Ctrl-C, plain text
printf '\033[A\033[B\033OC\033OD' >"$OUT/keys/arrows"
printf '\033[5~\033[6~\033[1~\033[4~\033[7~\033[8~\033[H\033[F' >"$OUT/keys/paging"
printf '\033[99999999999999999999~x' >"$OUT/keys/long-number"
printf '\033\033[\033O\033[Z q\r\n\177\b\003' >"$OUT/keys/odd"
printf 'jjkk gG.rc\r' >"$OUT/keys/text"

# passphrase files: plain, CRLF, empty, no newline, one byte too long, NUL bytes, several lines
printf 'correct horse battery staple\n' >"$OUT/passfile/plain"
printf 'crlf\r\n' >"$OUT/passfile/crlf"
printf '\n' >"$OUT/passfile/empty"
printf 'no newline' >"$OUT/passfile/no-newline"
head -c 1024 /dev/zero | tr '\0' a >"$OUT/passfile/too-long"
printf 'a\0b\nsecond line\n' >"$OUT/passfile/nul"
echo "seeds in $OUT: $(find "$OUT" -type f | wc -l) files"

# group, kill, courier: from a real pair and group meeting (the test build's --test-setup)
head -c $((48 << 20)) /dev/urandom >"$W/rng-big"
export PNP_TEST_HWRNG="$W/rng-big"
PNP_TEST_SETUP_OPTS=slots=1,nloc=2,bytes=64,emergency=1 "$PNP" --test-setup pair "$W/p" 2>/dev/null
PNP_TEST_SETUP_OPTS=slots=1,nloc=2,bytes=64,emergency=2 "$PNP" --test-setup group:3 "$W/g" 2>/dev/null
cp "$W"/p/m1/pnp-group-*/group "$OUT/group/pair"
cp "$W"/g/m2/pnp-group-*/group "$OUT/group/group3"
printf 'x' >"$W/s" && "$PNP" --sign "$W/s" --groups "$W/g/m1" -q -o "$OUT/group/sig" 2>/dev/null || true
(cd "$W" && "$PNP" --kill group --groups "$W/g/m1" -q -o "$OUT/kill/group" 2>/dev/null) || true
(cd "$W" && "$PNP" --leave --groups "$W/p/m1" -q -o "$OUT/kill/pair-end" 2>/dev/null) || true
printf 'PNPKL001' >"$OUT/kill/short"
# couriers: a small store with a few records (the self stick of a pair, cut to its records' end)
end=$(od -An -t u8 -j 40 -N 8 "$W/p/self.1" | tr -d ' ')
if (( end < 65536 )); then head -c "$end" "$W/p/self.1" >"$OUT/courier/self"; fi
head -c 64 "$W/p/courier.1" >"$OUT/courier/empty"

# inputs the fuzzers once crashed on, kept so they're replayed on every run (tests/fuzz/regress/<harness>-<what>)
for f in "$HERE"/regress/*; do
    [[ -f $f ]] && cp "$f" "$OUT/$(basename "$f" | cut -d- -f1)/regress-$(basename "$f")"
done

