#!/usr/bin/env bash
# Seeds for the fuzz harnesses (tests/fuzz/): valid files of every kind, made with the test build, plus a few edge
# cases, so fuzzing starts from inputs that get deep into each parser.
#   tests/fuzz/seeds.sh build/pnp-test OUT     makes OUT/header, OUT/keys, OUT/passfile, OUT/verify
set -euo pipefail
PNP="$(realpath "$1")"
OUT="$(realpath -m "$2")"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"/{header,keys,passfile,verify}
head -c $((1 << 20)) /dev/urandom >"$W/rng"
export PNP_TEST_HWRNG="$W/rng" PNP_TEST_NO_RDSEED=1 PNP_TEST_VM=
printf 'pw\n' >"$W/pass"
P8=(--protect --kdf-memory 8 --passphrase-file "$W/pass")

# real files: small ones (the verify harness gives each file at most 65535 bytes)
cd "$W"
for size in 0 1 7 8 9 100 1000; do
    head -c "$size" /dev/urandom >"f$size"
done
"$PNP" -q f0 && "$PNP" -q f100 && "$PNP" -q --shares 3 f7 && "$PNP" -q "${P8[@]}" f9 &&
    "$PNP" -q --shares 2 "${P8[@]}" f8 && "$PNP" -q --shares 16 f1000
for f in f0.pnp f0.pnp.key f100.pnp f100.pnp.key f7.pnp f7.pnp.key.1 f9.pnp.key f8.pnp.key.2 f1000.pnp.key.16; do
    cp "$f" "$OUT/header/$f"
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
