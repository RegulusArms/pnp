#!/usr/bin/env bash
# pnp's test suite: make test runs it (it needs build/pnp, build/pnp-test, build/test_health and build/xorcheck).
# The tests run build/pnp-test, the same program with test hooks (src/rng.c): PNP_TEST_HWRNG points /dev/hwrng at a
# file or FIFO, and PNP_TEST_NO_RDSEED turns RDSEED off, so they give the same results on every machine, with or
# without hardware random sources. They don't touch the real /dev/hwrng.
set -uo pipefail
cd "$(dirname "$0")/.."
B="$PWD/build"
PNP="$B/pnp-test"
fails=0
check() { if eval "$1"; then echo "PASS $2"; else echo "FAIL $2"; fails=$((fails + 1)); fi; }

T="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; chmod -R u+rwX "$T"; rm -rf "$T"' EXIT
export PNP_TEST_NO_RDSEED=1
head -c $((8 << 20)) /dev/urandom >"$T/rng"         # the fake hardware source: 8 MiB of random bytes
export PNP_TEST_HWRNG="$T/rng"

no_parts() { ! find "$T" -name '*.pnp-part' | grep -q .; }
fresh() { rm -rf "$T/w" && mkdir "$T/w"; }

# --- the health tests (unit tests of src/rng.c's SP 800-90B tests)
"$B/test_health" || fails=$((fails + $?))

# --- encrypt and decrypt
for size in 0 1 65535 65536 65537 $((3 << 20 | 7)); do
    fresh
    head -c "$size" /dev/urandom >"$T/w/f"
    cp "$T/w/f" "$T/w/orig"
    check '"$PNP" -q "$T/w/f" && [[ -f "$T/w/f.pnp" && -f "$T/w/f.pnp.key" ]] &&
           [[ $(stat -c %s "$T/w/f.pnp") == $((size + 24)) && $(stat -c %s "$T/w/f.pnp.key") == $((size + 24)) ]]' \
        "encrypting a $size-byte file writes FILE.pnp and FILE.pnp.key, each 24 bytes longer than it"
    check '"$B/xorcheck" "$T/w/orig" "$T/w/f.pnp" "$T/w/f.pnp.key"' \
        "$size bytes: ciphertext XOR key is the plaintext, and both headers match (checked independently)"
    rm "$T/w/f"
    check '"$PNP" -q -d "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' "$size bytes: decrypting gives back the file"
done
fresh
yes 'the same line, over and over' | head -c 200000 >"$T/w/f"
"$PNP" -q "$T/w/f"
check '! cmp -s <(tail -c +25 "$T/w/f.pnp") "$T/w/f" && [[ $(tail -c +25 "$T/w/f.pnp" | gzip -c | wc -c) -gt 200000 ]]' \
    "a repetitive file's ciphertext doesn't resemble it and doesn't compress (the pad is random)"
cp "$T/w/f.pnp.key" "$T/w/key1"
rm "$T/w/f.pnp" "$T/w/f.pnp.key"
"$PNP" -q "$T/w/f"
check '! cmp -s <(tail -c +25 "$T/w/key1") <(tail -c +25 "$T/w/f.pnp.key")' \
    "encrypting the same file twice gives different keys (getrandom is mixed in even with a repeating fake source)"
check '"$PNP" "$T/w/f" -o "$T/w/g.pnp" 2>"$T/err" && grep -q "pad from /dev/hwrng + getrandom" "$T/err"' \
    "pnp says which sources made the pad"

# --- permissions
fresh
echo secret >"$T/w/f"
(umask 000; "$PNP" -q "$T/w/f")
check '[[ $(stat -c %a "$T/w/f.pnp.key") == 600 && $(stat -c %a "$T/w/f.pnp") == 666 ]]' \
    "the key is mode 600 even with umask 000; the ciphertext follows the umask"
rm "$T/w/f"
(umask 022; "$PNP" -q -d "$T/w/f.pnp")
check '[[ $(stat -c %a "$T/w/f") == 600 ]]' "a decrypted file is mode 600"

# --- never replacing without -f
fresh
echo one >"$T/w/f"
echo existing >"$T/w/f.pnp"
check '! "$PNP" -q "$T/w/f" 2>"$T/err" && grep -q "already exists" "$T/err" && [[ $(cat "$T/w/f.pnp") == existing ]] &&
       [[ ! -e "$T/w/f.pnp.key" ]]' "an existing FILE.pnp isn't replaced without -f (and no key is written)"
rm "$T/w/f.pnp"
echo existing >"$T/w/f.pnp.key"
check '! "$PNP" -q "$T/w/f" 2>/dev/null && [[ $(cat "$T/w/f.pnp.key") == existing && ! -e "$T/w/f.pnp" ]]' \
    "an existing FILE.pnp.key isn't replaced without -f"
echo existing >"$T/w/f.pnp"
check '"$PNP" -q -f "$T/w/f" && "$B/xorcheck" "$T/w/f" "$T/w/f.pnp" "$T/w/f.pnp.key"' "-f replaces both"
cp "$T/w/f" "$T/w/orig"
echo changed >"$T/w/f"
check '! "$PNP" -q -d "$T/w/f.pnp" 2>/dev/null && [[ $(cat "$T/w/f") == changed ]]' \
    "decrypting doesn't replace an existing file without -f"
check '"$PNP" -q -d -f "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' "decrypting with -f replaces it"
check '! "$PNP" -q -f -o "$T/w/f" "$T/w/f" 2>/dev/null && cmp -s "$T/w/f" "$T/w/orig"' \
    "encrypting refuses to write over the file being encrypted, even with -f"
check '! "$PNP" -q -d -f -o "$T/w/f.pnp" "$T/w/f.pnp" 2>/dev/null && "$B/xorcheck" "$T/w/orig" "$T/w/f.pnp" "$T/w/f.pnp.key"' \
    "decrypting refuses to write over the ciphertext, even with -f"

# --- options and naming
fresh
echo hi >"$T/w/f"
check '"$PNP" -q -o "$T/w/other" "$T/w/f" && [[ -f "$T/w/other" && -f "$T/w/other.key" ]]' "-o names the ciphertext; the key is OUT.key"
check '"$PNP" -q -d -o "$T/w/back" "$T/w/other" && cmp -s "$T/w/back" "$T/w/f"' \
    "a ciphertext not ending in .pnp decrypts with -o"
"$PNP" -q -d "$T/w/other" 2>/dev/null
check '[[ $? == 2 ]]' "without -o, a ciphertext not ending in .pnp is a usage error (status 2)"
mv "$T/w/other.key" "$T/w/k"
check '"$PNP" -q -d -k "$T/w/k" -o "$T/w/back2" "$T/w/other" && cmp -s "$T/w/back2" "$T/w/f"' "-k names the key"
"$PNP" -q -k "$T/w/k" "$T/w/f" 2>/dev/null
check '[[ $? == 2 ]]' "-k without -d is a usage error"
check '[[ "$("$B/pnp" --version)" == "pnp $(cat VERSION)" ]]' "--version prints the version from VERSION"
check '! "$PNP" -q "$T/w" 2>"$T/err" && grep -q "regular file" "$T/err"' "a folder is refused"
check '! "$PNP" -q "$T/w/missing" 2>/dev/null && no_parts' "a missing file is refused"

# --- wrong or damaged keys
fresh
head -c 1000 /dev/urandom >"$T/w/a"
head -c 1000 /dev/urandom >"$T/w/b"
"$PNP" -q "$T/w/a" && "$PNP" -q "$T/w/b"
check '! "$PNP" -q -d -k "$T/w/b.pnp.key" -o "$T/w/out" "$T/w/a.pnp" 2>"$T/err" && grep -q "isn.t the key for" "$T/err" &&
       [[ ! -e "$T/w/out" ]]' "another file's key (same size) is refused"
cp "$T/w/a.pnp.key" "$T/w/short"
truncate -s 900 "$T/w/short"
check '! "$PNP" -q -d -k "$T/w/short" -o "$T/w/out" "$T/w/a.pnp" 2>"$T/err" && grep -q "different sizes" "$T/err" &&
       [[ ! -e "$T/w/out" ]] && no_parts' "a truncated key is refused"
check '! "$PNP" -q -d -k "$T/w/a.pnp" -o "$T/w/out" "$T/w/a.pnp" 2>"$T/err" && grep -q "is a pnp ciphertext, not a key" "$T/err"' \
    "a ciphertext given as the key is refused"
check '! "$PNP" -q -d -k "$T/w/a.pnp.key" -o "$T/w/out" "$T/w/a" 2>"$T/err" && grep -q "isn.t a pnp ciphertext" "$T/err"' \
    "a file that isn't a ciphertext is refused"

# --- failing closed: no hardware source, no encryption
fresh
echo secret >"$T/w/f"
check '! PNP_TEST_HWRNG="$T/none" "$PNP" "$T/w/f" 2>"$T/err" && grep -q "no usable hardware random source" "$T/err" &&
       [[ ! -e "$T/w/f.pnp" && ! -e "$T/w/f.pnp.key" ]] && no_parts' \
    "with no hardware source, pnp refuses to encrypt and writes nothing (getrandom alone isn't enough)"
check '! PNP_TEST_HWRNG="$T/none" "$PNP" --sources >/dev/null 2>&1' "--sources fails when there's no hardware source"
check '"$PNP" --sources | grep -q "/dev/hwrng  in use"' "--sources lists a usable source"
check '! PNP_TEST_HWRNG=/dev/zero "$PNP" "$T/w/f" 2>"$T/err" && grep -q "failed its start-up health test" "$T/err" &&
       [[ ! -e "$T/w/f.pnp" ]] && no_parts' "a stuck source (all zeros) fails its start-up test and isn't used"
if [[ $(id -u) != 0 ]]; then
    cp "$T/rng" "$T/denied" && chmod 000 "$T/denied"
    check '! PNP_TEST_HWRNG="$T/denied" "$PNP" "$T/w/f" 2>"$T/err" && grep -q "pnp group" "$T/err" && no_parts' \
        "an unreadable /dev/hwrng is explained: what to do about the pnp group"
else
    echo "SKIP an unreadable /dev/hwrng is explained (running as root, which can read anything)"
fi

# --- a source failing part-way: nothing is written
fresh
head -c $((3 << 20)) /dev/urandom >"$T/w/f"
{ head -c $((1 << 20)) /dev/urandom; head -c $((1 << 20)) /dev/zero; } >"$T/goesbad"
check '! PNP_TEST_HWRNG="$T/goesbad" "$PNP" "$T/w/f" 2>"$T/err" && grep -q "failed a health test" "$T/err" &&
       [[ ! -e "$T/w/f.pnp" && ! -e "$T/w/f.pnp.key" ]] && no_parts' \
    "a source going bad part-way stops the run, and no ciphertext, key or part is left"
head -c 100000 /dev/urandom >"$T/runsout"
check '! PNP_TEST_HWRNG="$T/runsout" "$PNP" "$T/w/f" 2>"$T/err" && grep -q "stopped working" "$T/err" &&
       [[ ! -e "$T/w/f.pnp" ]] && no_parts' "a source that stops giving data stops the run, and nothing is left"

# --- a write failing part-way (file size limit): nothing is left
fresh
head -c $((1 << 20)) /dev/urandom >"$T/w/f"
check '! (trap "" XFSZ; ulimit -f 200; exec "$PNP" -q "$T/w/f") 2>"$T/err" && grep -q "File too large" "$T/err" &&
       [[ ! -e "$T/w/f.pnp" && ! -e "$T/w/f.pnp.key" ]] && no_parts' \
    "a write failing part-way (RLIMIT_FSIZE) leaves no ciphertext, key or part"
"$PNP" -q "$T/w/f"
mv "$T/w/f" "$T/w/orig"
check '! (trap "" XFSZ; ulimit -f 200; exec "$PNP" -q -d "$T/w/f.pnp") 2>/dev/null && [[ ! -e "$T/w/f" ]] && no_parts' \
    "a decrypt failing part-way leaves no output or part"

# --- stopped by a signal while waiting for the source: parts removed, dies of the signal
fresh
head -c $((4 << 20)) /dev/urandom >"$T/w/f"
mkfifo "$T/fifo"
( head -c $((1 << 20)) /dev/urandom; exec sleep 300 ) >"$T/fifo" &
writer=$!
PNP_TEST_HWRNG="$T/fifo" "$PNP" -q "$T/w/f" 2>/dev/null &
pid=$!
# 1 MiB from the FIFO = the 4096-byte start-up test + 15 whole 64 KiB chunks; then pnp blocks reading the 16th
want=$((24 + 15 * 65536))
for _ in $(seq 600); do
    part="$(find "$T/w" -name '.f.pnp.key.*.pnp-part')"
    [[ -n "$part" && $(stat -c %s "$part" 2>/dev/null || echo 0) -ge $want ]] && break
    sleep 0.05
done
kill -TERM "$pid"
wait "$pid"
status=$?
kill "$writer" 2>/dev/null
wait "$writer" 2>/dev/null
check '[[ $status == 143 && ! -e "$T/w/f.pnp" && ! -e "$T/w/f.pnp.key" ]] && no_parts' \
    "SIGTERM while waiting for the source removes the parts, writes nothing, and exits by the signal (143)"

# --- the shipped binary has no test hooks
check 'grep -qa PNP_TEST_HWRNG "$B/pnp-test" && ! grep -qa PNP_TEST_ "$B/pnp"' \
    "the test hooks are only in the test build, not in build/pnp"

echo
if ((fails)); then echo "$fails check(s) failed"; exit 1; fi
echo "All checks passed"
