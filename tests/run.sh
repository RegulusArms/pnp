#!/usr/bin/env bash
# pnp's test suite: make test runs it (it needs build/pnp, build/pnp-test, build/test_health, build/test_mac,
# build/test_kdf and build/xorcheck, and script(1) from bsdutils for the interactive mode).
# The tests run build/pnp-test, the same program with test hooks: PNP_TEST_HWRNG points /dev/hwrng at a file or FIFO
# and PNP_TEST_NO_RDSEED turns RDSEED off (src/rng.c), so they give the same results on every machine, with or
# without hardware random sources; PNP_TEST_VM says whether to act as a virtual machine (src/rng.c);
# PNP_TEST_MEMINFO replaces /proc/meminfo (src/protect.c); PNP_TEST_MEDIA replaces /media/$USER and PNP_TEST_FDS lists
# the files still open on quitting (src/tui.c). They don't touch the real /dev/hwrng or drives. PNP_SANITIZE=1 (make
# sanitize) skips the one check AddressSanitizer makes meaningless.
set -uo pipefail
cd "$(dirname "$0")/.."
B="$PWD/build"
PNP="$B/pnp-test"
fails=0
check() { if eval "$1"; then echo "PASS $2"; else echo "FAIL $2"; fails=$((fails + 1)); fi; }

T="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; chmod -R u+rwX "$T"; rm -rf "$T"' EXIT
export PNP_TEST_NO_RDSEED=1
export PNP_TEST_VM= # a physical machine, even when the tests run in one (CI runners are virtual machines)
head -c $((8 << 20)) /dev/urandom >"$T/rng"         # the fake hardware source: 8 MiB of random bytes
export PNP_TEST_HWRNG="$T/rng"

no_parts() { ! find "$T" -name '*.pnp-part' | grep -q .; }
fresh() { rm -rf "$T/w" && mkdir "$T/w"; }

# --- the health tests (unit tests of src/rng.c's SP 800-90B tests)
"$B/test_health" || fails=$((fails + $?))
# --- the integrity check's MAC (unit tests of src/mac.c)
"$B/test_mac" || fails=$((fails + $?))
# --- --protect's hashes and cipher (unit tests of src/kdf.c, blake2b.c, chacha20.c, protect.c)
"$B/test_kdf" || fails=$((fails + $?))

# --- encrypt and decrypt
for size in 0 1 65535 65536 65537 $((3 << 20 | 7)); do
    fresh
    head -c "$size" /dev/urandom >"$T/w/f"
    cp "$T/w/f" "$T/w/orig"
    check '"$PNP" -q "$T/w/f" && [[ -f "$T/w/f.pnp" && -f "$T/w/f.pnp.key" ]] &&
           [[ $(stat -c %s "$T/w/f.pnp") == $((size + 40)) && $(stat -c %s "$T/w/f.pnp.key") == $((size + 56)) ]]' \
        "encrypting a $size-byte file writes FILE.pnp (+ 24-byte header, 16-byte tag) and FILE.pnp.key (+ 24, 32-byte MAC key)"
    check '"$B/xorcheck" "$T/w/orig" "$T/w/f.pnp" "$T/w/f.pnp.key"' \
        "$size bytes: ciphertext XOR pad is the plaintext, the headers match and the MAC tag is right (checked independently)"
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

# --- --key-out: the key goes straight to another folder or file name
fresh
mkdir "$T/w/usb" "$T/w/usb2"
head -c 70000 /dev/urandom >"$T/w/f"
check '"$PNP" -q --key-out "$T/w/usb" "$T/w/f" && [[ -f "$T/w/f.pnp" && -f "$T/w/usb/f.pnp.key" && ! -e "$T/w/f.pnp.key" ]] &&
       [[ $(stat -c %a "$T/w/usb/f.pnp.key") == 600 ]] && "$B/xorcheck" "$T/w/f" "$T/w/f.pnp" "$T/w/usb/f.pnp.key"' \
    "--key-out FOLDER writes FOLDER/FILE.pnp.key (mode 600) and nothing beside the ciphertext"
check '"$PNP" -q -d -k "$T/w/usb/f.pnp.key" -o "$T/w/back" "$T/w/f.pnp" && cmp -s "$T/w/back" "$T/w/f"' \
    "a key written with --key-out decrypts with -k"
check '"$PNP" -q --key-out "$T/w/usb2/mykey" -o "$T/w/g.pnp" "$T/w/f" && [[ -f "$T/w/usb2/mykey" && ! -e "$T/w/g.pnp.key" ]] &&
       "$B/xorcheck" "$T/w/f" "$T/w/g.pnp" "$T/w/usb2/mykey"' "--key-out FILE writes the key under exactly that name"
check '! "$PNP" -q --key-out "$T/w/nofolder/" -o "$T/w/h.pnp" "$T/w/f" 2>"$T/err" && grep -q "no such folder" "$T/err" &&
       [[ ! -e "$T/w/h.pnp" ]] && no_parts' "--key-out to a missing folder is refused, and nothing is written"
check '! "$PNP" -q --key-out "$T/w/usb" -o "$T/w/i/f.pnp" "$T/w/f" 2>"$T/err" && grep -q "usb/f.pnp.key already exists" "$T/err"' \
    "--key-out doesn't replace a key already in the folder without -f"
"$PNP" -q -d --key-out "$T/w/usb" "$T/w/f.pnp" 2>/dev/null
check '[[ $? == 2 ]]' "--key-out when decrypting is a usage error"
"$PNP" -q --key-out "$T/w/usb" --key-out "$T/w/usb2" -o "$T/w/j.pnp" "$T/w/f" 2>/dev/null
check '[[ $? == 1 && ! -e "$T/w/j.pnp" ]]' "--key-out twice without --shares is refused"
# while pnp waits for the (stalled) source, the key's part is in the --key-out folder and no key part is beside
# the ciphertext: the key never touches the ciphertext's disk
fresh
mkdir "$T/w/usb"
head -c $((4 << 20)) /dev/urandom >"$T/w/f"
mkfifo "$T/fifo2"
( head -c $((1 << 20)) /dev/urandom; exec sleep 300 ) >"$T/fifo2" &
writer=$!
PNP_TEST_HWRNG="$T/fifo2" "$PNP" -q --key-out "$T/w/usb" "$T/w/f" 2>/dev/null &
pid=$!
want=$((24 + 15 * 65536))
for _ in $(seq 600); do
    part="$(find "$T/w/usb" -name '.f.pnp.key.*.pnp-part')"
    [[ -n "$part" && $(stat -c %s "$part" 2>/dev/null || echo 0) -ge $want ]] && break
    sleep 0.05
done
check '[[ -n "$part" ]] && ! ls -A "$T/w" | grep -q "key"' \
    "with --key-out, the key is written only in that folder (no key part beside the ciphertext)"
kill -TERM "$pid"
wait "$pid" 2>/dev/null
kill "$writer" 2>/dev/null
wait "$writer" 2>/dev/null
check 'no_parts' "stopping it removes the parts in both folders"

# --- --shares: the key split into shares, all needed to decrypt
fresh
yes 'the same line, over and over' | head -c 100000 >"$T/w/f"
check '"$PNP" -q --shares 3 "$T/w/f" && [[ ! -e "$T/w/f.pnp.key" ]] &&
       for i in 1 2 3; do [[ $(stat -c %s "$T/w/f.pnp.key.$i") == 100058 && $(stat -c %a "$T/w/f.pnp.key.$i") == 600 ]] || exit 1; done' \
    "--shares 3 writes FILE.pnp.key.1, .2 and .3 (mode 600, each 26 + 32 bytes longer than the file) and no whole key"
check '"$B/xorcheck" "$T/w/f" "$T/w/f.pnp" "$T/w/f.pnp.key.1" "$T/w/f.pnp.key.2" "$T/w/f.pnp.key.3"' \
    "ciphertext XOR all three shares is the plaintext, and the share headers are right (checked independently)"
check 'for i in 1 2 3; do [[ $(tail -c +27 "$T/w/f.pnp.key.$i" | gzip -c | wc -c) -gt 100000 ]] || exit 1; done &&
       ! cmp -s "$T/w/f.pnp.key.1" "$T/w/f.pnp.key.2"' "each share looks random (doesn't compress), and they differ"
cp "$T/w/f" "$T/w/orig"
rm "$T/w/f"
check '"$PNP" -q -d "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' "decrypting finds FILE.pnp.key.1, .2, .3 by itself"
check '"$PNP" -q -d -k "$T/w/f.pnp.key.3" -k "$T/w/f.pnp.key.1" -k "$T/w/f.pnp.key.2" -o "$T/w/back" "$T/w/f.pnp" &&
       cmp -s "$T/w/back" "$T/w/orig"' "the shares can be given with -k in any order"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.1" -k "$T/w/f.pnp.key.3" -o "$T/w/out" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "only 2 of the key.s 3 shares.*missing: 2" "$T/err" && [[ ! -e "$T/w/out" ]] && no_parts' \
    "an incomplete set of shares is refused, naming the missing one"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.2" -o "$T/w/out" "$T/w/f.pnp" 2>/dev/null && [[ ! -e "$T/w/out" ]]' \
    "one share alone is refused"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.1" -k "$T/w/f.pnp.key.1" -k "$T/w/f.pnp.key.2" -o "$T/w/out" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "same share" "$T/err"' "the same share given twice is refused"
mv "$T/w/f.pnp.key.2" "$T/w/s2"
rm "$T/w/f"
check '! "$PNP" -q -d "$T/w/f.pnp" 2>"$T/err" && grep -q "all 3 shares" "$T/err" && [[ ! -e "$T/w/f" ]]' \
    "a share missing from beside the ciphertext is reported"
mv "$T/w/s2" "$T/w/f.pnp.key.2"
cp "$T/w/orig" "$T/w/g"
"$PNP" -q --shares 3 "$T/w/g"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.1" -k "$T/w/g.pnp.key.2" -k "$T/w/f.pnp.key.3" -o "$T/w/out" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "isn.t the key for" "$T/err"' "a share from another encryption is refused"
"$PNP" -q -o "$T/w/h.pnp" "$T/w/g"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.1" -k "$T/w/h.pnp.key" -o "$T/w/out" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "isn.t the key for\|whole key" "$T/err"' "a whole key mixed with shares is refused"
cp "$T/w/f.pnp.key.3" "$T/w/short3"
truncate -s 50000 "$T/w/short3"
check '! "$PNP" -q -d -k "$T/w/f.pnp.key.1" -k "$T/w/f.pnp.key.2" -k "$T/w/short3" -o "$T/w/out" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "different sizes" "$T/err"' "a truncated share is refused"
fresh
mkdir "$T/w/a" "$T/w/b"
echo secret >"$T/w/f"
check '"$PNP" -q --shares 2 --key-out "$T/w/a" --key-out "$T/w/b" "$T/w/f" && [[ -f "$T/w/a/f.pnp.key.1" && -f "$T/w/b/f.pnp.key.2" ]] &&
       "$B/xorcheck" "$T/w/f" "$T/w/f.pnp" "$T/w/a/f.pnp.key.1" "$T/w/b/f.pnp.key.2"' \
    "--shares 2 with --key-out twice puts share 1 in the first folder and share 2 in the second"
check '! "$PNP" -q -f --shares 2 --key-out "$T/w/k" --key-out "$T/w/../w/k" -o "$T/w/x.pnp" "$T/w/f" 2>"$T/err" &&
       grep -q "written twice" "$T/err" && [[ ! -e "$T/w/k" ]]' "two shares going to the same file are refused, even with -f"
check '! "$PNP" -q --shares 2 --key-out "$T/w/onefile" -o "$T/w/x.pnp" "$T/w/f" 2>"$T/err" && grep -q "isn.t a folder" "$T/err"' \
    "--shares with a single --key-out that isn't a folder is refused"
for bad in 1 17 x; do
    "$PNP" -q --shares "$bad" -o "$T/w/x.pnp" "$T/w/f" 2>/dev/null
    check '[[ $? == 2 && ! -e "$T/w/x.pnp" ]]' "--shares $bad is a usage error"
done
head -c 60000 /dev/urandom >"$T/w/big"
head -c 100000 /dev/urandom >"$T/runsout2"
check '! PNP_TEST_HWRNG="$T/runsout2" "$PNP" -q --shares 2 --key-out "$T/w/a" "$T/w/big" 2>"$T/err" && grep -q "stopped working" "$T/err" &&
       [[ ! -e "$T/w/big.pnp" && ! -e "$T/w/a/big.pnp.key.1" ]] && no_parts' \
    "shares take fresh hardware randomness: a source too short for them stops the run and leaves nothing"

# --- the integrity check: a changed ciphertext or key is detected, and nothing is written
flip() { # flip one bit of byte $2 of file $1
    local b
    b=$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')
    printf "$(printf '\\%03o' $((b ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc status=none
}
fresh
head -c 100000 /dev/urandom >"$T/w/f"
"$PNP" -q "$T/w/f"
cp "$T/w/f.pnp" "$T/w/ct" && cp "$T/w/f.pnp.key" "$T/w/key" && mv "$T/w/f" "$T/w/orig"
for where in "ciphertext 24" "ciphertext 50000" "ciphertext 100023" "ciphertext 100039" "key 30" "key 45" "key 56" "key 70000" "key 100055"; do
    set -- $where
    cp "$T/w/ct" "$T/w/f.pnp" && cp "$T/w/key" "$T/w/f.pnp.key"
    if [[ $1 == ciphertext ]]; then flip "$T/w/f.pnp" "$2"; else flip "$T/w/f.pnp.key" "$2"; fi
    check '! "$PNP" -q -d "$T/w/f.pnp" 2>"$T/err" && grep -q "integrity check failed" "$T/err" && [[ ! -e "$T/w/f" ]] && no_parts' \
        "one flipped bit in the $1 at byte $2 is detected, and nothing is written"
done
cp "$T/w/ct" "$T/w/f.pnp" && cp "$T/w/key" "$T/w/f.pnp.key"
check '"$PNP" -q -d "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' "the unchanged files still decrypt (the check passes)"
rm "$T/w/f"
printf x >>"$T/w/f.pnp" && printf y >>"$T/w/f.pnp.key"
check '! "$PNP" -q -d "$T/w/f.pnp" 2>"$T/err" && grep -q "integrity check failed" "$T/err" && [[ ! -e "$T/w/f" ]]' \
    "a byte appended to both files is detected"
cp "$T/w/ct" "$T/w/f.pnp" && cp "$T/w/key" "$T/w/f.pnp.key"
truncate -s 100039 "$T/w/f.pnp" && truncate -s 100055 "$T/w/f.pnp.key"
check '! "$PNP" -q -d "$T/w/f.pnp" 2>/dev/null && [[ ! -e "$T/w/f" ]]' "both files cut short by a byte is detected"
fresh
head -c 70000 /dev/urandom >"$T/w/f"
"$PNP" -q --shares 2 "$T/w/f"
mv "$T/w/f" "$T/w/orig"
flip "$T/w/f.pnp.key.2" 40000
check '! "$PNP" -q -d "$T/w/f.pnp" 2>"$T/err" && grep -q "integrity check failed" "$T/err" && [[ ! -e "$T/w/f" ]]' \
    "a flipped bit in one share is detected"
# format 001 (pnp 0.1.0-alpha.2 and older, no check) still decrypts, with a note. A zero plaintext makes the
# ciphertext body equal the pad, so the files can be made here without pnp.
fresh
head -c 16 /dev/urandom >"$T/id" && head -c 5000 /dev/urandom >"$T/pad"
cat <(printf PNPCT001) "$T/id" "$T/pad" >"$T/w/old.pnp"
cat <(printf PNPKY001) "$T/id" "$T/pad" >"$T/w/old.pnp.key"
check '"$PNP" -d "$T/w/old.pnp" 2>"$T/err" && cmp -s "$T/w/old" <(head -c 5000 /dev/zero) && grep -q "no integrity check" "$T/err"' \
    "a format 001 file from an older pnp still decrypts, with a note that it has no integrity check"

# --- --protect: the key encrypted under a passphrase (8 MiB settings here, to keep the tests quick)
fresh
printf 'correct horse battery staple\n' >"$T/pass"
printf 'correct horse battery staple\r\n' >"$T/pass-crlf"
printf 'wrong horse battery staple\n' >"$T/wrong"
: >"$T/empty"
P8=(--protect --kdf-memory 8 --passphrase-file "$T/pass")
head -c 100000 /dev/zero >"$T/w/f" # zeros: the ciphertext's body is then the pad itself
check '"$PNP" -q "${P8[@]}" "$T/w/f" && [[ $(head -c 8 "$T/w/f.pnp.key") == PNPKP002 &&
       $(stat -c %s "$T/w/f.pnp.key") == $((24 + 52 + 32 + 100000)) && $(stat -c %a "$T/w/f.pnp.key") == 600 &&
       $(stat -c %s "$T/w/f.pnp") == $((24 + 100000 + 16)) ]]' \
    "--protect writes a PNPKP002 key (header, 52-byte protection block, key material) and an ordinary ciphertext"
check '! cmp -s <(tail -c +109 "$T/w/f.pnp.key") <(tail -c +25 "$T/w/f.pnp" | head -c 100000)' \
    "the protected key doesn't hold the pad as it is"
mv "$T/w/f" "$T/w/orig"
check '"$PNP" -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" && cmp -s "$T/w/f" "$T/w/orig" &&
       grep -q "unlocking the key" "$T/err"' "a protected key decrypts with the right passphrase"
rm "$T/w/f"
check '"$PNP" -q -d --passphrase-file "$T/pass-crlf" "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' \
    "a passphrase file with a Windows line ending (\\r\\n) gives the same passphrase"
rm "$T/w/f"
check '! "$PNP" -q -d --passphrase-file "$T/wrong" "$T/w/f.pnp" 2>"$T/err" && grep -q "wrong passphrase" "$T/err" &&
       [[ ! -e "$T/w/f" ]] && no_parts' "a wrong passphrase is refused at once, and nothing is written"
check '! setsid -w "$PNP" -q -d "$T/w/f.pnp" </dev/null 2>"$T/err" && grep -q "no terminal" "$T/err" && [[ ! -e "$T/w/f" ]]' \
    "with no terminal to ask on and no --passphrase-file, decrypting a protected key stops with a clear message"
cp "$T/w/f.pnp.key" "$T/w/key"
printf '\377\377\377\377' | dd of="$T/w/f.pnp.key" bs=1 seek=32 conv=notrunc status=none
check '! "$PNP" -q -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" && grep -q "settings pnp doesn.t accept" "$T/err"' \
    "a protected key asking for 4 TiB of memory is refused, not attempted"
cp "$T/w/key" "$T/w/f.pnp.key" && flip "$T/w/f.pnp.key" 44
check '! "$PNP" -q -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" && grep -q "wrong passphrase" "$T/err"' \
    "a changed salt fails the passphrase check"
cp "$T/w/key" "$T/w/f.pnp.key" && flip "$T/w/f.pnp.key" 5000
check '! "$PNP" -q -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" && grep -q "integrity check failed" "$T/err" &&
       [[ ! -e "$T/w/f" ]] && no_parts' "a flipped bit in the protected key's body is caught by the integrity check"
cp "$T/w/key" "$T/w/f.pnp.key"
printf 'MemTotal:       8000000 kB\nMemAvailable:      20480 kB\n' >"$T/meminfo-20m"
check '! PNP_TEST_MEMINFO="$T/meminfo-20m" "$PNP" -q -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" &&
       grep -q "needs about 24 MiB of free memory, but only 20 MiB" "$T/err" && [[ ! -e "$T/w/f" ]] && no_parts' \
    "decrypting refuses with a clear message when there isn't enough free memory for the passphrase hashing"
check '! PNP_TEST_MEMINFO="$T/meminfo-20m" "$PNP" -q "${P8[@]}" -o "$T/w/m.pnp" "$T/w/orig" 2>"$T/err" &&
       grep -q "only 20 MiB is available: choose less with --kdf-memory" "$T/err" && [[ ! -e "$T/w/m.pnp" ]] && no_parts' \
    "encrypting with --protect refuses when there isn't enough free memory, and writes nothing"
printf 'MemTotal:       8000000 kB\nMemAvailable:      24576 kB\n' >"$T/meminfo-24m"
check 'PNP_TEST_MEMINFO="$T/meminfo-24m" "$PNP" -q -d --passphrase-file "$T/pass" "$T/w/f.pnp" && cmp -s "$T/w/f" "$T/w/orig"' \
    "exactly enough free memory is enough"
rm -f "$T/w/f"
check '[[ $(od -An -tu4 -j 40 -N4 "$T/w/f.pnp.key" | tr -d " ") == $(nproc | awk "{print (\$1 > 64 ? 64 : \$1)}") ]]' \
    "the key records one Argon2id lane per CPU (at most 64)"
head -c 1000 /dev/urandom >"$T/w/other" && "$PNP" -q "${P8[@]}" "$T/w/other"
check '! setsid -w "$PNP" -q -d -k "$T/w/other.pnp.key" "$T/w/f.pnp" </dev/null 2>"$T/err" && grep -q "isn.t the key for" "$T/err"' \
    "another encryption's protected key is refused before the passphrase is asked for"
check '! "$PNP" -q --protect --kdf-memory 8 --passphrase-file "$T/empty" -o "$T/w/e.pnp" "$T/w/orig" 2>"$T/err" &&
       grep -q "passphrase is empty" "$T/err" && [[ ! -e "$T/w/e.pnp" ]] && no_parts' "an empty passphrase is refused"
check '! "$PNP" -q -d --protect "$T/w/f.pnp" 2>/dev/null && ! "$PNP" -q --kdf-memory 8 "$T/w/orig" 2>/dev/null &&
       ! "$PNP" -q --protect --kdf-memory 7 "$T/w/orig" 2>/dev/null' \
    "--protect is for encrypting, --kdf-memory needs --protect and at least 8 MiB"
fresh
head -c 70000 /dev/urandom >"$T/w/f" && cp "$T/w/f" "$T/w/orig"
"$PNP" -q --shares 3 "${P8[@]}" "$T/w/f" && rm "$T/w/f"
check '[[ $(head -c 8 "$T/w/f.pnp.key.1") == PNPSP002 && $(head -c 8 "$T/w/f.pnp.key.3") == PNPSP002 ]] &&
       "$PNP" -d --passphrase-file "$T/pass" "$T/w/f.pnp" 2>"$T/err" && cmp -s "$T/w/f" "$T/w/orig" &&
       [[ $(grep -c "unlocking" "$T/err") == 1 ]]' \
    "--protect with --shares protects every share (PNPSP002), and decrypting hashes the passphrase only once"

# --- --gen-passphrase
check '[[ $(cut -f2 data/eff_large_wordlist.txt | sort -u | wc -l) == 7776 ]]' "the word list has 7776 different words"
"$PNP" -q --gen-passphrase >"$T/pp1" && "$PNP" -q --gen-passphrase >"$T/pp2"
check '[[ $(wc -w <"$T/pp1") == 7 ]] && ! cmp -s "$T/pp1" "$T/pp2" && [[
       -z $(tr " " "\n" <"$T/pp1" | grep -vxFf <(cut -f2 data/eff_large_wordlist.txt)) ]]' \
    "--gen-passphrase prints 7 words, all from the list, different each time"
check '[[ $("$PNP" -q --gen-passphrase=5 | wc -w) == 5 ]] && ! "$PNP" -q --gen-passphrase=4 2>/dev/null' \
    "--gen-passphrase=5 prints 5 words; fewer than 5 is refused"
check '! PNP_TEST_HWRNG="$T/none" "$PNP" -q --gen-passphrase >/dev/null 2>"$T/err" && grep -q "won.t make a passphrase" "$T/err"' \
    "--gen-passphrase needs a hardware source, like the pad"

# --- the interactive mode ("pnp" alone in a terminal), driven through script(1) with the keys piped in.
# PNP_TEST_MEDIA stands in for /media/$USER: KEYS (the code cylinder) and OTHER are two "drives".
tui() { # $1: the keys to press (printf format); the screen output goes to $T/tui.out
    (cd "$T/tw" && printf "$1" | TERM=xterm PNP_TEST_MEDIA="$T/media" script -qec "$PNP" "$T/tui.out" >/dev/null 2>&1)
}
rm -rf "$T/tw" "$T/media" && mkdir -p "$T/tw" "$T/media/KEYS" "$T/media/OTHER"
echo "made in the interactive mode" >"$T/tw/a.txt" && cp "$T/tw/a.txt" "$T/a.orig"
printf x >"$T/tw/$(printf 'n\033]0;pwned\007.txt')" # a file name with an escape sequence (sets the window title)
# the list: .., a.txt, n...; j a.txt, Enter, then the rows key-goes-to, split, lock, [Encrypt]: jjj Enter
tui 'j\rjjj\r\nq'
check '[[ -f "$T/tw/a.txt.pnp" && -f "$T/media/KEYS/a.txt.pnp.key" && ! -e "$T/tw/a.txt.pnp.key" ]] &&
       "$B/xorcheck" "$T/a.orig" "$T/tw/a.txt.pnp" "$T/media/KEYS/a.txt.pnp.key" && grep -q "Will write" "$T/tui.out"' \
    "interactive: Enter on a file shows what will be written, and encrypts it with its key on the code cylinder"
check '! grep -q $'"'"'\033\]0;pwned'"'"' "$T/tui.out" && grep -q "n?\]0;pwned?.txt" "$T/tui.out"' \
    "interactive: an escape sequence in a file name is shown as ?, never sent to the terminal"
rm "$T/tw/a.txt"
tui 'j\r\r\nq' # the list: .., a.txt.pnp, n...; Enter, [Decrypt]
check 'cmp -s "$T/tw/a.txt" "$T/a.orig" && grep -q "media/KEYS/a.txt.pnp.key" "$T/tui.out"' \
    "interactive: Enter on a .pnp file shows the key it found on the code cylinder, and decrypts with it"
rm "$T/tw/a.txt.pnp" "$T/media/KEYS/a.txt.pnp.key"
tui 'j\rjljjjj\r\nq' # split: 2 shares (share 1 to the cylinder, share 2 to the other drive), [Encrypt]
check '[[ -f "$T/media/KEYS/a.txt.pnp.key.1" && -f "$T/media/OTHER/a.txt.pnp.key.2" ]]' \
    "interactive: a key split into 2 shares goes to two different drives"
rm "$T/tw/a.txt"
tui 'j\r\r\nq'
check 'cmp -s "$T/tw/a.txt" "$T/a.orig"' "interactive: the shares are found on both drives and the file decrypts"
rm "$T/tw/a.txt" && mv "$T/media/OTHER" "$T/unplugged"
tui 'j\rj\rq' # one drive unplugged: [Back]
check 'grep -q "only 1 of 2 shares found" "$T/tui.out" && [[ ! -e "$T/tw/a.txt" ]]' \
    "interactive: with a drive unplugged it says which share is missing, and decrypts nothing"
check '"$PNP" </dev/null >/dev/null 2>&1; [[ $? == 2 ]] &&
       (cd "$T/tw" && printf q | TERM=dumb script -qec "$PNP" "$T/tui.out" >/dev/null 2>&1; grep -q "usage: pnp" "$T/tui.out" && ! grep -q "1049h" "$T/tui.out")' \
    "pnp alone prints its usage when not in a terminal, or with TERM=dumb"

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

# --- replacing (-f) never loses an old key, even if saving the new ciphertext fails after the new key is in place
if [[ $(id -u) != 0 ]]; then
    fresh
    mkdir "$T/w/c" "$T/w/k"
    head -c 1000 /dev/urandom >"$T/w/small"
    "$PNP" -q --key-out "$T/w/k" -o "$T/w/c/f.pnp" "$T/w/small"
    cp "$T/w/c/f.pnp" "$T/w/old.pnp" && cp "$T/w/k/f.pnp.key" "$T/w/old.key"
    head -c $((4 << 20)) /dev/urandom >"$T/w/big"
    rm -f "$T/fifo" "$T/gate" && mkfifo "$T/fifo" "$T/gate"
    ( head -c $((1 << 20)) "$T/rng"; read -r _ <"$T/gate"; cat "$T/rng" ) >"$T/fifo" &
    writer=$!
    PNP_TEST_HWRNG="$T/fifo" "$PNP" -q -f --key-out "$T/w/k" -o "$T/w/c/f.pnp" "$T/w/big" 2>"$T/err" &
    pid=$!
    for _ in $(seq 600); do # pnp has read the first MiB and waits for more: make the ciphertext's folder read-only
        part="$(find "$T/w/k" -name '.f.pnp.key.*.pnp-part')"
        [[ -n "$part" && $(stat -c %s "$part" 2>/dev/null || echo 0) -ge $((24 + 15 * 65536)) ]] && break
        sleep 0.05
    done
    chmod a-w "$T/w/c"
    echo go >"$T/gate"
    wait "$pid"
    status=$?
    wait "$writer" 2>/dev/null
    chmod u+w "$T/w/c"
    check '[[ $status == 1 ]] && cmp -s "$T/w/k/f.pnp.key" "$T/w/old.key" && cmp -s "$T/w/c/f.pnp" "$T/w/old.pnp" &&
           ! find "$T/w" -name "*.pnp-old" | grep -q .' \
        "-f: when the new ciphertext can't be saved, the old key and ciphertext are put back as they were"
    check '"$PNP" -q -d -k "$T/w/k/f.pnp.key" -o "$T/w/back" "$T/w/c/f.pnp" && cmp -s "$T/w/back" "$T/w/small"' \
        "-f: and they still decrypt"
    if [[ -z "${PNP_SANITIZE:-}" ]]; then # AddressSanitizer replaces mlock() with a no-op, so it can't fail there
        check '(ulimit -l 0; "$PNP" -f "$T/w/small" 2>"$T/err"; grep -q "couldn.t lock its buffers" "$T/err")' \
            "when its buffers can't be locked in memory (ulimit -l 0), pnp says so"
    fi
else
    echo "SKIP -f rollback and memory-locking checks (running as root, which ignores folder permissions and ulimit -l)"
fi
fresh
echo one >"$T/w/f" && "$PNP" -q "$T/w/f" && echo two >"$T/w/f"
check '"$PNP" -q -f "$T/w/f" && ! find "$T/w" -name "*.pnp-old" | grep -q . && "$PNP" -q -f -d "$T/w/f.pnp" &&
       [[ $(cat "$T/w/f") == two ]]' "-f replaces the old ciphertext and key, and leaves none of the old files behind"
check 'PNP_TEST_VM=KVMKVMKVM "$PNP" -f "$T/w/f" 2>"$T/err" && grep -q "virtual machine (KVMKVMKVM).*host can read" "$T/err" &&
       "$PNP" -f "$T/w/f" 2>"$T/err" && ! grep -q "virtual machine" "$T/err"' \
    "in a virtual machine, pnp warns that the host can read the pad; on a physical machine it doesn't"

# --- the interactive mode closes the random sources after each file (it keeps running between them).
# PNP_TEST_FDS: on quitting, pnp-test lists what it still has open (pnp is non-dumpable, so /proc can't be read
# from outside).
rm -rf "$T/tw" "$T/media" && mkdir -p "$T/tw" "$T/media/KEYS" && echo x >"$T/tw/a.txt" && echo y >"$T/tw/b.txt"
(cd "$T/tw" && printf 'j\rjjj\r\njj\rjjj\r\nq' |
    TERM=xterm PNP_TEST_MEDIA="$T/media" PNP_TEST_FDS="$T/fds" script -qec "$PNP" "$T/tui.out" >/dev/null 2>&1)
check '[[ -f "$T/tw/a.txt.pnp" && -f "$T/tw/b.txt.pnp" && -s "$T/fds" ]] && ! grep -q "$T/rng" "$T/fds"' \
    "interactive: after encrypting two files, no random source is left open"

# --- the shipped binary has no test hooks
check 'grep -qa PNP_TEST_HWRNG "$B/pnp-test" && ! grep -qa PNP_TEST_ "$B/pnp"' \
    "the test hooks are only in the test build, not in build/pnp"

echo
if ((fails)); then echo "$fails check(s) failed"; exit 1; fi
echo "All checks passed"
