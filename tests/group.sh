# Pairs and groups (docs/group.md): sourced by tests/run.sh, which provides check, $PNP, $B and $T.
# Meetings are made with the test build's --test-setup: every member's laptop, self stick and courier as files,
# through the real meeting protocol (src/meeting.c). PNP_TEST_NOW fakes today's date.

G="$T/groups"
rm -rf "$G" && mkdir -p "$G"
head -c $((96 << 20)) /dev/urandom >"$T/rng-big" # meetings need more random bytes than one file
export PNP_TEST_HWRNG="$T/rng-big"
gx() { "$PNP" "$@"; } # a group command
hexdump1() { od -An -v -tx1 "$1" | tr -d ' \n'; }
gid() { basename "$(ls -d "$1"/pnp-group-*)" | sed 's/^pnp-group-//'; }
mtimes_fixed() { # every file and folder of the group dir $1 has mtime and atime $2 (seconds); lists any that don't
    local bad
    bad=$(find "$1" -printf '%T@ %A@ %p\n' | awk -v t="$2" '$1 + 0 != t || $2 + 0 != t')
    [[ -z $bad ]] || echo "$bad" >&2
    [[ -z $bad ]]
}

# ---- pairs: seals
gx --test-setup pair "$G/p" 2>"$T/err"
check '[[ -d $(ls -d "$G"/p/m1/pnp-group-*) && -d $(ls -d "$G"/p/m2/pnp-group-*) ]]' \
    "a pair's meeting (the real protocol: self sticks, couriers, import) makes a group folder for each person"
check '[[ $(gid "$G/p/m1") == $(gid "$G/p/m2") && $(stat -c %a "$(ls -d "$G"/p/m1/pnp-group-*)") == 700 ]] &&
       ! find "$G/p/m1" -type f ! -perm 600 | grep -q .' \
    "both sides hold the same group; its folders are 0700 and every file 0600"
W="$G/pw" && mkdir -p "$W"
printf 'the contract, version 1\n' >"$W/doc"
gx --seal "$W/doc" --to bob --groups "$G/p/m1" -q
check '[[ $(stat -c %s "$W/doc.pnp.seal") == 40 ]] &&
       gx --check-seal "$W/doc" --groups "$G/p/m2" >"$T/out" && grep -q "^Sealed by alice. Only you and alice" "$T/out"' \
    "a seal is 40 bytes and checks for the other person (\"proves nothing to anyone else\")"
check '! grep -qi signature "$T/out"' "a seal is never called a signature"
check '! gx --check-seal "$W/doc" --groups "$G/p/m2" >"$T/out" 2>&1' "a seal can't be checked twice (a replay is refused)"
gx --seal "$W/doc" --to bob --groups "$G/p/m1" -q -f
printf 'x' >>"$W/doc"
check '! gx --check-seal "$W/doc" --groups "$G/p/m2" >/dev/null 2>&1' "a changed file fails its seal"
check '! gx --check-seal "$W/doc" --groups "$G/p/m1" >/dev/null 2>&1' \
    "a seal sent back to the one who made it isn't accepted as the other's (separate pools per direction)"
truncate -s -1 "$W/doc"
check 'gx --check-seal "$W/doc" --groups "$G/p/m2" >/dev/null' \
    "the real file still checks after a failed attempt (a failed check uses nothing up)"
check '! gx --sign "$W/doc" --groups "$G/p/m1" 2>"$T/err" && grep -q "seals, not signatures" "$T/err"' \
    "a pair can't sign: pnp says a signature needs a group of 3 or more"
for i in 1 2 3; do printf 'f%d\n' "$i" >"$W/o$i" && gx --seal "$W/o$i" --to bob --groups "$G/p/m1" -q; done
check 'gx --check-seal "$W/o3" --groups "$G/p/m2" >/dev/null && gx --check-seal "$W/o1" --groups "$G/p/m2" >/dev/null &&
       gx --check-seal "$W/o2" --groups "$G/p/m2" >/dev/null' "seals arriving out of order all check"
check '[[ $(cmp -l "$W/o1.pnp.seal" "$W/o2.pnp.seal" | wc -l) -gt 30 ]] &&
       ! hexdump1 "$W/o1.pnp.seal" | grep -q "$(gid "$G/p/m1")" &&
       ! hexdump1 "$W/o1.pnp.seal" | grep -q "$(basename "$(ls -d "$G"/p/m1/pnp-group-*/set-* | head -1)" | sed s/set-//)"' \
    "seal headers are random one-time locators: no group or key set ID inside, nothing shared between two seals"
gx --info --groups "$G/p/m1" >"$T/info"
check 'grep -q "^Pair " "$T/info" && grep -q "→ bob: 6 of 9 items" "$T/info" && grep -q "readable by you and bob only" "$T/info"' \
    "--info shows the pair, items used per direction and who can read them"

# exhausting a pool, and the lookahead
PNP_TEST_SETUP_OPTS=nloc=20 gx --test-setup pair "$G/p20" 2>/dev/null
for i in $(seq 1 20); do printf '%d' "$i" >"$W/n$i" && gx --seal "$W/n$i" --to bob --groups "$G/p20/m1" -q; done
check '! gx --seal "$W/n1" --to bob --groups "$G/p20/m1" -f 2>"$T/err" && grep -q "meet again" "$T/err"' \
    "a used-up pool refuses with \"meet again\""
check '! gx --check-seal "$W/n18" --groups "$G/p20/m2" >/dev/null 2>&1 &&
       gx --check-seal "$W/n18" --lookahead 20 --groups "$G/p20/m2" >/dev/null' \
    "an item more than 16 ahead is found only with a wider --lookahead"

# ---- validity windows and the clock guard
PNP_TEST_SETUP_OPTS=start=2030-05-01,days=31,grace=3 gx --test-setup pair "$G/pwin" 2>/dev/null
printf 'w' >"$W/w"
check '! PNP_TEST_NOW=2030-04-30 gx --seal "$W/w" --to bob --groups "$G/pwin/m1" 2>/dev/null' \
    "sealing before the key set's window opens is refused"
PNP_TEST_NOW=2030-05-31 gx --seal "$W/w" --to bob --groups "$G/pwin/m1" -q
check '[[ -f "$W/w.pnp.seal" ]] && PNP_TEST_NOW=2030-06-03 gx --check-seal "$W/w" --groups "$G/pwin/m2" >/dev/null' \
    "sealed on the window's last day, checked within the grace days"
PNP_TEST_NOW=2030-05-31 gx --seal "$W/w" --to bob --groups "$G/pwin/m1" -q -f
check '! PNP_TEST_NOW=2030-06-04 gx --check-seal "$W/w" --groups "$G/pwin/m2" >/dev/null 2>&1' \
    "after the grace days it's refused, whatever the seal was made on"
check '! PNP_TEST_NOW=2030-05-20 gx --info --groups "$G/pwin/m1" 2>"$T/err" >/dev/null && grep -q "clock may be wrong" "$T/err" &&
       PNP_TEST_NOW=2030-05-20 gx --info --clock-ok --groups "$G/pwin/m1" >/dev/null 2>&1' \
    "the clock guard: a clock earlier than a day already seen stops pnp until --clock-ok"
pw=$(ls "$G"/pwin/m1/pnp-group-*/set-*/pool.1-2 | xargs ls -S | head -1) # the period's pool (the larger one)
check '[[ $(tail -c +65 "$pw" | tr -d "\0" | wc -c) -gt 1000 ]]' "before the window closes, the pool holds unused pad"
PNP_TEST_NOW=2030-06-10 gx --info --groups "$G/pwin/m1" >"$T/info" 2>&1
check '[[ $(tail -c +65 "$pw" | tr -d "\0" | wc -c) == 0 ]] && grep -q "has closed" "$T/info" && grep -q "closed" "$T/info"' \
    "once a window and its grace days have passed, the next run wipes every byte of unused pad"

# ---- groups: signatures
gx --test-setup group:3 "$G/g3" 2>/dev/null
printf 'board minutes\n' >"$W/min"
gx --sign "$W/min" --groups "$G/g3/m1" -q
check 'gx --verify-sig "$W/min" --groups "$G/g3/m2" >"$T/out" && grep -q "^Signed by alice, accepted at level 1.$" "$T/out" &&
       gx --verify-sig "$W/min" --groups "$G/g3/m3" >/dev/null' \
    "a group of 3: a signature is accepted, exactly, at the top level by both other members"
check '! gx --verify-sig "$W/min" --groups "$G/g3/m1" 2>"$T/err" && grep -q "own signature" "$T/err"' \
    "the signer can't check their own signature (only the others hold verify keys)"
cp "$W/min" "$W/min2" && printf 'x' >>"$W/min2" && cp "$W/min.pnp.sig" "$W/min2.pnp.sig"
check '! gx --verify-sig "$W/min2" --groups "$G/g3/m2" >/dev/null 2>&1' "a changed file fails its signature"
cp "$W/min.pnp.sig" "$W/bad.sig" && head -c 300 /dev/zero | tr '\0' '\377' | dd of="$W/bad.sig" bs=1 seek=100 conv=notrunc 2>/dev/null
gx --verify-sig "$W/min" "$W/bad.sig" --groups "$G/g3/m2" >"$T/out" 2>&1
check '! grep -q "level 1.$" "$T/out" && grep -q "NOT EXACT\|doesn.t check" "$T/out"' \
    "a signature with changed tags is never reported as exact (each verifier holds half the functions, so 300 bytes are changed)"
PNP_TEST_CHEAT=borderline:0.10 gx --sign "$W/min" -o "$W/cheat.sig" --groups "$G/g3/m1" -q
check 'gx --verify-sig "$W/min" "$W/cheat.sig" --groups "$G/g3/m2" >"$T/out" && grep -q "accepted at level 0, but NOT EXACT" "$T/out"' \
    "a cheating signer's borderline signature is accepted at a lower level, and flagged as not exact"
check '! gx --verify-sig "$W/min" "$W/cheat.sig" --level 1 --groups "$G/g3/m3" >/dev/null' \
    "and it isn't accepted at the level asked for (--level 1)"
PNP_TEST_CHEAT=borderline:0.60 gx --sign "$W/min" -o "$W/cheat2.sig" --groups "$G/g3/m1" -q
check '! gx --verify-sig "$W/min" "$W/cheat2.sig" --groups "$G/g3/m2" >/dev/null' "a signature mostly wrong is refused"
v3=$(ls -S "$G"/g3/m3/pnp-group-*/set-*/verify.1 | head -1) # the period's (the emergency set's is smaller)
PNP_TEST_SPLITS="leak:$v3" gx --sign "$W/min" -o "$W/leak.sig" --groups "$G/g3/m1" -q
check 'gx --verify-sig "$W/min" "$W/leak.sig" --groups "$G/g3/m2" >"$T/out" && grep -q "level 1.$" "$T/out" &&
       ! gx --verify-sig "$W/min" "$W/leak.sig" --groups "$G/g3/m3" >/dev/null' \
    "a signer who knew one member's split could fool that member alone (why custody of the splits matters)"
PNP_TEST_KEEP_SLOT=1 gx --sign "$W/min" -o "$W/r1.sig" --groups "$G/g3/m1" -q
PNP_TEST_KEEP_SLOT=1 gx --sign "$W/min2" -o "$W/r2.sig" --groups "$G/g3/m1" -q
gx --verify-sig "$W/min" "$W/r1.sig" --groups "$G/g3/m2" >/dev/null
check 'gx --verify-sig "$W/min2" "$W/r2.sig" --groups "$G/g3/m2" >"$T/out" && grep -q "slot for a different message" "$T/out"' \
    "a slot used for two messages is reported: the signer misbehaved"
check '[[ $(stat -c %s "$W/min.pnp.sig") == $((36 + (4 * 1600 + 3) / 4)) ]]' \
    "a 3-person signature is 36 bytes + 2 bits per function (1.6 KiB)"
gx --test-setup group:5 "$G/g5" 2>/dev/null
gx --sign "$W/min" -o "$W/g5.sig" --groups "$G/g5/m3" -q
ok=1
for m in 1 2 4 5; do gx --verify-sig "$W/min" "$W/g5.sig" --groups "$G/g5/m$m" >"$T/out" && grep -q "level 0.$" "$T/out" || ok=0; done
check '((ok))' "a group of 5 (2 cheaters tolerated, 0 hand-ons): every other member accepts exactly"
gx --info --groups "$G/g5/m1" >"$T/info"
check 'grep -q "up to 2 cheaters tolerated, 0 guaranteed hand-ons · kill threshold 2" "$T/info"' \
    "--info shows the group's tolerance, hand-ons and kill threshold"

# ---- messages
for size in 0 1 20000; do
    head -c "$size" /dev/urandom >"$W/m$size"
    gx --send "$W/m$size" --to bob --groups "$G/g3/m1" -q
    check 'gx --receive "$W/m$size.pnp" -o "$W/got$size" --groups "$G/g3/m2" >"$T/out" && cmp -s "$W/m$size" "$W/got$size" &&
           grep -q "^From alice (deniable" "$T/out"' "a $size-byte message from alice reaches bob intact (unsigned: deniable)"
done
check '[[ $(stat -c %s "$W/m20000.pnp") -gt 20000 ]] && ! hexdump1 "$W/m20000.pnp" | head -c 48 | grep -q "$(gid "$G/g3/m1" | head -c 16)"' \
    "a message's header doesn't name its group"
check '! gx --receive "$W/m1.pnp" -o "$W/again" --groups "$G/g3/m2" >/dev/null 2>&1 && [[ ! -e "$W/again" ]]' \
    "a message can't be received twice"
gx --send "$W/m1" --to bob --groups "$G/g3/m1" -q -f
check '! gx --receive "$W/m1.pnp" -o "$W/carol" --groups "$G/g3/m3" >/dev/null 2>&1 && [[ ! -e "$W/carol" ]]' \
    "a message for bob can't be read by carol"
flip "$W/m1.pnp" 30
check '! gx --receive "$W/m1.pnp" -o "$W/t1" --groups "$G/g3/m2" 2>"$T/err" && [[ ! -e "$W/t1" ]] && grep -q integrity "$T/err"' \
    "a changed message fails the integrity check and nothing is written"
gx --send "$W/m20000" --to bob --sign --groups "$G/g3/m1" -q -f
check 'gx --receive "$W/m20000.pnp" -o "$W/s" --groups "$G/g3/m2" >"$T/out" && grep -q "signed (accepted at level 1)" "$T/out" &&
       cmp -s "$W/s" "$W/m20000" && [[ -f "$W/s.pnp-signed" ]]' \
    "a signed message arrives with its signature checked, and bob keeps it as evidence (.pnp-signed)"
check 'gx --verify-sig "$W/s.pnp-signed" --groups "$G/g3/m3" >"$T/out" && grep -q "Signed by alice" "$T/out" &&
       grep -q "It was sent to: bob." "$T/out"' \
    "bob can pass it on: carol checks alice's signature, and sees it was sent to bob (forwarding shows)"
PNP_TEST_SETUP_OPTS=signed=1 gx --test-setup group:3 "$G/g3s" 2>/dev/null
gx --send "$W/m1" --to carol --groups "$G/g3s/m2" -q -o "$W/sd.pnp"
check 'gx --receive "$W/sd.pnp" -o "$W/sd" --groups "$G/g3s/m3" >"$T/out" && grep -q signed "$T/out"' \
    "in a signed-by-default group every message is signed"

# ---- kill notices, leaving
gx --test-setup group:3 "$G/k3" 2>/dev/null
K="$G/kw" && mkdir -p "$K" && cd "$K"
gx --kill group --groups "$G/k3/m1" -o notice.pnp-kill -q
check '! gx --sign "$W/min" -o "$W/k.sig" --groups "$G/k3/m2" 2>"$T/err" && grep -q "reports the whole group compromised" "$T/err" &&
       grep -q despite-warning "$T/err"' \
    "one member's kill notice (in the current folder) only warns; sending asks for --despite-warning"
check 'gx --sign "$W/min" -o "$W/k.sig" --groups "$G/k3/m2" --despite-warning -q' "--despite-warning goes ahead"
check '! gx --kill-sign notice.pnp-kill --groups "$G/k3/m1" 2>"$T/err" && grep -q "already signed" "$T/err"' \
    "the same member can't sign a notice twice"
gx --kill-sign notice.pnp-kill --groups "$G/k3/m3" -q
check '! gx --sign "$W/min" -o "$W/k2.sig" --groups "$G/k3/m2" --despite-warning 2>"$T/err" && grep -q killed "$T/err"' \
    "a second member's signature kills: nobody can sign with those keys any more"
check 'gx --info --groups "$G/k3/m2" >"$T/info" && grep -q "KILLED (compromised)" "$T/info"' "--info shows the kill"
cd "$T"
gx --test-setup group:4 "$G/l4" 2>/dev/null
mkdir -p "$G/lw" && cd "$G/lw"
gx --leave --groups "$G/l4/m3" -o leave.pnp-kill -q
check 'gx --send "$W/m1" --to dave --groups "$G/l4/m1" -f -o "$G/lw/d.pnp" 2>"$T/err" && grep -q "carol left the group" "$T/err" &&
       grep -q "tolerance left" "$T/err"' "after a leave the others carry on, warned of the reduced tolerance"
check '! gx --send "$W/m1" --to carol --groups "$G/l4/m1" -f -o "$G/lw/c.pnp" 2>"$T/err" && grep -q "no longer in the group" "$T/err"' \
    "nobody can send to a member who left"
check 'ls "$G"/l4/m3/pnp-group-*/set-*/verify.1 >/dev/null 2>&1' "the leaver keeps their verify keys by default"
cd "$T"
gx --test-setup pair "$G/pk" 2>/dev/null
mkdir -p "$G/pkw" && cd "$G/pkw" && printf 'z' >f
gx --leave --groups "$G/pk/m1" -o end.pnp-kill -q
check '! gx --seal f --to alice --groups "$G/pk/m2" 2>"$T/err" && grep -q killed "$T/err"' \
    "in a pair either person can end it alone (threshold 1)"
cd "$T"
# a notice travels inside messages: carol never sees the file, only a message from alice
gx --test-setup group:3 "$G/s3" 2>/dev/null
mkdir -p "$G/s3w" && cd "$G/s3w"
gx --kill group --groups "$G/s3/m1" -o n.pnp-kill -q
mv n.pnp-kill "$T/n.pnp-kill.away"
gx --send "$W/m1" --to carol --groups "$G/s3/m1" --despite-warning -q -o msg.pnp
check 'gx --receive msg.pnp -o got --groups "$G/s3/m3" >/dev/null 2>&1 && ! gx --sign "$W/min" -o x.sig --groups "$G/s3/m3" 2>"$T/err" &&
       grep -q "alice reports" "$T/err"' \
    "a kill notice travels inside messages: the recipient learns of it from any message"
cd "$T"

# ---- no activity log
gc=$(ls -d "$G"/g3/m2/pnp-group-*)
created=$(( $(date -u -d "$(date -u +%F)" +%s) ))
check 'mtimes_fixed "$gc" "$created"' \
    "after a session of seals, signatures and messages, every group file's mtime and atime are one fixed time"
PNP_TEST_SETUP_OPTS=anon=1 gx --test-setup pair "$G/an" 2>/dev/null
printf 'a' >"$W/an" && gx --seal "$W/an" --to 2 --groups "$G/an/m1" -q && gx --check-seal "$W/an" --groups "$G/an/m2" >"$T/out"
check 'mtimes_fixed "$(ls -d "$G"/an/m2/pnp-group-*)" 946684800 && grep -q "Sealed by member 1" "$T/out" &&
       ! grep -rqa alice "$G/an/m1" "$G/an/m2"' \
    "an anonymous group: members are numbers, no name in any file, timestamps all 2000-01-01"

# ---- courier sticks and import
check '! PNP_TEST_COURIER_LIE=drop gx --test-setup pair "$G/lie1" 2>"$T/err" && grep -q "ignores writes or isn.t as big" "$T/err"' \
    "a courier that ignores writes is caught by the read-back and refused"
check '! PNP_TEST_COURIER_LIE=wrap gx --test-setup pair "$G/lie2" 2>"$T/err" && grep -q "ignores writes or isn.t as big" "$T/err"' \
    "a courier that fakes its size (wraps around) is caught by the read-back"
check 'gx --info "$G/p/self.1" >"$T/out" && grep -q "self drive of member 1" "$T/out" && grep -q "pool contribution" "$T/out"' \
    "--info on a self stick lists its records"
check '! gx --import "$G/p/self.1" "$G/p/m1" 2>"$T/err" && grep -q "already exists" "$T/err"' \
    "a meeting can't be imported twice onto the same cylinder"
cp --sparse=always "$G/p/self.1" "$T/self.bad" && flip "$T/self.bad" 300
mkdir -p "$G/imp"
check '! gx --import "$T/self.bad" "$G/imp" 2>"$T/err" && grep -q damaged "$T/err" && ! ls "$G/imp" | grep -q .' \
    "a damaged record on a self stick is caught by its checksum, and nothing is imported"
rm -f "$T/self.bad"
check '[[ $(od -An -tx1 -N 4096 "$G/p/courier.1" | tr -d " \n" | grep -c "504e504352303031") == 1 ]] &&
       gx --info "$G/p/courier.1" >"$T/out" && grep -q "0 bytes used\|64 bytes used" "$T/out"' \
    "after the meeting each courier holds nothing but its header (overwritten after every visit)"

# ---- crash safety: killed at every step of sealing, no item is ever used twice
gx --test-setup pair "$G/cr" 2>/dev/null
printf 'c' >"$W/cr"
crp=$(ls "$G"/cr/m1/pnp-group-*/set-*/pool.1-2 | xargs ls -S | head -1) # the period's pool (the larger one)
pool_even() { # each seal reserves 32 bytes (its MAC key): next offset (48) == 32 × next locator (36), or it's torn
    (($(od -An -tu8 -j48 -N8 "$crp") == 32 * $(od -An -tu4 -j36 -N4 "$crp")))
}
torn=0
for n in 1 2 3 4; do # 1, 2: before and after pool_reserve saves the header; 3, 4: writing the seal
    PNP_TEST_CRASH_AT=$n gx --seal "$W/cr" --to bob --groups "$G/cr/m1" -f -o "$W/cr.$n" >/dev/null 2>&1
    pool_even || torn=1
done
check '((torn == 0))' \
    "a crash inside pool_reserve never leaves its header torn (the new locator saved without the new offset)"
gx --seal "$W/cr" --to bob --groups "$G/cr/m1" -q -f -o "$W/cr.ok"
check 'gx --check-seal "$W/cr" "$W/cr.ok" --groups "$G/cr/m2" >/dev/null' \
    "after crashes at every step of sealing, the next seal still checks"
locs=$(for f in "$W"/cr.[0-9] "$W/cr.ok"; do [[ -f $f ]] && head -c 16 "$f" | od -An -tx1; done | sort | uniq -d | wc -l)
check '[[ $locs == 0 ]]' "no locator was ever used twice across the crashes"

# ---- the sandbox: a group command can't touch anything outside its folders
printf 's' >"$W/sb"
gx --seal "$W/sb" --to bob --groups "$G/p/m1" -q -f 2>/dev/null
PNP_TEST_PROBE=/etc/hostname gx --seal "$W/sb" --to bob --groups "$G/p/m1" -f -q 2>"$T/probe"
if [[ -z "${PNP_SANITIZE:-}" ]] && grep -q "Permission denied" "$T/probe"; then
    check 'grep -q "probe read /etc/hostname: Permission denied" "$T/probe" && grep -q "probe create: Permission denied" "$T/probe"' \
        "a group command is fenced in (Landlock): nothing outside its folders can be read or made"
else
    echo "SKIP group fence check (no Landlock in this kernel, or a sanitizer build)"
fi

# ---- the meeting wizard: three laptops at once, sticks as files, the answers typed in advance
M="$G/meet" && mkdir -p "$M/st" "$M/run" "$M/cyl1" "$M/cyl2" "$M/cyl3" "$M/vault"
for i in 1 2 3; do truncate -s 1G "$M/st/self$i" "$M/st/cour$i"; truncate -s 16M "$M/st/card$i"; done
printf 'c\n3\nn\nField team\nalice\nbob\ncarol\nm\n2\n2030-05-01\n2\n4\n1\n\nn\n\n\n0\ny\n' >"$M/a1"
printf 'j\n2\ny\n' >"$M/a2" && printf 'j\n3\ny\n' >"$M/a3"
for i in 1 2 3; do
    XDG_RUNTIME_DIR="$M/run" gx --meet --self "$M/st/self$i" --courier "$M/st/cour$i" --sticks "$M/st" <"$M/a$i" >"$M/o$i" 2>&1 &
    mpid[$i]=$!
done
mok=1
for i in 1 2 3; do wait "${mpid[$i]}" || mok=0; done
check '((mok)) && grep -q "✓ bob: test signature and test seal check" "$M/o1" && grep -q "✓ alice" "$M/o3" &&
       [[ $(grep -h "^Check code" "$M"/o[123] | sort -u | wc -l) == 1 ]]' \
    "the meeting wizard: three laptops at once, the same check code everywhere, every test checks for everyone"
check '! ls "$M/run" | grep -q .' "the meeting's check leaves nothing behind in memory's runtime folder"
for i in 1 2 3; do XDG_RUNTIME_DIR="$M/run" gx --import "$M/st/self$i" "$M/cyl$i" --kill-card "$M/st/card$i" 2>/dev/null; done
for f in "$M"/cyl1/pnp-group-*/set-*/sign; do # the emergency set's: 8 signatures + the meeting's test
    [[ $(od -An -t u4 -j 32 -N 4 "$f" | tr -d " ") == 9 ]] && esign=$f
done
check '[[ $(od -An -t u4 -j 36 -N 4 "$esign" | tr -d " ") == 5 ]]' \
    "the emergency slots are split at import: the cylinder starts after the kill card's half, so none is ever used twice"
printf 'memo\n' >"$M/memo"
PNP_TEST_NOW=2030-05-02 gx --sign "$M/memo" --groups "$M/cyl1" -q
check 'PNP_TEST_NOW=2030-05-02 gx --verify-sig "$M/memo" --groups "$M/cyl3" >"$T/out" && grep -q "Signed by alice, accepted at level 1." "$T/out"' \
    "after importing at home, signatures work between the members' cylinders"
check 'gx --info "$M/st/card2" >"$T/out" && grep -q "kill card of member 2" "$T/out"' "--info recognises a kill card"
mkdir -p "$M/kc" && cd "$M/kc"
XDG_RUNTIME_DIR="$M/run" PNP_TEST_NOW=2030-05-03 gx --kill group --kill-card "$M/st/card2" -o k.pnp-kill -q 2>"$T/card"
check '! grep -q "written back" "$T/card" && [[ -f k.pnp-kill ]]' \
    "a kill card is written back after use (its emergency slot is used up on the card too)"
PNP_TEST_NOW=2030-05-03 gx --kill-sign k.pnp-kill --groups "$M/cyl3" -q
check '! PNP_TEST_NOW=2030-05-03 gx --sign "$M/memo" -o x.sig --groups "$M/cyl1" --despite-warning 2>"$T/err" && grep -q killed "$T/err"' \
    "a kill notice signed with a kill card (no cylinder needed), co-signed by another member, kills the group"
cd "$T"
s2=$(PNP_TEST_NOW=2030-05-02 gx --info --groups "$M/cyl2" 2>/dev/null | grep "^Key set" | tail -1 | awk '{print $3}')
PNP_TEST_NOW=2030-05-02 gx --move "$s2" --to "$M/vault" --groups "$M/cyl2" 2>/dev/null
check 'PNP_TEST_NOW=2030-05-02 gx --info --groups "$M/cyl2" 2>/dev/null | grep "$s2" | grep -q "not on this cylinder" &&
       PNP_TEST_NOW=2030-05-02 gx --info --groups "$M/vault" 2>/dev/null | grep "$s2" | grep -q "not valid yet"' \
    "--move takes a future key set to the vault; --info says where each one is"
# a pair's wizard: one creator, one joiner
mkdir -p "$M/p/st" && truncate -s 1G "$M/p/st/s1" "$M/p/st/c1" "$M/p/st/s2" "$M/p/st/c2"
printf 'c\n2\na\ni\n4\n1\n\n0\ny\n' >"$M/p/a1" && printf 'j\n2\ny\n' >"$M/p/a2"
XDG_RUNTIME_DIR="$M/run" gx --meet --self "$M/p/st/s1" --courier "$M/p/st/c1" --sticks "$M/p/st" <"$M/p/a1" >"$M/p/o1" 2>&1 &
pp=$!
XDG_RUNTIME_DIR="$M/run" gx --meet --self "$M/p/st/s2" --courier "$M/p/st/c2" --sticks "$M/p/st" <"$M/p/a2" >"$M/p/o2" 2>&1
check 'wait $pp && grep -q "✓ member 2: test item and test seal check" "$M/p/o1" && grep -q "anonymous" "$M/p/o2"' \
    "a pair's meeting through the wizard (anonymous, no time limit)"

# a re-meeting after a leave: same group ID, next generation, the leaver out, the old generation retired
R2="$M/re" && mkdir -p "$R2/st" && cd "$R2"
gx --test-setup group:4 g 2>/dev/null
(cd g && gx --leave --groups m3 -o leave.pnp-kill -q) && cp g/leave.pnp-kill .
gx --info --groups g/m1 >/dev/null 2>&1
for i in 1 2 3; do truncate -s 1G "st/self$i" "st/cour$i"; done
printf 'c\n1\n3\nm\n1\n\n2\n4\n1\n\nn\n\n\n0\ny\n' >a1 && printf 'j\n2\ny\n' >a2 && printf 'j\n3\ny\n' >a3
XDG_RUNTIME_DIR="$M/run" gx --meet --from "$(ls -d g/m1/pnp-group-*)" --self st/self1 --courier st/cour1 --sticks st <a1 >o1 2>&1 &
r1=$!
XDG_RUNTIME_DIR="$M/run" gx --meet --self st/self2 --courier st/cour2 --sticks st <a2 >o2 2>&1 &
r2=$!
XDG_RUNTIME_DIR="$M/run" gx --meet --self st/self3 --courier st/cour3 --sticks st <a3 >o3 2>&1
wait $r1 && wait $r2 && gx --import st/self1 g/m1 2>/dev/null
check 'gx --info --groups g/m1 >"$T/out" 2>/dev/null && grep -q "3 members · you: alice (1) · generation 2" "$T/out" &&
       grep -q "· replaced" "$T/out" && grep -q "dave" o1' \
    "a re-meeting: the same group, the next generation, the leaver out; the old generation's key sets are retired"
check '! grep -q carol o1' "the member who left isn't on the new roster"
cd "$T"

# ---- couriers before a meeting: --courier-check
head -c $((1 << 20)) /dev/zero >"$T/stick"
check 'gx --courier-check "$T/stick" 2>/dev/null' "--courier-check accepts a stick that keeps what's written"
check '! PNP_TEST_COURIER_LIE=wrap gx --courier-check "$T/stick" 2>"$T/err" && grep -q "isn.t as big" "$T/err"' \
    "--courier-check catches a stick that holds less than it claims"

# ---- --info on today's keys
printf 'k' >"$W/ki" && "$PNP" -q --shares 3 "$W/ki"
check 'gx --info "$W/ki.pnp.key.2" >"$T/out" && grep -q "key share (format 003) .* a range key with pad for 1 bytes" "$T/out" &&
       grep -q "share 2 of 3" "$T/out" && gx --info "$W/ki.pnp" >"$T/out" &&
       grep -q "ciphertext (format 003) .* a container of 1048576 bytes" "$T/out" &&
       "$PNP" -q --format 2 -o "$W/ki2.pnp" "$W/ki" && gx --info "$W/ki2.pnp.key" >"$T/out" &&
       grep -q "key (format 002) .* for 1 bytes" "$T/out"' \
    "--info works for every pnp key type (here a share), from its header alone"


# ---- the interactive mode: the same actions from the file browser (s and p), driven through script(1)
gtui() { # $1 folder, $2 media folder (stands in for /media/$USER), $3 keys; the screen goes to $T/gtui.out
    (cd "$1" && printf "$3" | TERM=xterm PNP_TEST_MEDIA="$2" PNP_TEST_STICKS="$G/tuisticks" \
        script -qec "$PNP" "$T/gtui.out" >/dev/null 2>&1)
}
I="$G/tui" && mkdir -p "$I/a/KEYS" "$I/b/KEYS" "$I/wa" "$I/wb" "$G/tuisticks"
gx --test-setup pair "$I/p" 2>/dev/null
mv "$I"/p/m1/pnp-group-* "$I/a/KEYS/" && mv "$I"/p/m2/pnp-group-* "$I/b/KEYS/"
printf 'the lease\n' >"$I/wa/doc"
gtui "$I/wa" "$I/a" 'js\r\r\nq' # the list: .., doc; s on doc: [Seal it], [bob]; Enter after; quit
check '[[ -f "$I/wa/doc.pnp.seal" ]] && grep -q "sealed for bob" "$T/gtui.out"' \
    "interactive: s on a file seals it for the other member of a pair"
cp "$I/wa/doc" "$I/wa/doc.pnp.seal" "$I/wb/"
gtui "$I/wb" "$I/b" 'jj\r\nq' # .., doc, doc.pnp.seal: Enter on the seal
check 'grep -q "Sealed by alice. Only you and alice could have made this" "$T/gtui.out"' \
    "interactive: Enter on a seal checks it"
printf 'meet at noon\n' >"$I/wa/note"
gx --send "$I/wa/note" --to bob --groups "$I/a/KEYS" -q -o "$I/wb/note.pnp"
gtui "$I/wb" "$I/b" 'jjj\r\nq' # .., doc, doc.pnp.seal, note.pnp: Enter receives it
check 'grep -q "From alice (deniable" "$T/gtui.out" && cmp -s "$I/wb/note" "$I/wa/note"' \
    "interactive: Enter on a group message receives it"
gtui "$I/wa" "$I/a" 'pj\rqqq' # no drives yet: the meeting can't start, and the groups screen says why
check 'grep -q "No pnp drives found" "$T/gtui.out"' \
    "interactive: a meeting with no pnp drives plugged in says so on the groups screen"
truncate -s 64M "$G/tuisticks/s1"
gtui "$I/wa" "$I/a" 'pj\rqqq' # p: the groups screen; the second item, Start or join a meeting: the stick list
check 'grep -q "Pairs and groups" "$T/gtui.out" && grep -q "Pair \"test group\": 2 members, you are alice" "$T/gtui.out" &&
       grep -q "blank pnp drive" "$T/gtui.out"' \
    "interactive: p lists your groups, and a meeting starts by choosing among the pnp sticks plugged in"
mkdir -p "$I/g/a/KEYS" "$I/g/b/KEYS" "$I/g/wa" "$I/g/wb"
gx --test-setup group:3 "$I/g/s" 2>/dev/null
mv "$I"/g/s/m1/pnp-group-* "$I/g/a/KEYS/" && mv "$I"/g/s/m2/pnp-group-* "$I/g/b/KEYS/"
printf 'minutes\n' >"$I/g/wa/min"
gtui "$I/g/wa" "$I/g/a" 'js\r\nq' # s on min: [Sign it]
cp "$I/g/wa/min" "$I/g/wa/min.pnp.sig" "$I/g/wb/" 2>/dev/null
gtui "$I/g/wb" "$I/g/b" 'jj\r\nq' # .., min, min.pnp.sig: Enter checks it
check 'grep -q "Signed by alice, accepted at level 1." "$T/gtui.out"' \
    "interactive: in a group, s signs a file, and Enter on the signature checks it for another member"
gtui "$I/wa" "$I/a" 'p\rjj\rj\r\nqq' # p, the pair, Leave..., Yes
check 'ls "$I"/wa/leave-*.pnp-kill >/dev/null 2>&1 && grep -q "end of this pair is written" "$T/gtui.out"' \
    "interactive: leaving (ending a pair) from the groups screen writes the notice to send"

export PNP_TEST_HWRNG="$T/rng"
