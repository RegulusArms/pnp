# Groups: signatures and encrypted messages that stay secure if P = NP (design, not yet implemented)

Status: design for review. Nothing is built until the whole design is complete and the user has approved it. When it
is built, the formats move into docs/format.md.

A group of 3 or more people meets in person, each with their own laptop and a set of courier sticks. Code
cylinders stay at home (see "Cylinders and courier sticks"). At the meeting they swap two kinds of key material:

- **Signing keys**, so any member can sign a file and every other member can check it. See "Signatures".
- **Pads**, so members can send each other encrypted messages. See "Encrypted messages".

A message can be signed as well as encrypted. A signed message is proof the whole group accepts. An unsigned one is
deniable.

The key material comes in **key sets**, each valid for an agreed window (a week up to a year) or indefinitely. A
**roster** in every key says who can read what. Members can report a compromise with **kill notices**, which need
signatures from at least two members. `pnp --info` shows all of it. A **meeting wizard** in the TUI walks every
member through each step.

# Signatures

## What it gives

Afterwards any member can sign a file, and every other member can check the signature. Against an attacker with
unlimited computing power:

- **No forging.** A member, or several members working together, can't make a signature that another honest member
  accepts in someone else's name.
- **No repudiation.** A signer can't make a signature that one honest member accepts and the group later rejects.
- **Transferable.** If Bob accepts Alice's signature, he can pass it to Carol, and Carol accepts it too.

These hold only if all of the following hold, in the same way the four OTP rules must:

1. **Honest majority.** Fewer than half of the group cheat: with n people, at most ω cheat, where
   ω < n/2. Three people tolerate one cheater. Five tolerate two.
2. **Secret pairwise channels at setup.** Each transfer at the meeting happens between two people only, on a
   courier stick that only those two handle. The signer must never get hold of what one recipient gives another
   (see "Courier sticks").
3. **Truly random keys** from pnp's hardware RNG path. Each recipient's random split is made on that recipient's
   own machine.
4. **One message per slot.** Every signature uses up a slot of keys. A slot is never used twice.
5. **The group is fixed.** Only people at the meeting can verify. A newcomer needs a new meeting.

The signature can be checked only by group members. It isn't a public signature, and an outsider can't verify
it. That is the price of not relying on computational hardness.

## The scheme

pnp uses the scheme from R. Amiri, A. Abidin, P. Wallden, E. Andersson, "Efficient unconditionally secure
signatures using universal hashing", ACNS 2018, LNCS 10892, pp. 143-162 (open copy:
https://www.esat.kuleuven.be/cosic/publications/article-2892.pdf). Theorem numbers below refer to it. Every
source used here, and exactly what was taken from it, is in [research.md](research.md).

Why this one and not Hanaoka-Shikata-Zheng-Imai (ASIACRYPT 2000):

- **No trusted dealer.** HSZI needs a trusted authority that knows everyone's keys. Amiri et al. needs only
  pairwise secret channels and an honest majority. An in-person meeting gives exactly that.
- **Built from universal-hash MACs.** pnp already has one, constant-time and tested (src/mac.c).
- **Signature size doesn't grow with file size.** HSZI works in a field as large as the message.

Notation: one signer P0 and N recipients P1..PN (so n = N+1 people), at most ω cheaters, and
d_R = (ω−1)/N. Security parameter k.

### Setup, per signer, per slot (paper section 3.1)

1. The signer draws N²k random hash functions f_1..f_{N²k}.
2. The signer gives recipient P_i the block of Nk functions numbered (i−1)Nk+1 .. iNk.
3. P_i shuffles the positions of that block at random and splits them into N sets of k: R_{i→1} .. R_{i→N}. P_i
   keeps R_{i→i}, and gives each other recipient P_j the set R_{i→j} together with those functions.
4. P_j now holds N sets of k functions, one from each recipient (its own included), and knows the positions of
   each set.

The signer knows every function but not where any of them ended up. That is what stops repudiation: the signer
can't put bad tags only where one recipient will look.

### Signing and verifying (section 3.2)

- **Signature:** the tags of all N²k functions on the message: t_r = f_r(m).
- **Test:** for each of P_j's N sets (the one from P_i), count the mismatches between the signature's tags and
  P_j's own functions at those positions. The set passes at level l if mismatches < s_l·k.
- **Accept at level l:** P_j accepts at level l if more than N·δ_l sets pass, where δ_l = 1/2 + (l+1)·d_R.
- **Levels:** levels run from −1 (disputes only) to l_max, with thresholds 1/2 > s_{−1} > s_0 > … > s_{l_max}.
  Accepting at level l guarantees that every other honest member accepts at level l−1 or lower. pnp verifies at
  the highest level that passes and reports it.
- **Dispute:** the signature is valid if more than half of the recipients accept it at level −1 (Definition 6).
  pnp only computes each person's answer. Gathering the votes is up to the people.

### Bounds (Theorems 1-3), all made rigorous with union bounds (1−(1−p)^n ≤ np)

```
P(forge)              ≤ (N−ω)² · P[Bin(k, 1−ε) < s_0·k]
P(non-transfer at l)  ≤ N_p · (N(δ_l − d_R) + 1) · exp(−(s_{l−1} − s_l)²·k/2)     for l = 1..l_max
P(repudiation)        ≤ the same with l = 0
N_p = N(1−d_R)·(N(1−d_R) − 1) / 2
```

### pnp's hash family (ε-ASU₂, ε = 1/4 + L/p, 2-bit tags)

Each function is f(m) = A·h_K(m) ⊕ c, where:

- h_K is pnp's existing polynomial hash mod p = 2^127 − 1 (src/mac.c, the part before the pad is added) over the
  framed message. Its key K is uniform below p, and two different messages collide with probability at most L/p,
  where L is the number of 8-byte blocks.
- A is a random 2×127 bit matrix, applied to the 127-bit value as two parities (popcount(a ∧ x) mod 2).
- c is 2 random bits.

Why this works: for x ≠ x′, A·(x ⊕ x′) is uniform, and c makes each tag uniform on its own. So the second stage is
exactly strongly universal with ε = 1/4. Composing it with an L/p-almost-universal first stage gives
ε = 1/4 + L/p (Stinson's composition). For a 1 TiB file, L/p < 2^−90.

Each function takes 49 bytes: K (16), A (32), c (1).

Every function needs its own K. If a set of functions shared one K, the members who hold any of them would know K.
An unbounded attacker could then find a colliding message, and the tags of all functions sharing that K would
carry over. This is the main cost: every function makes its own pass over the file.

### Parameters

Defaults: l_max = 1 (one guaranteed hand-on, plus disputes), s = (0.49, 0.25, 0.01), each failure ≤ 2^−64,
ω = the largest the honest-majority rule allows. Computed with the bounds above (scratch script, to become
tests/uss_params.py):

| people | ω | k    | signature | signer's keys per slot | each recipient's keys per slot per signer |
|-------:|--:|-----:|----------:|-----------------------:|------------------------------------------:|
| 3      | 1 | 1600 | 1.6 KiB   | 306 KiB                | 166 KiB                                   |
| 4      | 1 | 1650 | 3.6 KiB   | 711 KiB                | 256 KiB                                   |
| 5      | 2 | 1650 | 6.4 KiB   | 1.2 MiB                | 342 KiB                                   |
| 7      | 3 | 1700 | 15 KiB    | 2.9 MiB                | 528 KiB                                   |
| 9      | 4 | 1750 | 27 KiB    | 5.2 MiB                | 725 KiB                                   |

k barely depends on ω. It depends mostly on the gaps between the s_l, so each extra level of l_max roughly
doubles k.

Cylinder space per person, per key set, for ψ slots each (everyone signs): ψ × (signer column + (n−1) × recipient column). For
1000 signatures each: about 640 MiB per person with 3 people, 2.6 GiB with 5, and 11 GiB with 9.

Time: one polynomial pass per function, measured at 2.9 ms per MiB per function on the dev machine. Signing
1 MiB with 3 people (6400 functions) takes 19 s on one core, or about 0.6 s on 32 threads. Verifying takes half
that. With 5 people it's 4× more. This is for documents, contracts and keys. It isn't practical for
multi-gigabyte files.

# Encrypted messages

## What it gives

- **Secrecy against an unbounded attacker:** each message is OTP-encrypted with pad bytes used once, as pnp does
  now.
- **Integrity and sender authentication:** pnp's one-time MAC, with its key drawn from the same pool. Only the
  pool's holders could have made the message.
- **Forward secrecy:** both sides wipe the pad bytes after use. A cylinder stolen later can't decrypt old
  ciphertexts, because the key no longer exists anywhere.
- **A choice between proof and deniability:**
  - **Unsigned:** the recipient knows who sent it but can't prove it, because they hold the same pad and could have
    written it themselves.
  - **Signed:** the recipient can show it to the group, and the sender can't deny it.
- **Not hidden:** the fact that a pair talks, when, and roughly how much. The pool ID and length are in the clear.

## Pools (swapped at the meeting)

- **Pairwise pools (the default):** one per direction, A→B and B→A. Only the sender writes into a direction, so two
  people never use the same bytes. Both laptops contribute: pool = R_A ⊕ R_B, each R from that laptop's hardware
  RNG path. Neither machine controls the pool alone, the same rule as rng.c's combining. Each R travels on a
  courier stick, and pnp combines them at import.
- **The group pool (optional):** one pool held by every member, for messages to the whole group. It's split into
  one region per sender, so senders never collide. Every member contributes (XOR of all). Every member can make its
  MAC, so **group-pool messages must be signed.** The MAC only keeps outsiders out.
- **Sizes:** pools are as big as the messages they'll carry, plus 32 bytes of MAC key per message. With 1 GiB per
  direction, each person stores 2·(n−1) GiB: 4 GiB with 3 people, 8 GiB with 5.

## Sending: sign, then encrypt

1. **Frame:** `"PNPGM001" || group ID || from || to-list || message ID (16 random bytes) || u64 length || m`. The
   sender's and recipients' names go inside what's signed and what's encrypted. That stops surreptitious
   forwarding: B decrypting A's signed message and re-encrypting it to Carol, who would then believe A wrote it to
   her (Davis 2001, §1.1). Signing the recipient's name and encrypting the sender's name are the naming repairs in
   Davis §3.2. See research.md.
2. **Sign** the frame, if it's signed (always for the group pool, `--sign` for pairwise). This uses one signing
   slot.
3. **Encrypt** frame (+ signature) with the next pool bytes. The key material is laid out as now: a 32-byte MAC
   key, then pad as long as the data. The MAC covers header || plaintext as in format 002.
4. **Burn the pool range before releasing the message:** advance the pool's counter, wipe those bytes, and fsync.
   Then commit the message file.

It must be sign-then-encrypt, never encrypt-then-sign. A signature on the ciphertext proves nothing about the
content: B could reveal a made-up "pad" that turns the ciphertext into any text at all. Davis §1.2 gives the
computational version of the same warning.

## Receiving

1. Find the pool by its ID. **Refuse** it if the key set is killed, or if the receiver's clock is outside its window
   plus the grace days. **Refuse** a range that overlaps one already used: a replay, or the sender reusing pad.
2. Check the MAC as now. If it fails, nothing is written.
3. Decrypt. Check the frame matches the pool: "from" is the pool direction's owner, or the region's owner in the
   group pool; this member is on the to-list; the group ID is right.
4. If it's signed, verify the signature. Its signer must equal "from". Say the level it was accepted at.
5. Record the range in `used`, wipe those pad bytes, and commit the plaintext. A signed message's frame and
   signature are kept with it as `FILE.pnp.sig`, so it can be passed on.

The message file's layout is under "Files". The offset is in pool bytes, so messages can arrive in any order.

# Groups, key sets and validity windows

## The roster

Every group file carries the roster, so "who can read this" always comes from the key itself, never from memory:

- **Group:** the group ID (16 random bytes) and the group name.
- **Members:** index and name for each member, and which index is "me".
- **Agreed settings:** time zone, grace days, kill threshold.

Each key file also says what it is for:

- **Signing:** "your signing keys for group X, key set 2030-05".
- **Verify:** "Alice's signatures, checkable by all 5 members".
- **Pool:** "messages Alice → Bob, readable by Alice and Bob only".
- **Group pool:** "readable by all 5 members".

**Anonymous groups**, chosen at the meeting:

- **On the roster:** only a generic name derived from the group ID ("Group 7F3A") and numbers ("Member 1…5, you
  are 3"). Real names never go on any key or courier stick.
- **Nicknames:** each member may keep private nicknames ("3 = Carol") in a local file that's never shared.
- **In messages:** the from and to fields are numbers too.
- **The meeting date** is stored as a month, or not at all.
- **The limit, stated in the docs:** cylinders seized together still show they hold the same group ID. Anonymous
  hides *who*, not *that*.

The wizard asks named or anonymous on its first screen, with no default, so the group decides it consciously.

## Key sets

A meeting makes one or more **key sets**. A key set is everything the group uses during one period: signing slots,
verify keys, pairwise pools and the group pool. Each has its own 16-byte ID, its own amounts (signatures and pool
size per member), and a **validity window**:

- **A period:** one week, month, quarter or year, starting on a date. The wizard can make a series in one meeting,
  for example the 12 months of 2030, each a separate key set.
- **Indefinite:** no window. It's valid until its slots or pool run out, and then the group meets again. The
  wizard points out that one stolen cylinder then exposes everything unused in it.

Windows use the time zone agreed in the roster (UTC by default), so "May" means the same thing on every laptop.

## How windows are enforced (a group policy, enforced by honest members' clocks)

- **Sending:** pnp refuses to sign or encrypt with a key set outside its window. A future set isn't valid yet, so
  June's keys can't be used in May by mistake.
- **Receiving:** pnp accepts a signature or message only while **the receiver's own clock** is inside the window
  plus the grace days agreed for delivery (for example 3). The date written inside a message is only the sender's
  claim. A thief who steals May's keys in July and writes "sent 15 May" is still refused by every honest member.
- **Afterwards:** a message accepted during its window stays valid evidence. `--verify-sig` still checks it, and
  says "key set 2030-05, window closed: only messages received during the window count". Disputes still go to a
  majority vote.
- **When a window closes:** the next run of pnp wipes the set's unused signing slots and pad on every member's
  cylinder. Leftover pad is wasted, but it can no longer leak. Verify keys are kept for disputes, until an
  optional dispute period agreed at the meeting ends.
- **Clock guard:** each cylinder records the latest date pnp has seen, to the day. If the clock goes back before
  that date, pnp warns and refuses until the user confirms. This catches a dead CMOS battery or a mistaken clock
  change. A thief is stopped by the receiver's check above, not by this. The stored date is metadata (roughly when
  pnp was last used), and the docs say so.

pnp has no network, so it can't know the true date. Windows don't change the cryptography. They limit how long a
stolen key is useful, and the docs say exactly that.

# Kill notices

Any member can report that keys are compromised (a stolen cylinder, a laptop found tampered with). It takes
signatures from **at least two different members** to kill keys. That number is the **kill threshold**, agreed at
the meeting: 2 by default, up to a majority.

## The emergency key set

A kill notice must not be signed with the keys it reports as compromised. The person most likely to send one has
just lost their cylinder. So each meeting also makes an **emergency key set**:

- A few signing slots per member (default 8), used only for kill notices.
- **No window:** a kill must work at any time.
- **Stored twice:** in the group on the cylinder, and on a separate **kill card**. The kill card is a small
  raw-format stick (like a courier stick), kept apart from the cylinder.
- **If you lost both,** two other members can send the kill without you. Tell them by phone or in person.

## The notice

```
"PNPKL001" || group ID || notice ID (16 random) || scope || suspect since (optional) || reason (optional)
followed by one or more signatures over that frame, each from a different member's emergency slot
```

- **Scope** is one of: one or more key sets; everything that was on one member's cylinder (the wizard asks "what
  was on it?"); one pool; or the whole group.
- **Suspect since** is a date, or a member + slot ("Alice's signatures from slot 413 on"). It lets members check
  messages they already accepted.
- **Making one:** the first member makes the notice. Others add their signature to the same file, in any order.

## What receiving one does

- **Fewer valid signatures than the threshold:** a **warning** on every group action, for example "Alice reports
  key set 2030-05 compromised; waiting for a second member to confirm". Nothing is killed yet.
- **The threshold reached** (distinct members, each signature valid): pnp **kills** the scope at once.
  - It stops sending and receiving with it.
  - It wipes its unused slots and pad.
  - It flags every message accepted from it after "suspect since".
  - It keeps verify keys only for disputes.
- **A kill is final.** There's no un-kill. Recovery means using the next period's key set, if it wasn't on the lost
  cylinder, or meeting again.
- **A thief or one cheater** holding one member's emergency keys can only raise a warning. Killing needs the
  threshold. Nobody can forge a notice, because it uses the same signatures as everything else.

## How a kill spreads (no network)

- **Readable without a pad:** the notice is signed plaintext. It isn't encrypted with a pool that may itself be
  compromised. It reveals to outsiders only that "group 7F3A had a compromise".
- **Checked first:** before any sign, send, receive or `--info`, pnp looks for `*.pnp-kill` files in the group's
  folder and the current folder.
- **Passed on:** once a member's pnp knows a notice, it attaches it inside every message that member sends on
  pools that aren't killed. The receiver's pnp learns it and passes it on too. Anyone who receives *anything* from
  a member who knows also learns of it.
- `--info` shows kills and pending warnings first, in red.

# Cylinders and courier sticks

## Code cylinders: only into machines under your full control

- **Where it goes:** a code cylinder is plugged into a machine only if you fully control that machine, and it
  **never comes to a meeting**. Any computer it's plugged into can copy whatever is unlocked, corrupt its LUKS
  header, or leave a malicious filesystem for your kernel to parse later.
- **Several cylinders by trust level:** the docs advise keeping more than one, for example:
  - **daily:** the current period of everyday groups, used on your own laptop.
  - **vault:** future periods and kill cards, kept somewhere safe and opened only when you're alone.
  - **one per high-trust group,** so that losing one cylinder never exposes another group.
- **One LUKS2 volume per cylinder,** as docs/code-cylinder.md already advises (computational, a second lock on top
  of physical custody).
- **Trust labels:** pnp's existing drive identity file ($XDG_STATE_HOME/pnp/drives) gets an optional trust label
  per cylinder. `--info` shows it, and `--import` and `--move` ask for the destination by label.

## Courier sticks

All transfers at a meeting use **courier sticks**. Each member brings one cheap USB stick for each other member,
plus one "self" stick for their own material, all prepared beforehand.

- **Raw, no filesystem.** A courier stick holds one GPT partition with pnp's own partition type GUID, and inside it
  pnp's own simple record format. Desktops don't auto-mount it, and the kernel never parses a filesystem that a
  foreign laptop shaped. pnp reads it with a parser that's fuzzed like the header parsers.
- **Permissions:** a udev rule gives the `pnp` group read and write access to partitions of that type, as
  60-pnp-hwrng.rules does for /dev/hwrng. pnp still never needs root.
- **Preparation:** `pnp-courier-setup DEVICE` is a short script run once per stick with sudo. It wipes the stick,
  makes the partition (sgdisk), and writes the courier header. gdisk goes in the .deb's `Suggests:`.
- **Header:** `"PNPCR001"`, the owner, and who it's for ("Alice → for Bob"), set when the group is created at the
  meeting. pnp refuses to write to a stick not addressed to this laptop's member. That catches mixed-up sticks. The
  sticks carry physical labels too.
- **Records:** type, from, to, key set ID, length, data, and a BLAKE2b checksum. The checksum only catches
  accidents (a bad stick or a bad copy). Security comes from custody: a stick only ever passes between its owner
  and one other member.
- **Custody:** Alice's stick for Bob goes from Alice to Bob's laptop and straight back to Alice. Nobody else's
  laptop ever sees it. This is the "secret pairwise channel" the signature scheme needs. In particular, the signer
  of a set of functions never handles a stick that carries a split of them.
- **Afterwards:** keep each stick with the vault or destroy it. Overwriting flash isn't a reliable erase (wear
  levelling keeps old copies), the same caveat the docs give for shredding.

# The meeting wizard

Everyone brings **their own laptop** (under their full control, with a hardware RNG) and their courier sticks.
Nobody brings a cylinder. pnp keeps key material in mlocked memory and on the sticks only, never on the laptop's
disk. Every laptop runs the wizard, and the group moves through it together. Nothing secret is ever shown on
screen, so people may watch each other's screens. What matters is who handles which stick.

1. **Roster.**
   - One laptop creates the group: the ID, the name (or anonymous), the time zone, the grace days, the kill
     threshold, and the key sets (periods and amounts, or indefinite).
   - The others type in the group ID and the same settings.
   - Each screen shows a **check code**: 8 characters of a BLAKE2b hash of the roster and settings. Everyone reads
     theirs aloud, and they must all match. This only catches typos and a wrong member order. It isn't a security
     feature; being there in person is.
   - Each laptop writes the courier headers onto its own sticks.
2. **Round 1.** Each stick goes to the member it's for, whose laptop writes:
   - its signer blocks for the stick's owner (every key set, plus the emergency set);
   - its pool randomness for the pair (R for both directions, every key set);
   - its group pool contribution.

   The stick then goes straight back to its owner. Each laptop also writes its own signer files and its own R
   values onto its self stick.
3. **Round 2.** Each laptop now has, on its returned sticks, the blocks every other signer made for it. For each
   signer, key set and slot, it makes the random split, using **its own hardware RNG**. The sticks go out again,
   and each member's laptop writes:
   - its splits for the stick's owner;
   - a test signature from its first slot of each key set (that slot is given up);
   - a short test message on its pool to the owner.

   R_{i→i}, the part each member keeps, goes onto the self stick.
4. **Check.** With round 2 back, each laptop combines everything in memory and verifies every test signature and
   test message. It shows a ✓ grid: every signer × every verifier, and every pool direction. A failed cell names
   the sticks to redo. Nothing is left half-written under a real name.
5. **Kill cards.** Each laptop writes the member's emergency slots onto their kill card stick, and reminds them to
   keep it apart from their cylinders.

Rounds 1 and 2 each pass n−1 sticks out and back per person, all in parallel. The wizard shows who is holding what
("waiting for your stick from Carol").

## At home, alone: import

- **Import:** `pnp --import`, or the TUI's "Import from a meeting", reads the self stick and the returned sticks,
  checks them against the check code, and combines them: pool = R_A ⊕ R_B, and the verify files from the splits.
  It writes the group onto the cylinder you choose, by trust label (atomic: part files, then rename, as now).
- **Placing key sets:** the wizard suggests the current period on the daily cylinder and future periods on the
  vault. `pnp --move KEYSET --to LABEL` moves one later. pnp refuses to move a set that's already been killed.
- **The sticks:** pnp offers to overwrite them. The docs still say to keep them with the vault or destroy them.

**Later top-ups without meeting again (optional, later):** new key sets can travel as pnp-encrypted files over any
medium, with a pairwise pool as the secret channel. Each top-up uses as much pool as it carries, so pools can't
grow this way, only be turned into signing slots.

# Key info: `pnp --info`

`pnp --info FILE|DIR|DEVICE` works for **every** pnp key type: today's .pnp.key, shares, protected keys, group
folders, courier sticks and kill cards. It reads only headers and counters, never secrets, and keeps no activity
log.

```
Group "Field team" · 5 members · you: Carol (3) · kill threshold 2 · cylinder "daily"
!! Alice reports key set 2030-05 compromised: waiting for a second member
Key set 2030-05  valid 2030-05-01 → 2030-05-31 (UTC, +3 days delivery) · 12 days left
  Signing   412 of 1000 used
  Pools     → Alice 1.2 of 2 GiB · ← Alice 0.3 GiB received · → group 40 of 500 MiB (your region)
  Readable  pool → Alice: Carol, Alice · group pool: all 5 · your signatures: checkable by all 5
Key set 2030-06  on this cylinder (not valid yet) · 2030-07..12 not here (vault?)
Closed: 2030-04 used 37 of 1000 signatures, 0.2 GiB of pools · Emergency: 8 slots left
```

On a courier stick it lists what's there: records, from and to, and key sets. That's useful during the meeting.

# Files (in each member's cylinder, `pnp-group-<ID>/`)

```
group                 magic PNPGR001: roster (group ID, name or anonymous, members, my index, time zone, grace days,
                      kill threshold, dispute period), the list of key sets with their windows, the clock guard date
names.local           optional private nicknames, never shared (anonymous groups)
set-<KSID>/sign       magic PNPSG001, key set ID, my index, ψ, next-slot counter, then ψ × N²k functions (49 bytes)
set-<KSID>/verify.<j> magic PNPVF001, key set ID, signer j, ψ, then per slot: N sets × k × (u32 position + function)
set-<KSID>/used.<j>   slots of signer j already seen, with the message's ID: catches a slot used twice
set-<KSID>/pool.<a>-<b>  magic PNPPL001, pool ID, from a to b, size, next-offset counter, then pad (wiped as used)
set-<KSID>/pool.group the group pool: per-sender regions and counters
set-<KSID>/pool.used  ranges received per incoming pool: catches replays and reused pad
emergency/            the emergency key set (sign, verify.<j>, used.<j>), no window
kills/                notices received, with their state (warning, killed)
FILE.pnp.sig          magic PNPUS001, key set ID, signer index, slot (u32), k (u32), then N²k tags, 4 per byte
FILE.pnp              magic PNPGM001, key set ID, pool ID, offset (u64), length (u64), ciphertext, 16-byte tag
FILE.pnp-kill         magic PNPKL001, the notice frame, then its signatures
```

The framed message each signature function hashes is
`"PNPUS001" || key set ID || signer || slot || u64 length || file bytes`. This binds the signature to its key set,
signer and slot. The key set ID identifies the group through the group file.

# Commands (sketch)

```
pnp                                    TUI: meeting wizard, import, sign, verify, send, receive, kill, info
pnp --sign FILE [--group G]            → FILE.pnp.sig (the current key set's next slot)
pnp --verify-sig FILE [SIG]            → "signed by Alice, accepted at level 1 (key set 2030-05, slot 17)"
pnp --verify-sig FILE --level -1       the dispute check: one person's vote
pnp --send FILE --to bob [--sign]      → FILE.pnp from the me→bob pool (unsigned: deniable)
pnp --send FILE --to group             → FILE.pnp from my region of the group pool (always signed)
pnp FILE.pnp                           a group message: checks, decrypts, verifies, wipes the pad
pnp --kill SCOPE [--since …]           makes a kill notice (emergency slot) → FILE.pnp-kill
pnp --kill-sign FILE.pnp-kill          adds my signature to someone's notice
pnp --import / --move KEYSET --to L    after the meeting, alone
pnp --info FILE|DIR|DEVICE             key info, for every pnp key type
pnp-courier-setup DEVICE               (sudo) prepare a courier stick or kill card
```

# Rules (never weaken)

- **Burn the slot before releasing the signature.** On signing, overwrite the slot's functions in `sign`, advance
  the counter, and fsync before writing the .sig.
- **Never back up `sign` or a pool, and never restore one.** Restoring rolls the counter back and reuses slots or
  pad. A slot used twice lets recipients forge in the signer's name. Pad used twice leaks both messages.
  (`--shares` may split them across drives.)
- **Recipients keep their verify keys** for disputes, until the dispute period ends.
- **Refuse with no slots or pad left.** Say "meet again".
- **The split randomness comes from the recipient's own hardware RNG,** never from the signer's machine.
- **Courier custody:** a stick only ever passes between its owner and the one member it's for. Cylinders never go
  to meetings, and are plugged only into machines under the owner's full control.
- **Windows:** send only inside the window, and receive only while the receiver's own clock is inside the window
  plus the grace days. Wipe unused slots and pad when a window closes.
- **Kills:** fewer signatures than the threshold only warn. Reaching the threshold kills for good. Check for
  notices before every group action, and pass them on in every message.
- **Never encrypt-then-sign.** Names go inside both the signature and the encryption.
- **Group-pool messages are always signed.**
- **No activity log.** Counters and the clock guard date only.
- **Constant-time comparison isn't needed for tags,** because they're public once released. Key handling follows
  the usual rules: mlock, wipe, 0600.
- **Docs say what it isn't:** members only, a fixed group, honest majority, limited slots, windows enforced by
  clocks, and anonymity that hides who but not that.

# Implementation stages (each finished and confirmed before the next, once the design is approved)

1. **Hash family** `src/uss.c`: the function and tag code, with tests against an independent Python check, and a test
   that it is exactly uniform over all A and c for small cases. Parameter calculator and its test.
2. **Formats and storage:** the group, key set, sign, verify, used, pool, sig, message and kill files, with header
   parsing in format.c and fuzz targets.
3. **Signatures:** CLI `--sign` / `--verify-sig` / dispute level, with windows and the clock guard, using a group
   made by a test-only setup command.
4. **Pools and messages:** `--send`, receiving, the replay and used-range checks, and crash tests (a crash at any write
   must never let pad or a slot be reused).
5. **Kill notices:** the emergency set, `--kill`, `--kill-sign`, the threshold, spreading.
6. **Courier sticks:** the raw format, its fuzzed parser, the udev rule, `pnp-courier-setup`, `--import`, `--move`.
7. **`--info`** for every key type.
8. **The TUI meeting wizard,** with the custody prompts.
9. **Docs:** README section, man page, threat-model.md, format.md, code-cylinder.md (several cylinders by trust level,
   courier sticks), and the site's P = NP page.

# Open decisions

- Group size cap (9? 16?) and the default amounts per key set (signatures, pool size).
- l_max: default 1. Is l_max = 2 wanted (twice the key size)?
- Kill threshold: settable at the meeting, from 2 up to a majority, or always 2?
- A kill warning (below the threshold): warn only, or stop sending automatically until it's resolved?
- Default grace days for delivery (3?) and the default dispute period.
- Courier sticks: one per other member (strict), or one per person, overwritten between members (cheaper, but the
  flash chip may keep remnants)?
- Named or anonymous: an explicit choice with no default (proposed), or anonymous by default?
- Whether the later top-ups over pairwise pools are in the first version.
- Whether the group pool is in the first version.
- Unsigned pairwise messages as the default (deniable), or signed by default?
- Hiding which pair is talking: pool IDs in the clear for now, or a later version.
- 2^61 − 1 instead of 2^127 − 1 for the first stage: about 3-4× faster with ε still ≈ 1/4. It's a second field to
  audit, though, so the default is to reuse mac.c.
