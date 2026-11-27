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
2. **Secret pairwise channels at setup.** Each transfer at the meeting happens between two people only. The signer
   must never get hold of what one recipient gives another (see "Courier sticks"). Courier sticks are reused
   between members (decision 8), so this rests on a **physical assumption**: no member reads flash below the USB
   interface (vendor debug commands, or desoldering the chip) during the minutes they hold another member's
   stick. A group that won't rely on that uses strict mode, with one stick per pair.
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

ω and l_max trade against each other. The paper allows a combination only if (l_max + 1)·d_R < 1/2, with
d_R = (ω−1)/N, so tolerating more cheaters leaves room for fewer guaranteed hand-ons.

**Decided default:** the largest ω the honest-majority rule allows, then the largest l_max that ω leaves room for.
The wizard also shows the other choice (fewer cheaters tolerated, more hand-ons) with its cost, and the group may
pick it instead.

The thresholds s_{−1} > … > s_{l_max} are spaced evenly from 0.49 down to 0.01, and each failure probability is
≤ 2^−64. The numbers below were computed with the bounds above (scratch script, to become tests/uss_params.py):

| people | ω | l_max | k    | signature | signer's keys per slot | each recipient's, per slot per signer | per person, 1000 signatures each |
|-------:|--:|------:|-----:|----------:|-----------------------:|---------------------------------------:|---------------------------------:|
| 3      | 1 | 1     | 1600 | 1.6 KiB   | 306 KiB                | 166 KiB                                | 0.6 GiB                          |
| 4      | 1 | 1     | 1650 | 3.6 KiB   | 711 KiB                | 256 KiB                                | 1.4 GiB                          |
| 5      | 2 | 0     | 450  | 1.8 KiB   | 345 KiB                | 93 KiB                                 | 0.7 GiB                          |
| 6      | 2 | 1     | 1700 | 10.4 KiB  | 2.0 MiB                | 440 KiB                                | 4.0 GiB                          |
| 7      | 3 | 0     | 450  | 4.0 KiB   | 775 KiB                | 140 KiB                                | 1.5 GiB                          |
| 8      | 3 | 0     | 450  | 5.4 KiB   | 1.0 MiB                | 163 KiB                                | 2.1 GiB                          |
| 9      | 4 | 0     | 450  | 7.0 KiB   | 1.35 MiB               | 186 KiB                                | 2.7 GiB                          |

The alternatives the wizard shows: 1 hand-on at 5 people needs ω=1 (2.5 GiB); at 7 and 9 people it needs ω=2
(5.8 and 10.6 GiB). Each extra level of l_max roughly doubles k, and k barely depends on ω.

**What l_max means in practice.** An honest signer's signature is exact: zero mismatches for every member, at
every level. Levels only matter against a cheating signer (with up to ω−1 colluding recipients) who makes a
borderline signature, so that one member accepts it and another rejects it.

- **l_max = 0:** a signature one honest member accepts is guaranteed to be upheld by a group dispute vote, so it
  can't be denied. Another member's ordinary check might still reject a borderline one, and that member then takes
  it to the group.
- **l_max = 1:** the next member's ordinary check is also guaranteed to accept it.

**Inexact signatures are flagged.** Since honest signatures always have zero mismatches, pnp reports any
signature with mismatches, even an accepted one, as "accepted, not exact: someone tampered with it (the signer or
another member); raise it with the group". A cheating signer's borderline signature exposes them.

**Group size:** the wizard offers 3-9 people as choices. A larger number is typed in by hand, and pnp shows a
warning with the storage per person and the number of stick handoffs. Storage grows roughly with the square of the
group size, but what is too much today may be small in ten years, so there's no hard cap below the format's limit
of 255 members (one-byte index).

**Amounts per key set (decided):** the wizard asks how many signed messages each person expects to send, and how
much data each expects to send each member. It suggests starting values scaled to the period (for a month: 200
signatures and 256 MiB per direction; the emergency set: 8 slots each). It shows the total storage per person,
and per cylinder if daily and vault are split, before anything is made.

Time: one polynomial pass per function (the signer computes N²k, each verifier Nk), measured at 2.9 ms per MiB
per function on the dev machine. With the defaults, signing 1 MiB takes 19 s on one core with 3 people (6400
functions), about the same with 5 people (7200), and 84 s with 9 people (28,800). On 32 threads that's 0.6-2.6 s.
Verifying takes 1/N of that. This is for documents, contracts and keys. It isn't practical for
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
- **Unlinkable headers:** a message's header is a one-time random locator, so an outsider can't tell which group,
  pair or period it belongs to, or link two messages together, whatever their computing power. **Not hidden:**
  the file's size, and when it is sent.

## Message headers reveal nothing (decision 13)

Each pairwise pool has a small **locator area** next to its pad. It holds one 24-byte entry per message the pool
can carry: a 16-byte locator and an 8-byte offset mask, all random from the meeting.

- **Sending:** message i of a pool starts with locator i, then its pad offset XORed with mask i. Then come the
  ciphertext and the tag. Both are used once, like pad.
- **Receiving:** pnp keeps a lookahead table holding the next 16 unused locators of every incoming pool. That's
  enough for messages that arrive out of order. A message's first 16 bytes are looked up in it: a hit names the
  pool and the message number, and the mask reveals the offset. A miss means "not for me, or too far ahead":
  `--lookahead N` widens the table.
- **To an outsider,** every header is 16 random bytes that never repeat. Nothing names the group, the key set, the
  pair or the period, and no two messages can be linked by their headers.
- **The cost** is 24 bytes of pool per message. The wizard sizes the locator area from the expected number of
  messages.
- **Standalone signatures and kill notices aren't hidden.** A `.pnp.sig` file names its key set and signer, and a
  kill notice names its group. To keep a signature private, send it inside a message.

## Pools (swapped at the meeting)

- **Pairwise pools (the default):** one per direction, A→B and B→A. Only the sender writes into a direction, so two
  people never use the same bytes. Both laptops contribute: pool = R_A ⊕ R_B, each R from that laptop's hardware
  RNG path. Neither machine controls the pool alone, the same rule as rng.c's combining. Each R travels on a
  courier stick, and pnp combines them at import.
- **The group pool (later version, decision 11):** one pool held by every member, for messages to the whole group. It's split into
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
2. **Sign** the frame, if it's signed: always in a signed-by-default group, otherwise with `--sign` (decision 12). This uses one signing
   slot.
3. **Encrypt** frame (+ signature) with the next pool bytes. The key material is laid out as now: a 32-byte MAC
   key, then pad as long as the data. The MAC covers header || plaintext as in format 002.
4. **Burn the pool range before releasing the message:** advance the pool's counter, wipe those bytes, and fsync.
   Then commit the message file.

It must be sign-then-encrypt, never encrypt-then-sign. A signature on the ciphertext proves nothing about the
content: B could reveal a made-up "pad" that turns the ciphertext into any text at all. Davis §1.2 gives the
computational version of the same warning.

## Receiving

1. Find the pool by looking up the locator. **Refuse** the message if its key set is killed, or if the receiver's clock is outside its window
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
the meeting: 2 by default, up to n − ω (the honest members), so cheaters can't block a real kill.

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
  key set 2030-05 compromised; waiting for a second member to confirm". Every send or sign with the reported keys
  asks "send anyway? [y/N]", and the CLI refuses without `--despite-warning`. Received messages are labelled.
  Nothing is killed or wiped yet.
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

All transfers at a meeting use **courier sticks**. Each member brings **one courier stick**, which visits every
other member in turn and is overwritten between visits (decision 8). Each member also brings a **self stick**,
which never leaves its owner and collects everything the courier brings back. Both are prepared beforehand. In
**strict mode**, offered in the wizard, each member brings one courier stick per other member, tied to that pair
for good, and nothing is overwritten between members.

- **Raw, no filesystem.** A courier stick holds one GPT partition with pnp's own partition type GUID, and inside it
  pnp's own simple record format. Desktops don't auto-mount it, and the kernel never parses a filesystem that a
  foreign laptop shaped. pnp reads it with a parser that's fuzzed like the header parsers.
- **Permissions:** a udev rule gives the `pnp` group read and write access to partitions of that type, as
  60-pnp-hwrng.rules does for /dev/hwrng. pnp still never needs root.
- **Preparation:** `pnp-courier-setup DEVICE` is a short script run once per stick with sudo. It wipes the stick,
  makes the partition (sgdisk), and writes the courier header. gdisk goes in the .deb's `Suggests:`.
- **Header:** `"PNPCR001"`, the owner, and the member it's currently visiting ("Alice's courier, now for Bob"),
  set by the owner's laptop before each visit. pnp refuses to write to a stick not addressed to this laptop's
  member. That catches mix-ups. The sticks carry physical labels with the owner's name too.
- **Sized small:** the courier partition is made only as large as the largest single transfer, not the whole
  stick, so overwriting it between visits takes seconds to a minute or two.
- **Between visits:** the owner's laptop copies the returned data onto the self stick and checks it. Then it
  overwrites the whole courier partition with fresh random data and **reads every block back** to confirm the
  overwrite happened. A stick that ignores writes or fakes its capacity is refused, and `pnp-courier-setup` tests
  real capacity when the stick is first set up, like the f3 tool.
- **Records:** type, from, to, key set ID, length, data, and a BLAKE2b checksum. The checksum only catches
  accidents (a bad stick or a bad copy). Security comes from custody: a stick only ever passes between its owner
  and one other member.
- **Custody:** on each visit, Alice's courier goes from Alice to one member's laptop and straight back to Alice.
  What that member wrote is moved off and overwritten before the next member gets the stick. This is the "secret
  pairwise channel" the signature scheme needs: the signer of a set of functions must never read a split of them.
  With a reused stick, that holds only under the physical assumption above. In strict mode it holds outright.
- **Afterwards:** keep each stick with the vault or destroy it. Overwriting flash isn't a reliable erase (wear
  levelling keeps old copies), the same caveat the docs give for shredding.

# The meeting wizard

Everyone brings **their own laptop** (under their full control, with a hardware RNG) and their courier and self
sticks. Nobody brings a cylinder. pnp keeps key material in mlocked memory and on the sticks only, never on the laptop's
disk. Every laptop runs the wizard, and the group moves through it together. Nothing secret is ever shown on
screen, so people may watch each other's screens. What matters is who handles which stick.

1. **Roster.**
   - One laptop creates the group: the ID, the name (or anonymous), the time zone, the grace days, the kill
     threshold, and the key sets (periods and amounts, or indefinite).
   - The others type in the group ID and the same settings.
   - Each screen shows a **check code**: 8 characters of a BLAKE2b hash of the roster and settings. Everyone reads
     theirs aloud, and they must all match. This only catches typos and a wrong member order. It isn't a security
     feature; being there in person is.
   - Each laptop checks its own courier and self stick, and makes the rotation schedule.
2. **Round 1** (rotation: each courier visits every other member once). The visited member's laptop writes:
   - its signer blocks for the stick's owner (every key set, plus the emergency set);
   - its pool randomness for the pair (R for both directions, every key set);
   - its group pool contribution (later version).

   After each visit the stick goes straight back to its owner, whose laptop moves the data onto the self stick,
   then overwrites the courier and reads it back before the next visit. Each laptop also writes its own signer
   files and its own R values onto its self stick.
3. **Round 2.** Each laptop now has, on its self stick, the blocks every other signer made for it. For each
   signer, key set and slot, it makes the random split, using **its own hardware RNG**. The couriers rotate again,
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

Each round runs on a **rotation schedule**: at every step, each member's courier is at a different member's laptop.
A round takes n−1 steps, with every laptop busy at once, and between steps the owners move data off and overwrite.
The wizard shows each person where their courier goes next and whose courier they should be holding ("give your
courier to Carol; you should have Dave's").

## At home, alone: import

- **Import:** `pnp --import`, or the TUI's "Import from a meeting", reads the self stick, which holds everything,
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
set-<KSID>/pool.<a>-<b>  magic PNPPL001, pool ID, from a to b, size, counters, locator area, then pad (wiped as used)
set-<KSID>/pool.group the group pool, later version: per-sender regions and counters
set-<KSID>/pool.used  ranges received per incoming pool: catches replays and reused pad
emergency/            the emergency key set (sign, verify.<j>, used.<j>), no window
kills/                notices received, with their state (warning, killed)
FILE.pnp.sig          magic PNPUS001, key set ID, signer index, slot (u32), k (u32), then N²k tags, 4 per byte
FILE.pnp              locator (16), offset XOR mask (8), ciphertext, 16-byte tag (no magic: it would link messages)
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
pnp --send FILE --to group             → one message per member (group pool: later version)
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
- **Courier custody:** a courier goes from its owner to one member and straight back. Before its next visit, it's
  moved off, overwritten and read back. Never hand a stick on without the read-back passing. Cylinders never go
  to meetings, and are plugged only into machines under the owner's full control.
- **Windows:** send only inside the window, and receive only while the receiver's own clock is inside the window
  plus the grace days. Wipe unused slots and pad when a window closes.
- **Kills:** fewer signatures than the threshold only warn. Reaching the threshold kills for good. Check for
  notices before every group action, and pass them on in every message.
- **Never encrypt-then-sign.** Names go inside both the signature and the encryption.
- **Group-pool messages are always signed** (later version).
- **Message files carry no magic or IDs,** only the one-time locator.
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

# Decisions (walked through with the user, 2026-11-27)

1. **Group size:** the wizard offers 3-9 people. Above 9, the number is typed by hand and pnp shows a storage and
   handoff warning. There's no hard cap below 255.
2. **Amounts per key set:** the wizard asks the expected use, suggests values scaled to the period, and shows the
   storage cost first.
3. **Cheaters vs hand-ons:** default to the most cheaters tolerated, plus the most hand-ons that leaves room for.
   The wizard shows the alternative and its cost. pnp flags inexact signatures.
4. **Kill threshold:** set at the meeting from 2 up to n − ω (the honest members, so cheaters can't block a real
   kill), default 2.
5. **Below the threshold:** warn and ask each time. Every send or sign with the reported keys asks "send anyway?
   [y/N]", and the CLI refuses without `--despite-warning`. Messages received from the reported scope are labelled
   "received while a compromise report was pending". Nothing is wiped until the threshold is reached.
6. **Grace days:** set at the meeting, 0-30, default 3. The docs advise stopping sending near a window's end when
   delivery is slow.
7. **Dispute period:** verify keys are kept indefinitely by default. The group may set a period at the meeting
   (for example 1 year). When it ends, pnp wipes them, first saying which signatures stop being checkable.
8. **Courier sticks:** one per person, overwritten and read back between visits, on a rotation schedule. This
   rests on a stated physical assumption (no reading flash below the USB interface while holding a stick). Strict
   mode (one stick per pair) is offered in the wizard for groups that won't rely on it.
9. **Named or anonymous:** an explicit choice on the wizard's first screen, with no default.
10. **Top-ups without meeting again:** later, not in the first version.
11. **The group pool:** later, not in the first version. A message to everyone is sent separately on each pairwise
    pool.
12. **Signed or unsigned pairwise messages:** the group sets its default at the meeting, and the wizard suggests
    unsigned (deniable). `--sign` signs one message. In a signed-by-default group, every message is signed, and the
    wizard sizes the signature amounts to cover every message.
13. **Hiding which pair is talking:** in the first version, with one-time locators (see "Message headers reveal
    nothing"). Size and timing still show.
14. **Field:** keep mac.c's 2^127 − 1. 2^61 − 1 measured about 2.1× faster (1.33 against 2.86 ms per MiB per
    function, before constant-time hardening). That isn't enough to justify a second field to audit. It can be
    revisited later behind a format number.

# Open decisions

None left from the first walk-through. New ones get added here as the design is reviewed.
