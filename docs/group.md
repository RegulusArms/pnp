# Pairs and groups

People who meet in person can afterwards authenticate files and send each other encrypted messages, in a way that
stays secure even if P = NP.

- **A pair** (two people) gets **seals**: anyone else's forgery succeeds only with a tiny probability (below), but
  a seal proves nothing to anyone outside the pair.
- **A group** (3 or more) also gets **signatures**:
  - every other member can check them;
  - forging one, or denying one later, succeeds only with a tiny probability, under the assumptions below;
  - they can be passed on to another member.
- **Both** can send each other one-time-pad **messages**.

What makes this possible is the meeting: the key material is swapped by hand, so nothing rests on a problem being
hard to compute. The price is that only the people who were there can take part, and everything has a limited
supply. When it runs out, you meet again.

## What each one gives

| | Pair: seal | Group: signature | Message |
|---|---|---|---|
| A forgery by an outsider succeeds with probability at most | (L + 1) / (2^127 − 1) per attempt | 2^-64 | (L + 1) / (2^127 − 1) per attempt |
| A forgery by other members succeeds with probability at most | (the other person could make it) | 2^-64, if at most ω members collude | (the other person could make it) |
| Contents secret | (not encrypted) | (not encrypted) | yes: perfect secrecy (one-time pad) |
| The recipient can prove it to others | **no**: deniable | yes, to the group's members | only if signed |
| The signer can deny it later | yes (deniable) | only with probability at most 2^-64 | only if unsigned |
| Who can check it | the other person | every other member | the recipient |

L is the file's (or message's) length in 8-byte blocks: (L + 1) / (2^127 − 1) is about 2^-90 for a 1 TiB file.
These bounds hold whatever the attacker's computing power, even if P = NP. A signature's three failures (forgery,
repudiation, one honest member accepting what another rejects) are each at most 2^-64, the target pnp's
parameters are chosen for ("How it works"). The bounds hold only if:

1. **The keys are truly random.** They come from pnp's hardware sources, as for any pad.
2. **Nothing is used twice.** pnp uses up every slot and pad range before releasing anything, and never restores
   them. Never back up or restore a group folder's key files.
3. **For signatures, an honest majority:** fewer than half the group cheat. The exact number tolerated (ω) is set
   at the meeting and shown by `pnp --info`.
4. **Custody at the meeting:** a courier drive only ever passes between its owner and the member it's addressed
   to. With one courier per person, reused between members, pnp overwrites each courier and reads it back between
   visits, and this also assumes nobody recovers what that overwrite didn't reach while they hold the drive:
   - **on a spinning disk** (preferred), only sectors the disk itself has remapped, which normal reads don't reach;
   - **on flash** (USB sticks, SSDs), old copies that wear levelling keeps in the chip, reachable with vendor debug
     commands or by removing the chip.

Seals and messages need only the first two.

## Before the meeting

Each person brings:

- **Their own laptop:** one under their full control, with a hardware random source (`pnp --sources`).
- **Two external drives,** a courier and a self drive, prepared once:

  ```
  sudo pnp-courier-setup /dev/sdX      # erases the drive: one partition of pnp's own type, no filesystem
  pnp --courier-check /dev/sdX1        # writes the whole drive and reads it back: catches fake-capacity drives
  ```

  - **Prefer external spinning hard disks** (and among them CMR rather than SMR, "shingled", disks), especially for
    the courier. A spinning disk overwrites data in place, so pnp's overwrite between visits really removes the
    previous member's data, apart from sectors the disk has remapped after errors. Flash (USB sticks, SD cards,
    SSDs) uses wear levelling, which keeps old copies in the chip where an overwrite can't reach them. That
    widens the custody assumption above. An SMR disk buffers writes in a cache area and moves them later, which
    has a similar, smaller effect.
  - **Flash still works.** `pnp-courier-setup` says when a drive is flash, and the assumption is then the wider one.
  - **Size:** a few GB is plenty for most meetings. `--courier-check` writes the whole drive, which takes hours on a
    large disk, so a small or old disk is the practical choice. It's needed once per drive, not per meeting.
  - **No filesystem:** the drives have none, so nothing mounts them, and no kernel ever parses a filesystem someone
    else's laptop wrote. The `pnp` group can use them without root, through a udev rule installed with pnp (join it
    with `sudo usermod -aG pnp $USER`).
- **Optionally, a third drive for a kill card** (see "Kill notices"). A USB stick is fine for that: it's never
  reused between people.

**Nobody brings a code cylinder.** It stays at home and only ever goes into machines its owner fully controls.

## The meeting

Everyone runs the wizard on their own laptop: from the interactive mode (`pnp` alone, then `p`, "Start or join a
meeting", and choose your two drives), or directly:

```
pnp --meet --self /dev/sdX1 --courier /dev/sdY1
```

1. **The roster.** One person creates the group and answers the wizard's questions:
   - how many people;
   - **named or anonymous**, an explicit choice;
   - the names;
   - the key set periods (a week, month, quarter or year, several in a row, or indefinite);
   - how much each person expects to sign and send per period (the wizard shows the storage this needs);
   - for groups: cheaters tolerated, kill threshold, whether every message is signed, how long verify keys are kept;
   - grace days and time zone.

   Everyone else chooses "join" and types their number on the list. Each gives their courier to the creator, whose
   laptop writes the roster onto it. Everyone's screen then shows a **check code**, and everyone reads theirs
   aloud: they must all match.
2. **Two rounds of courier swaps.** The wizard says, step by step, whose courier to hand on and whose you'll get.
   Your laptop writes onto the courier it receives, you hand it straight back, and when your own courier returns
   your laptop moves its contents onto your self drive, overwrites it and reads it back. Each step is checked: a
   courier addressed to someone else is refused.
3. **The check.** Each laptop verifies a test signature and a test seal from every other member, in memory, and
   shows a ✓ for each.

Nothing secret is ever shown on screen, so people may watch each other's screens. What matters is who handles which
drive.

## At home, alone

```
pnp --import /dev/sdX1 /media/you/CYLINDER [--kill-card /dev/sdZ1]
```

This makes the group's folder on your cylinder and checks every test from the meeting again. Afterwards, overwrite
the self drive and courier, or keep them with your vault.

**Several cylinders by trust level** are a good idea:

- a **daily** one, for the current period of everyday groups;
- a **vault**, for future periods and kill cards, opened only when you're alone;
- **one per high-trust group**, so that losing one cylinder never exposes another group.

`pnp --move KEYSET --to /media/you/VAULT` moves a key set between them. `pnp --info` says which key sets are on
which cylinder.

## Daily use

```
pnp --seal FILE --to bob             → FILE.pnp.seal (40 bytes)       pairs (and any two group members)
pnp --check-seal FILE                "Sealed by alice. Only you and alice could have made this ..."
pnp --sign FILE                      → FILE.pnp.sig                    groups of 3 or more
pnp --verify-sig FILE                "Signed by alice, accepted at level 1."
pnp --send FILE --to bob [--sign]    → FILE.pnp (several: --to 2,3 or --to all)
pnp --receive FILE.pnp               the file, and FILE.pnp-signed (if signed: proof to show the group)
pnp --info                           what's left, who can read what, warnings
```

pnp finds your groups on mounted drives (`/media/$USER/*`); `--groups FOLDER` points it elsewhere, and
`--group NAME` picks one when you're in several.

In the interactive mode (`pnp` alone), the same actions are a key away:
- `s` on a file seals, signs or sends it.
- Enter on a seal, a signature or a message checks or receives it.
- `p` opens your groups: info, kill notices, leaving, meetings and imports.

- **A message's header** is a one-time random locator. It names no group, pair or key set, and no two messages
  share one. File size and timing still show.
- **A message names its sender and recipients** inside both the signature and the encryption. So a signed message
  passed on to someone else shows who it was originally sent to (Davis, 2001).
- **Messages arriving out of order** are found up to 16 items ahead; `--lookahead N` looks further.
- **A signature isn't exact** when any of its tags fails to match. An honest signer's signatures, checked with
  undamaged keys, are always exact,
  so pnp reports any other as "NOT EXACT: someone tampered with it", even when it's still accepted at a lower
  level. Raise it with the group.
- **`--level -1`** is your vote in a dispute. A signature is valid if more than half the members accept it at that
  level.

## Key sets and validity windows

Each key set is valid for its window, in the group's time zone.

- **Sending** is refused outside the window.
- **Receiving** is refused once the **receiver's own clock** is past the window plus the grace days. So a stolen
  key set is useless afterwards, whatever date a forger writes into a message.
- **When a window has closed,** the next run of pnp wipes the set's unused slots and pad.
- **Verify keys** are kept for disputes, unless the group set a dispute period.
- **The clock guard:** if the laptop's clock goes back before a day pnp has already seen, pnp stops until you
  confirm with `--clock-ok`.

Windows are a group policy enforced by honest members' clocks. pnp has no network, so it can't know the true date.

## Kill notices, leaving

- **Reporting a compromise:**
  - `pnp --kill group|member:M|sets:ID,... [--reason compromised|ended] [--since DATE|MEMBER:SLOT]` makes a notice,
    signed with an emergency slot (or the kill card: `--kill-card DEVICE`).
  - Others add their signature with `pnp --kill-sign FILE.pnp-kill`.
  - Below the group's **kill threshold** (2 by default), a notice only warns, and sending asks for
    `--despite-warning`. At the threshold it **kills, for good**: the keys stop working and their unused parts are
    wiped.
  - In a pair, either person can kill alone.
- **How notices spread:** pnp checks for notices in the group's `kills/` folder and the current folder before every
  action, and passes them on inside every message.
- **Leaving:** `pnp --leave` ends your own signing keys and pools, and only yours. The others carry on, warned that
  their tolerance for cheaters is now lower, until they meet again. You keep your verify keys unless you add
  `--wipe-verify`.
- **What a leave or kill can't do:** it can't take back what others already received.
- **Kill cards:** a kill card holds half of your emergency slots (the cylinder keeps the other half, so no slot is
  ever used twice). With it you can report a stolen cylinder without having the cylinder.

## Limits

- **Only members can check.** A seal or signature isn't a public signature. Only the people at the meeting can check
  it.
- **The group is fixed.** Newcomers join at a new meeting.
- **Supplies run out.** Seals, signatures and pad are limited, and pnp says "meet again" when they run out.
- **Speed:** every hash function makes its own pass over the file, so a signature costs time in proportion to the
  file's size. It's fine for documents, and impractical for multi-gigabyte files.
- **Timestamps:** pnp keeps no activity log. Group files' modification and access times are reset to one fixed time
  after every write (2000-01-01 for anonymous groups). Their change time (ctime) can't be reset without root, so
  someone holding an *unlocked* cylinder can see roughly when it was last used. Encrypt the cylinder with LUKS (see
  [code-cylinder.md](code-cylinder.md)).
- **Anonymous groups** hide *who* is in a group, not *that* cylinders seized together belong to the same group.
- **The sandbox:** each group command can touch only its group's folder, its files' folders and the current folder
  (Landlock), with no network and no running other programs.

## How it works

- **Seals and messages** use pnp's one-time MAC (Wegman and Carter; see [format.md](format.md)), with keys from a
  pool shared by the two people. There is one pool per direction: each person's laptop contributes random bytes,
  and the pool is the XOR of the two, so neither machine controls it.
- **Group signatures** use the scheme of Amiri, Abidin, Wallden and Andersson (ACNS 2018):
  1. The signer holds N²k hash functions per signature slot (N = the other members).
  2. At the meeting, each recipient got a block of Nk of them, shuffled it with its own hardware randomness, and gave
     a set of k to each other recipient.
  3. A signature is the 2-bit tags of all N²k functions on the file.
  4. A verifier checks the sets it holds. The signer can't know which functions ended up where, so it can't make a
     signature that one honest member accepts and another rejects.
- **pnp's hash family:** h_K, the MAC's polynomial mod 2^127 − 1, followed by two random 127-bit parity rows and 2
  random bits. That's strongly universal with ε = 1/4 + L/p.
- **Parameters:** each failure probability (forging, repudiation, non-transferability) is at most 2^−64.

[research.md](research.md) lists every source and exactly what was taken from it, and [format.md](format.md) has
the file formats.

| people | cheaters tolerated | hand-ons | k | signature | storage per person, 1000 signatures each |
|-------:|------:|------:|-----:|---------:|------:|
| 3 | 1 | 1 | 1600 | 1.6 KiB | 0.6 GiB |
| 4 | 1 | 1 | 1650 | 3.6 KiB | 1.4 GiB |
| 5 | 2 | 0 | 450 | 1.8 KiB | 0.7 GiB |
| 7 | 3 | 0 | 450 | 4.0 KiB | 1.5 GiB |
| 9 | 4 | 0 | 450 | 7.0 KiB | 2.7 GiB |

"Hand-ons" are how many times a signature is guaranteed to pass on through members' ordinary checks. With 0, a
signature one honest member accepts is still guaranteed to be upheld by a group dispute vote.
