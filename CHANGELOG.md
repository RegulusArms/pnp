# Changelog

What changed in each version of pnp, newest first.

## 0.1.0-alpha.12

- **Tests:** three checks that damage a file to make sure the damage is caught now flip a bit instead of writing
  a fixed byte. The fixed byte was already there about once in 256 runs, so the file didn't change and the check
  failed at random. pnp itself is unchanged.

## 0.1.0-alpha.11

- **Interactive mode, pairs and groups screen:** choosing "Start or join a meeting", "Import a meeting" or "Check a
  new drive" with no pnp drives plugged in now says so on the screen, and explains how to prepare a drive. Before,
  the message was hidden and the choice seemed to do nothing. The menu also stays on the item you chose.

## 0.1.0-alpha.10

- **pnp is now described as what it has become:** an experimental information-theoretic cryptography and
  communications suite, designed for a world beyond computational security. In it:
  - physical meetings replace public-key exchanges;
  - code cylinders replace key stores;
  - finite signing material replaces reusable signatures;
  - trusted groups replace a public-key infrastructure;
  - kill notices replace revocation;
  - randomness is a finite resource that's generated, carried, protected and used up.
- **Courier drives: external spinning hard disks are now preferred** over USB sticks. A spinning disk overwrites
  in place, so the overwrite between visits really removes the previous member's data. Flash keeps old copies
  through wear levelling, which widens the meeting's custody assumption. `pnp-courier-setup` says when a drive is
  flash. On-screen text says "drive" instead of "stick".
- **The docs state guarantees as bounds and assumptions,** not absolutes:
  - a forgery's probability per attempt, and what it depends on;
  - secrecy as long as the pad is truly random, used once and kept secret;
  - surviving a power cut as a design objective until real power-loss testing is done (only kills are tested
    so far).

- **Pairs and groups in the interactive mode.** In `pnp` alone:
  - **`s` on a file** seals it, signs it, or sends it to a member (or everyone), signed or not.
  - **Enter on a seal, a signature, a kept signed message or a group message** checks it or receives it. Enter on
    a kill notice offers to add your signature.
  - **`p`** lists your groups and walks you through a meeting: pick your self drive and courier from the pnp drives
    plugged in, and the wizard guides each step. It also imports a meeting at home and checks a new drive. Per
    group it shows info, makes a kill notice, leaves, or starts a re-meeting.

  Each action runs the same command as the command line, with the same checks.

## 0.1.0-alpha.9

- **Pairs and groups (new).** People who meet in person can now authenticate files and send each other
  encrypted messages afterwards, still secure even if P = NP ([docs/group.md](docs/group.md)):
  - **Seals, for two people** (`pnp --seal FILE --to NAME`, `pnp --check-seal FILE`): anyone else's forgery
    succeeds with probability at most about 2^-90 for a 1 TiB file.
    A seal proves nothing to anyone outside the pair, so it's deniable, and pnp says so.
  - **Signatures, for groups of 3 or more** (`pnp --sign FILE`, `pnp --verify-sig FILE`): every other member can
    check them, and they can be passed on to another member. Forging one, or denying one later, succeeds with
    probability at most 2^-64 each, if no more members cheat than the group tolerates.
    Built on an unconditionally secure scheme from universal hashing (Amiri, Abidin, Wallden and Andersson, ACNS
    2018). It relies on an honest majority and a fixed group instead of hard problems.
  - **Messages** (`pnp --send FILE --to NAME`, `pnp --receive FILE.pnp`): one-time-pad encrypted, optionally
    signed. Their headers name no group, pair or period, and the pad is wiped as it's used.
  - **Key sets with validity windows** (a week to a year, or no limit), **kill notices** for stolen keys (two
    members to kill, one to warn; either person in a pair), **leaving a group**, and **`pnp --info`**.
  - **Meetings** use courier sticks in a raw format (no filesystem), so a code cylinder never goes into anyone
    else's laptop.

## 0.1.0-alpha.7

- **A new page on the website: [if P = NP](https://pnp.regulusarms.com/p-np.html).** Pick how good a P = NP
  algorithm is and how many GPU racks an attacker has, and see how long a key locked with `--protect` would hold
  out at each memory setting. The install page links to it.
- **The docs say plainly who `--protect` and an encrypted key drive stop:** common criminals, not a state with
  real resources. If P = NP, the lock's ChaCha20 key can be searched directly, so the memory setting doesn't
  help; physical custody and `--shares` do. The key drive guide now sets the drive up with LUKS encryption.

## 0.1.0-alpha.6

- **`pnp --verify FILE.pnp`** checks a ciphertext against its key or shares (that they belong together, their
  sizes, and the integrity check over every byte) without writing anything. For checking archives now and then.
- **A sandbox.** pnp can never open a network connection or run another program, and once a command-line run has
  its files open, it can only touch the folders its outputs go to (seccomp and Landlock). `-v` says what the
  kernel allowed.
- **`--strict`** refuses to run when pad, file or passphrase bytes can't be locked in memory, instead of only
  warning. More is locked now: the interactive mode's passphrases, short-lived secrets on the stack, and the
  passphrase hashes' memory when the limit allows.
- **Leftovers of an interrupted run are pointed out.** If a crash, a kill or a power cut left hidden part files or
  moved-aside old files in a folder, the next run there lists them and says what to do
  ([docs/recovery.md](docs/recovery.md)).
- **The interactive mode notices a swapped key drive**: it remembers the drives it wrote keys to by filesystem
  UUID, and warns when another drive with the same name (KEYS) shows up.
- **The integrity check runs in constant time**: its arithmetic had branches that depended on the key and the file
  ([docs/constant-time.md](docs/constant-time.md)).
- Fixed: a long run of digits in a terminal key sequence overflowed a counter in the interactive mode.
- Fixed: when keys went to another folder, the leftovers note listed them under the ciphertext's folder.
- **Releases can be checked**: the .deb is reproducible (rebuild it from the source and compare,
  [docs/reproducible.md](docs/reproducible.md)), and GitHub releases carry signed `SHA256SUMS` and the build's
  tool versions.
- Built with stronger hardening: `_FORTIFY_SOURCE=3`, control-flow protection (CET), and zeroed local variables.
- Behind the scenes: every parser of untrusted input is fuzzed in CI, three static analysers check the code, and
  tests kill pnp at every step of saving to check that nothing is lost.
- New documents: a threat model ([docs/threat-model.md](docs/threat-model.md)), NIST SP 800-90B measurements of
  real hardware sources ([docs/entropy.md](docs/entropy.md)), and [SECURITY.md](SECURITY.md) for reporting a
  vulnerability privately.
- The interactive mode lets you choose how many words a generated passphrase has (5 to 20, 7 by default), as
  `--gen-passphrase=WORDS` already did. The help and man page say what each length is worth: 10 words is about
  128 bits, 20 about 256, as strong as the key the lock ends in.

## 0.1.0-alpha.5

- **A progress line** for every file encrypted or decrypted (how far, how fast, how long is left), and for the
  passphrase hashing of `--protect`. Shown only on a terminal, never in logs or pipes, and not with `-q`.
- **Replacing files with `-f` can no longer lose an old key.** The files being replaced are moved aside and deleted
  only once every new file is in place; if saving one fails, the old ones are put back.
- pnp now warns when it runs in a virtual machine (whose host can read the pad and choose what the hardware
  sources return), and when it can't keep its buffers out of swap.
- Fixed: the hardware random sources were left open after each file, so the interactive mode leaked a file
  descriptor per file encrypted.
- The README has a new section, "What the guarantee rests on", and says plainly that health tests catch failing
  sources but can't prove one is random.

## 0.1.0-alpha.4

- **`--protect` locks the key with a passphrase**, so a stolen key file alone isn't enough. Every passphrase guess
  costs about a gigabyte of memory and several seconds (two memory-hard password hashes, Balloon then Argon2id; the
  key is then encrypted with ChaCha20). This layer is only computationally secure, unlike the rest of pnp: it slows
  down a thief, it isn't part of the P = NP guarantee. `--kdf-memory` chooses the memory, and
  `--passphrase-file` reads the passphrase from a file for scripts. Works with `--shares` and `--key-out`.
  Argon2id uses every CPU core, so large settings stay quick (50 GiB in about 30 seconds on 32 cores), and pnp
  checks there's enough free memory before it starts instead of swapping for hours.
- **An interactive mode: type `pnp` on its own.** A file browser for the current folder: select files, and pnp
  shows exactly what it will write and where (the ciphertext here, the key on your code cylinder) before
  encrypting, or which key on which drive it will use before decrypting. It finds the key drive by itself (a
  drive labelled `KEYS` is preferred), matches each file to its key even if renamed, finds shares spread over
  several drives, and walks through shares and passphrase locks.
- File names are shown safely everywhere: a name containing terminal control codes can't affect the terminal.
- **`--gen-passphrase` prints a strong random passphrase**: 7 words (about 90 bits) from the EFF's word list,
  chosen with the same hardware randomness as the pad.
- The README, the manual and the key drive guide now say plainly that how you physically store your keys is the
  weakest link in pnp.

## 0.1.0-alpha.3

- **`--key-out PATH` writes the key straight to another folder** (a USB stick, say) or file name, instead of beside
  the ciphertext. The key never touches the computer's own disk, where a deleted file may stay recoverable on an
  SSD.
- **`--shares N` splits the key into N shares** (2 to 16), each one useless alone, all of them needed to decrypt.
  Like the one-time pad itself, this holds against any amount of computing power. Decrypting finds
  `FILE.pnp.key.1`, `.2`… by itself, or takes `-k` once per share, and refuses an incomplete set.
- **Tampering and damage are detected.** Each encryption gets a one-time MAC (an information-theoretic integrity
  check, so it holds even if P = NP, unlike HMAC or a hash). If the ciphertext or the key has changed by even one
  bit, decrypting fails and writes nothing. The file format is now version 002; files from older versions still
  decrypt, with a note that they have no integrity check.
- The README has a new section, "Keeping your keys".

## 0.1.0-alpha.2

- **The README has the complete install guide.** Adding the repository, checking its key, installing, joining the
  `pnp` group, updating and removing pnp are all there, so there's no need to visit the website.
- Documentation-only changes no longer start a build.

## 0.1.0-alpha.1 (2026-11-26)

- First version: one-time pad encryption and decryption of any file, with the pad made from hardware random
  sources (`/dev/hwrng` and RDSEED, health-tested, combined with `getrandom()`). pnp refuses to encrypt without a
  hardware source. Packaged as one .deb for Debian 12+ and Ubuntu 22.04+, with a udev rule letting the `pnp` group
  read `/dev/hwrng`.
