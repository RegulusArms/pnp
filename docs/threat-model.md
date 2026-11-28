# Threat model

What pnp protects against, what it can't, and every assumption its guarantee rests on. The README's "What the
guarantee rests on" is the short version; this is the long one.

## What pnp promises

For a file encrypted with an honest copy of pnp on a trustworthy computer:

1. **Secrecy.** Without the key, the ciphertext tells an attacker nothing about the file except its length, however
   much computing power they have, even if P = NP, as long as the pad is truly random, used once and kept secret.
   (One-time pad: [format.md](format.md).)
2. **Integrity.** Any change to the ciphertext or the key, even one bit, is detected when decrypting (or with
   `--verify`), and nothing is written, except with probability at most (L + 1) / (2^127 − 1) per forgery attempt
   (L: the file's length in 8-byte blocks; about 2^-90 for a 1 TiB file), whatever the forger's computing power. (Wegman-Carter one-time MAC: src/mac.c.)
3. **No lost files (a design objective).** A failure, a cancel or a crash is designed never to leave a
   half-written file under a real name, never to replace an existing file without `-f`, and never to lose the
   old key when `-f` replaces one. This is tested by killing pnp at every step of saving. A power cut is meant to
   be covered by the same design (fsyncs before each rename and of the folder after), but that remains an
   objective until real power-loss testing is done (TODO.md). ([recovery.md](recovery.md).)

Secrecy and integrity are *information-theoretic*: they don't depend on any problem being hard to compute. That's
the point of pnp. Everything below is about what they rest on.

## Who pnp defends against

| Attacker | What they have | Why they lose |
|---|---|---|
| Someone who gets the ciphertext | The `.pnp` file: a stolen laptop or backup, cloud storage, a network capture | The pad is random, as long as the file and used once: the ciphertext is uniformly random to them. No computing power helps, now or after P = NP. |
| Someone who changes the ciphertext | Write access to the `.pnp` file or the key | The one-time MAC: a change passes only by luck, about 2^-90 at worst. |
| Someone with a stolen key file, under `--protect` | The key file, no passphrase | Each passphrase guess costs about 1 GiB of memory and seconds (Balloon and Argon2id). **Computationally secure only**: this slows them, it doesn't stop a state-level attacker, and it isn't part of the P = NP claim. |
| A state, with a practical P = NP algorithm, holding a stolen locked key and its ciphertext | Both files, no passphrase | **Nothing in `--protect` or LUKS stops them for long.** They search the 256-bit ChaCha20 (or AES) key directly; a guess is checked with one cipher block against known bytes of the file, with no memory-hard hashing in it. The time depends only on how good the algorithm is ([chart](https://pnp.regulusarms.com/p-np.html)). Physical custody and shares are what keep them out. |
| Someone who finds or steals your key drive, locked | The drive, encrypted with LUKS as [code-cylinder.md](code-cylinder.md) sets it up, no passphrase | They must copy the whole drive and guess the passphrase at about 1 GiB and seconds per guess (Argon2id). **Computationally secure only**, like `--protect`: it makes stolen keys expensive, not safe, and isn't part of the P = NP claim. Unlocked, it protects nothing. |
| Someone with some but not all shares (`--shares N`) | Up to N-1 shares | Any N-1 shares are uniformly random whatever the pad is: they reveal nothing, information-theoretically. |
| A future attacker with a P = NP algorithm | Old ciphertexts, recorded today | Same as the first row: a one-time pad isn't a computational problem to solve. |
| A bug in pnp, exploited through a crafted file | A ciphertext, key, passphrase file or file name you open | Parsers are fuzzed and statically analysed in CI; once its files are open, pnp's sandbox stops it from reaching the network, running programs or touching other files (src/sandbox.c). Defence in depth, not a promise. |
| Someone who swaps your key drive for one with the same name | A USB stick labelled KEYS | The interactive mode remembers the drives it wrote keys to by filesystem UUID and warns about a stranger with a known name. A warning only: a careful attacker can copy a UUID too. |

## Who pnp can't defend against

These aren't bugs: no file encryption program can stop them, and pnp doesn't pretend to.

- **Anyone who controls the computer that encrypts or decrypts.** Malware, a keylogger, another user with root, a
  compromised kernel, or physical access while it runs: they can read the file and the pad from memory, change
  pnp, or replace the random sources. pnp locks its buffers in memory and keeps them out of core dumps and swap,
  but that only stops accidents, not an attacker who owns the machine.
- **The host of a virtual machine.** It sees all of the guest's memory and decides what RDSEED and `/dev/hwrng`
  return. pnp says so when it detects a hypervisor (`note: this is a virtual machine`). Encrypt on a physical
  machine.
- **Anyone who holds the key** (and the passphrase, with `--protect`). The key *is* the secret. Keeping it apart
  from the ciphertext and in your physical custody is your part ([code-cylinder.md](code-cylinder.md)).
- **Side channels on the same machine at the hardware level** beyond what pnp's constant-time code covers:
  power analysis, electromagnetic emanations, cold-boot attacks on RAM. See [constant-time.md](constant-time.md)
  for what is covered.
- **Traffic analysis.** The ciphertext is exactly as long as the file (plus 40 bytes). If the length itself is
  secret, pad the file before encrypting it.
- **A forged pnp package, if P = NP.** The apt repository's RSA signature, HTTPS and git's hashes are only
  computationally secure. The README's "Disclaimer: if P = NP, build from source" says how to avoid trusting
  them. [reproducible.md](reproducible.md) says how to check a published package against your own build.

## The assumptions, one by one

Each is something pnp relies on and can't prove by itself.

### 1. At least one hardware random source is truly random

The pad is the XOR of every healthy hardware source (`/dev/hwrng`, RDSEED) and `getrandom()`. If the sources are
independent, the XOR is at least as unpredictable as the best of them, so one weak or backdoored source can't
make the pad worse. But if *every* hardware source is predictable to the attacker (a backdoored CPU and a
backdoored RNG chip working together, say), the pad is only as strong as `getrandom()`'s ChaCha20: still
excellent, but computationally secure only.

- What pnp does: SP 800-90B health tests on each source's raw bytes (start-up and continuous; src/rng.h has the
  numbers), and refuses to encrypt without at least one healthy hardware source. It never falls back to
  `getrandom()` alone.
- What it can't do: no test can prove a source unpredictable. The health tests catch failures (stuck, repeating,
  badly biased output), not a clever backdoor. [entropy.md](entropy.md) has measurements of real sources.
- What you can do: use more than one kind of source (a CPU with RDSEED *and* a separate hardware RNG, such as a
  USB TRNG behind `/dev/hwrng`); check `pnp --sources`.

### 2. The pad is never reused

pnp makes a fresh pad for every file and never writes it anywhere but the key file. Reuse could only come from
outside: copying a key file and using it for another file by hand, or two machines with identical, broken
sources (assumption 1 again). pnp has no option to encrypt with an existing key.

### 3. The key stays secret and apart from the ciphertext

pnp can help (`--key-out` writes the key straight to another drive, so it never touches the ciphertext's disk;
`--shares` splits it; `--protect` locks it), but where you keep the key is up to you.

Note what pnp can't control on the disk itself: a key once written to a disk may survive deletion (SSD wear
levelling, copy-on-write filesystems, backups, snapshots). Write keys to a drive you control from the start.

### 4. The computer is trustworthy while pnp runs

See "Who pnp can't defend against". Defence in depth only: no swap or core dumps for secrets (locked memory,
`--strict` to insist on it), wiped buffers, a sandbox once files are open, a warning in virtual machines.

### 5. The pnp you run is honest

Build from reviewed source if P = NP worries you, or check the published package against your own build
([reproducible.md](reproducible.md)). The code is kept small and libc-only so it can be read by hand.

### 6. The MAC's arithmetic and the format are implemented correctly

The integrity bound is a theorem about the Wegman-Carter construction; it holds only if mac.c computes it right.
tests/test_mac.c and tests/xorcheck.c recompute every tag independently (a different multiplication method), and
the format parser is fuzzed. An independent audit is still planned (TODO.md).

### 7. Pairs and groups (docs/group.md)

Seals and messages rest on the same one-time MAC and pad as everything else, with keys swapped at a meeting. Group
signatures add three assumptions of their own:

- **An honest majority:** at most ω members cheat (set at the meeting, shown by `pnp --info`). Members who leave
  or are removed count against ω.
- **Custody of the splits:** no signer ever reads how the recipients split its functions. A courier only passes
  between its owner and one member. With one courier per person, reused between members, this also assumes nobody
  reads the stick's flash chip below its USB interface while holding it. pnp overwrites and reads back every
  courier between visits.
- **No restored key files:** a signing slot or pad range used twice breaks everything. pnp burns each one before
  using it, but a group folder restored from a backup would bring used ones back.

Validity windows rely on honest members' clocks (each checks messages against its own clock), not on cryptography.
Who talks to whom is hidden from outsiders, but file sizes and timing aren't.

## Where each defence lives

| Defence | Code | Checked by |
|---|---|---|
| Hardware sources, health tests, fail closed | src/rng.c | tests/test_health.c, run.sh |
| One-time pad, key and share files | src/main.c | tests/xorcheck.c (independent) |
| One-time MAC | src/mac.c | tests/test_mac.c, xorcheck.c, constant-time check in run.sh |
| Header parsing (CLI and interactive mode) | src/format.c | tests/fuzz/fuzz_header.c, fuzz_verify.c |
| Atomic writes, crash safety | src/fileio.c | crash tests in run.sh (PNP_TEST_CRASH_AT) |
| Locked, wiped memory; `--strict` | src/main.c, kdf.c | run.sh |
| Sandbox (seccomp, Landlock, no_new_privs) | src/sandbox.c | run.sh (PNP_TEST_PROBE) |
| `--protect` (computational only) | src/protect.c, kdf.c, blake2b.c, chacha20.c | tests/test_kdf.c (RFC vectors) |
| Terminal safety (file names, key input) | src/main.c pnp_clean, src/tui.c, src/keys.c | run.sh, tests/fuzz/fuzz_keys.c |
| Key drive identity | src/tui.c | run.sh |
| Seals and messages (pairs, groups) | src/gmsg.c, group.c | tests/group.sh |
| Group signatures, parameters | src/uss.c, meeting.c | tests/test_uss.c (independent vectors, exhaustive check), group.sh |
| Meetings, courier sticks | src/meeting.c, courier.c, gmeet.c | tests/group.sh, tests/fuzz/fuzz_courier.c |
| Kill notices, leaving | src/kill.c | tests/group.sh, tests/fuzz/fuzz_kill.c |
| Group file parsing | src/group.c | tests/fuzz/fuzz_group.c |
