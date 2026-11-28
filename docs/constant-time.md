# Constant-time review

Which of pnp's code runs on secrets, whether its running time (and the memory it touches) can depend on them, and
why. Done for 0.1.0-alpha.6; redo it when this code changes.

**Why it matters.** A program whose timing depends on a secret can leak it to anyone who can measure that timing
closely: another process on the same machine (through shared caches and branch predictors), or a remote observer
if the program answers requests. pnp runs once and exits, without a network, so the realistic observer is local
software on the same machine, which [threat-model.md](threat-model.md) already counts as able to read pnp's
memory directly. Constant time is defence in depth here, not the main line. It's still worth doing right: a
partial observer (an unprivileged process measuring cache timing) is weaker than one reading memory.

**What "constant time" means here:** no branch and no memory address depends on a secret value. Loop counts and
branches on public values (file lengths, how many shares, header fields) are fine.

## The secrets

| Secret | Where it's processed |
|---|---|
| Pad bytes, plaintext | the XOR loops (main.c), the MAC (mac.c), the health tests (rng.c, raw source bytes) |
| The MAC key (k, s) | mac.c |
| The MAC tag before comparison | `pnp_mac_tag_cmp` (mac.c) |
| The passphrase | Balloon (kdf.c on BLAKE2b), Argon2id (kdf.c on BLAKE2b) |
| The key a passphrase makes | ChaCha20 (chacha20.c), the check value comparison (protect.c) |

## Findings

### The MAC's arithmetic (mac.c): fixed in this release

The tag is a polynomial in the key k, evaluated over every 8-byte block of the plaintext with Horner's rule:
`acc = (acc + block) * k mod 2^127 - 1`. So its arithmetic touches both the key and the plaintext.

- **Before 0.1.0-alpha.6** the reduction `x >= P ? x - P : x` and the carry `(lo < p00)` in the 128-bit multiply
  compiled (gcc -O2) to conditional jumps: the time depended on the key and the plaintext.
- **Now** every choice is made with a mask built from a borrow or carry bit, with no comparison a compiler could
  turn into a jump: `canon` subtracts P, takes bit 127 of the result as "it went negative", and selects with
  `(x & keep) | (d & ~keep)`; `mul` takes the carry from the usual formula
  `((a & b) | ((a | b) & ~sum)) >> 127`.
- The four 64x64-bit multiplies (`mul` instruction on x86-64, `mul`/`umulh` on arm64) take the same time
  whatever their operands on every current x86-64 and arm64 core.
- `load`/`store` loop over a public length (8 bytes, or the last block's length, which follows from the file
  size).
- **Checked automatically:** tests/run.sh compiles mac.c at -O1, -O2, -O3 and -Os and fails if `block`, `canon`,
  `add` or `mul` contain any conditional jump. (Breaking either fix makes it fail; that was tried.)

### The tag comparison (`pnp_mac_tag_cmp`) and the passphrase check (`pnp_protect_unlock`): constant time

Both OR together the XOR of every byte pair and test the result once at the end: no early exit at the first
difference. The single final branch reveals only "match or not", which pnp says anyway.

(Strictly, a tag comparison needn't be constant time here: the tag's one-time key is used for one message only,
and a forger can't submit many tries against the same key the way they could against a server. It's constant
time anyway.)

### BLAKE2b (blake2b.c): constant time

Only 64-bit additions, XORs and rotations by fixed amounts (an ARX design). The message schedule `SIGMA` is a
public table of indexes into the message words, chosen by the round number, never by data. Loop counts depend
only on lengths. No table lookups on data.

### ChaCha20 (chacha20.c): constant time

32-bit additions, XORs and fixed rotations only (ARX). The block counter and nonce are public. Used to wrap a key
file's bytes under the key a passphrase makes.

### Balloon (kdf.c): data-independent memory access

Balloon's "other block" indexes come from hashing the salt and counters, not the passphrase, so the memory it
touches is the same for every passphrase with that salt. Its compression function is BLAKE2b (above).

### Argon2id (kdf.c): data-dependent by design

Argon2id's first half of the first pass picks blocks by a counter-driven generator (Argon2i: data-independent,
resisting cache-timing attacks), and from then on by the previous block's contents (Argon2d: data-dependent,
resisting GPU and time-memory trade-off attacks). That second half's memory access depends on the passphrase, as
RFC 9106 intends: the "id" mix is the RFC's recommended balance. A local observer measuring cache timing during
hashing could learn something about the passphrase from it. That's accepted: `--protect` is computationally
secure only and isn't part of the P = NP claim, and a local observer is outside what pnp can defend against.
The compression function (BLAKE2b's round, `fBlaMka`'s 32x32-bit multiplies) is constant time.

### The XOR loops (main.c): constant time

`out[i] = in[i] ^ pad[i]` over a public length; the shares are XORed the same way.

### The health tests (rng.c): data-dependent, accepted

The repetition-count and adaptive-proportion tests compare each raw source byte with the previous one or the
window's first: branches on the raw bytes of each hardware source. A cache- or branch-timing observer could learn
something about one source's raw output (for example, where two equal bytes follow each other).

Why that's accepted: the pad is the XOR of every hardware source *and* `getrandom()`, and `getrandom()`'s output
goes through no data-dependent code. Learning partial information about one source's raw bytes tells an observer
nothing about the pad, unless they learn every source fully, including `getrandom()`, which is the "owns the
machine" case. Making the tests branch-free is possible but would make the audit-critical counting harder to read
for no gain in that model.

### Things that are public

Lengths, share counts, file names, header IDs (compared with `memcmp`: the ID is stored in the clear in both the
ciphertext and the key), protection-block parameters, error paths: none of these is secret, so their branches
don't matter.

## Limits of this review

- It's by reading the source and checking the compiled code with gcc 15 (and gcc 11/12 for the build release) at
  the usual optimisation levels; a future compiler could still introduce a branch, which is why the MAC check
  runs in `make test` on every CI compiler.
- It covers timing and memory addresses, not power or electromagnetic side channels.
- It predates pairs and groups (0.1.0-alpha.9). Seals and messages use the MAC and the tag comparison reviewed
  here (mac.c, called from gmsg.c), but the signature code (uss.c's hash family and tag checks) and the rest of
  the group code haven't had this review yet.
- An independent review is still planned (TODO.md).
