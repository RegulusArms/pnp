# pnp file format (version 002)

pnp writes two files: the ciphertext (`FILE.pnp`) and the key (`FILE.pnp.key`). With `--shares N`, the key is
written as N share files instead (`FILE.pnp.key.1` … `FILE.pnp.key.N`, see [Key shares](#key-shares)). For a file
of n bytes:

| Offset | Length | Ciphertext (`.pnp`)              | Offset | Length | Key (`.pnp.key`)                 |
|-------:|-------:|----------------------------------|-------:|-------:|----------------------------------|
| 0      | 8      | magic `PNPCT002` (ASCII)         | 0      | 8      | magic `PNPKY002` (ASCII)         |
| 8      | 16     | ID                               | 8      | 16     | the same ID                      |
| 24     | n      | plaintext XOR pad                | 24     | 16     | MAC key k (little-endian)        |
| 24 + n | 16     | MAC tag (little-endian)          | 40     | 16     | MAC key s (little-endian)        |
|        |        |                                  | 56     | n      | pad                              |

- **ID:** 16 random bytes made for each encryption, the same in both files. Decrypting refuses a key whose ID
  doesn't match, so a key from another file can't silently produce garbage. The ID isn't secret, and it reveals
  nothing about the contents.
- **Pad:** n bytes, each the XOR of every hardware source in use and the kernel's `getrandom()` (see
  [src/rng.c](../src/rng.c)).
- **MAC key and tag:** the integrity check (see [below](#the-integrity-check)). k and s are fresh random values from
  the same sources as the pad, each below p = 2^127 − 1. The tag is public: it reveals nothing without s.
- The trailing `002` in the magic is the format version. A later version that changes the layout gets a new number,
  and older pnp versions refuse it instead of misreading it.

## The integrity check

A one-time pad hides the contents but doesn't detect changes: flipping a bit in the ciphertext flips the same bit
in the decrypted file. HMAC or a hash would detect changes only *computationally*, which P = NP could break. So pnp
uses a **one-time MAC** (Wegman–Carter), which is information-theoretically secure, like the pad itself.

M is the ID followed by the plaintext (16 + n bytes). Cut M into 8-byte blocks m₁ … m_L, read as little-endian
integers, with the last block padded with zero bytes. Then, with all arithmetic mod p = 2^127 − 1:

```
acc = 0
for each block m:   acc = (acc + m) × k
acc = (acc + len(M)) × k
tag = acc + s
```

That is, tag = m₁k^(L+1) + m₂k^L + … + m_Lk² + len(M)·k + s (mod p).

- **Why it can't be forged:** s is used once, so the tag tells an attacker nothing about k. For any change to the
  ciphertext (or to the key's pad), the difference between the true and the changed tag is a nonzero polynomial in
  k of degree at most L + 1, so a change goes unnoticed with probability at most (L + 1) / p. That's about 2^-90 for
  a 1 TiB file, whatever computing power the attacker has.
- **What it covers:** the decrypted plaintext. So it catches a changed or damaged ciphertext, a damaged tag, and
  also a damaged key or share (a wrong pad gives the wrong plaintext, and a wrong k or s gives the wrong tag).
- **When it's checked:** pnp decrypts into a hidden temporary file and renames it into place only if the tag
  matches. If it doesn't, nothing is written.

## Key shares

With `--shares N` (2 to 16), there is no single key file. Each share has a 26-byte header, then a body of 32 + n
bytes:

| Offset | Length | Share (`.pnp.key.1` … `.pnp.key.N`)                  |
|-------:|-------:|------------------------------------------------------|
| 0      | 8      | magic `PNPSH002` (ASCII)                             |
| 8      | 16     | the ciphertext's ID                                  |
| 24     | 1      | this share's number, 1 to N                          |
| 25     | 1      | N, the number of shares                              |
| 26     | 32 + n | share body                                           |

- The **key material** is what a whole key holds after its header: MAC key k, MAC key s, then the pad (32 + n bytes).
- Shares 1 to N−1 are fresh random bytes from the same hardware sources. Share N is the key material XOR all of
  them. So the XOR of all N share bodies is the key material.
- Any N−1 shares are uniformly random whatever the key is: they reveal nothing about it, however much computing
  power is used. This is the same information-theoretic argument as for the pad itself.
- The order doesn't matter (XOR is commutative). The number and count are there so pnp can refuse an incomplete
  set, or the same share given twice, instead of producing garbage.

## Version 001

pnp 0.1.0-alpha.2 and older wrote version 001: the same 24-byte headers with magics `PNPCT001` and `PNPKY001`,
then the body (ciphertext: plaintext XOR pad; key: the pad), with no MAC key, no tag and no shares. pnp still
decrypts these, with a note that changes to them can't be detected, but never writes them.

## Decrypting without pnp

The format is simple enough to undo by hand. For example, in Python, checking the integrity check too:

```python
P = 2**127 - 1

def mac(k, s, msg):
    acc = 0
    for i in range(0, len(msg), 8):
        acc = (acc + int.from_bytes(msg[i:i + 8], "little")) * k % P
    acc = (acc + len(msg)) * k % P
    return (acc + s) % P

ct = open("FILE.pnp", "rb").read()
assert ct[:8] == b"PNPCT002"
key = open("FILE.pnp.key", "rb").read()
assert key[:8] == b"PNPKY002" and key[8:24] == ct[8:24]
material = key[24:]
# with shares instead of a key, replace the three lines above by these, XORing the share bodies (here three):
#   shares = [open(f"FILE.pnp.key.{i}", "rb").read() for i in (1, 2, 3)]
#   assert all(s[:8] == b"PNPSH002" and s[8:24] == ct[8:24] and s[25] == len(shares) for s in shares)
#   material = bytes(len(shares[0]) - 26)
#   for s in shares:
#       material = bytes(a ^ b for a, b in zip(material, s[26:]))
k, s, pad = int.from_bytes(material[:16], "little"), int.from_bytes(material[16:32], "little"), material[32:]
plain = bytes(a ^ b for a, b in zip(ct[24:-16], pad))
assert mac(k, s, ct[8:24] + plain) == int.from_bytes(ct[-16:], "little"), "integrity check failed"
open("FILE", "wb").write(plain)
```
