# pnp file format (version 002)

pnp writes two files: the ciphertext (`FILE.pnp`) and the key (`FILE.pnp.key`). With `--shares N`, the key is
written as N share files instead (`FILE.pnp.key.1` … `FILE.pnp.key.N`, see [Key shares](#key-shares)). With
`--protect`, the key or each share is locked with a passphrase (see [Protected keys](#protected-keys)). For a file
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

## Protected keys

With `--protect`, a key or share carries a 48-byte **protection block** after its header, and its body (the key
material, or the share body) is encrypted. The magic says so: `PNPKP002` for a protected key, `PNPSP002` for a
protected share. The ciphertext is unchanged.

| Offset (after the 24- or 26-byte header) | Length | Protection block                              |
|-----------------------------------------:|-------:|-----------------------------------------------|
| 0                                        | 4      | Balloon space cost: 64-byte blocks (LE32)     |
| 4                                        | 4      | Balloon rounds (LE32)                         |
| 8                                        | 4      | Argon2id memory in KiB (LE32)                 |
| 12                                       | 4      | Argon2id passes (LE32); always one lane       |
| 16                                       | 16     | salt (random for each encryption)             |
| 32                                       | 16     | check value                                   |

The body follows: the same 32 + n bytes as an unprotected key or share body, XORed with a ChaCha20 keystream.

```
b      = Balloon-BLAKE2b(passphrase, salt, space cost, rounds, delta = 3)   (64 bytes)
a      = Argon2id(password = b, salt, memory, passes, lanes = 1, no secret, no associated data, 64 bytes)
key    = a[0..31]
check  = a[32..47]
nonce  = LE32(share number, or 0 for a whole key) || 8 zero bytes
body   = (key material) XOR ChaCha20(key, nonce, block counter from 0)      (RFC 8439)
```

- **Balloon** (Boneh, Corrigan-Gibbs and Schechter, 2016, Algorithm 1) with BLAKE2b-512 and 64-byte blocks. Every
  hash is BLAKE2b-512(LE64(counter) || inputs), with the counter starting at 0 and counting every hash. Expand:
  block 0 = hash(passphrase || salt), block m = hash(block m−1). Then for each round t and each block m: block m =
  hash(block m−1 (cyclically) || block m), and three times (i = 0, 1, 2): other = hash(salt || LE64(t) || LE64(m) ||
  LE64(i)) read as a little-endian integer, mod the number of blocks; block m = hash(block m || block other). The
  result is the last block.
- **Argon2id** is version 0x13 from RFC 9106.
- The passphrase is the bytes typed (or the first line of `--passphrase-file`, without its `\n` or `\r\n`),
  with no Unicode normalisation.
- All the shares of one encryption have the same protection block (same salt, so the passphrase is hashed once);
  the nonce keeps their keystreams apart. A new encryption gets a new salt, so a key and nonce are never reused.
- The check value lets pnp reject a wrong passphrase before decrypting anything. Changing the settings or the salt
  changes the key and so fails the check. Damage to the encrypted body isn't caught here but by the
  [integrity check](#the-integrity-check), as for an unprotected key.
- pnp accepts Argon2id memory from 8 MiB to 64 GiB, up to 1 GiB for Balloon, and up to 16 passes or rounds, so a
  damaged or hostile key can't make it allocate terabytes or run for days. It writes 1 GiB with 2 passes and
  16 MiB with 2 rounds by default (`--kdf-memory` sets the Argon2id memory; Balloon gets 1/64 of it, at most
  16 MiB).
- ChaCha20 has a 32-bit block counter, so one keystream covers 256 GiB: `--protect` refuses larger files.
- **This layer is only computationally secure.** It makes a stolen key file expensive to use; it isn't part of
  the information-theoretic guarantee, which rests on the pad, the one-time MAC and the shares alone.

Unwrapping a protected key or share without pnp, in Python (with `argon2-cffi` and `cryptography`):

```python
import hashlib
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def balloon(pw, salt, s, t):
    cnt = 0
    def h(*parts):
        nonlocal cnt
        x = hashlib.blake2b(cnt.to_bytes(8, "little"), digest_size=64)
        for p in parts:
            x.update(p)
        cnt += 1
        return x.digest()
    buf = [h(pw, salt)]
    for m in range(1, s):
        buf.append(h(buf[m - 1]))
    for r in range(t):
        for m in range(s):
            buf[m] = h(buf[(m - 1) % s], buf[m])
            for i in range(3):
                idx = h(salt, r.to_bytes(8, "little") + m.to_bytes(8, "little") + i.to_bytes(8, "little"))
                buf[m] = h(buf[m], buf[int.from_bytes(idx, "little") % s])
    return buf[s - 1]

def unwrap(data, passphrase):
    """a protected key or share file's bytes -> its key material (or share body), as if unprotected"""
    share = data[:8] == b"PNPSP002"
    assert share or data[:8] == b"PNPKP002"
    hdr = 26 if share else 24
    p = data[hdr:hdr + 48]
    blocks, rounds, kib, passes = (int.from_bytes(p[i:i + 4], "little") for i in (0, 4, 8, 12))
    salt, check = p[16:32], p[32:48]
    a = hash_secret_raw(balloon(passphrase, salt, blocks, rounds), salt, passes, kib, 1, 64, Type.ID)
    assert a[32:48] == check, "wrong passphrase"
    nonce = (data[24] if share else 0).to_bytes(4, "little") + bytes(8)
    # the library takes the 32-bit block counter (0) before the 12-byte nonce
    return Cipher(algorithms.ChaCha20(a[:32], bytes(4) + nonce), None).decryptor().update(data[hdr + 48:])
```

Then use `unwrap(...)` in place of `key[24:]` (or of each `s[26:]`) in the example under
[Decrypting without pnp](#decrypting-without-pnp). The pure-Python Balloon is slow at pnp's default 16 MiB
(minutes).

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
