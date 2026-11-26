# pnp file format (version 001)

pnp writes two files: the ciphertext (`FILE.pnp`) and the key (`FILE.pnp.key`). Both have a 24-byte header
followed by a body exactly as long as the original file. With `--shares N`, the key is written as N share files
instead (`FILE.pnp.key.1` … `FILE.pnp.key.N`, see [Key shares](#key-shares)).

| Offset | Length | Ciphertext (`.pnp`)              | Key (`.pnp.key`)                 |
|-------:|-------:|----------------------------------|----------------------------------|
| 0      | 8      | magic `PNPCT001` (ASCII)         | magic `PNPKY001` (ASCII)         |
| 8      | 16     | ID                               | the same ID                      |
| 24     | n      | plaintext XOR pad                | pad                              |

- **ID:** 16 random bytes made for each encryption, the same in both files. Decrypting refuses a key whose ID
  doesn't match, so a key from another file can't silently produce garbage. The ID isn't secret, and it reveals
  nothing about the contents.
- **Pad:** n bytes, each the XOR of every hardware source in use and the kernel's `getrandom()` (see
  [src/rng.c](../src/rng.c)).
- **No integrity check:** a one-time pad hides the contents but doesn't detect changes. Flipping a bit in the
  ciphertext flips the same bit in the decrypted file.
- The trailing `001` in the magic is the format version. A later version that changes the layout gets a new number,
  and older pnp versions refuse it instead of misreading it.

## Key shares

With `--shares N` (2 to 16), there is no single key file. Each share has a 26-byte header and a body as long as
the original file:

| Offset | Length | Share (`.pnp.key.1` … `.pnp.key.N`)                  |
|-------:|-------:|------------------------------------------------------|
| 0      | 8      | magic `PNPSH001` (ASCII)                             |
| 8      | 16     | the ciphertext's ID                                  |
| 24     | 1      | this share's number, 1 to N                          |
| 25     | 1      | N, the number of shares                              |
| 26     | n      | share body                                           |

- Shares 1 to N−1 are fresh pads from the same hardware sources as the pad itself. Share N is the pad XOR all of
  them. So the XOR of all N share bodies is the pad.
- Any N−1 shares are uniformly random whatever the pad is: they reveal nothing about it, however much computing
  power is used. This is the same information-theoretic argument as for the pad itself.
- The order doesn't matter (XOR is commutative). The number and count are there so pnp can refuse an incomplete
  set, or the same share given twice, instead of producing garbage.

## Decrypting without pnp

The format is simple enough to undo by hand. For example, in Python:

```python
ct, key = open("FILE.pnp", "rb").read(), open("FILE.pnp.key", "rb").read()
assert ct[:8] == b"PNPCT001" and key[:8] == b"PNPKY001" and ct[8:24] == key[8:24]
open("FILE", "wb").write(bytes(a ^ b for a, b in zip(ct[24:], key[24:])))
```

With shares, XOR all of them in (here three):

```python
ct = open("FILE.pnp", "rb").read()
shares = [open(f"FILE.pnp.key.{i}", "rb").read() for i in (1, 2, 3)]
assert all(s[:8] == b"PNPSH001" and s[8:24] == ct[8:24] and s[25] == len(shares) for s in shares)
pad = bytes(len(ct) - 24)
for s in shares:
    pad = bytes(a ^ b for a, b in zip(pad, s[26:]))
open("FILE", "wb").write(bytes(a ^ b for a, b in zip(ct[24:], pad)))
```
