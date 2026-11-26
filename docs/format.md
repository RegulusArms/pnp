# pnp file format (version 001)

pnp writes two files: the ciphertext (`FILE.pnp`) and the key (`FILE.pnp.key`). Both have a 24-byte header
followed by a body exactly as long as the original file.

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

## Decrypting without pnp

The format is simple enough to undo by hand. For example, in Python:

```python
ct, key = open("FILE.pnp", "rb").read(), open("FILE.pnp.key", "rb").read()
assert ct[:8] == b"PNPCT001" and key[:8] == b"PNPKY001" and ct[8:24] == key[8:24]
open("FILE", "wb").write(bytes(a ^ b for a, b in zip(ct[24:], key[24:])))
```
