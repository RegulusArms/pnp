# pnp

A command-line file encryption tool for Debian, Ubuntu, Linux Mint and other Debian-based systems, built to stay
secure even if P = NP.

pnp encrypts any file with a **one-time pad**: a key of truly random bytes, as long as the file, read from your
machine's hardware random number generators. The file and the key are combined with XOR. A one-time pad's security
doesn't depend on any problem being hard to compute, so faster computers or new algorithms can't break it.

```
pnp photo.jpg        # writes photo.jpg.pnp (encrypted) and photo.jpg.pnp.key (the key)
```

Keep the `.pnp.key` file secret and separate from the `.pnp` file, and never reuse it. Anyone holding both can
decrypt the file; without the key, nobody can.

**Status:** early development, not yet usable. Install instructions will be at https://pnp.regulusarms.com.
