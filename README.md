# pnp

**Version 0.1.0-alpha.1**: early alpha. Install instructions will be at https://pnp.regulusarms.com.

A command-line file encryption tool for Debian, Ubuntu, Linux Mint and other Debian-based systems, built to stay
secure even if P = NP.

pnp encrypts any file with a **one-time pad**: a key of truly random bytes, as long as the file, read from your
machine's hardware random number generators. The file and the key are combined with XOR. A one-time pad's security
doesn't depend on any problem being hard to compute, so faster computers or new algorithms can't break it.

```
pnp photo.jpg              # writes photo.jpg.pnp (encrypted) and photo.jpg.pnp.key (the key)
pnp -d photo.jpg.pnp       # uses photo.jpg.pnp.key to write photo.jpg again
pnp --sources              # which hardware random sources this machine has
```

Keep the `.pnp.key` file secret and separate from the `.pnp` file, and never reuse it. Anyone holding both can
decrypt the file; without the key, nobody can.

The catch: the key is as big as the file, and losing it means losing the file. So from now on you'll need to carry
an Imperial code cylinder on your belt at all times to keep your keys safe. Uniform sold separately.

## Where the randomness comes from

A one-time pad is only unbreakable if its key is truly random. pnp reads the hardware random sources directly:

- **`/dev/hwrng`**: the kernel's hardware random number generator (a chip on the board or in the CPU, a TPM, a USB
  device).
- **RDSEED**: the random number instruction built into Intel and AMD CPUs.

pnp checks each source's output as it reads it, using the start-up and continuous health tests from NIST SP
800-90B. It then combines all the sources with XOR, together with the kernel's own generator. Even if one source
were weak, the key would be as unpredictable as the best of them.

**If no hardware source works, pnp refuses to encrypt.** Software randomness alone isn't safe if P = NP. Decrypting
needs no random source.

Only root can read `/dev/hwrng` by default. The package adds a `pnp` group that can read it; join it once:

```
sudo usermod -aG pnp $USER     # then log out and back in
```

## Options

| Option | Meaning |
|---|---|
| `-d`, `--decrypt` | Decrypt instead of encrypting |
| `-k KEY`, `--key KEY` | The key to decrypt with (default `FILE.pnp.key`) |
| `-o OUT`, `--output OUT` | Where to write: the ciphertext when encrypting (its key goes to `OUT.key`), the plaintext when decrypting |
| `-f`, `--force` | Replace files that already exist. Without it, pnp never replaces anything |
| `-q`, `--quiet` | Don't print which sources made the key, or what was written |
| `-v`, `--verbose` | List every random source and its state |
| `--sources` | List the hardware random sources and exit |

pnp writes each output under a hidden temporary name and renames it into place only once it's complete. A failure,
a full disk or Ctrl-C never leaves half a file behind. The key is created readable by you only. `man pnp` has the
details, and [docs/format.md](docs/format.md) describes the file format.

**pnp doesn't detect tampering.** A one-time pad hides what's in a file but can't tell whether the ciphertext was
changed: a modified `.pnp` file decrypts to modified data without an error.

## Building from source

pnp is plain C using only the standard C library. It builds on any Debian, Ubuntu or Mint system:

```
sudo apt install build-essential
make                    # builds build/pnp
make test               # runs the tests
sudo make install       # installs to /usr/local (PREFIX=... to change)
sudo make install-udev  # the udev rule and pnp group, so pnp can read /dev/hwrng
make deb                # builds a .deb in build/ (needs dpkg-dev)
```

## Disclaimer: if P = NP, build from source

pnp's encryption doesn't depend on P ≠ NP. **The way you get pnp does.**

The apt repository is signed with an RSA key, and GitHub's HTTPS and git's commit hashes rely on problems being
hard to compute. If P = NP is proven *with a practical algorithm*, all of these could be forged. An attacker could
then hand you a fake pnp package with a valid signature, and apt would install it.

Today, no digital signature scheme is known to stay secure if P = NP: they all rest on some problem being hard,
which a practical P = NP algorithm could solve. Until a P = NP-resistant way to sign and deliver software exists,
building from source is the safest way to get pnp:

1. Get the source from more than one place, and check the copies match.
2. **Read it before you build it.** pnp is deliberately small, written in plain C with no libraries beyond the
   standard C library, so the whole program can be reviewed by hand. Check above all how the key is generated
   (only hardware random sources) and that nothing is sent over the network.
3. Build it yourself with your distribution's own compiler (`make`, then `sudo make install`).

The installed apt package is fine for everyday use as long as P ≠ NP, or as long as no practical algorithm exists.
**Files you encrypted with an honest copy of pnp stay safe either way**: a one-time pad can't be broken by any
amount of computing power.

## License

MIT. See [LICENSE](LICENSE).
