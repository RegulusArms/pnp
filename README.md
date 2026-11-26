# pnp

[![Release build](https://img.shields.io/github/actions/workflow/status/RegulusArms/pnp/deb.yml?branch=main&label=release%20build)](https://github.com/RegulusArms/pnp/actions/workflows/deb.yml?query=branch%3Amain)
[![Dev build](https://img.shields.io/github/actions/workflow/status/RegulusArms/pnp/deb.yml?branch=DEV&label=dev%20build)](https://github.com/RegulusArms/pnp/actions/workflows/deb.yml?query=branch%3ADEV)
[![Release](https://img.shields.io/github/v/release/RegulusArms/pnp?include_prereleases&sort=semver&filter=v*)](https://github.com/RegulusArms/pnp/releases)
[![apt repository](https://img.shields.io/badge/apt-pnp.regulusarms.com-blue?logo=debian&logoColor=white)](#installing)
[![Runs on](https://img.shields.io/badge/runs%20on-Debian%2012%2B%20%C2%B7%20Ubuntu%2022.04%2B%20%C2%B7%20Mint%2021%2B%20%C2%B7%20KDE%20neon-A81D33?logo=debian&logoColor=white)](#installing)
[![C11, libc only](https://img.shields.io/badge/C11-libc%20only-A8B9CC?logo=c&logoColor=white)](#building-from-source)
[![License: MIT](https://img.shields.io/github/license/RegulusArms/pnp)](LICENSE)

**Version 0.1.0-alpha.5**: early alpha. See [Installing](#installing).

A command-line file encryption tool for Debian, Ubuntu, Linux Mint and other Debian-based systems, built to stay
secure even if P = NP.

pnp encrypts any file with a **one-time pad**: a key of truly random bytes, as long as the file, read from your
machine's hardware random number generators. The file and the key are combined with XOR. A one-time pad's security
doesn't depend on any problem being hard to compute, so faster computers or new algorithms can't break it.

```
pnp                        # browse this folder and encrypt or decrypt step by step (see below)
pnp photo.jpg              # writes photo.jpg.pnp (encrypted) and photo.jpg.pnp.key (the key)
pnp -d photo.jpg.pnp       # uses photo.jpg.pnp.key to write photo.jpg again
pnp --sources              # which hardware random sources this machine has

pnp --key-out /media/usb photo.jpg      # the key goes straight onto the USB stick, never onto this disk
pnp -d -k /media/usb/photo.jpg.pnp.key photo.jpg.pnp
pnp --shares 2 photo.jpg                # the key as two shares, both needed to decrypt
pnp --protect photo.jpg                 # the key also locked with a passphrase (see below)
pnp --gen-passphrase                    # print a strong random passphrase
```

Keep the `.pnp.key` file secret and separate from the `.pnp` file, and never reuse it. Anyone holding both can
decrypt the file; without the key, nobody can. **That makes the way you store your keys the weakest link in pnp**:
see [Keeping your keys](#keeping-your-keys).

The catch: the key is as big as the file, and losing it means losing the file. So from now on you'll need to carry
an Imperial code cylinder on your belt at all times to keep your keys safe. Uniform sold separately.

## Installing

Works on Debian 12 and newer, Ubuntu 22.04 and newer, and systems based on them (Linux Mint 21+, Kubuntu, KDE
neon), on 64-bit PCs (amd64). One package works on all of them. Read the
[disclaimer](#disclaimer-if-p--np-build-from-source) first: if you're guarding against P = NP, build from source
instead.

**1. Add the repository's signing key**

```
sudo install -d -m 0755 /etc/apt/keyrings
sudo wget -qO /etc/apt/keyrings/pnp.asc https://pnp.regulusarms.com/pnp.asc
gpg --show-keys /etc/apt/keyrings/pnp.asc
```

The last command must show this fingerprint. If it doesn't, stop, delete the file, and don't continue:

```
B605C24B0B68BEF13104D1048A29173719C44365
```

**2. Add the repository and install pnp**

```
printf 'Types: deb\nURIs: https://pnp.regulusarms.com/\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/pnp.asc\n' \
  | sudo tee /etc/apt/sources.list.d/pnp.sources
sudo apt update
sudo apt install pnp
```

For development builds (newer, less tested), write `Suites: dev` instead of `Suites: stable`.

**3. Let pnp read your hardware random generator**

```
sudo usermod -aG pnp $USER
```

Then log out and back in. `pnp --sources` shows which hardware sources pnp can use. See
[where the randomness comes from](#where-the-randomness-comes-from).

**Updating:** `sudo apt update && sudo apt upgrade` updates pnp with the rest of your system.

**Removing:** `sudo apt remove pnp` removes the program. `sudo apt purge pnp` also removes the `pnp` group. To
stop using the repository too:

```
sudo rm /etc/apt/sources.list.d/pnp.sources /etc/apt/keyrings/pnp.asc
```

Files you encrypted stay encrypted after pnp is removed. Keep their keys: you can decrypt them later with pnp, or
with the few lines of Python in [docs/format.md](docs/format.md) (keys locked with `--protect` need two Python
packages as well, `argon2-cffi` and `cryptography`).

## Where the randomness comes from

A one-time pad is only unbreakable if its key is truly random. pnp reads the hardware random sources directly:

- **`/dev/hwrng`**: the kernel's hardware random number generator (a chip on the board or in the CPU, a TPM, a USB
  device).
- **RDSEED**: the random number instruction built into Intel and AMD CPUs.

pnp checks each source's output as it reads it, using the start-up and continuous health tests from NIST SP
800-90B. It then combines all the sources with XOR, together with the kernel's own generator. As long as the
sources are independent, the key is at least as unpredictable as the best of them, so one weak or dishonest source
can't spoil it.

What the health tests can't do is prove a source is truly random. They catch a source that breaks (stuck, repeating,
badly biased), but a source that secretly ran a hidden algorithm would pass them. So pnp's information-theoretic
guarantee rests on at least one of your hardware sources really being random. The sources pnp used are named every
time it makes a key (`pnp --sources -v` lists them with their drivers).

**In a virtual machine**, the host decides what RDSEED and `/dev/hwrng` return, and can read the machine's memory
anyway, pad and file included. pnp says so when it detects one. Encrypt on a physical machine unless the host is
yours.

**If no hardware source works, pnp refuses to encrypt.** Software randomness alone isn't safe if P = NP. Decrypting
needs no random source.

Only root can read `/dev/hwrng` by default. The package adds a `pnp` group that can read it; join it once:

```
sudo usermod -aG pnp $USER     # then log out and back in
```

## The interactive mode

Type `pnp` on its own in a terminal and it opens a file browser for the folder you're in:

```
    ____  _   ______
   / __ \/ | / / __ \
  / /_/ /  |/ / /_/ /
 / ____/ /|  / ____/
/_/   /_/ |_/_/          p = np. now what?   pnp 0.1.0-alpha.5
Folder:        /home/you/documents
Code cylinder: /media/you/KEYS
--------------------------------------------------------------------------------
    ../                                        folder
[ ] report.pdf                                 2.1 MB
[x] tax-2026.xlsx                              40.0 KB
[ ] taxes-2025.xlsx.pnp                        encrypted, key found
--------------------------------------------------------------------------------
Enter: encrypt. Writes report.pdf.pnp here
and its key to /media/you/KEYS/report.pdf.pnp.key
```

- **Move** with the arrow keys (or `j`/`k`), **select** files with Space, **open** a folder with Enter, go
  **up** with Backspace. `.` shows hidden files, `q` quits.
- **Enter on files to encrypt** shows exactly what will be written before anything is: each `.pnp` file and
  where its key goes. There you choose where the key goes, whether to split it into shares (each share on a
  different drive), and whether to lock it with a passphrase (pnp can make one for you).
- **Enter on `.pnp` files** shows which key decrypting will use, on which drive, before it does. pnp matches
  each file to its key by the ID they share, so renamed files are still matched, and shares spread over
  several drives are all found. If a key or a share is missing, it says which, and skips that file.
- **The code cylinder** (your key drive, see [docs/code-cylinder.md](docs/code-cylinder.md)) is found among the
  drives mounted in `/media/$USER` or `/run/media/$USER`, preferring one labelled `KEYS`. Press `c` to choose
  another drive or type a folder, and `r` to look again after plugging a drive in. pnp looks for keys at the top
  of each drive and beside the `.pnp` file.

It runs the same encryption and decryption as the commands above, with the same checks.

## What the guarantee rests on

pnp's encryption and integrity check are information-theoretically secure, which no amount of computing power
(or proof that P = NP) can change, **as long as**:

1. **the key is truly random:** at least one hardware source is (see above);
2. **the key stays secret:** stored apart from the ciphertext, in your physical custody;
3. **the key is used once:** pnp makes a new one for every file and never reuses it;
4. **the computer encrypting or decrypting is trustworthy:** malware on it, or the host of a virtual machine, sees
   the file and the key in memory, whatever the mathematics says.

The passphrase lock (`--protect`) and the way pnp is delivered (the signed apt repository, HTTPS) are only
computationally secure, as their own sections explain.

## Options

| Option | Meaning |
|---|---|
| `-d`, `--decrypt` | Decrypt instead of encrypting |
| `-k KEY`, `--key KEY` | The key to decrypt with (default `FILE.pnp.key`, or the shares `FILE.pnp.key.1`, `.2`…). For a key split into shares, give `-k` once per share, in any order |
| `-o OUT`, `--output OUT` | Where to write: the ciphertext when encrypting (its key goes to `OUT.key`), the plaintext when decrypting |
| `--key-out PATH` | Write the key straight into the folder `PATH` (as `FILE.pnp.key`), or to the file name `PATH`, instead of beside the ciphertext. With `--shares`: once for all shares (a folder), or once per share |
| `--shares N` | Write the key as `N` shares (2 to 16) instead of one key file. Every share is needed to decrypt |
| `--protect` | Also lock the key (or each share) with a passphrase, asked for twice. Decrypting asks for it. See [Locking a key with a passphrase](#locking-a-key-with-a-passphrase) |
| `--kdf-memory MIB` | With `--protect`: the memory each passphrase guess costs, in MiB (default 1024, 8 to 65536). The decrypting computer needs this much free memory; pnp checks before it starts |
| `--passphrase-file FILE` | Read the passphrase from the first line of `FILE` instead of asking (for scripts). Anyone who can read that file has the passphrase |
| `--gen-passphrase[=WORDS]` | Print a random passphrase of 7 words (or `WORDS`, 5 to 20) and exit |
| `-f`, `--force` | Replace files that already exist. Without it, pnp never replaces anything |
| `-q`, `--quiet` | Don't print which sources made the key, or what was written |
| `-v`, `--verbose` | List every random source and its state |
| `--sources` | List the hardware random sources and exit |

pnp writes each output under a hidden temporary name and renames it into place only once it's complete. A failure,
a full disk or Ctrl-C never leaves half a file behind. The key is created readable by you only. `man pnp` has the
details, and [docs/format.md](docs/format.md) describes the file format.

**pnp detects tampering and damage.** Every encryption also gets a one-time MAC, keyed by 32 more hardware-random
bytes kept in the key: like the pad, it can't be forged with any amount of computing power (HMAC or a hash
couldn't promise that if P = NP). If the `.pnp` file, or the key, has been changed or damaged by even one bit,
decrypting fails and writes nothing. Files made by pnp 0.1.0-alpha.2 or older have no such check; pnp still
decrypts them and says so.

## Keeping your keys

A one-time pad moves the whole problem of secrecy onto the key: the ciphertext is safe anywhere, the key has to
be guarded.

**The weakest link in pnp is how well you physically store your keys.** The mathematics can't be broken: no
computer, new algorithm or proof that P = NP will ever read a pnp file without its key. So nobody serious will
try. They'll go after the key instead: a USB stick left in a laptop bag, a key copied to a cloud folder or
emailed "just this once", a backup drive in an unlocked drawer, an old stick thrown away without being destroyed.
In practice, your files are exactly as safe as the place your keys are kept, and no more. Everything else pnp does
(hardware randomness, health tests, the integrity check, shares, `--protect`) is there so that this is the only
thing left to get right.

[docs/code-cylinder.md](docs/code-cylinder.md) walks through setting up a key drive to carry. Some rules:

- **Guard keys physically, and don't rely on encryption to do it.** An AES-encrypted drive, a password manager or
  a cloud account is only as strong as the very ciphers P = NP would break, and so is pnp's own `--protect`. A USB
  stick in a drawer, a safe or a bank deposit box doesn't depend on any of that.
- **Keep the ciphertext anywhere and the key offline.** Never store a key with its ciphertext, in cloud storage,
  or in email.
- **Keep keys off the computer's SSD.** A deleted file on an SSD may stay recoverable, because the drive moves data
  around internally and can't be relied on to overwrite it. Write the key straight to removable media with
  `--key-out`, so it never touches the internal disk:

  ```
  pnp --key-out /media/$USER/KEYS photo.jpg
  ```

- **Keep two or more copies of a key in different places**, and for long-term archives on more than one kind of
  storage (USB sticks, SD cards, optical discs), since all of them fail eventually. Keep a checksum list
  (`sha256sum *.key > SHA256SUMS`) beside each copy and check it now and then (`sha256sum -c SHA256SUMS`) to catch
  corruption early.
- **Or split the key into shares**, so that no single place holds it. `--shares N` writes `N` share files: each
  one alone, or any `N`−1 together, is just random noise, and all `N` are needed to decrypt. Like the pad itself,
  this holds against any amount of computing power. Put each share in a different place, for example:

  ```
  pnp --shares 2 --key-out /media/$USER/STICK1 --key-out /media/$USER/STICK2 photo.jpg
  pnp -d -k /media/$USER/STICK1/photo.jpg.pnp.key.1 -k /media/$USER/STICK2/photo.jpg.pnp.key.2 photo.jpg.pnp
  ```

  Losing any one share loses the file, so back up each share as you would a key.
- **Optionally, lock the key with a passphrase too** (`--protect`, below). It doesn't replace any of the rules
  above: it only slows down someone who already has your key file.
- **Destroying every copy of a key makes the file unreadable for good**, which can be what you want. Remember that
  overwriting may not destroy data on SSDs and flash media: physically destroy the medium if it matters.

## Locking a key with a passphrase

`--protect` encrypts the key file (or each share) under a passphrase, so a stolen key alone isn't enough:

```
pnp --gen-passphrase                    # e.g. "wizard foothold applied provoke hatred whoever attendant"
pnp --protect photo.jpg                 # asks for the passphrase twice
pnp -d photo.jpg.pnp                    # asks for it once
```

**This is not part of pnp's P = NP guarantee.** It uses ordinary, computationally secure cryptography: the
passphrase goes through two memory-hard password hashes one after the other (Balloon, then Argon2id), and the
result encrypts the key with ChaCha20. Its job is to make guessing expensive: each guess costs about a gigabyte of
memory and several seconds, so trying passphrases by the million on graphics cards isn't practical. That's a real
obstacle for a thief or a casual attacker, and none at all for someone who can break these algorithms. If they
did, they'd be left holding the plain key, exactly as without `--protect`: the one-time pad inside is unchanged.

- **The passphrase is what matters most.** Hashing slows each guess, but a short or common passphrase is still
  found quickly. `--gen-passphrase` picks words from the [EFF's list of 7776](https://www.eff.org/dice) with the
  same hardware randomness as the pad: 7 words is about 90 bits, far beyond guessing. Write it down and keep it
  apart from the key.
- **Forget the passphrase and the file is gone**, just as if the key were lost.
- **Decrypting needs the memory too**: 1 GiB by default. pnp checks there's enough free memory before it starts,
  and stops with a message if not. On a smaller machine, choose less when encrypting (`--kdf-memory 256`), which
  makes each guess cheaper as well.
- **More memory makes each guess costlier still.** `--kdf-memory 51200` (50 GiB) costs an attacker about 2,500
  times more per guess than the default, and pnp uses every CPU core for it: on a 32-core machine it takes about
  30 seconds. But every computer you'll ever decrypt on needs 50 GiB free, or the file can't be opened there. A
  longer passphrase is the cheaper gain: each extra `--gen-passphrase` word multiplies the guessing work by
  7776, at no cost to you.
- pnp still checks the key belongs to the file before asking for the passphrase, and says "wrong passphrase" at
  once instead of after decrypting. Changes to a locked key are caught by the integrity check, as for any key.

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
   (only hardware random sources) and that nothing is sent over the network. The optional passphrase lock
   (`--protect`: src/protect.c, kdf.c, blake2b.c, chacha20.c) is the only part that relies on problems being hard,
   and it only ever adds to the pad's protection. The interactive mode (src/tui.c) is the largest file but never
   touches key bytes: it only reads file headers to match files with keys, then calls the same functions as the
   command line.
3. Build it yourself with your distribution's own compiler (`make`, then `sudo make install`).

The installed apt package is fine for everyday use as long as P ≠ NP, or as long as no practical algorithm exists.
**Files you encrypted with an honest copy of pnp stay safe either way**: a one-time pad can't be broken by any
amount of computing power.

## License

MIT. See [LICENSE](LICENSE).

## Documentation

| Document | What's in it |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | What changed in each version |
| [docs/code-cylinder.md](docs/code-cylinder.md) | Setting up a key drive (an external hard disk) to carry with you, and why pnp relies on physical security |
| [docs/format.md](docs/format.md) | The file formats (ciphertext, key, key shares, keys locked with a passphrase), and how to decrypt without pnp |
| [man/pnp.1](man/pnp.1) | The manual page (`man pnp` once installed) |
| [TODO.md](TODO.md) | Planned work |
| [LICENSE](LICENSE) | The MIT license |
| [pnp.regulusarms.com](https://pnp.regulusarms.com) | The install page and apt repository |
