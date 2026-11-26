# Changelog

What changed in each version of pnp, newest first.

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
