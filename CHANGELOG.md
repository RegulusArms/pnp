# Changelog

What changed in each version of pnp, newest first.

## 0.1.0-alpha.3

- **`--key-out PATH` writes the key straight to another folder** (a USB stick, say) or file name, instead of beside
  the ciphertext. The key never touches the computer's own disk, where a deleted file may stay recoverable on an
  SSD.
- **`--shares N` splits the key into N shares** (2 to 16), each one useless alone, all of them needed to decrypt.
  Like the one-time pad itself, this holds against any amount of computing power. Decrypting finds
  `FILE.pnp.key.1`, `.2`… by itself, or takes `-k` once per share, and refuses an incomplete set.
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
