# To do

Planned work for pnp, roughly in priority order.

## Hardening

pnp's design is as strong as cryptography gets. These items are about the implementation: what turns a careful
young program into a hardened one.

- [ ] **An independent security audit** of rng.c, mac.c, kdf.c/protect.c, fileio.c and tui.c's terminal handling,
  by someone who didn't write them, together with format.c (every header parsed), keys.c (terminal input) and
  sandbox.c (the seccomp filter and Landlock rules). docs/threat-model.md and docs/constant-time.md are the
  starting points.
- [ ] **Power-cut testing of the commit sequence.** Simulate a real power cut (dm-log-writes or dm-flakey, needs
  root), which would also check that the fsyncs are in the right places. Kills at every write are already
  tested.
- [ ] **Entropy measurements on more machines,** especially Intel CPUs and a USB TRNG (docs/entropy.md has the
  method).

## Pairs and groups

The first version is in 0.1.0-alpha.8 ([docs/group.md](docs/group.md)). Still to come:

- [ ] **A group pool:** one pad shared by the whole group, so a message to everyone is one ciphertext instead of one
  per member. Messages on it would always be signed, since every member could make its MAC.
- [ ] **Top-ups without meeting again:** new key sets sent over the pairwise pools (each uses as much pad as it
  carries).
- [ ] **Strict courier mode in the wizard:** one courier per pair, kept for good, for groups that won't rely on the
  overwritten-courier assumption.
- [ ] **Group actions in the interactive mode** (`pnp` alone in a terminal). For now the meeting wizard is
  `pnp --meet`.
- [ ] **Telling a member who missed a re-meeting** that a newer generation exists, when something from it arrives.

## Risky quality-of-life improvements

Convenient, but each works against part of the design. Only with a good answer to the risk.

- [ ] **Show a generated passphrase as a QR code** (interactive mode and `--gen-passphrase --qr`), opt-in only.
  Risks: the encoder must be hand-written (libc only: about 400-600 lines of Reed-Solomon, layout and masking to
  audit, and a wrong code still scans as something); a phone that scans it keeps the passphrase in its photos,
  clipboard or history, often backed up to the cloud, which breaks "keep it apart from the key"; and a camera
  can read it from across the room. If done: a warning beside it, and tests that decode the drawn code with an
  independent decoder.

## Other

- [ ] TPM 2.0 (`/dev/tpmrm0`) as an extra hardware source, for machines whose TPM isn't already behind
  `/dev/hwrng`.
- [ ] arm64 packages (no RDSEED there: `/dev/hwrng` only).
