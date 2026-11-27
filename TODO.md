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

## Groups

- [ ] **Signatures and encrypted messages for groups of 3 or more, secure even if P = NP.** Members meet once in
  person and swap key material on courier sticks. Afterwards any member can sign a file so that every other member
  can check it, nobody can forge it and the signer can't deny it, and members can send each other one-time-pad
  messages. The signatures use an unconditionally secure scheme built on universal hashing (Amiri, Abidin,
  Wallden and Andersson, ACNS 2018), so they rely on an honest majority and a fixed group instead of hard
  problems. Key sets with validity windows, kill notices for stolen keys, and `pnp --info` for every key type are
  part of the design.

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
