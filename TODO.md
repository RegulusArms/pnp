# To do

Planned work for pnp, roughly in priority order.

## Hardening

pnp's design is as strong as cryptography gets. These items are about the implementation: what turns a careful
young program into a hardened one.

- [ ] **An independent security audit** of rng.c, mac.c, kdf.c/protect.c, fileio.c and tui.c's terminal handling,
  by someone who didn't write them, together with format.c (every header parsed), keys.c (terminal input) and
  sandbox.c (the seccomp filter and Landlock rules), and the pairs and groups code (uss.c, gmsg.c, meeting.c,
  courier.c, kill.c, group.c), including a constant-time review of uss.c. docs/threat-model.md and
  docs/constant-time.md are the starting points.
- [ ] **Power-cut testing of the commit sequence.** Simulate a real power cut (dm-log-writes or dm-flakey, needs
  root), which would also check that the fsyncs are in the right places. Kills at every write are already
  tested.
- [ ] **Entropy measurements on more machines,** especially Intel CPUs and a USB TRNG (docs/entropy.md has the
  method).

## Containers, decoys and hidden files

Containers (format 003) are in 0.1.0-alpha.15 ([docs/format.md](docs/format.md)). Still to come:

- [ ] **Decoy keys (`--decoy`):** a second key, made later from the container alone, that opens a range of it to an
  innocent file of your choice. Nothing in the bytes tells it from a real key, so nobody can prove another key
  exists (deniability, not immunity: they can still disbelieve you).
- [ ] **Hidden files (`--hide`):** more files in the same container at encryption time, each at a random place with
  its own independent key. Whoever holds one key sees only random bytes where the others are.
- [ ] **Padding for seals and messages in pairs and groups** (files only for now: a group's pool is finite, and
  padding would use it up faster).

## Pairs and groups

The first version is in 0.1.0-alpha.9 ([docs/group.md](docs/group.md)). Still to come:

- [ ] **A group pool:** one pad shared by the whole group, so a message to everyone is one ciphertext instead of one
  per member. Messages on it would always be signed, since every member could make its MAC.
- [ ] **Top-ups without meeting again:** new key sets sent over the pairwise pools (each uses as much pad as it
  carries).
- [ ] **Strict courier mode in the wizard:** one courier per pair, kept for good, for groups that won't rely on the
  overwritten-courier assumption.
- [ ] **Telling a member who missed a re-meeting** that a newer generation exists, when something from it arrives.

## Interactive mode

- [ ] **Prepare drives from the interactive mode:** set up each kind of drive pnp uses without leaving it: a
  code cylinder (a key drive, with LUKS2 encryption if wanted) and the raw pnp drives used by pairs and groups
  (courier, self drive, kill card), followed by the capacity check. Today that takes `cryptsetup` and
  `pnp-courier-setup` by hand. Erasing a drive needs root and pnp never runs as root, so the interactive mode
  would hand that one step to a small, separately readable helper (asking for the password through `sudo` or
  `pkexec`), with the same safeguards as now: external drives only, nothing mounted, the drive shown and ERASE
  typed before anything is changed.

## Risky quality-of-life improvements

Convenient, but each works against part of the design. Only with a good answer to the risk.

- [ ] **Show a generated passphrase as a QR code** (interactive mode and `--gen-passphrase --qr`), opt-in only.
  Risks: the encoder must be hand-written (libc only: about 400-600 lines of Reed-Solomon, layout and masking to
  audit, and a wrong code still scans as something); a phone that scans it keeps the passphrase in its photos,
  clipboard or history, often backed up to the cloud, which breaks "keep it apart from the key"; and a camera
  can read it from across the room. If done: a warning beside it, and tests that decode the drawn code with an
  independent decoder.

## Other

- [ ] **Physical noise as extra random sources:** a microphone listening to background noise, or an SDR tuned to an
  empty frequency (mostly the receiver's own thermal noise). Each would be XORed in with the others, never used
  alone. Each needs its own SP 800-90B assessment, extraction that's information-theoretic rather than a hash,
  and health tests that catch someone injecting sound or a radio signal. To stay libc-only, likely as an "external
  source": a separately audited capture program feeding pnp through a FIFO.
- [ ] TPM 2.0 (`/dev/tpmrm0`) as an extra hardware source, for machines whose TPM isn't already behind
  `/dev/hwrng`.
- [ ] arm64 packages (no RDSEED there: `/dev/hwrng` only).
