# To do

Planned work for pnp, roughly in priority order.

## Hardening

pnp's design is as strong as cryptography gets. These items are about the implementation: what turns a careful
young program into a hardened one.

### Testing

- [x] **Fuzz everything that reads untrusted input.** That's ciphertext, key, share and protection-block headers
  (`open_pnp_file`, `pnp_protect_decode`), the interactive mode's header peek, passphrase files and terminal key
  sequences. Use small libFuzzer/AFL harnesses seeded with valid files, and run a short fuzzing job in CI.
  Done in 0.1.0-alpha.6: tests/fuzz/ (header parser, a whole `--verify`, passphrase files, key sequences), seeds
  from real files, `make fuzz-run` in CI; `make test` replays the seeds with gcc. Found and fixed: a signed
  overflow in the key decoder.
- [x] **Static analysis in CI:** `gcc -fanalyzer`, clang's `scan-build` and `cppcheck`, with each finding fixed or
  explained.
  Done in 0.1.0-alpha.6: `make analyze`, a CI job. Its findings were fixed in the code (no suppressions).
- [x] **Crash and power-loss testing of the commit sequence.** Kill pnp at every step of writing (parts, renames,
  `-f`'s moved-aside files, keys and shares on separate drives), then check that nothing is lost and that
  whatever is left is recoverable.
  Done in 0.1.0-alpha.6 for kills (PNP_TEST_CRASH_AT, every write, fsync, rename, link and unlink; keys on a
  second filesystem). Not done: a real power-cut simulation (dm-log-writes or dm-flakey, needs root), which
  would also test that the fsyncs are in the right places.
- [x] **Constant-time review.** Confirm the MAC's 128-bit multiply, the tag comparison, BLAKE2b and ChaCha20 take the
  same time whatever the secret, and write down why. Argon2id's data-dependent half is that way by design.
  Done in 0.1.0-alpha.6: docs/constant-time.md. Found and fixed: branches in the MAC's arithmetic; run.sh now
  checks the compiled code has none.

### Build and release

- [x] **Reproducible builds.** The same source and `SOURCE_DATE_EPOCH` should give a bit-identical .deb. Have CI build
  twice and compare. Document how to check a published package against your own build, which strengthens the
  "build from source" disclaimer.
  Done in 0.1.0-alpha.6: docs/reproducible.md; CI builds twice and compares.
- [x] **Stronger compiler hardening** where the build compiler supports it: `-D_FORTIFY_SOURCE=3`,
  `-fcf-protection`, `-ftrivial-auto-var-init=zero` (gcc 12+; the build container's gcc 11 needs a check).
  Done in 0.1.0-alpha.6: probed per flag; the .deb is built with gcc-12 on 22.04.
- [x] **A `SECURITY.md`:** how to report a vulnerability privately, and what happens next.
  Done in 0.1.0-alpha.6. Needs GitHub's private vulnerability reporting turned on (Settings →
  Security).
- [x] **Signed checksums** (`SHA256SUMS` and its signature) on GitHub releases, for people who download the .deb
  directly.
  Done in 0.1.0-alpha.6, with a .buildinfo file beside each .deb.

### Running

- [x] **Sandbox pnp once its files are open.** Use `prctl(PR_SET_NO_NEW_PRIVS)`, a seccomp filter (plain BPF, no
  libseccomp) allowing only the system calls pnp needs (no network at all), and Landlock to limit file access to
  the paths involved.
  Done in 0.1.0-alpha.6: src/sandbox.c.
- [x] **Lock more memory:** the passphrase hashes' buffers when the limit allows, the interactive mode's stack copies
  of passphrases, and `MADV_WIPEONFORK` on sensitive buffers. Add a `--strict` option that refuses to run when
  locking fails, instead of only warning.
  Done in 0.1.0-alpha.6.
- [x] **Leftover files on start:** if a folder holds hidden `.pnp-part` or `.pnp-old` files from a crash, say so and
  explain how to recover.
  Done in 0.1.0-alpha.6: docs/recovery.md.

### Verifying

- [x] **`pnp --verify FILE.pnp`:** check a ciphertext against its key or shares (IDs, sizes, the MAC) without writing
  any plaintext. Useful for checking long-term archives now and then, and as a check before a real decrypt.
  Done in 0.1.0-alpha.6.
- [x] **Code cylinder identity:** remember the key drive's filesystem UUID, and warn when a different drive with the
  same label (`KEYS`) shows up.
  Done in 0.1.0-alpha.6 (interactive mode).

### Evidence

- [x] **Measure the hardware sources.** Run NIST's SP 800-90B entropy assessment (`ea_non_iid`) on raw output from
  `/dev/hwrng` and RDSEED on reference machines, publish the results, and check that the health tests' assumed
  4 bits per byte is conservative. Needs a test-build hook that dumps raw source bytes.
  Done in 0.1.0-alpha.6 on one machine (AMD CCP and RDSEED: about 7.2 bits per byte), docs/entropy.md and
  tests/entropy/assess.sh. More machines welcome, especially Intel and a USB TRNG.
- [x] **A threat model document (docs/threat-model.md)** expanding "What the guarantee rests on": who pnp defends
  against, who it can't (malware on the machine, a VM host, someone holding the key), and each assumption.
  Done in 0.1.0-alpha.6.
- [ ] **An independent security audit** of rng.c, mac.c, kdf.c/protect.c, fileio.c and tui.c's terminal handling,
  by someone who didn't write them. Since 0.1.0-alpha.6 also format.c (every header parsed), keys.c (terminal
  input) and sandbox.c (the seccomp filter and Landlock rules). docs/threat-model.md and docs/constant-time.md are
  the starting points.

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
