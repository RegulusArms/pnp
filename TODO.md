# To do

Planned work for pnp, roughly in priority order.

## Hardening

pnp's design is as strong as cryptography gets. These items are about the implementation: what turns a careful
young program into a hardened one.

### Testing

- [ ] **Fuzz everything that reads untrusted input.** That's ciphertext, key, share and protection-block headers
  (`open_pnp_file`, `pnp_protect_decode`), the interactive mode's header peek, passphrase files and terminal key
  sequences. Use small libFuzzer/AFL harnesses seeded with valid files, and run a short fuzzing job in CI.
- [ ] **Static analysis in CI:** `gcc -fanalyzer`, clang's `scan-build` and `cppcheck`, with each finding fixed or
  explained.
- [ ] **Crash and power-loss testing of the commit sequence.** Kill pnp at every step of writing (parts, renames,
  `-f`'s moved-aside files, keys and shares on separate drives), then check that nothing is lost and that
  whatever is left is recoverable.
- [ ] **Constant-time review.** Confirm the MAC's 128-bit multiply, the tag comparison, BLAKE2b and ChaCha20 take the
  same time whatever the secret, and write down why. Argon2id's data-dependent half is that way by design.

### Build and release

- [ ] **Reproducible builds.** The same source and `SOURCE_DATE_EPOCH` should give a bit-identical .deb. Have CI build
  twice and compare. Document how to check a published package against your own build, which strengthens the
  "build from source" disclaimer.
- [ ] **Stronger compiler hardening** where the build compiler supports it: `-D_FORTIFY_SOURCE=3`,
  `-fcf-protection`, `-ftrivial-auto-var-init=zero` (gcc 12+; the build container's gcc 11 needs a check).
- [ ] **A `SECURITY.md`:** how to report a vulnerability privately, and what happens next.
- [ ] **Signed checksums** (`SHA256SUMS` and its signature) on GitHub releases, for people who download the .deb
  directly.

### Running

- [ ] **Sandbox pnp once its files are open.** Use `prctl(PR_SET_NO_NEW_PRIVS)`, a seccomp filter (plain BPF, no
  libseccomp) allowing only the system calls pnp needs (no network at all), and Landlock to limit file access to
  the paths involved.
- [ ] **Lock more memory:** the passphrase hashes' buffers when the limit allows, the interactive mode's stack copies
  of passphrases, and `MADV_WIPEONFORK` on sensitive buffers. Add a `--strict` option that refuses to run when
  locking fails, instead of only warning.
- [ ] **Leftover files on start:** if a folder holds hidden `.pnp-part` or `.pnp-old` files from a crash, say so and
  explain how to recover.

### Verifying

- [ ] **`pnp --verify FILE.pnp`:** check a ciphertext against its key or shares (IDs, sizes, the MAC) without writing
  any plaintext. Useful for checking long-term archives now and then, and as a check before a real decrypt.
- [ ] **Code cylinder identity:** remember the key drive's filesystem UUID, and warn when a different drive with the
  same label (`KEYS`) shows up.

### Evidence

- [ ] **Measure the hardware sources.** Run NIST's SP 800-90B entropy assessment (`ea_non_iid`) on raw output from
  `/dev/hwrng` and RDSEED on reference machines, publish the results, and check that the health tests' assumed
  4 bits per byte is conservative. Needs a test-build hook that dumps raw source bytes.
- [ ] **A threat model document (docs/threat-model.md)** expanding "What the guarantee rests on": who pnp defends
  against, who it can't (malware on the machine, a VM host, someone holding the key), and each assumption.
- [ ] **An independent security audit** of rng.c, mac.c, kdf.c/protect.c, fileio.c and tui.c's terminal handling,
  by someone who didn't write them.

## Other

- [ ] TPM 2.0 (`/dev/tpmrm0`) as an extra hardware source, for machines whose TPM isn't already behind
  `/dev/hwrng`.
- [ ] arm64 packages (no RDSEED there: `/dev/hwrng` only).
