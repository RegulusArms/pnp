# Research pnp relies on

Every paper and standard that pnp's design or code relies on, with what was taken from it and where it is used.
An auditor checking a claim in the code can start here. When a new source is used, it's added here in the same
change that uses it.

Each entry has a full citation, a link to an open copy where one exists, what pnp took from it (definitions,
theorems, constants, algorithms), and the files that depend on it.

## Papers

### Shannon 1949: perfect secrecy

C. E. Shannon, "Communication Theory of Secrecy Systems", *Bell System Technical Journal* 28(4), pp. 656-715,
1949.

- **Used:** the one-time pad's information-theoretic secrecy, and its conditions (a truly random pad, as long as
  the message, used once, kept secret). These are the four conditions in README "What the guarantee rests on".
- **Where:** the whole design: README "What the guarantee rests on", docs/threat-model.md.

### Wegman and Carter 1981: one-time MAC

M. N. Wegman, J. L. Carter, "New hash functions and their use in authentication and set equality", *Journal of
Computer and System Sciences* 22(3), pp. 265-279, 1981.

- **Used:** authentication by a universal hash plus a one-time pad on the tag, which is information-theoretically
  secure.
- **Where:** src/mac.c, docs/format.md "The integrity check", docs/threat-model.md.
- **Still to pin:** the exact source for mac.c's polynomial-evaluation forgery bound (L/p for L blocks mod
  2^127 − 1) isn't recorded yet. It's a standard result for polynomial-evaluation hashing. Record the paper and
  theorem once it has been checked.

### Boneh, Corrigan-Gibbs and Schechter 2016: Balloon hashing

D. Boneh, H. Corrigan-Gibbs, S. Schechter, "Balloon Hashing: A Memory-Hard Function Providing Provable Protection
Against Sequential Attacks", *Advances in Cryptology: ASIACRYPT 2016*, LNCS 10031, Springer, pp. 220-248, 2016.
Open copy: https://eprint.iacr.org/2016/027

- **Used:** Algorithm 1 (Balloon), with delta = 3, over BLAKE2b-512.
- **Where:** src/kdf.c, docs/format.md "Protected keys", tests/test_kdf.c, tests/kdf_vectors.py.
- **Computationally secure only.** It isn't part of the P = NP claim.

## Standards and advisories

- **NIST SP 800-90B:** M. S. Turan, E. Barker, J. Kelsey, K. A. McKay, M. L. Baish, M. Boyle, "Recommendation for
  the Entropy Sources Used for Random Bit Generation", NIST SP 800-90B, January 2018.
  doi:10.6028/NIST.SP.800-90B.
  - Used: the repetition-count and adaptive-proportion tests (4.4), the start-up test (4.3), the cutoff formulas,
    and the entropy assessment tool.
  - Where: src/rng.h, src/rng.c, docs/entropy.md, tests/entropy/.
- **RFC 7693:** M-J. Saarinen, J-P. Aumasson, "The BLAKE2 Cryptographic Hash and Message Authentication Code
  (MAC)", 2015.
  - Used: BLAKE2b and its test vectors.
  - Where: src/blake2b.c, tests/test_kdf.c.
- **RFC 8439:** Y. Nir, A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", 2018.
  - Used: ChaCha20, sections 2.3-2.4.
  - Where: src/chacha20.c, docs/format.md.
- **RFC 9106:** A. Biryukov, D. Dinu, D. Khovratovich, S. Josefsson, "Argon2 Memory-Hard Function for Password
  Hashing and Proof-of-Work Applications", 2021.
  - Used: Argon2id version 0x13 and its test vectors.
  - Where: src/kdf.c, tests/test_kdf.c.
- **AMD-SB-7055:** AMD security bulletin on RDSEED returning 0 as valid in its 16- and 32-bit forms on some Zen 5
  CPUs.
  - Used: pnp uses only the native-width form.
  - Where: src/rng.c.
