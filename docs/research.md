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
- **Where:** src/mac.c, docs/format.md "The integrity check", docs/threat-model.md; pairs' seals and group
  messages (src/gmsg.c), which use the same MAC with keys from a shared pool.
- **Still to pin:** the exact source for mac.c's polynomial-evaluation forgery bound (L/p for L blocks mod
  2^127 − 1) isn't recorded yet. It's a standard result for polynomial-evaluation hashing. Record the paper and
  theorem once it has been checked.

### Carter and Wegman 1979: universal hashing

J. L. Carter, M. N. Wegman, "Universal classes of hash functions", *Journal of Computer and System Sciences*
18(2), pp. 143-154, 1979.

- **Used:** the definition of universal hash families, which the ε-ASU₂ definition in Amiri et al. builds on.
- **Where:** docs/group.md, src/uss.c (the hash family's definition).

### Bierbrauer, Johansson, Kabatianskii and Smeets 1994: compact ε-ASU₂ families

J. Bierbrauer, T. Johansson, G. Kabatianskii, B. Smeets, "On families of hash functions via geometric codes and
concatenation", *Advances in Cryptology: CRYPTO '93*, LNCS 773, Springer, pp. 331-342, 1994.

- **Used:** cited by Amiri et al. (Proposition 1) for the key size of an ε-ASU₂ family. pnp doesn't use their
  construction. It uses its own two-stage family instead (docs/group.md "How it works").
- **Where:** docs/group.md (background only).

### Stinson 1994: composing universal hash families

D. R. Stinson, "Universal hashing and authentication codes", *Designs, Codes and Cryptography* 4(4),
pp. 369-380, 1994.

- **Used:** the composition result: an ε₁-almost-universal family followed by an ε₂-almost-strongly-universal
  family is (ε₁ + ε₂)-ASU₂. It gives pnp's signature hash ε = L/p + 1/4.
- **Where:** src/uss.c (top comment), docs/group.md "How it works".

### Chaum and Roijakkers 1990: unconditionally secure signatures

D. Chaum, S. Roijakkers, "Unconditionally-secure digital signatures", *Advances in Cryptology: CRYPTO '90*,
LNCS 537, Springer, pp. 206-214, 1991.

- **Used:** background only (the first USS scheme). Not implemented.
- **Where:** docs/group.md (background only).

### Hanaoka, Shikata, Zheng and Imai 2000: USS with a trusted authority

G. Hanaoka, J. Shikata, Y. Zheng, H. Imai, "Unconditionally secure digital signature schemes admitting
transferability", *Advances in Cryptology: ASIACRYPT 2000*, LNCS 1976, Springer, pp. 130-142, 2000.

- **Used:** the alternative that was considered and rejected, because it needs a trusted authority that knows
  everyone's keys.
- **Where:** docs/group.md (background: the alternative not taken).

### Amiri, Abidin, Wallden and Andersson 2018: USS from universal hashing

R. Amiri, A. Abidin, P. Wallden, E. Andersson, "Efficient unconditionally secure signatures using universal
hashing", *Applied Cryptography and Network Security (ACNS 2018)*, LNCS 10892, Springer, pp. 143-162, 2018.
doi:10.1007/978-3-319-93387-0_8. Open copy:
https://www.esat.kuleuven.be/cosic/publications/article-2892.pdf

- **Used:**
  - Definitions 1-9: the USS scheme, verification levels, the ε-ASU₂ family, majority-vote disputes, forging,
    non-transferability and repudiation.
  - Section 3: the protocol. The signer makes N²k functions. Each recipient splits its Nk at random into N sets
    of k and passes one set to each other recipient. The acceptance test is test (1) and rule (2), with
    δ_l = 1/2 + (l+1)·d_R and d_R = (ω−1)/N.
  - Theorems 1-3: the forging, non-transferability and repudiation bounds behind pnp's parameter table.
  - Section 5.1: the extended protocol, one distribution per message.
  - The honest-majority condition ω < (N+1)/2.
  - Section 5.2's example (51 people, k = 1700 at 10^−10), used as a sanity check on pnp's numbers.
- **Changed by pnp:**
  - The hash family: 2-bit tags with ε = 1/4 + L/p, instead of the paper's ε = 2/|T|.
  - The "≈" in Theorems 1-3 is replaced by the rigorous union bound 1−(1−p)^n ≤ np.
- **Where:** src/uss.c (scheme, levels, parameter calculator), src/meeting.c (distribution), tests/uss_vectors.py and
  tests/test_uss.c (the parameter table), docs/group.md.

### Davis 2001: sign-and-encrypt done wrong

D. Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML", *Proceedings of the 2001 USENIX
Annual Technical Conference*, pp. 65-78, 2001. Open copy:
https://www.usenix.org/legacy/events/usenix01/full_papers/davis/davis_html/index.html

- **Used:**
  - §1.1, surreptitious forwarding: after sign-then-encrypt, the recipient can re-encrypt the signed message to a
    third party, who will assume it was sent to them directly.
  - §1.2, "Don't Sign Ciphertexts": the case against encrypt-then-sign.
  - §3.2, the naming repairs: sign the recipient's name along with the message (§3.2, on I'Anson's X.509 repair),
    and put the sender's name inside the encryption (eqn 19).
  - pnp's message frame puts both names inside both layers and signs before encrypting.
- **Changed by pnp:**
  - The paper is about public-key mail. In pnp, the encryption is an OTP with pairwise pools, and the signature is
    the group scheme.
  - Encrypt-then-sign is worse with an OTP than in the paper's setting: a recipient can make up a pad that opens a
    ciphertext to any text at all.
- **Checked:** §§1-4.3 were read verbatim. §5 ("Repair Options") hasn't been read in full yet (still to pin), so
  nothing here relies on it.
- **Where:** src/gmsg.c (the frame: names inside the signature and the encryption), docs/group.md.

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
