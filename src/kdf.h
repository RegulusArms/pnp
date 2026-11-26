/* Memory-hard password hashing for --protect: Balloon (BLAKE2b) and Argon2id. See kdf.c. These are only
 * computationally secure: they make guessing a passphrase expensive, they're not part of pnp's P = NP guarantee. */
#ifndef PNP_KDF_H
#define PNP_KDF_H

#include <stddef.h>
#include <stdint.h>

#define PNP_BALLOON_BLOCK 64 /* bytes: one BLAKE2b-512 output */

/* Balloon hashing with BLAKE2b-512 and delta = 3: s_cost blocks of 64 bytes (>= 2), t_cost rounds (>= 1). Writes
 * 64 bytes. Returns 0, or -1 if the memory can't be had or the costs are out of range. */
int pnp_balloon(uint8_t out[PNP_BALLOON_BLOCK], const uint8_t *pwd, size_t pwdlen, const uint8_t *salt,
                size_t saltlen, uint64_t s_cost, uint32_t t_cost);

/* Argon2id version 0x13 (RFC 9106): m_kib KiB of memory (>= 8 * lanes), t passes (>= 1), lanes (1..255, computed one
 * after another: pnp has no threads). secret and ad may be empty (NULL, 0). Writes outlen (4..1024) bytes. Returns
 * 0, or -1 if the memory can't be had or a parameter is out of range. */
int pnp_argon2id(uint8_t *out, size_t outlen, const uint8_t *pwd, size_t pwdlen, const uint8_t *salt, size_t saltlen,
                 const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen, uint32_t m_kib, uint32_t t,
                 uint32_t lanes);

#endif
