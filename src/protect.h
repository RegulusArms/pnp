/* --protect: the key (or each share) encrypted under a passphrase, to make a stolen key file expensive to use.
 * Computationally secure only; see protect.c. */
#ifndef PNP_PROTECT_H
#define PNP_PROTECT_H

#include "chacha20.h"

#include <stddef.h>
#include <stdint.h>

#define PNP_PROTECT_LEN 48     /* the protection block after a protected key's or share's header (docs/format.md) */
#define PNP_PROTECT_SALT 16
#define PNP_PROTECT_CHECK 16
#define PNP_PROTECT_MIB 1024   /* default Argon2id memory */
#define PNP_PROTECT_MIB_MIN 8
#define PNP_PROTECT_MIB_MAX 65536
#define PNP_PASS_MAX 1024      /* bytes, including the terminating zero */

struct pnp_protect {
    uint32_t balloon_blocks, balloon_rounds; /* Balloon: 64-byte blocks, rounds */
    uint32_t argon_kib, argon_passes;        /* Argon2id: memory in KiB, passes (one lane) */
    uint8_t salt[PNP_PROTECT_SALT];
    uint8_t check[PNP_PROTECT_CHECK];        /* proves the passphrase right before the key is used */
};

/* New parameters for argon_mib MiB of Argon2id memory, with a fresh salt. -1 if getrandom fails. */
int pnp_protect_new(struct pnp_protect *p, uint32_t argon_mib);
void pnp_protect_encode(const struct pnp_protect *p, uint8_t out[PNP_PROTECT_LEN]);
/* -1 if the parameters are outside what pnp accepts (a damaged key, or one from a newer pnp) */
int pnp_protect_decode(struct pnp_protect *p, const uint8_t in[PNP_PROTECT_LEN]);
/* The ChaCha20 key from the passphrase (slow on purpose). lock (encrypting) also sets p->check; unlock (decrypting)
 * compares it. Return 0, -1 if the memory can't be had, or (unlock) -2 for the wrong passphrase. */
int pnp_protect_lock(struct pnp_protect *p, const char *pass, size_t passlen, uint8_t key[32]);
int pnp_protect_unlock(const struct pnp_protect *p, const char *pass, size_t passlen, uint8_t key[32]);
/* The keystream for one key file: share 1..16, or 0 for a whole key. */
void pnp_protect_stream(struct pnp_chacha20 *c, const uint8_t key[32], int share);
/* The most key material ChaCha20 can wrap with one stream (2^32 blocks of 64 bytes). */
#define PNP_PROTECT_MAX_BYTES ((uint64_t)1 << 38)

/* Reads a passphrase: the first line of file, or (file NULL) from the terminal with echo off, asked twice when
 * confirm is set. Returns its length, or -1 with the reason in err. */
long pnp_read_passphrase(const char *file, int confirm, char *buf, size_t buflen, char *err, size_t errlen);

#endif
