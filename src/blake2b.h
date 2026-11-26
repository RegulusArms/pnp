/* BLAKE2b (RFC 7693), unkeyed, any output length 1..64. Used by Balloon and Argon2id (src/kdf.c). */
#ifndef PNP_BLAKE2B_H
#define PNP_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define PNP_BLAKE2B_OUT 64

struct pnp_blake2b {
    uint64_t h[8], t[2];
    uint8_t b[128];
    size_t c;      /* bytes in b */
    size_t outlen;
};

void pnp_blake2b_init(struct pnp_blake2b *s, size_t outlen);
void pnp_blake2b_update(struct pnp_blake2b *s, const void *in, size_t n);
void pnp_blake2b_final(struct pnp_blake2b *s, uint8_t *out); /* writes outlen bytes, then wipes s */
void pnp_blake2b(uint8_t *out, size_t outlen, const void *in, size_t n);

#endif
