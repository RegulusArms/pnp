/* ChaCha20 (RFC 8439 section 2.4), the stream cipher --protect wraps the key with. See protect.c. */
#ifndef PNP_CHACHA20_H
#define PNP_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

struct pnp_chacha20 {
    uint32_t state[16];
    uint8_t ks[64]; /* the current keystream block */
    unsigned used;  /* bytes of it used */
};

/* key 32 bytes, nonce 12 bytes, block counter starting at 0 */
void pnp_chacha20_init(struct pnp_chacha20 *c, const uint8_t key[32], const uint8_t nonce[12]);
/* XORs the next n keystream bytes into buf (encrypting and decrypting are the same) */
void pnp_chacha20_xor(struct pnp_chacha20 *c, uint8_t *buf, size_t n);

#endif
