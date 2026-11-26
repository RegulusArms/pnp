/* ChaCha20 from RFC 8439 section 2.3-2.4: only additions, rotations and XORs, so it takes the same time whatever the
 * key (no tables to leak through the cache). Checked against Python's cryptography package in tests/test_kdf.c. */
#define _GNU_SOURCE
#include "chacha20.h"

#include <string.h>

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define QR(a, b, c, d)                                                                                                \
    do {                                                                                                              \
        x[a] += x[b];                                                                                                 \
        x[d] = rotl(x[d] ^ x[a], 16);                                                                                 \
        x[c] += x[d];                                                                                                 \
        x[b] = rotl(x[b] ^ x[c], 12);                                                                                 \
        x[a] += x[b];                                                                                                 \
        x[d] = rotl(x[d] ^ x[a], 8);                                                                                  \
        x[c] += x[d];                                                                                                 \
        x[b] = rotl(x[b] ^ x[c], 7);                                                                                  \
    } while (0)

/* the next 64-byte keystream block: 20 rounds (10 column + diagonal pairs), add the input, then count on */
static void block(struct pnp_chacha20 *c)
{
    uint32_t x[16];
    memcpy(x, c->state, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(0, 4, 8, 12);
        QR(1, 5, 9, 13);
        QR(2, 6, 10, 14);
        QR(3, 7, 11, 15);
        QR(0, 5, 10, 15);
        QR(1, 6, 11, 12);
        QR(2, 7, 8, 13);
        QR(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + c->state[i];
        for (int j = 0; j < 4; j++)
            c->ks[4 * i + j] = (uint8_t)(v >> (8 * j));
    }
    c->state[12]++; /* 2^32 blocks = 256 GiB per key; pnp checks the key length against that (protect.c) */
    c->used = 0;
    explicit_bzero(x, sizeof x);
}

void pnp_chacha20_init(struct pnp_chacha20 *c, const uint8_t key[32], const uint8_t nonce[12])
{
    c->state[0] = 0x61707865; /* "expand 32-byte k" */
    c->state[1] = 0x3320646e;
    c->state[2] = 0x79622d32;
    c->state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        c->state[4 + i] = load32(key + 4 * i);
    c->state[12] = 0;
    for (int i = 0; i < 3; i++)
        c->state[13 + i] = load32(nonce + 4 * i);
    c->used = sizeof c->ks; /* none yet */
}

void pnp_chacha20_xor(struct pnp_chacha20 *c, uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (c->used == sizeof c->ks)
            block(c);
        buf[i] ^= c->ks[c->used++];
    }
}
