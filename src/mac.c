/* The integrity check: a one-time MAC that stays secure even if P = NP.
 *
 * A one-time pad hides the contents but doesn't detect changes. HMAC or a hash would detect them, but only
 * computationally (a forger who could break SHA-2 could forge them), which would undo the point of pnp. So pnp uses a
 * Wegman-Carter MAC instead, which is information-theoretically secure, like the pad:
 *
 *   tag = (h_k(M) + s) mod p,   p = 2^127 - 1 (a prime)
 *   h_k(M) = m_1 k^(L+1) + m_2 k^L + ... + m_L k^2 + len k   (mod p), evaluated with Horner's rule
 *
 * where M is cut into 8-byte little-endian blocks m_1..m_L (the last one padded with zeros) and len is M's length in
 * bytes. k and s are fresh hardware-random values below p, made for this one file and never used again; they're
 * stored in the key, so only the key's holder can make or check a tag.
 *
 * Why a forgery fails, however much computing power is used:
 *   - s is uniform and used once, so the tag (stored in the ciphertext, readable by anyone) reveals nothing about k.
 *   - For two different messages, h_k(M) - h_k(M') is a nonzero polynomial in k of degree at most L+1 (if the
 *     lengths differ, the len coefficients differ; if not, some block differs). So it has at most L+1 roots, and a
 *     forger's change goes unnoticed with probability at most (L+1)/p: about 2^-90 for a 1 TiB file.
 * pnp MACs ID || plaintext (main.c). A change to the ciphertext XORs a nonzero difference into some plaintext blocks,
 * which (whatever the plaintext is) changes those coefficients, so the same bound holds. Damage to the key's pad is
 * caught the same way, and damage to k or s makes the tag wrong. */
#define _GNU_SOURCE
#include "mac.h"

#include <string.h>

#define P (((pnp_u128)1 << 127) - 1)

/* x mod p for any 128-bit x: 2^127 = 1 (mod p), so fold the top bit down, then subtract p once if needed */
static pnp_u128 canon(pnp_u128 x)
{
    x = (x & P) + (x >> 127); /* at most 2^127 = p + 1 */
    return x >= P ? x - P : x;
}

static pnp_u128 add(pnp_u128 a, pnp_u128 b) { return canon(a + b); } /* a, b < p: no overflow */

/* a * b mod p for a, b < p: the 254-bit product as hi * 2^128 + lo from four 64x64-bit products, then
 * 2^128 = 2 (mod p) */
static pnp_u128 mul(pnp_u128 a, pnp_u128 b)
{
    uint64_t a0 = (uint64_t)a, a1 = (uint64_t)(a >> 64), b0 = (uint64_t)b, b1 = (uint64_t)(b >> 64);
    pnp_u128 p00 = (pnp_u128)a0 * b0, p11 = (pnp_u128)a1 * b1;
    pnp_u128 mid = (pnp_u128)a0 * b1 + (pnp_u128)a1 * b0; /* a1, b1 < 2^63: each < 2^127, no overflow */
    pnp_u128 lo = p00 + (mid << 64);
    pnp_u128 hi = p11 + (mid >> 64) + (lo < p00); /* < 2^127 */
    return add(canon(lo), canon(hi << 1));
}

static pnp_u128 load(const uint8_t *b, unsigned n)
{
    pnp_u128 v = 0;
    for (unsigned i = n; i-- > 0;)
        v = (v << 8) | b[i];
    return v;
}

static void store(uint8_t *b, pnp_u128 v)
{
    for (int i = 0; i < 16; i++, v >>= 8)
        b[i] = (uint8_t)v;
}

int pnp_mac_key_fix(uint8_t key[PNP_MAC_KEY_LEN])
{
    key[15] &= 0x7f;
    key[31] &= 0x7f;
    return load(key, 16) == P || load(key + 16, 16) == P ? -1 : 0;
}

int pnp_mac_init(struct pnp_mac *m, const uint8_t key[PNP_MAC_KEY_LEN])
{
    memset(m, 0, sizeof *m);
    m->k = load(key, 16);
    m->s = load(key + 16, 16);
    return m->k < P && m->s < P ? 0 : -1;
}

static void block(struct pnp_mac *m, pnp_u128 v) { m->acc = mul(add(m->acc, v), m->k); }

void pnp_mac_feed(struct pnp_mac *m, const uint8_t *buf, size_t n)
{
    m->total += n;
    while (n) {
        if (m->npart == 0 && n >= 8) { /* whole blocks straight from buf */
            block(m, load(buf, 8));
            buf += 8;
            n -= 8;
            continue;
        }
        m->part[m->npart++] = *buf++;
        n--;
        if (m->npart == 8) {
            block(m, load(m->part, 8));
            m->npart = 0;
        }
    }
}

void pnp_mac_final(struct pnp_mac *m, uint8_t tag[PNP_MAC_TAG_LEN])
{
    if (m->npart)
        block(m, load(m->part, m->npart)); /* the last block, zero-padded */
    block(m, m->total);
    store(tag, add(m->acc, m->s));
    explicit_bzero(m, sizeof *m); /* k and s are secret */
}

int pnp_mac_tag_cmp(const uint8_t a[PNP_MAC_TAG_LEN], const uint8_t b[PNP_MAC_TAG_LEN])
{
    uint8_t d = 0;
    for (int i = 0; i < PNP_MAC_TAG_LEN; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d != 0;
}
