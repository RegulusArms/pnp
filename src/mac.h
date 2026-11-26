/* The integrity check: a one-time MAC that stays secure even if P = NP. See mac.c for the design. */
#ifndef PNP_MAC_H
#define PNP_MAC_H

#include <stddef.h>
#include <stdint.h>

/* the arithmetic is mod p = 2^127 - 1 on unsigned 128-bit integers (a GCC/Clang extension) */
__extension__ typedef unsigned __int128 pnp_u128;

#define PNP_MAC_KEY_LEN 32 /* k then s, 16 bytes each, little-endian, both < p */
#define PNP_MAC_TAG_LEN 16 /* little-endian, < p */

struct pnp_mac {
    pnp_u128 k, s;   /* the one-time keys */
    pnp_u128 acc;    /* the polynomial so far */
    uint8_t part[8]; /* bytes of a block not yet complete */
    unsigned npart;
    uint64_t total;  /* message bytes fed so far */
};

/* Makes a fresh MAC key from 32 random bytes in place: clears the top bit of k and of s, so each is a uniform
 * value below 2^127. Returns 0, or -1 if one of them came out as p itself (chance 2^-127 each): draw new bytes. */
int pnp_mac_key_fix(uint8_t key[PNP_MAC_KEY_LEN]);
/* Starts a MAC with the 32-byte key. Returns -1 if k or s isn't below p (a damaged key). */
int pnp_mac_init(struct pnp_mac *m, const uint8_t key[PNP_MAC_KEY_LEN]);
void pnp_mac_feed(struct pnp_mac *m, const uint8_t *buf, size_t n);
/* Finishes the MAC and writes its 16-byte tag. */
void pnp_mac_final(struct pnp_mac *m, uint8_t tag[PNP_MAC_TAG_LEN]);
/* 0 when the two tags are equal (compared in constant time) */
int pnp_mac_tag_cmp(const uint8_t a[PNP_MAC_TAG_LEN], const uint8_t b[PNP_MAC_TAG_LEN]);

#endif
