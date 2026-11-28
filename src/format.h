/* pnp's file headers (docs/format.md): the magics and lengths, shared by main.c, which reads and writes them, and
 * tui.c, which only peeks at them to tell ciphertexts, keys and shares apart and match them up. Both read headers
 * with pnp_hdr_parse (format.c). */
#ifndef PNP_FORMAT_H
#define PNP_FORMAT_H

#include "protect.h"

#include <stddef.h>
#include <stdint.h>

#define MAGIC_LEN 8
#define ID_LEN 16
#define HEADER_LEN (MAGIC_LEN + ID_LEN)       /* ciphertext and whole key */
#define SHARE_HEADER_LEN (HEADER_LEN + 2)     /* a key share: then its number (1..count) and the count */
#define PNP_HDR_MAX (SHARE_HEADER_LEN + PNP_PROTECT_LEN) /* the longest header: a protected share's */
/* "PNP" + the kind + the format version.
 * Version 003 (the default): the ciphertext is a container, a circle of n random-looking bytes (no trailer), and
 * a key opens one range of it. Every key's (or share's) material starts with the range prefix (PNP_RANGE_LEN:
 * offset LE64, length LE64, the MAC key, the tag pad), then the pad: length bytes (short form) or n (padded form,
 * the rest random). docs/format.md has the layout.
 * Version 002 (--format 2): the key's (or each share's) body starts with the MAC key (PNP_MAC_KEY_LEN), and the
 * ciphertext ends with the tag (PNP_MAC_TAG_LEN). Version 001 (pnp 0.1.0-alpha.2 and older; no shares) is still
 * decrypted, without a check, and never written. */
static const char MAGIC_CT[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '3'};
static const char MAGIC_KEY[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '3'};
static const char MAGIC_SHARE[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'H', '0', '0', '3'};
/* a key or share protected with a passphrase (--protect): the protection block (PNP_PROTECT_LEN) follows the header */
static const char MAGIC_KEY_P[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'P', '0', '0', '3'};
static const char MAGIC_SHARE_P[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'P', '0', '0', '3'};
static const char MAGIC_CT_V2[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '2'};
static const char MAGIC_KEY_V2[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '2'};
static const char MAGIC_SHARE_V2[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'H', '0', '0', '2'};
static const char MAGIC_KEY_P_V2[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'P', '0', '0', '2'};
static const char MAGIC_SHARE_P_V2[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'P', '0', '0', '2'};
static const char MAGIC_CT_V1[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '1'};
static const char MAGIC_KEY_V1[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '1'};

/* format 003: a range's tag is stored XORed with the tag pad, so its bytes are uniform like the noise around it
 * (a clear tag is < 2^127 - 1, so one bit of it would always be 0) */
#define PNP_RANGE_LEN (8 + 8 + 32 + 16) /* offset, length, MAC key (k, s), tag pad */
#define PNP_CONTAINER_MIN ((uint64_t)1 << 20) /* the smallest automatic container: 1 MiB */

enum pnp_hdr_kind { PNP_H_NONE, PNP_H_CT, PNP_H_KEY, PNP_H_SHARE };

/* what a header says */
struct pnp_hdr {
    enum pnp_hdr_kind kind;
    int version;        /* 1 (no integrity check), 2 or 3 (a container and range keys) */
    int prot;           /* protected with a passphrase (--protect): pp holds its settings */
    int num, count;     /* a share: its number (1..count, count 2..MAX_SHARES) */
    uint8_t id[ID_LEN]; /* shared by a ciphertext and its key or shares */
    size_t len;         /* header bytes before the body (the key material or the ciphertext proper) */
    uint64_t body;      /* 001/002: the plaintext's length (size less header, MAC key or tag). 003: a container's
                         * n; a key's pad bytes (its range's length, or n when padded: size less header and
                         * PNP_RANGE_LEN) */
    struct pnp_protect pp;
};

enum {
    PNP_HDR_OK,
    PNP_HDR_NOT_PNP,     /* no pnp magic (or one from a newer version) */
    PNP_HDR_BAD_SHARE,   /* a share whose number or count is impossible */
    PNP_HDR_SHORT,       /* shorter than its header and trailer */
    PNP_HDR_BAD_PROTECT, /* a protection block with settings outside pnp_protect_decode's bounds */
};

/* Parses the first n bytes of a file of size bytes (n = min(size, PNP_HDR_MAX) is enough). Returns PNP_HDR_OK or
 * the reason it isn't a usable header; h->kind is set as soon as the magic is known, even on a later error. */
int pnp_hdr_parse(const uint8_t *b, size_t n, uint64_t size, struct pnp_hdr *h);

#endif
