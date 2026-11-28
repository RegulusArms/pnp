/* Reading pnp's file headers (docs/format.md, format.h): the one parser for every header pnp reads, used by main.c
 * (decrypting, --verify) and tui.c (telling files apart in the browser). Headers come from files anyone could have
 * made or damaged, so this works on a byte buffer only, checks every length and bound, and never trusts a count
 * or size it reads. tests/fuzz/ runs it on arbitrary bytes. */
#include "format.h"
#include "mac.h"
#include "pnp.h"

#include <string.h>

static int is(const uint8_t *b, const char *magic) { return memcmp(b, magic, MAGIC_LEN) == 0; }

int pnp_hdr_parse(const uint8_t *b, size_t n, uint64_t size, struct pnp_hdr *h)
{
    memset(h, 0, sizeof *h);
    if (n > size)
        n = (size_t)size; /* never read past what the file holds */
    if (n < HEADER_LEN)
        return PNP_HDR_NOT_PNP;
    static const struct {
        const char *magic;
        enum pnp_hdr_kind kind;
        int version, prot;
    } known[] = {
        {MAGIC_CT, PNP_H_CT, 3, 0},           {MAGIC_KEY, PNP_H_KEY, 3, 0},
        {MAGIC_SHARE, PNP_H_SHARE, 3, 0},     {MAGIC_KEY_P, PNP_H_KEY, 3, 1},
        {MAGIC_SHARE_P, PNP_H_SHARE, 3, 1},   {MAGIC_CT_V2, PNP_H_CT, 2, 0},
        {MAGIC_KEY_V2, PNP_H_KEY, 2, 0},      {MAGIC_SHARE_V2, PNP_H_SHARE, 2, 0},
        {MAGIC_KEY_P_V2, PNP_H_KEY, 2, 1},    {MAGIC_SHARE_P_V2, PNP_H_SHARE, 2, 1},
        {MAGIC_CT_V1, PNP_H_CT, 1, 0},        {MAGIC_KEY_V1, PNP_H_KEY, 1, 0},
    };
    size_t i = 0;
    while (i < sizeof known / sizeof *known && !is(b, known[i].magic))
        i++;
    if (i == sizeof known / sizeof *known)
        return PNP_HDR_NOT_PNP;
    h->kind = known[i].kind;
    h->version = known[i].version;
    h->prot = known[i].prot;
    memcpy(h->id, b + MAGIC_LEN, ID_LEN);
    h->len = HEADER_LEN;
    /* what follows the body (002's tag) or must start it (the MAC key, 003's range prefix); 003's container has
     * neither, but holds at least one range: a tag's 16 bytes */
    uint64_t trailer = h->version == 1   ? 0
                       : h->version == 3 ? (h->kind == PNP_H_CT ? PNP_MAC_TAG_LEN : PNP_RANGE_LEN)
                       : h->kind == PNP_H_CT ? PNP_MAC_TAG_LEN
                                             : PNP_MAC_KEY_LEN;
    if (h->kind == PNP_H_SHARE) {
        if (n < SHARE_HEADER_LEN)
            return PNP_HDR_BAD_SHARE;
        h->num = b[HEADER_LEN];
        h->count = b[HEADER_LEN + 1];
        if (h->count < 2 || h->count > MAX_SHARES || h->num < 1 || h->num > h->count)
            return PNP_HDR_BAD_SHARE;
        h->len = SHARE_HEADER_LEN;
    }
    if (h->prot) {
        if (n < h->len + PNP_PROTECT_LEN)
            return PNP_HDR_SHORT;
        if (pnp_protect_decode(&h->pp, b + h->len) < 0)
            return PNP_HDR_BAD_PROTECT;
        h->len += PNP_PROTECT_LEN;
    }
    if (size < h->len + trailer)
        return PNP_HDR_SHORT;
    h->body = size - h->len - (h->version == 3 && h->kind == PNP_H_CT ? 0 : trailer);
    return PNP_HDR_OK;
}
