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
    int ct1 = is(b, MAGIC_CT_V1), key1 = is(b, MAGIC_KEY_V1);
    int keyp = is(b, MAGIC_KEY_P), sharep = is(b, MAGIC_SHARE_P);
    if (ct1 || is(b, MAGIC_CT))
        h->kind = PNP_H_CT;
    else if (key1 || keyp || is(b, MAGIC_KEY))
        h->kind = PNP_H_KEY;
    else if (sharep || is(b, MAGIC_SHARE))
        h->kind = PNP_H_SHARE;
    else
        return PNP_HDR_NOT_PNP;
    memcpy(h->id, b + MAGIC_LEN, ID_LEN);
    h->version = ct1 || key1 ? 1 : 2;
    h->prot = keyp || sharep;
    h->len = HEADER_LEN;
    uint64_t trailer = h->version == 1 ? 0 : h->kind == PNP_H_CT ? PNP_MAC_TAG_LEN : PNP_MAC_KEY_LEN;
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
    h->body = size - h->len - trailer;
    return PNP_HDR_OK;
}
