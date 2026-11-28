/* Fuzzing pnp_hdr_parse (src/format.c): every header pnp reads, from the command line and in the interactive
 * mode's browser, goes through it, protection blocks (pnp_protect_decode) included. The input is a whole file. */
#include "format.h"
#include "mac.h"
#include "pnp.h"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct pnp_hdr h;
    size_t n = size < PNP_HDR_MAX ? size : PNP_HDR_MAX;
    int r = pnp_hdr_parse(data, n, size, &h);
    if (r == PNP_HDR_OK) {
        /* what decrypting relies on: lengths that add up, counts in range, bounded hashing costs */
        /* 002: the tag after the body, or the MAC key before it; 003: a key's range prefix before its pad, and a
         * container (no trailer) at least a tag long */
        uint64_t trailer = h.version == 1   ? 0
                           : h.version == 3 ? (h.kind == PNP_H_CT ? 0 : PNP_RANGE_LEN)
                           : h.kind == PNP_H_CT ? PNP_MAC_TAG_LEN
                                                : PNP_MAC_KEY_LEN;
        if (h.len > n || h.len + trailer + h.body != size || (h.version == 3 && h.kind == PNP_H_CT && h.body < 16))
            abort();
        if (h.kind == PNP_H_SHARE && (h.count < 2 || h.count > MAX_SHARES || h.num < 1 || h.num > h.count))
            abort();
        if (h.prot && (h.pp.argon_kib > (uint32_t)PNP_PROTECT_MIB_MAX * 1024 || h.pp.argon_lanes > 64))
            abort();
    }
    /* the same bytes with a larger file size claimed: the parser must still read only n bytes */
    pnp_hdr_parse(data, n, (uint64_t)size + 1000, &h);
    return 0;
}
