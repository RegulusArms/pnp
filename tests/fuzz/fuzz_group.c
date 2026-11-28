/* Fuzzing the group file parser (grp_parse, src/group.c) and the signature header (uss_sig_parse): both read bytes
 * from a removable drive or a file someone sent. */
#include "group.h"
#include "uss.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct grp g;
    if (grp_parse(data, size, &g) == 0) {
        /* what the rest of pnp relies on */
        if (g.n < 2 || g.me >= g.n || g.nsets > GRP_MAX_SETS || g.threshold < 1 || g.threshold > g.n ||
            size != grp_file_len(g.n, g.nsets) || memchr(g.name, 0, sizeof g.name) == NULL)
            abort();
        for (int i = 0; i < g.nsets; i++)
            if (g.sets[i].start_day > g.sets[i].end_day || g.sets[i].suspect_member >= g.n)
                abort();
        /* it serialises back to the same bytes */
        uint8_t *b = malloc(size);
        if (b) {
            grp_serialise(&g, b);
            if (memcmp(b, data, 64) != 0)
                abort();
            free(b);
        }
        free(g.sets);
    }
    uint8_t id[GRP_ID_LEN];
    int signer, N;
    uint32_t slot, k;
    if (uss_sig_parse(data, size, id, &signer, &N, &slot, &k) == 0 && size != uss_sig_len(N, k))
        abort();
    return 0;
}
