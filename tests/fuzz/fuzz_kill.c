/* Fuzzing the kill notice parser (kill_parse, src/kill.c): notices arrive as files and inside messages. */
#include "kill.h"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct kill_notice k;
    if (kill_parse(data, size, &k) == 0) {
        if (k.nsets > KILL_MAX_SETS || k.frame_len > size || k.nsig > GRP_MAX_MEMBERS)
            abort();
        for (int i = 0; i < k.nsig; i++)
            if (k.sig[i].len > size || (k.sig[i].kind != 1 && k.sig[i].kind != 2))
                abort();
        kill_free(&k);
    }
    return 0;
}
