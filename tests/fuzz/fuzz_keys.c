/* Fuzzing pnp_key_decode (src/keys.c): the interactive mode's keyboard input, which can be any bytes (a paste, a
 * misbehaving terminal). The whole input is decoded key by key until it runs out. */
#include "keys.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct src {
    const uint8_t *p;
    size_t left;
};

static int next(void *ctx, int wait_ms)
{
    (void)wait_ms;
    struct src *s = ctx;
    if (!s->left)
        return PNP_KEY_EOF;
    s->left--;
    return *s->p++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct src s = {data, size};
    for (;;) {
        size_t before = s.left;
        int k = pnp_key_decode(next, &s);
        if (!(k >= 0 && k <= 255) && !(k >= K_NONE && k <= K_QUIT))
            abort();
        if (before == 0) { /* the end of input is K_QUIT, and nothing else */
            if (k != K_QUIT)
                abort();
            break;
        }
        if (s.left >= before) /* every key press consumes input */
            abort();
    }
    return 0;
}
