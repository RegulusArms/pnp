/* Decoding key presses for the interactive mode (tui.c). What a terminal sends is untrusted input like any file:
 * a paste, a misbehaving terminal or a program writing to it can send any bytes at all. So this reads at most what
 * one sequence needs, keeps every number bounded, and never waits on more than the source gives. tests/fuzz/
 * runs it on arbitrary bytes. */
#include "keys.h"

int pnp_key_decode(pnp_key_source next, void *ctx)
{
    int c = next(ctx, -1);
    if (c == PNP_KEY_EINTR)
        return K_NONE; /* a resize, or a signal: the caller checks pnp_stop */
    if (c < 0)
        return K_QUIT; /* the terminal went away */
    if (c == '\r' || c == '\n')
        return K_ENTER;
    if (c == 127 || c == 8)
        return K_BKSP;
    if (c == 3 || c == 4) /* Ctrl-C, Ctrl-D */
        return K_QUIT;
    if (c != 27)
        return c;
    /* Esc alone, or the start of an arrow key's sequence (Esc [ A, Esc O A, Esc [ 5 ~ ...): wait briefly for more */
    int s0 = next(ctx, 50);
    if (s0 != '[' && s0 != 'O')
        return K_ESC;
    int s1 = next(ctx, -1);
    switch (s1) {
    case 'A': return K_UP;
    case 'B': return K_DOWN;
    case 'C': return K_RIGHT;
    case 'D': return K_LEFT;
    case 'H': return K_HOME;
    case 'F': return K_END;
    }
    if (s1 < '0' || s1 > '9')
        return s1 < 0 ? K_ESC : K_NONE;
    /* Esc [ number ~ : the number is read whole (so the sequence is swallowed), but only small ones mean anything
     * here, so it stops growing past 1000 instead of overflowing on a long run of digits */
    int n = s1 - '0', d;
    while ((d = next(ctx, -1)) >= '0' && d <= '9')
        if (n < 1000)
            n = n * 10 + (d - '0');
    switch (n) {
    case 1: case 7: return K_HOME;
    case 4: case 8: return K_END;
    case 5: return K_PGUP;
    case 6: return K_PGDN;
    }
    return K_NONE;
}
