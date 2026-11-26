/* The interactive mode's keyboard decoding (keys.c), apart from the terminal so it can be tested and fuzzed. */
#ifndef PNP_KEYS_H
#define PNP_KEYS_H

/* what pnp_key_decode returns, besides a plain character (0..255) */
enum {
    K_NONE = 1000, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN, K_HOME, K_END, K_ENTER, K_ESC, K_BKSP, K_QUIT
};

/* the byte source: the next byte (0..255), PNP_KEY_EOF at the end or when wait_ms (>= 0) passes without one, or
 * PNP_KEY_EINTR when a signal interrupted the wait. wait_ms < 0: wait as long as it takes. */
#define PNP_KEY_EOF (-1)
#define PNP_KEY_EINTR (-2)
typedef int (*pnp_key_source)(void *ctx, int wait_ms);

/* Reads one key press: a character, or an arrow, Page Up/Down, Home or End from its escape sequence, Enter,
 * Backspace, Esc alone, K_QUIT (Ctrl-C, Ctrl-D, the end of input) or K_NONE (interrupted, or a sequence pnp
 * doesn't use, which is swallowed whole). */
int pnp_key_decode(pnp_key_source next, void *ctx);

#endif
