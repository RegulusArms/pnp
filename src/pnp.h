/* What main.c offers the interactive mode (tui.c), and the interactive mode's entry point. */
#ifndef PNP_PNP_H
#define PNP_PNP_H

#include <stddef.h>
#include <stdint.h>

#define MAX_SHARES 16 /* also the most key files decrypting takes */

/* --protect and its settings */
struct protect_opts {
    int on;
    uint32_t mib;         /* Argon2id memory */
    const char *passfile; /* NULL: ask on the terminal (or use the preset passphrase) */
};

/* the format written (--format, --size, --key-form) */
struct format_opts {
    int version;   /* 3 (a container: the default) or 2 (ciphertext as long as the file, + its tag) */
    uint64_t size; /* 003: the container's size in bytes; 0 = automatic (a power of two, at least 1 MiB) */
    int padded;    /* 003: keys padded to the length of a key for the whole container (--key-form padded) */
};

/* Encrypts in_path to out_opt (default in_path.pnp), with the key (or each share) at key_outs (folders or file
 * names; none: beside the ciphertext). The same as the command line. Returns 0, or 1 after saying why. */
int pnp_encrypt(const char *in_path, const char *out_opt, char *const *key_outs, int n_key_outs, int shares,
                int force, int verbose, const struct protect_opts *po, const struct format_opts *fo);
/* Decrypts ct_path with the key files given (none: found beside it). With verify, does every check decrypting
 * does (headers, IDs, sizes, the integrity check) but writes nothing (--verify). Returns 0, or 1 or 2 after saying
 * why. */
int pnp_decrypt(const char *ct_path, char *const *key_opts, int n_key_opts, const char *out_opt, int force,
                const char *passfile, int verify);
/* A passphrase used instead of asking, until cleared (for a batch of files). */
void pnp_preset_passphrase(const char *p, size_t len);
void pnp_clear_passphrase(void);
/* n words from the EFF list into buf, chosen with the hardware sources. 0, or -1 after saying why. */
int pnp_make_passphrase(int n, char *buf, size_t len, int verbose);

/* a scratch passphrase buffer of PNP_PASS_MAX bytes (which: 0 or 1) in main.c's locked, wiped region: for the
 * interactive mode's passphrases, so no copy sits in unlocked memory */
char *pnp_secure_buf(int which);

/* replaces control characters in s with "?", so a file name printed can't drive the terminal */
void pnp_clean(char *s);

/* the interactive mode: "pnp" alone in a terminal */
int pnp_tui(void);

#endif
