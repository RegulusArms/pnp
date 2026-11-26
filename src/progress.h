/* A progress line for encrypting and decrypting (on stderr, only when it's a terminal). See progress.c. */
#ifndef PNP_PROGRESS_H
#define PNP_PROGRESS_H

#include <stdint.h>
#include <time.h>

struct pnp_progress {
    int on;              /* drawing at all (stderr is a terminal, not -q) */
    int drawn;           /* a line is on the screen now */
    int bytes;           /* counting bytes (sizes and speed shown), or just steps (percentage and time left) */
    const char *verb;    /* "encrypting", "decrypting" */
    char name[256];      /* the file, cleaned of control characters */
    uint64_t total, done;
    struct timespec start, last;
};

/* Starts a progress line for total bytes of name; enabled 0 makes every call a no-op. */
void pnp_progress_start(struct pnp_progress *p, const char *verb, const char *name, uint64_t total, int enabled);
/* The same for work counted in steps (the passphrase hashes): no sizes or speed. */
void pnp_progress_start_steps(struct pnp_progress *p, const char *verb, const char *name, uint64_t total,
                              int enabled);
/* n more bytes (or steps) done, or done in all: redraws now and then */
void pnp_progress_add(struct pnp_progress *p, uint64_t n);
void pnp_progress_set(struct pnp_progress *p, uint64_t done);
/* Wipes the line (when the file is done, or failed). Safe to call twice. */
void pnp_progress_end(struct pnp_progress *p);
/* Wipes the line before a message is printed; it comes back with the next update. */
void pnp_progress_interrupt(void);

#endif
