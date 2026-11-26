/* The pad's random bytes: hardware sources read directly, checked while they're read, combined with XOR.
 * See rng.c for the design. */
#ifndef PNP_RNG_H
#define PNP_RNG_H

#include <stddef.h>
#include <stdint.h>

/* SP 800-90B 4.4 continuous health tests on one source's raw bytes (one byte = one sample).
 * Cutoffs for an assessed min-entropy of H = 4 bits per byte (half of full entropy, deliberately low) and a false
 * alarm rate of alpha = 2^-40 per test:
 *   Repetition Count Test: C = 1 + ceil(40 / H) = 11 identical bytes in a row fails.
 *   Adaptive Proportion Test: window W = 512; C = the smallest c with P(X >= c) <= 2^-40, X ~ Binomial(512, 2^-4),
 *   which is 78: the window's first byte seen 78 or more times in the window fails.
 * Good sources have close to 8 bits per byte, so a false alarm is far rarer than 2^-40. */
#define PNP_RCT_CUTOFF 11
#define PNP_APT_WINDOW 512
#define PNP_APT_CUTOFF 78

struct pnp_health {
    uint8_t rct_last;
    unsigned rct_run;    /* 0 = no sample yet */
    uint8_t apt_first;
    unsigned apt_count;
    unsigned apt_seen;   /* samples so far in the current window, 0 = start a new one */
};

void pnp_health_init(struct pnp_health *h);
/* Feeds n bytes to the tests. Returns 0, or -1 when a test fails (and the source must not be used). */
int pnp_health_feed(struct pnp_health *h, const uint8_t *buf, size_t n);

/* Start-up test (SP 800-90B 4.3): this many bytes are read, health-tested and thrown away before a source is used. */
#define PNP_STARTUP_BYTES 4096

enum pnp_source_state {
    PNP_SRC_OK,          /* in use */
    PNP_SRC_ABSENT,      /* not on this machine */
    PNP_SRC_DENIED,      /* there, but this user may not read it (/dev/hwrng without the pnp group) */
    PNP_SRC_FAILED,      /* there, but it failed to read or failed the start-up health test */
};

#define PNP_MAX_SOURCES 2

struct pnp_source {
    const char *name;            /* "/dev/hwrng", "RDSEED" */
    char detail[96];             /* what's behind it (the kernel's current hwrng), or why it isn't used */
    enum pnp_source_state state;
    int fd;
    struct pnp_health health;
};

struct pnp_rng {
    struct pnp_source src[PNP_MAX_SOURCES];
    int count;
    int hardware_ok;             /* how many hardware sources are in use */
};

/* Finds and start-up-tests every hardware source. Never fails: check rng->hardware_ok (0 = refuse to encrypt). */
void pnp_rng_open(struct pnp_rng *rng);
/* Fills buf with n pad bytes: the XOR of every source in use, and getrandom(). Returns 0, or -1 with errno set
 * (EIO: a source failed a health test or stopped; EINTR: interrupted by a signal) and a message in err. */
int pnp_rng_fill(struct pnp_rng *rng, uint8_t *buf, size_t n, char *err, size_t errlen);
void pnp_rng_close(struct pnp_rng *rng);
/* "/dev/hwrng (ccp-1-rng) + RDSEED + getrandom" */
void pnp_rng_describe(const struct pnp_rng *rng, char *out, size_t outlen);

#endif
