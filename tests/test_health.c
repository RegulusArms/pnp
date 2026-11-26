/* The SP 800-90B health tests (src/rng.c pnp_health_feed): each cutoff fails exactly at its limit, and random data
 * passes. Prints PASS/FAIL lines like tests/run.sh; exit status = number of failures. */
#define _GNU_SOURCE
#include "rng.h"

#include <stdio.h>
#include <string.h>
#include <sys/random.h>

static int fails;

static void check(int ok, const char *what)
{
    printf("%s health: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        fails++;
}

static int feed(const uint8_t *buf, size_t n)
{
    struct pnp_health h;
    pnp_health_init(&h);
    return pnp_health_feed(&h, buf, n);
}

int main(void)
{
    static uint8_t buf[1 << 20];

    /* Repetition Count Test: one short of the cutoff passes, the cutoff fails */
    memset(buf, 0xAB, sizeof buf);
    buf[0] = 1;
    check(feed(buf, 1 + PNP_RCT_CUTOFF - 1) == 0, "a byte repeated one time fewer than the RCT cutoff passes");
    check(feed(buf, 1 + PNP_RCT_CUTOFF) < 0, "a byte repeated RCT-cutoff times in a row fails");
    memset(buf, 0, 4096);
    check(feed(buf, 4096) < 0, "all zeros (a stuck source) fails");

    /* Adaptive Proportion Test: the window's first byte, spread out so the RCT never trips */
    {
        struct pnp_health h;
        uint8_t w[PNP_APT_WINDOW];
        for (size_t i = 0; i < sizeof w; i++)
            w[i] = (uint8_t)(i % 251 + 1); /* distinct bytes, no 0 */
        for (int i = 0; i < PNP_APT_CUTOFF - 1; i++)
            w[i * 6] = 0; /* cutoff-1 zeros, the first at position 0 */
        pnp_health_init(&h);
        check(pnp_health_feed(&h, w, sizeof w) == 0, "the window's first byte seen one time fewer than the APT cutoff passes");
        w[(PNP_APT_CUTOFF - 1) * 6] = 0;
        pnp_health_init(&h);
        check(pnp_health_feed(&h, w, sizeof w) < 0, "the window's first byte seen APT-cutoff times in a window fails");
        /* the count starts over with each window: cutoff-1 in each of two windows passes */
        uint8_t two[2 * PNP_APT_WINDOW];
        w[(PNP_APT_CUTOFF - 1) * 6] = (uint8_t)((PNP_APT_CUTOFF - 1) * 6 % 251 + 1);
        memcpy(two, w, sizeof w);
        memcpy(two + sizeof w, w, sizeof w);
        pnp_health_init(&h);
        check(pnp_health_feed(&h, two, sizeof two) == 0, "the APT count starts over in each window");
    }

    /* fed in pieces, the tests carry their state across calls */
    {
        struct pnp_health h;
        uint8_t b = 7;
        int failed = 0;
        pnp_health_init(&h);
        for (int i = 0; i < PNP_RCT_CUTOFF; i++)
            failed |= pnp_health_feed(&h, &b, 1) < 0;
        check(failed, "a repeat split across calls still fails the RCT");
    }

    /* random data passes (a false alarm is far rarer than 2^-40 per window) */
    for (size_t done = 0; done < sizeof buf;) {
        ssize_t r = getrandom(buf + done, sizeof buf - done, 0);
        if (r > 0)
            done += (size_t)r;
    }
    check(feed(buf, sizeof buf) == 0, "1 MiB of random bytes passes");

    return fails;
}
