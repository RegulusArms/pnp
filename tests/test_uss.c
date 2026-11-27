#define _GNU_SOURCE
/* Unit tests of the group signature's hash family and parameters (src/uss.c).
 *   - vectors from tests/uss_vectors.py, an independent implementation written from the definitions
 *   - the second stage is exactly strongly universal: checked exhaustively at a reduced width (4-bit x, so every
 *     A and c can be tried), and seen to fail when c is cut to one bit (so the check can fail)
 *   - the parameter calculator gives the table in tests/uss_vectors.h, refuses impossible combinations, and its
 *     defaults are docs/group.md's
 *   - the level rules at their boundaries
 *   - the same tags whatever the number of threads */
#include "mac.h"
#include "uss.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uss_vectors.h"

static int fails;
#define CHECK(c, what)                                                                                                \
    do {                                                                                                              \
        if (c)                                                                                                        \
            printf("PASS %s\n", what);                                                                                \
        else {                                                                                                        \
            printf("FAIL %s\n", what);                                                                                \
            fails++;                                                                                                  \
        }                                                                                                             \
    } while (0)

static const char *MSGS[] = {"", "a", "12345678", "123456789", NULL, "pnp meeting test"};

static int tag_on(const uint8_t fn[USS_FN_LEN], const uint8_t *m, size_t n)
{
    struct pnp_mac mac;
    uint8_t key[32] = {0}, x[16];
    memcpy(key, fn, 16);
    pnp_mac_init(&mac, key);
    pnp_mac_feed(&mac, m, n);
    pnp_mac_final(&mac, x);
    return uss_tag_of(fn, x);
}

/* counts, over every function (a0, a1 < 16, c < cmax), how often (f(x), f(x')) is each of the 16 tag pairs */
static int strongly_universal(int cmax)
{
    for (uint64_t x = 0; x < 16; x++)
        for (uint64_t y = 0; y < 16; y++) {
            if (x == y)
                continue;
            int count[4][4] = {{0}}, total = 0;
            for (uint64_t a0 = 0; a0 < 16; a0++)
                for (uint64_t a1 = 0; a1 < 16; a1++)
                    for (int c = 0; c < cmax; c++) {
                        count[uss_stage2(a0, a1, c, x)][uss_stage2(a0, a1, c, y)]++;
                        total++;
                    }
            for (int t = 0; t < 4; t++)
                for (int u = 0; u < 4; u++)
                    if (count[t][u] * 16 != total)
                        return 0;
        }
    return 1;
}

int main(void)
{
    uint8_t m100[100];
    for (int i = 0; i < 100; i++)
        m100[i] = (uint8_t)i;
    int ok = 1;
    for (size_t i = 0; i < sizeof VEC / sizeof VEC[0]; i++) {
        const uint8_t *m = VEC[i].msg == 4 ? m100 : (const uint8_t *)MSGS[VEC[i].msg];
        size_t n = VEC[i].msg == 4 ? 100 : strlen(MSGS[VEC[i].msg]);
        ok &= tag_on(VEC[i].fn, m, n) == VEC[i].tag;
    }
    CHECK(ok, "hash family: tags match the independent Python implementation (48 vectors)");

    CHECK(strongly_universal(4), "second stage: exactly strongly universal (every x != x', every tag pair: |F|/16)");
    CHECK(!strongly_universal(2), "second stage: with c cut to one bit it isn't (the check can fail)");

    ok = 1;
    for (size_t i = 0; i < sizeof KTAB / sizeof KTAB[0]; i++)
        ok &= uss_k(KTAB[i].N, KTAB[i].omega, KTAB[i].lmax) == KTAB[i].k;
    CHECK(ok, "parameters: k matches the independent table for every allowed combination (2-8 recipients)");
    CHECK(!uss_valid(4, 2, 1) && !uss_valid(8, 4, 1) && !uss_valid(4, 3, 0) && uss_k(4, 2, 1) == 0,
          "parameters: combinations the paper doesn't allow are refused");
    static const int want[][2] = {{1, 1}, {1, 1}, {2, 0}, {2, 1}, {3, 0}, {3, 0}, {4, 0}};
    ok = 1;
    for (int n = 3; n <= 9; n++) {
        int w, l;
        uss_defaults(n, &w, &l);
        ok &= w == want[n - 3][0] && l == want[n - 3][1];
    }
    CHECK(ok, "parameters: the defaults for 3-9 people (most cheaters, then most hand-ons up to 1)");

    /* k = 1600, l_max = 1: s = 0.49, 0.25, 0.01, so fewer than 784, 400 and 16 mismatches */
    CHECK(uss_set_passes(15, 1600, 1, 1) && !uss_set_passes(16, 1600, 1, 1) && uss_set_passes(399, 1600, 0, 1) &&
              !uss_set_passes(400, 1600, 0, 1) && uss_set_passes(783, 1600, -1, 1) &&
              !uss_set_passes(784, 1600, -1, 1),
          "levels: a set passes below s_l·k mismatches, exactly at the boundary");
    /* N = 4, ω = 2: δ_0 = 1/2 + 1/4, so more than 3 of 4 sets; δ_-1 = 1/2, more than 2 */
    CHECK(uss_accepts(4, 4, 0, 2) && !uss_accepts(3, 4, 0, 2) && uss_accepts(3, 4, -1, 2) &&
              !uss_accepts(2, 4, -1, 2),
          "levels: accepted with more than N·δ_l sets passed");

    /* the same tags whatever the number of threads (PNP_TEST_THREADS, test builds) */
    size_t nf = 2000;
    uint8_t *fns = malloc(nf * USS_FN_LEN), *a = malloc(nf), *b = malloc(nf), *big = malloc(3 << 20);
    for (size_t i = 0; i < nf * USS_FN_LEN; i++)
        fns[i] = (uint8_t)(i * 131 + 7);
    for (size_t i = 0; i < nf; i++)
        uss_fn_fix(fns + i * USS_FN_LEN);
    for (size_t i = 0; i < (3u << 20); i++)
        big[i] = (uint8_t)(i * 31);
    setenv("PNP_TEST_THREADS", "1", 1);
    struct uss_eval *e = uss_eval_new(fns, USS_FN_LEN, nf);
    uss_eval_feed(e, big, 3 << 20);
    uss_eval_finish(e, a);
    setenv("PNP_TEST_THREADS", "7", 1);
    e = uss_eval_new(fns, USS_FN_LEN, nf);
    uss_eval_feed(e, big, 1 << 20);
    uss_eval_feed(e, big + (1 << 20), 2 << 20);
    uss_eval_finish(e, b);
    CHECK(memcmp(a, b, nf) == 0, "threads: the same tags with 1 thread and with 7, fed in different pieces");
    free(fns), free(a), free(b), free(big);
    return fails;
}
