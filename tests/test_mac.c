/* The integrity check's one-time MAC (src/mac.c): hand-computable answers, agreement with a slow double-and-add
 * reference on random keys and messages, the same tag however the message is split, and the key range rules.
 * Prints PASS/FAIL lines like tests/run.sh; exit status = number of failures. */
#define _GNU_SOURCE
#include "mac.h"

#include <stdio.h>
#include <string.h>
#include <sys/random.h>

static int fails;
static const pnp_u128 P = ((pnp_u128)1 << 127) - 1;

static void check(int ok, const char *what)
{
    printf("%s mac: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        fails++;
}

static void rnd(void *buf, size_t n)
{
    for (size_t done = 0; done < n;) {
        ssize_t r = getrandom((char *)buf + done, n - done, 0);
        if (r > 0)
            done += (size_t)r;
    }
}

static void put(uint8_t *b, pnp_u128 v)
{
    for (int i = 0; i < 16; i++, v >>= 8)
        b[i] = (uint8_t)v;
}

static pnp_u128 get(const uint8_t *b, size_t n)
{
    pnp_u128 v = 0;
    for (size_t i = n; i-- > 0;)
        v = (v << 8) | b[i];
    return v;
}

static pnp_u128 tag_of(pnp_u128 k, pnp_u128 s, const uint8_t *msg, size_t n, size_t step)
{
    uint8_t key[32], tag[16];
    struct pnp_mac m;
    put(key, k);
    put(key + 16, s);
    if (pnp_mac_init(&m, key) < 0)
        return P; /* never a valid tag */
    for (size_t i = 0; i < n; i += step)
        pnp_mac_feed(&m, msg + i, n - i < step ? n - i : step);
    pnp_mac_final(&m, tag);
    return get(tag, 16);
}

/* the reference: the definition in mac.c, with multiplication by repeated doubling */
static pnp_u128 addm(pnp_u128 a, pnp_u128 b) { return a + b >= P ? a + b - P : a + b; }
static pnp_u128 mulm(pnp_u128 a, pnp_u128 b)
{
    pnp_u128 r = 0;
    for (int i = 126; i >= 0; i--) {
        r = addm(r, r);
        if ((b >> i) & 1)
            r = addm(r, a);
    }
    return r;
}
static pnp_u128 ref(pnp_u128 k, pnp_u128 s, const uint8_t *msg, size_t n)
{
    pnp_u128 acc = 0;
    for (size_t i = 0; i < n; i += 8)
        acc = mulm(addm(acc, get(msg + i, n - i < 8 ? n - i : 8)), k);
    acc = mulm(addm(acc, n), k);
    return addm(acc, s);
}

int main(void)
{
    static uint8_t msg[4096];
    const uint8_t *abc = (const uint8_t *)"ABCDEFGHIJ";
    pnp_u128 b1 = get(abc, 8), b2 = get(abc + 8, 2);

    /* hand-computable: k = 1 makes the tag the sum of the blocks, the length and s */
    check(tag_of(1, 5, abc, 10, 10) == b1 + b2 + 10 + 5, "k = 1: tag = blocks + length + s");
    /* k = 0: every term has a factor k, so the tag is s */
    check(tag_of(0, 12345, abc, 10, 10) == 12345, "k = 0: tag = s");
    /* k = 2, empty message: tag = 0 * 2 + s */
    check(tag_of(2, 7, abc, 0, 1) == 7, "empty message, k = 2: tag = s (the length block is 0)");
    /* k = p - 1 = -1: tag = b1 (-1)^3 + b2 (-1)^2 + 10 (-1) + s */
    check(tag_of(P - 1, 0, abc, 10, 10) == addm(addm(P - b1, b2), P - 10), "k = p - 1 (reduction near p)");

    /* random keys and messages against the reference, including the largest values */
    int same = 1, splits = 1;
    for (int t = 0; t < 200; t++) {
        uint8_t key[32];
        rnd(key, sizeof key);
        size_t n;
        rnd(&n, sizeof n);
        n %= sizeof msg;
        rnd(msg, n);
        if (t < 10)
            memset(msg, 0xff, n); /* blocks of 2^64 - 1 */
        pnp_u128 k = t == 0 ? P - 1 : get(key, 16) & P, s = t == 1 ? P - 1 : get(key + 16, 16) & P;
        if (k == P || s == P)
            continue;
        pnp_u128 want = ref(k, s, msg, n);
        same &= tag_of(k, s, msg, n, n ? n : 1) == want;
        splits &= tag_of(k, s, msg, n, 1) == want && tag_of(k, s, msg, n, 3) == want &&
                  tag_of(k, s, msg, n, 13) == want;
    }
    check(same, "200 random keys and messages match the double-and-add reference");
    check(splits, "the tag doesn't depend on how the message is split between calls");

    /* a change anywhere changes the tag (for a random key: fails with chance about 2^-115 here) */
    {
        uint8_t key[32];
        rnd(key, sizeof key);
        pnp_mac_key_fix(key);
        pnp_u128 k = get(key, 16), s = get(key + 16, 16);
        rnd(msg, 1000);
        pnp_u128 t0 = tag_of(k, s, msg, 1000, 1000);
        int all = 1;
        for (int i = 0; i < 1000; i += 37) {
            msg[i] ^= 1;
            all &= tag_of(k, s, msg, 1000, 1000) != t0;
            msg[i] ^= 1;
        }
        all &= tag_of(k, s, msg, 999, 999) != t0;
        msg[1000] = 0;
        all &= tag_of(k, s, msg, 1001, 1001) != t0; /* a zero byte appended: the length block catches it */
        check(all, "a flipped bit, a truncation or an appended zero byte changes the tag");
    }

    /* key range */
    uint8_t key[32];
    memset(key, 0xff, sizeof key);
    check(pnp_mac_key_fix(key) == -1, "a key that comes out as p itself is rejected (draw again)");
    check(key[15] == 0x7f && key[31] == 0x7f, "pnp_mac_key_fix clears the top bit of k and s");
    key[0] = 0xfe;
    key[16] = 0xfe;
    check(pnp_mac_key_fix(key) == 0, "p - 1 is a valid k and s");
    struct pnp_mac m;
    memset(key, 0xff, sizeof key);
    check(pnp_mac_init(&m, key) == -1, "pnp_mac_init refuses k or s not below p (a damaged key)");

    uint8_t a[16] = {0}, b[16] = {0};
    b[15] = 1;
    check(pnp_mac_tag_cmp(a, a) == 0 && pnp_mac_tag_cmp(a, b) != 0, "tag comparison");
    return fails;
}
