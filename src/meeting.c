/* The meeting protocol (meeting.h; docs/group.md "The meeting wizard").
 *
 * Each member m, on m's own laptop:
 *   self:     the roster; m's signing functions (N²k per slot) for each key set; m's random contribution R_m to the
 *             two pools m shares with each other member, for each key set
 *   round 1:  onto o's courier: R_m for the pair (m, o), and m's signer block for o (the Nk functions o will split)
 *   splits:   for each other signer S, m shuffles the block S gave it (m's own hardware RNG) and cuts it into N sets
 *             of k, one per recipient of S
 *   round 2:  onto o's courier: m's set for o from every signer except o and m, a test signature (slot 0) and a
 *             test seal (the first item of the pool m -> o)
 * The owner moves each returned courier onto the self stick and overwrites the courier (meet_collect) before its
 * next visit. At home, meet_import combines it all: pool = R_m xor R_o, verify files from the sets, and checks the
 * tests. In a pair (2 members) there's no signer material: round 1 alone carries everything but the test seal.
 *
 * The custody rule this relies on: a courier only ever passes between its owner and the member it's visiting, so
 * no signer sees the sets its block was split into. */
#define _GNU_SOURCE
#include "meeting.h"
#include "fileio.h"
#include "mac.h"
#include "uss.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char TEST_MSG[] = "pnp meeting test";

static void put32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* member m's position among signer S's recipients, and back */
static int rpos(int S, int m) { return m < S ? m : m - 1; }
static int rmember(int S, int b) { return b < S ? b : b + 1; }

static uint64_t dir_len(const struct grp_set *s) { return (uint64_t)s->nloc * GRP_LOC_ENTRY + s->pool_bytes; }
uint64_t meet_pool_record_len(const struct grp_set *s) { return 2 * dir_len(s); }
static int has_sig(const struct grp *g, const struct grp_set *s) { return g->n >= 3 && s->slots > 0; }

static int fill_random(struct cwriter *w, struct pnp_rng *rng, uint64_t len, char *err, size_t errlen)
{
    uint8_t buf[65536];
    while (len) {
        size_t n = len < sizeof buf ? (size_t)len : sizeof buf;
        if (pnp_rng_fill(rng, buf, n, err, errlen) < 0)
            return -1;
        if (cs_write(w, buf, n) < 0) {
            snprintf(err, errlen, "%s: %s", w->c->path, strerror(errno));
            return -1;
        }
        len -= n;
    }
    explicit_bzero(buf, sizeof buf);
    return 0;
}

/* copies len bytes of record r (from off) in src into the open writer w */
static int copy_part(struct cstore *src, const struct crec *r, uint64_t off, uint64_t len, struct cwriter *w)
{
    uint8_t buf[65536];
    while (len) {
        size_t n = len < sizeof buf ? (size_t)len : sizeof buf;
        if (cs_read(src, r, off, buf, n) < 0 || cs_write(w, buf, n) < 0)
            return -1;
        off += n, len -= n;
    }
    explicit_bzero(buf, sizeof buf);
    return 0;
}

int meet_new_ids(struct grp *g, struct pnp_rng *rng, char *err, size_t errlen)
{
    if (pnp_rng_fill(rng, g->id, GRP_ID_LEN, err, errlen) < 0)
        return -1;
    for (int i = 0; i < g->nsets; i++)
        if (pnp_rng_fill(rng, g->sets[i].id, GRP_ID_LEN, err, errlen) < 0)
            return -1;
    return 0;
}

int meet_self_generate(const struct grp *roster, struct cstore *self, struct pnp_rng *rng, char *err, size_t errlen)
{
    int me = roster->me, N = roster->n - 1;
    size_t glen = grp_file_len(roster->n, roster->nsets);
    uint8_t *gb = malloc(glen);
    if (!gb)
        return -1;
    grp_serialise(roster, gb);
    struct crec r = {R_ROSTER, me, me, me, 0, glen, 0};
    struct cwriter w;
    int ok = cs_begin(self, &w, &r, err, errlen) == 0 && cs_write(&w, gb, glen) == 0 && cs_end(&w, err, errlen) == 0;
    free(gb);
    if (!ok)
        return -1;
    for (int si = 0; si < roster->nsets; si++) {
        const struct grp_set *s = &roster->sets[si];
        if (has_sig(roster, s)) {
            uint64_t nf = (uint64_t)s->slots * N * N * s->k;
            struct crec rs = {R_SIGN_FULL, me, me, me, si, nf * USS_FN_LEN, 0};
            if (cs_begin(self, &w, &rs, err, errlen) < 0)
                return -1;
            uint8_t fn[USS_FN_LEN];
            for (uint64_t i = 0; i < nf; i++) {
                do {
                    if (pnp_rng_fill(rng, fn, sizeof fn, err, errlen) < 0)
                        return -1;
                } while (uss_fn_fix(fn) < 0);
                if (cs_write(&w, fn, sizeof fn) < 0) {
                    snprintf(err, errlen, "%s: %s", self->path, strerror(errno));
                    return -1;
                }
            }
            explicit_bzero(fn, sizeof fn);
            if (cs_end(&w, err, errlen) < 0)
                return -1;
        }
        if (s->nloc == 0)
            continue;
        for (int o = 0; o < roster->n; o++) {
            if (o == me)
                continue;
            struct crec rp = {R_POOL, me, o, me, si, meet_pool_record_len(s), 0};
            if (cs_begin(self, &w, &rp, err, errlen) < 0 || fill_random(&w, rng, rp.len, err, errlen) < 0 ||
                cs_end(&w, err, errlen) < 0)
                return -1;
        }
    }
    return 0;
}

static int check_visit(const struct grp *roster, struct cstore *courier, int round, char *err, size_t errlen)
{
    if (memcmp(courier->group, roster->id, GRP_ID_LEN) != 0 || courier->gen != roster->gen ||
        courier->role != CS_COURIER) {
        snprintf(err, errlen, "%s is a courier for a different meeting", courier->path);
        return -1;
    }
    if (courier->visiting != roster->me || courier->round != round || courier->owner == roster->me) {
        char who[GRP_MEMBER_LEN + 16];
        snprintf(err, errlen, "this courier is addressed to %s (round %d), not to you: hand it back to its owner",
                 grp_member_name(roster, courier->visiting < roster->n ? courier->visiting : 0, who, sizeof who),
                 courier->round);
        return -1;
    }
    return 0;
}

static int copy_record(struct cstore *self, const struct crec *src, struct cstore *dst, struct crec *as, char *err,
                       size_t errlen)
{
    struct cwriter w;
    as->len = src->len;
    if (cs_begin(dst, &w, as, err, errlen) < 0)
        return -1;
    if (copy_part(self, src, 0, src->len, &w) < 0) {
        snprintf(err, errlen, "%s: %s", dst->path, strerror(errno));
        return -1;
    }
    return cs_end(&w, err, errlen);
}

int meet_round1(const struct grp *roster, struct cstore *self, struct cstore *courier, char *err, size_t errlen)
{
    if (check_visit(roster, courier, 1, err, errlen) < 0)
        return -1;
    int me = roster->me, o = courier->owner, N = roster->n - 1;
    for (int si = 0; si < roster->nsets; si++) {
        const struct grp_set *s = &roster->sets[si];
        struct crec r;
        if (s->nloc) {
            if (cs_find(self, R_POOL, me, o, -1, si, &r) < 0)
                goto missing;
            struct crec as = {R_POOL, me, o, me, si, 0, 0};
            if (copy_record(self, &r, courier, &as, err, errlen) < 0)
                return -1;
        }
        if (has_sig(roster, s)) {
            if (cs_find(self, R_SIGN_FULL, me, me, -1, si, &r) < 0)
                goto missing;
            uint64_t blk = (uint64_t)N * s->k * USS_FN_LEN, slot_len = (uint64_t)N * blk;
            struct crec as = {R_SIGN_BLOCK, me, o, me, si, (uint64_t)s->slots * blk, 0};
            struct cwriter w;
            if (cs_begin(courier, &w, &as, err, errlen) < 0)
                return -1;
            for (uint32_t sl = 0; sl < s->slots; sl++)
                if (copy_part(self, &r, sl * slot_len + (uint64_t)rpos(me, o) * blk, blk, &w) < 0) {
                    snprintf(err, errlen, "%s: %s", courier->path, strerror(errno));
                    return -1;
                }
            if (cs_end(&w, err, errlen) < 0)
                return -1;
        }
    }
    return 0;
missing:
    snprintf(err, errlen, "%s is missing this member's own material: run the self step first", self->path);
    return -1;
}

int meet_collect(struct cstore *courier, struct cstore *self, char *err, size_t errlen)
{
    if (cs_copy_all(courier, self, err, errlen) < 0)
        return -1;
    return cs_overwrite(courier, err, errlen);
}

/* a uniform index below n from the hardware sources (rejection sampling: no modulo bias) */
static int rand_below(struct pnp_rng *rng, uint32_t n, uint32_t *out, char *err, size_t errlen)
{
    uint32_t lim = UINT32_MAX - UINT32_MAX % n, v;
    do {
        uint8_t b[4];
        if (pnp_rng_fill(rng, b, 4, err, errlen) < 0)
            return -1;
        v = get32(b);
    } while (v >= lim);
    *out = v % n;
    return 0;
}

int meet_make_splits(const struct grp *roster, struct cstore *self, struct pnp_rng *rng, char *err, size_t errlen)
{
    int me = roster->me, N = roster->n - 1;
    if (roster->n < 3)
        return 0;
    for (int si = 0; si < roster->nsets; si++) {
        const struct grp_set *s = &roster->sets[si];
        if (!has_sig(roster, s))
            continue;
        uint32_t nk = (uint32_t)N * s->k;
        for (int S = 0; S < roster->n; S++) {
            if (S == me)
                continue;
            struct crec blk;
            if (cs_find(self, R_SIGN_BLOCK, S, me, S, si, &blk) < 0) {
                char who[48];
                snprintf(err, errlen, "no signer block from %s on the self drive: round 1 isn't complete",
                         grp_member_name(roster, S, who, sizeof who));
                return -1;
            }
            /* one random permutation of the block per slot, shared by the N sets cut from it */
            uint32_t *perm = malloc((size_t)s->slots * nk * sizeof *perm);
            if (!perm)
                return -1;
            for (uint32_t sl = 0; sl < s->slots; sl++) {
                uint32_t *p = perm + (size_t)sl * nk;
                for (uint32_t i = 0; i < nk; i++)
                    p[i] = i;
                for (uint32_t i = nk - 1; i > 0; i--) { /* Fisher-Yates */
                    uint32_t j;
                    if (rand_below(rng, i + 1, &j, err, errlen) < 0) {
                        free(perm);
                        return -1;
                    }
                    uint32_t t = p[i];
                    p[i] = p[j], p[j] = t;
                }
            }
            uint8_t *fns = malloc((size_t)nk * USS_FN_LEN);
            if (!fns) {
                free(perm);
                return -1;
            }
            uint32_t base = (uint32_t)rpos(S, me) * nk; /* where my block sits among S's N²k functions */
            for (int b = 0; b < N; b++) {
                struct crec as = {R_SPLIT, me, rmember(S, b), S, si, (uint64_t)s->slots * s->k * USS_SPLIT_LEN, 0};
                struct cwriter w;
                if (cs_begin(self, &w, &as, err, errlen) < 0)
                    goto fail;
                for (uint32_t sl = 0; sl < s->slots; sl++) {
                    if (cs_read(self, &blk, (uint64_t)sl * nk * USS_FN_LEN, fns, (size_t)nk * USS_FN_LEN) < 0)
                        goto io;
                    if ((size_t)(b + 1) * s->k > nk) /* N sets of k: always within the block */
                        goto fail;
                    const uint32_t *p = perm + (size_t)sl * nk + (size_t)b * s->k;
                    for (uint32_t i = 0; i < s->k; i++) {
                        uint8_t e[USS_SPLIT_LEN];
                        put32(e, base + p[i]);
                        memcpy(e + 4, fns + (size_t)p[i] * USS_FN_LEN, USS_FN_LEN);
                        if (cs_write(&w, e, sizeof e) < 0)
                            goto io;
                    }
                }
                if (cs_end(&w, err, errlen) < 0)
                    goto fail;
            }
            explicit_bzero(fns, (size_t)nk * USS_FN_LEN);
            free(fns);
            free(perm);
            continue;
        io:
            snprintf(err, errlen, "%s: %s", self->path, strerror(errno));
        fail:
            explicit_bzero(fns, (size_t)nk * USS_FN_LEN);
            free(fns);
            free(perm);
            return -1;
        }
    }
    return 0;
}

/* the test signature: slot 0 of my signing functions on TEST_MSG */
static uint8_t *test_signature(const struct grp *roster, const struct grp_set *s, struct cstore *self,
                               const struct crec *full, size_t *len)
{
    int N = roster->n - 1;
    uint64_t nf = (uint64_t)N * N * s->k;
    uint8_t *fns = malloc(nf * USS_FN_LEN), *tags = malloc(nf), *sig = NULL;
    if (!fns || !tags || cs_read(self, full, 0, fns, nf * USS_FN_LEN) < 0)
        goto out;
    struct uss_eval *e = uss_eval_new(fns, USS_FN_LEN, (size_t)nf);
    if (!e)
        goto out;
    uint8_t frame[USS_FRAME_LEN];
    uss_frame(frame, s->id, roster->me, 0, sizeof TEST_MSG - 1);
    uss_eval_feed(e, frame, sizeof frame);
    uss_eval_feed(e, (const uint8_t *)TEST_MSG, sizeof TEST_MSG - 1);
    uss_eval_finish(e, tags);
    *len = uss_sig_len(N, s->k);
    sig = calloc(*len, 1);
    if (!sig)
        goto out;
    memcpy(sig, "PNPUS001", 8);
    memcpy(sig + 8, s->id, GRP_ID_LEN);
    sig[24] = (uint8_t)roster->me, sig[25] = (uint8_t)N;
    put32(sig + 28, 0), put32(sig + 32, s->k);
    for (uint64_t i = 0; i < nf; i++)
        sig[USS_SIG_HDR + i / 4] |= (uint8_t)(tags[i] << (2 * (i % 4)));
out:
    if (fns)
        explicit_bzero(fns, nf * USS_FN_LEN);
    free(fns), free(tags);
    return sig;
}

/* the MAC key of the first item of the pool from -> to, from both contributions (mine and theirs) */
static int first_key(const struct grp_set *s, struct cstore *self, const struct crec *mine, const struct crec *theirs,
                     int from, int to, uint8_t key[GRP_KEY_LEN])
{
    int lo = from < to ? from : to;
    uint64_t at = (from == lo ? 0 : dir_len(s)) + (uint64_t)s->nloc * GRP_LOC_ENTRY;
    uint8_t a[GRP_KEY_LEN], b[GRP_KEY_LEN];
    if (s->pool_bytes < GRP_KEY_LEN || cs_read(self, mine, at, a, sizeof a) < 0 ||
        cs_read(self, theirs, at, b, sizeof b) < 0)
        return -1;
    for (int i = 0; i < GRP_KEY_LEN; i++)
        key[i] = a[i] ^ b[i];
    explicit_bzero(a, sizeof a), explicit_bzero(b, sizeof b);
    if (pnp_mac_key_fix(key) < 0) /* the pool's bytes are used as they come; a key equal to p (2^-127) is refused */
        return -1;
    return 0;
}

static void test_seal(const uint8_t key[GRP_KEY_LEN], const uint8_t set_id[GRP_ID_LEN], int from, int to,
                      uint8_t tag[PNP_MAC_TAG_LEN])
{
    struct pnp_mac m;
    uint8_t hdr[8 + GRP_ID_LEN + 2] = "PNPTEST1";
    memcpy(hdr + 8, set_id, GRP_ID_LEN);
    hdr[24] = (uint8_t)from, hdr[25] = (uint8_t)to;
    pnp_mac_init(&m, key);
    pnp_mac_feed(&m, hdr, sizeof hdr);
    pnp_mac_feed(&m, (const uint8_t *)TEST_MSG, sizeof TEST_MSG - 1);
    pnp_mac_final(&m, tag);
}

int meet_round2(const struct grp *roster, struct cstore *self, struct cstore *courier, char *err, size_t errlen)
{
    if (check_visit(roster, courier, 2, err, errlen) < 0)
        return -1;
    int me = roster->me, o = courier->owner;
    for (int si = 0; si < roster->nsets; si++) {
        const struct grp_set *s = &roster->sets[si];
        struct crec r;
        if (has_sig(roster, s)) {
            for (int S = 0; S < roster->n; S++) {
                if (S == me || S == o)
                    continue;
                if (cs_find(self, R_SPLIT, me, o, S, si, &r) < 0)
                    goto missing;
                struct crec as = {R_SPLIT, me, o, S, si, 0, 0};
                if (copy_record(self, &r, courier, &as, err, errlen) < 0)
                    return -1;
            }
            if (cs_find(self, R_SIGN_FULL, me, me, -1, si, &r) < 0)
                goto missing;
            size_t len = 0;
            uint8_t *sig = test_signature(roster, s, self, &r, &len);
            struct crec as = {R_TEST_SIG, me, o, me, si, len, 0};
            struct cwriter w;
            int ok = sig && cs_begin(courier, &w, &as, err, errlen) == 0 && cs_write(&w, sig, len) == 0 &&
                     cs_end(&w, err, errlen) == 0;
            free(sig);
            if (!ok)
                return -1;
        }
        if (s->nloc) {
            struct crec mine, theirs;
            uint8_t key[GRP_KEY_LEN], tag[PNP_MAC_TAG_LEN];
            if (cs_find(self, R_POOL, me, o, -1, si, &mine) < 0 || cs_find(self, R_POOL, o, me, -1, si, &theirs) < 0)
                goto missing;
            if (first_key(s, self, &mine, &theirs, me, o, key) < 0) {
                snprintf(err, errlen, "couldn't read the pool contributions on %s", self->path);
                return -1;
            }
            test_seal(key, s->id, me, o, tag);
            explicit_bzero(key, sizeof key);
            struct crec as = {R_TEST_SEAL, me, o, me, si, sizeof tag, 0};
            struct cwriter w;
            if (cs_begin(courier, &w, &as, err, errlen) < 0 || cs_write(&w, tag, sizeof tag) < 0 ||
                cs_end(&w, err, errlen) < 0)
                return -1;
        }
    }
    return 0;
missing:
    snprintf(err, errlen, "%s is missing material from round 1 or the splits: finish those first", self->path);
    return -1;
}

/* ---- import ---- */
static int rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return unlink(path);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char *p = NULL;
        if (asprintf(&p, "%s/%s", path, e->d_name) >= 0) {
            rm_tree(p);
            free(p);
        }
    }
    closedir(d);
    return rmdir(path);
}

/* writes a new file (0600) from pieces: header, then the XOR of two record regions (b may be NULL) */
static int write_combined(const struct grp *g, const char *path, const uint8_t *hdr, size_t hlen, struct cstore *self,
                          const struct crec *a, uint64_t aoff, const struct crec *b, uint64_t boff, uint64_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int ok = pnp_write_all(fd, hdr, hlen) == 0;
    uint8_t x[65536], y[65536];
    for (uint64_t off = 0; ok && off < len;) {
        size_t n = len - off < sizeof x ? (size_t)(len - off) : sizeof x;
        ok = cs_read(self, a, aoff + off, x, n) == 0 && (!b || cs_read(self, b, boff + off, y, n) == 0);
        if (ok && b)
            for (size_t i = 0; i < n; i++)
                x[i] ^= y[i];
        ok = ok && pnp_write_all(fd, x, n) == 0;
        off += n;
    }
    explicit_bzero(x, sizeof x), explicit_bzero(y, sizeof y);
    ok = ok && fsync(fd) == 0;
    close(fd);
    grp_touch(g, path);
    return ok ? 0 : -1;
}

static int import_set(struct grp *g, int si, struct cstore *self, char *err, size_t errlen)
{
    struct grp_set *s = &g->sets[si];
    int me = g->me, N = g->n - 1;
    char name[32];
    if (s->nloc) {
        for (int o = 0; o < g->n; o++) {
            if (o == me)
                continue;
            struct crec mine, theirs, ts;
            if (cs_find(self, R_POOL, me, o, -1, si, &mine) < 0 || cs_find(self, R_POOL, o, me, -1, si, &theirs) < 0 ||
                cs_find(self, R_TEST_SEAL, o, me, -1, si, &ts) < 0 || mine.len != meet_pool_record_len(s) ||
                theirs.len != mine.len || ts.len != PNP_MAC_TAG_LEN)
                goto missing;
            /* their test seal, made with the first key of the pool o -> me: proves both sides combined the same pool */
            uint8_t key[GRP_KEY_LEN], tag[PNP_MAC_TAG_LEN], want[PNP_MAC_TAG_LEN];
            if (first_key(s, self, &mine, &theirs, o, me, key) < 0 || cs_read(self, &ts, 0, want, sizeof want) < 0)
                goto missing;
            test_seal(key, s->id, o, me, tag);
            explicit_bzero(key, sizeof key);
            if (pnp_mac_tag_cmp(tag, want) != 0) {
                char who[48];
                snprintf(err, errlen, "the test seal from %s doesn't check: your pools differ. Redo the transfers with "
                         "%s", grp_member_name(g, o, who, sizeof who), who);
                return -1;
            }
            int lo = me < o ? me : o;
            for (int d = 0; d < 2; d++) {
                int from = d == 0 ? me : o, to = d == 0 ? o : me;
                uint64_t at = from == lo ? 0 : dir_len(s);
                uint8_t h[POOL_HDR_LEN];
                /* the first item of each direction was the test: used up on both sides */
                pool_header(h, s->id, from, to, s->nloc, 1, s->pool_bytes, GRP_KEY_LEN);
                snprintf(name, sizeof name, "pool.%d-%d", from + 1, to + 1);
                char *path = grp_set_path(g, s, name);
                if (!path || write_combined(g, path, h, sizeof h, self, &mine, at, &theirs, at, dir_len(s)) < 0) {
                    snprintf(err, errlen, "%s: %s", path ? path : "?", strerror(errno));
                    free(path);
                    return -1;
                }
                struct pool p;
                if (pool_open(g, s, from, to, &p, err, errlen) < 0)
                    return -1;
                int ok = pool_wipe_loc(&p, 0) == 0 && pool_wipe(&p, 0, GRP_KEY_LEN) == 0 && pool_sync(&p) == 0;
                pool_close(&p);
                grp_touch(g, path);
                free(path);
                if (!ok) {
                    snprintf(err, errlen, "couldn't write the pool files: %s", strerror(errno));
                    return -1;
                }
            }
            struct recv_state rs;
            if (recv_load(g, s, o, &rs, s->nloc) < 0 || recv_add(&rs, 0, 0, GRP_KEY_LEN) < 0 ||
                recv_save(g, s, o, &rs, err, errlen) < 0) {
                recv_free(&rs);
                return -1;
            }
            recv_free(&rs);
        }
    }
    if (!has_sig(g, s))
        return 0;
    /* my signing file: slot 0 was the test signature, so it's used up */
    struct crec full;
    if (cs_find(self, R_SIGN_FULL, me, me, -1, si, &full) < 0 ||
        full.len != uss_sign_len(N, s->k, s->slots) - USS_SIGN_HDR)
        goto missing;
    uint8_t h[USS_SIGN_HDR] = "PNPSG001";
    memcpy(h + 8, s->id, GRP_ID_LEN);
    h[24] = (uint8_t)me, h[25] = (uint8_t)N;
    put32(h + 28, s->k), put32(h + 32, s->slots), put32(h + 36, 1);
    char *path = grp_set_path(g, s, "sign");
    if (!path || write_combined(g, path, h, sizeof h, self, &full, 0, NULL, 0, full.len) < 0) {
        snprintf(err, errlen, "%s: %s", path ? path : "?", strerror(errno));
        free(path);
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    static const uint8_t zero[4096];
    uint64_t slot_bytes = (uint64_t)N * N * s->k * USS_FN_LEN;
    for (uint64_t off = 0; fd >= 0 && off < slot_bytes; off += sizeof zero)
        if (pwrite(fd, zero, slot_bytes - off < sizeof zero ? slot_bytes - off : sizeof zero,
                   (off_t)(USS_SIGN_HDR + off)) < 0)
            break;
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
    grp_touch(g, path);
    free(path);
    /* a verify file per other signer: per slot, the N sets in the signer's recipient order */
    for (int S = 0; S < g->n; S++) {
        if (S == me)
            continue;
        struct crec sets[GRP_MAX_MEMBERS];
        for (int b = 0; b < N; b++)
            if (cs_find(self, R_SPLIT, rmember(S, b), me, S, si, &sets[b]) < 0 ||
                sets[b].len != (uint64_t)s->slots * s->k * USS_SPLIT_LEN)
                goto missing;
        snprintf(name, sizeof name, "verify.%d", S + 1);
        char *vp = grp_set_path(g, s, name);
        int vfd = vp ? open(vp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600) : -1;
        uint8_t vh[USS_VERIFY_HDR] = "PNPVF001";
        memcpy(vh + 8, s->id, GRP_ID_LEN);
        vh[24] = (uint8_t)S, vh[25] = (uint8_t)me, vh[26] = (uint8_t)N;
        put32(vh + 28, s->k), put32(vh + 32, s->slots);
        int ok = vfd >= 0 && pnp_write_all(vfd, vh, sizeof vh) == 0;
        uint64_t part = (uint64_t)s->k * USS_SPLIT_LEN;
        uint8_t *buf = malloc(part);
        for (uint32_t sl = 0; ok && buf && sl < s->slots; sl++)
            for (int b = 0; ok && b < N; b++)
                ok = cs_read(self, &sets[b], sl * part, buf, part) == 0 && pnp_write_all(vfd, buf, part) == 0;
        ok = ok && buf && fsync(vfd) == 0;
        if (buf)
            explicit_bzero(buf, part);
        free(buf);
        if (vfd >= 0)
            close(vfd);
        if (vp)
            grp_touch(g, vp);
        if (!ok) {
            snprintf(err, errlen, "%s: %s", vp ? vp : "?", strerror(errno));
            free(vp);
            return -1;
        }
        free(vp);
        if (uss_sused_create(g, s, S, err, errlen) < 0)
            return -1;
    }
    return 0;
missing:
    snprintf(err, errlen, "%s doesn't hold everything from the meeting (a transfer is missing): it can't be imported",
             self->path);
    return -1;
}

/* After a re-meeting: every earlier generation of the group under root is retired. Its key sets are "replaced":
 * they can still receive what's in transit until their windows close, never send again, and their unused sending
 * parts (signing slots, pad to others) are wiped now. */
static void retire_older(const char *root, const struct grp *g)
{
    char *dirs[64];
    int n = grp_find_all(root, dirs, 64);
    for (int i = 0; i < n; i++) {
        struct grp o;
        char err[256];
        if (grp_load(dirs[i], &o, err, sizeof err) == 0) {
            if (memcmp(o.id, g->id, GRP_ID_LEN) == 0 && o.gen < g->gen) {
                for (int si = 0; si < o.nsets; si++) {
                    struct grp_set *s = &o.sets[si];
                    if (s->state != GRP_ACTIVE)
                        continue;
                    s->state = GRP_REPLACED;
                    for (int m = 0; m < o.n && s->nloc; m++) {
                        struct pool p;
                        if (m == o.me || pool_open(&o, s, o.me, m, &p, err, sizeof err) < 0)
                            continue;
                        pool_wipe(&p, p.next_off, p.bytes - p.next_off);
                        for (uint32_t li = p.next_loc; li < p.nloc; li++)
                            pool_wipe_loc(&p, li);
                        pool_sync(&p);
                        grp_touch(&o, p.path);
                        pool_close(&p);
                    }
                    if (o.n >= 3 && s->slots)
                        uss_wipe_unused(&o, s);
                }
                grp_save(&o, err, sizeof err);
            }
            grp_free(&o);
        }
        free(dirs[i]);
    }
}

/* the test message as a uss_read_fn source */
struct msg_src {
    const char *p;
    size_t n, at;
};
static long msg_read(void *ctx, uint8_t *buf, size_t n)
{
    struct msg_src *m = ctx;
    size_t left = m->n - m->at, take = left < n ? left : n;
    memcpy(buf, m->p + m->at, take);
    m->at += take;
    return (long)take;
}

int meet_import(struct cstore *self, const char *root, char **out_dir, char *err, size_t errlen)
{
    if (cs_verify(self, err, errlen) < 0)
        return -1;
    struct crec r;
    if (self->role != CS_SELF || cs_find(self, R_ROSTER, -1, -1, -1, -1, &r) < 0 || r.len > (1 << 20)) {
        snprintf(err, errlen, "%s isn't a self drive from a meeting", self->path);
        return -1;
    }
    uint8_t *gb = malloc(r.len ? (size_t)r.len : 1);
    struct grp g;
    if (!gb || cs_read(self, &r, 0, gb, (size_t)r.len) < 0 || grp_parse(gb, (size_t)r.len, &g) < 0 ||
        g.me != self->owner) {
        free(gb);
        snprintf(err, errlen, "%s: its roster is damaged", self->path);
        return -1;
    }
    free(gb);
    char hex[2 * GRP_ID_LEN + 1], *final = NULL, *tmp = NULL;
    grp_hex(g.id, hex);
    /* a later generation (a re-meeting) has its own folder; the earlier ones are retired below */
    char gen[16] = "";
    if (g.gen > 1)
        snprintf(gen, sizeof gen, "-g%u", g.gen);
    if (asprintf(&final, "%s/pnp-group-%s%s", root, hex, gen) < 0 ||
        asprintf(&tmp, "%s/.pnp-group-%s%s.pnp-part", root, hex, gen) < 0) {
        grp_free(&g);
        return -1;
    }
    struct stat st;
    if (stat(final, &st) == 0) {
        snprintf(err, errlen, "%s already exists: this meeting has been imported here", final);
        goto fail;
    }
    rm_tree(tmp); /* what an interrupted import left */
    g.dir = strdup(tmp);
    g.guard_day = grp_today(g.tz_min);
    if (!g.dir || grp_mkdirs(&g, err, errlen) < 0)
        goto fail;
    for (int si = 0; si < g.nsets; si++)
        if (import_set(&g, si, self, err, errlen) < 0)
            goto fail;
    if (grp_save(&g, err, errlen) < 0)
        goto fail;
    /* every test signature must check, exactly, at the highest level */
    for (int si = 0; si < g.nsets; si++) {
        struct grp_set *s = &g.sets[si];
        if (!has_sig(&g, s))
            continue;
        for (int S = 0; S < g.n; S++) {
            if (S == g.me)
                continue;
            struct crec ts;
            if (cs_find(self, R_TEST_SIG, S, g.me, -1, si, &ts) < 0 || ts.len > (64u << 20)) {
                snprintf(err, errlen, "%s has no test signature from member %d", self->path, S + 1);
                goto fail;
            }
            uint8_t *sig = malloc((size_t)ts.len);
            struct msg_src src = {TEST_MSG, sizeof TEST_MSG - 1, 0};
            struct uss_result res;
            int ok = sig && cs_read(self, &ts, 0, sig, (size_t)ts.len) == 0;
            ok = ok && uss_verify(&g, sig, (size_t)ts.len, src.n, msg_read, &src, 1, &res, err, errlen) == 0;
            free(sig);
            if (!ok)
                goto fail;
            if (res.level != g.lmax || !res.exact || res.signer != S) {
                char who[48];
                snprintf(err, errlen, "the test signature from %s doesn't check: redo the transfers with them",
                         grp_member_name(&g, S, who, sizeof who));
                goto fail;
            }
        }
    }
    char *kd = NULL;
    if (asprintf(&kd, "%s/kills", tmp) >= 0) {
        grp_touch(&g, kd);
        free(kd);
    }
    for (int si = 0; si < g.nsets; si++) {
        char *sd = grp_set_path(&g, &g.sets[si], NULL);
        if (sd)
            grp_touch(&g, sd);
        free(sd);
    }
    pnp_sync_dir(tmp);
    if (rename(tmp, final) < 0) {
        snprintf(err, errlen, "%s: %s", final, strerror(errno));
        goto fail;
    }
    pnp_sync_dir(final);
    grp_touch(&g, final);
    retire_older(root, &g);
    grp_free(&g);
    free(tmp);
    *out_dir = final;
    return 0;
fail:
    rm_tree(tmp);
    grp_free(&g);
    free(tmp), free(final);
    return -1;
}
