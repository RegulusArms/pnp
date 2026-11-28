/* Group signatures that stay secure if P = NP (uss.h).
 *
 * The scheme (Amiri, Abidin, Wallden, Andersson, ACNS 2018, section 3; docs/research.md): a signer P0 and N
 * recipients. For each slot, the signer holds N²k hash functions; recipient b got the block of Nk numbered
 * b·Nk .. (b+1)·Nk - 1 at the meeting, split it at random into N sets of k and gave one set to each recipient
 * (keeping one). So each verifier holds N sets of k functions, one set from each recipient, with their positions,
 * and the signer doesn't know which function went where.
 *
 *   signature  = the 2-bit tags of all N²k functions on the framed message
 *   a set passes at level l   if it has fewer than s_l·k mismatches, s_l from 0.49 (l = -1) down to 0.01 (l_max)
 *   accepted at level l       if more than N·δ_l sets pass, δ_l = 1/2 + (l+1)(ω-1)/N
 *
 * An honest signature has no mismatches at all, so it passes every level for everyone; the levels matter only
 * against a cheating signer, and any mismatch is reported (an "inexact" signature).
 *
 * The hash family, ε-ASU₂ with ε = 1/4 + L/p (docs/group.md): f(M) = A·h_K(M) xor c, where h_K is mac.c's
 * polynomial mod p = 2^127 - 1 (the MAC with its pad s = 0), A is two random 127-bit rows applied as parities, and c
 * is 2 random bits. For x != x', A·(x xor x') is uniform and c makes each tag uniform, so the second stage is exactly
 * strongly universal (ε = 1/4); h_K adds the collision chance L/p. Every function has its own K: functions sharing
 * a K would let anyone holding one of them find a colliding message.
 *
 * Constant time: K, A and c are secret until the signature is released. h_K is mac.c's constant-time arithmetic;
 * the parities are computed by folding XORs (no table, no branch), and run.sh checks they compile to no
 * conditional jumps. Tags themselves are public once released, so comparing them needn't be constant time. */
#define _GNU_SOURCE
#include "uss.h"
#include "blake2b.h"
#include "fileio.h"
#include "mac.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char MAGIC_SIG[8] = {'P', 'N', 'P', 'U', 'S', '0', '0', '1'};
static const char MAGIC_SIGN[8] = {'P', 'N', 'P', 'S', 'G', '0', '0', '1'};
static const char MAGIC_VERIFY[8] = {'P', 'N', 'P', 'V', 'F', '0', '0', '1'};
static const char MAGIC_SUSED[8] = {'P', 'N', 'P', 'S', 'U', '0', '0', '1'};

static void put32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static uint64_t get64(const uint8_t *b) { return (uint64_t)get32(b) | (uint64_t)get32(b + 4) << 32; }

/* ---- parameters (docs/group.md "Parameters"; Theorems 1-3 with union bounds) ---- */
int uss_valid(int N, int omega, int lmax)
{
    return N >= 2 && N <= GRP_MAX_MEMBERS - 1 && omega >= 1 && 2 * omega < N + 1 && lmax >= 0 && lmax <= 8 &&
           2 * (lmax + 1) * (omega - 1) < N;
}

static double s_of(int l, int lmax) { return 0.49 - (l + 1) * (0.48 / (lmax + 1)); }

/* log2 P[Bin(k, 1-eps) < s·k]: the chance a forger, guessing each unknown tag right with probability eps, gets
 * fewer than s·k mismatches in a set */
static double log2_pt(uint32_t k, double s0)
{
    const double eps = 0.25 + ldexp(1, -60), l2 = log(2);
    double m = -INFINITY, sum = 0;
    uint32_t top = (uint32_t)ceil(s0 * k);
    for (uint32_t v = 0; v < top; v++) {
        double t = (lgamma(k + 1.0) - lgamma(v + 1.0) - lgamma(k - v + 1.0) + v * log(1 - eps) + (k - v) * log(eps)) / l2;
        if (t > m) {
            sum = sum * exp2(m - t) + 1;
            m = t;
        } else {
            sum += exp2(t - m);
        }
    }
    return top ? m + log2(sum) : -INFINITY;
}

static int bounds_ok(int N, int omega, int lmax, uint32_t k)
{
    const double target = -64;
    double dR = (omega - 1) / (double)N;
    if (log2((double)(N - omega) * (N - omega)) + log2_pt(k, s_of(0, lmax)) > target)
        return 0;
    double hon = N * (1 - dR), Np = hon * (hon - 1) / 2;
    for (int l = 0; l <= lmax; l++) {
        double dl = 0.5 + (l + 1) * dR, gap = s_of(l - 1, lmax) - s_of(l, lmax);
        double b = Np * (N * (dl - dR) + 1) * exp(-gap * gap * k / 2);
        if (b > 0 && log2(b) > target)
            return 0;
    }
    return 1;
}

uint32_t uss_k(int N, int omega, int lmax)
{
    if (!uss_valid(N, omega, lmax))
        return 0;
    for (uint32_t k = 100; k <= 100000; k += 50)
        if (bounds_ok(N, omega, lmax, k))
            return k;
    return 0;
}

void uss_defaults(int n, int *omega, int *lmax)
{
    int N = n - 1;
    *omega = (n - 1) / 2;
    *lmax = 0;
    while (*lmax < 1 && uss_valid(N, *omega, *lmax + 1))
        (*lmax)++;
}

int uss_set_passes(uint32_t mismatches, uint32_t k, int l, int lmax)
{
    /* mismatches < s_l·k, in integers: s_l·100·(l_max+1) = 49·(l_max+1) - 48·(l+1) */
    return (uint64_t)mismatches * 100 * (uint64_t)(lmax + 1) < (uint64_t)(49 * (lmax + 1) - 48 * (l + 1)) * k;
}

int uss_accepts(int passed, int N, int l, int omega)
{
    return 2 * passed > N + 2 * (l + 1) * (omega - 1); /* passed > N·δ_l */
}

/* ---- the hash family ---- */
int uss_fn_fix(uint8_t fn[USS_FN_LEN])
{
    fn[15] &= 0x7f; /* K below 2^127 */
    fn[48] &= 3;
    static const uint8_t p[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    return memcmp(fn, p, 16) == 0 ? -1 : 0;
}

static int fn_ok(const uint8_t fn[USS_FN_LEN])
{
    uint8_t t[USS_FN_LEN];
    memcpy(t, fn, sizeof t);
    int ok = (fn[15] & 0x80) == 0 && (fn[48] & ~3) == 0 && uss_fn_fix(t) == 0;
    explicit_bzero(t, sizeof t);
    return ok;
}

/* parity of a 64-bit word by folding: no table lookups or branches on the secret */
static __attribute__((noinline)) uint64_t parity64(uint64_t v)
{
    v ^= v >> 32, v ^= v >> 16, v ^= v >> 8, v ^= v >> 4, v ^= v >> 2, v ^= v >> 1;
    return v & 1;
}

int uss_stage2(uint64_t a0, uint64_t a1, int c, uint64_t x)
{
    return (int)((parity64(a0 & x) | parity64(a1 & x) << 1) ^ (uint64_t)(c & 3));
}

int uss_tag_of(const uint8_t fn[USS_FN_LEN], const uint8_t x[16])
{
    uint64_t xl = get64(x), xh = get64(x + 8);
    uint64_t b0 = parity64((get64(fn + 16) & xl) ^ (get64(fn + 24) & xh));
    uint64_t b1 = parity64((get64(fn + 32) & xl) ^ (get64(fn + 40) & xh));
    return (int)((b0 | b1 << 1) ^ (uint64_t)(fn[48] & 3));
}

void uss_frame(uint8_t out[USS_FRAME_LEN], const uint8_t set_id[GRP_ID_LEN], int signer, uint32_t slot,
               uint64_t len)
{
    memcpy(out, MAGIC_SIG, 8);
    memcpy(out + 8, set_id, GRP_ID_LEN);
    out[24] = (uint8_t)signer;
    put32(out + 25, slot);
    put64(out + 29, len);
}

#define EVAL_BUF (1 << 20)
#define MAX_THREADS 64
struct uss_eval {
    size_t nf;
    const uint8_t *fns;
    size_t stride;
    struct pnp_mac *m;
    size_t mlen;
    uint8_t *buf;
    size_t n;
    int threads;
};
struct eval_job {
    struct uss_eval *e;
    size_t lo, hi;
};

static void *eval_part(void *arg)
{
    struct eval_job *j = arg;
    for (size_t i = j->lo; i < j->hi; i++)
        pnp_mac_feed(&j->e->m[i], j->e->buf, j->e->n);
    return NULL;
}

static void eval_flush(struct uss_eval *e)
{
    if (!e->n)
        return;
    struct eval_job jobs[MAX_THREADS];
    pthread_t th[MAX_THREADS];
    int made[MAX_THREADS] = {0}, t = e->threads;
    for (int i = 0; i < t; i++) {
        jobs[i].e = e, jobs[i].lo = e->nf * (size_t)i / (size_t)t, jobs[i].hi = e->nf * (size_t)(i + 1) / (size_t)t;
        if (i < t - 1 && pthread_create(&th[i], NULL, eval_part, &jobs[i]) == 0)
            made[i] = 1;
        else
            eval_part(&jobs[i]); /* the last part (or one a thread couldn't be made for) runs here */
    }
    for (int i = 0; i < t; i++)
        if (made[i])
            pthread_join(th[i], NULL);
    e->n = 0;
}

struct uss_eval *uss_eval_new(const uint8_t *fns, size_t stride, size_t nf)
{
    struct uss_eval *e = calloc(1, sizeof *e);
    if (!e)
        return NULL;
    e->nf = nf, e->fns = fns, e->stride = stride;
    e->mlen = (nf ? nf : 1) * sizeof *e->m;
    e->m = mmap(NULL, e->mlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    e->buf = malloc(EVAL_BUF);
    if (e->m == MAP_FAILED || !e->buf) {
        if (e->m != MAP_FAILED)
            munmap(e->m, e->mlen);
        free(e->buf), free(e);
        return NULL;
    }
    madvise(e->m, e->mlen, MADV_DONTDUMP);
    mlock(e->m, e->mlen); /* the MACs' state holds K: kept out of swap where the limit allows */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    size_t t = nf / 256 + 1;
    if (cpus > 0 && t > (size_t)cpus)
        t = (size_t)cpus;
    e->threads = (int)(t > MAX_THREADS ? MAX_THREADS : t);
#ifdef PNP_TEST
    const char *one = getenv("PNP_TEST_THREADS"); /* test hook: the same signature with any number of threads */
    if (one && atoi(one) > 0 && atoi(one) <= MAX_THREADS)
        e->threads = atoi(one);
#endif
    for (size_t i = 0; i < nf; i++) {
        uint8_t key[PNP_MAC_KEY_LEN] = {0};
        memcpy(key, fns + i * stride, 16); /* K; s = 0 gives h_K itself */
        pnp_mac_init(&e->m[i], key);
        explicit_bzero(key, sizeof key);
    }
    return e;
}

void uss_eval_feed(struct uss_eval *e, const uint8_t *buf, size_t n)
{
    while (n) {
        size_t take = EVAL_BUF - e->n < n ? EVAL_BUF - e->n : n;
        memcpy(e->buf + e->n, buf, take);
        e->n += take, buf += take, n -= take;
        if (e->n == EVAL_BUF)
            eval_flush(e);
    }
}

void uss_eval_finish(struct uss_eval *e, uint8_t *tags)
{
    eval_flush(e);
    for (size_t i = 0; i < e->nf; i++) {
        uint8_t x[16];
        pnp_mac_final(&e->m[i], x); /* wipes the MAC's state */
        tags[i] = (uint8_t)uss_tag_of(e->fns + i * e->stride, x);
        explicit_bzero(x, sizeof x);
    }
    explicit_bzero(e->buf, EVAL_BUF);
    explicit_bzero(e->m, e->mlen);
    munmap(e->m, e->mlen);
    free(e->buf);
    free(e);
}

/* ---- files ---- */
uint64_t uss_sign_len(int N, uint32_t k, uint32_t slots)
{
    return USS_SIGN_HDR + (uint64_t)slots * N * N * k * USS_FN_LEN;
}
uint64_t uss_verify_len(int N, uint32_t k, uint32_t slots)
{
    return USS_VERIFY_HDR + (uint64_t)slots * N * k * USS_SPLIT_LEN;
}
size_t uss_sig_len(int N, uint32_t k) { return USS_SIG_HDR + ((size_t)N * N * k + 3) / 4; }

static int open_rw(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM)
        fd = open(path, O_RDWR | O_CLOEXEC);
    return fd;
}

static int pread_all(int fd, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r <= 0)
            return -1;
        p += r, n -= (size_t)r, off += (uint64_t)r;
    }
    return 0;
}

static int write_zeros(int fd, uint64_t off, uint64_t len)
{
    static const uint8_t zero[65536];
    while (len) {
        size_t n = len < sizeof zero ? (size_t)len : sizeof zero;
        if (pwrite(fd, zero, n, (off_t)off) != (ssize_t)n)
            return -1;
        off += n, len -= n;
    }
    return 0;
}

/* a locked buffer for one slot's functions */
static uint8_t *secret_alloc(size_t len)
{
    uint8_t *p = mmap(NULL, len ? len : 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    madvise(p, len, MADV_DONTDUMP);
    mlock(p, len);
    return p;
}
static void secret_free(uint8_t *p, size_t len)
{
    if (p) {
        explicit_bzero(p, len);
        munmap(p, len ? len : 1);
    }
}

/* feeds frame + len bytes from rd to e (and to a BLAKE2b of the same, if h) */
static int feed_message(struct uss_eval *e, struct pnp_blake2b *h, const uint8_t *frame, uint64_t len,
                        uss_read_fn rd, void *ctx)
{
    uint8_t buf[65536];
    uss_eval_feed(e, frame, USS_FRAME_LEN);
    if (h)
        pnp_blake2b_update(h, frame, USS_FRAME_LEN);
    uint64_t got = 0;
    for (;;) {
        long r = rd(ctx, buf, sizeof buf);
        if (r < 0)
            return -1;
        if (r == 0)
            break;
        got += (uint64_t)r;
        if (got > len)
            return -1;
        uss_eval_feed(e, buf, (size_t)r);
        if (h)
            pnp_blake2b_update(h, buf, (size_t)r);
    }
    explicit_bzero(buf, sizeof buf);
    return got == len ? 0 : -1;
}

uint8_t *uss_sign(struct grp *g, struct grp_set *s, uint64_t len, uss_read_fn rd, void *ctx, size_t *siglen,
                  uint32_t *slot_out, char *err, size_t errlen)
{
    int N = g->n - 1;
    uint64_t nf = (uint64_t)N * N * s->k, slot_bytes = nf * USS_FN_LEN;
    char *path = grp_set_path(g, s, "sign");
    int fd = path ? open_rw(path) : -1;
    uint8_t h[USS_SIGN_HDR], *fns = NULL, *sig = NULL, *tags = NULL;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || pread_all(fd, h, sizeof h, 0) < 0) {
        snprintf(err, errlen, "no signing keys for this key set (%s)", path ? path : "?");
        goto out;
    }
    uint32_t slots = get32(h + 32), next = get32(h + 36);
    if (memcmp(h, MAGIC_SIGN, 8) != 0 || memcmp(h + 8, s->id, GRP_ID_LEN) != 0 || h[24] != g->me || h[25] != N ||
        get32(h + 28) != s->k || slots != s->slots || next > slots ||
        (uint64_t)st.st_size != uss_sign_len(N, s->k, slots)) {
        snprintf(err, errlen, "%s isn't this key set's signing file, or it's damaged", path);
        goto out;
    }
    if (next >= slots) {
        snprintf(err, errlen, "no signatures left in this key set: meet again");
        goto out;
    }
    uint64_t at = USS_SIGN_HDR + (uint64_t)next * slot_bytes;
    fns = secret_alloc(slot_bytes);
    tags = malloc(nf ? nf : 1);
    if (!fns || !tags || pread_all(fd, fns, slot_bytes, at) < 0) {
        snprintf(err, errlen, "%s: %s", path, errno ? strerror(errno) : "out of memory");
        goto out;
    }
    /* burn the slot before the signature exists: a crash after this wastes it, never reuses it */
    uint8_t c[4];
    put32(c, next + 1);
    int keep = 0;
#ifdef PNP_TEST
    keep = getenv("PNP_TEST_KEEP_SLOT") != NULL; /* test hook: a misbehaving signer that reuses a slot */
#endif
    if (!keep && (pwrite(fd, c, 4, 36) != 4 || fsync(fd) < 0))
        goto io;
    pnp_crash_point("sign slot");
    if (!keep && (write_zeros(fd, at, slot_bytes) < 0 || fsync(fd) < 0))
        goto io;
    grp_touch(g, path);
    for (uint64_t i = 0; i < nf; i++)
        if (!fn_ok(fns + i * USS_FN_LEN)) {
            snprintf(err, errlen, "%s: slot %u is damaged (it has been used up)", path, next + 1);
            goto out;
        }
    struct uss_eval *e = uss_eval_new(fns, USS_FN_LEN, (size_t)nf);
    if (!e) {
        snprintf(err, errlen, "out of memory");
        goto out;
    }
    uint8_t frame[USS_FRAME_LEN];
    uss_frame(frame, s->id, g->me, next, len);
    int fr = feed_message(e, NULL, frame, len, rd, ctx);
    uss_eval_finish(e, tags);
    if (fr < 0) {
        snprintf(err, errlen, "the file changed size or couldn't be read while it was being signed");
        goto out;
    }
#ifdef PNP_TEST
    /* test hooks: a cheating signer. borderline:F changes a fraction F of its tags (it can't know where they went);
     * leak:FILE also knows one verifier's split (FILE, that verifier's verify file) and changes exactly those */
    const char *cheat = getenv("PNP_TEST_CHEAT"), *leak = getenv("PNP_TEST_SPLITS");
    if (cheat && strncmp(cheat, "borderline:", 11) == 0) {
        uint64_t per_mille = (uint64_t)(atof(cheat + 11) * 1000);
        for (uint64_t i = 0; i < nf; i++)
            if ((i * 2654435761u) % 1000 < per_mille)
                tags[i] ^= 1;
    }
    if (leak && strncmp(leak, "leak:", 5) == 0) {
        int lf = open(leak + 5, O_RDONLY | O_CLOEXEC);
        uint64_t vn = (uint64_t)N * s->k;
        uint8_t ent[USS_SPLIT_LEN];
        for (uint64_t i = 0; lf >= 0 && i < vn; i++)
            if (pread_all(lf, ent, sizeof ent, USS_VERIFY_HDR + ((uint64_t)next * vn + i) * USS_SPLIT_LEN) == 0 &&
                get32(ent) < nf)
                tags[get32(ent)] ^= 1;
        if (lf >= 0)
            close(lf);
    }
#endif
    *siglen = uss_sig_len(N, s->k);
    sig = calloc(*siglen, 1);
    if (!sig)
        goto out;
    memcpy(sig, MAGIC_SIG, 8);
    memcpy(sig + 8, s->id, GRP_ID_LEN);
    sig[24] = (uint8_t)g->me, sig[25] = (uint8_t)N;
    put32(sig + 28, next), put32(sig + 32, s->k);
    for (uint64_t i = 0; i < nf; i++)
        sig[USS_SIG_HDR + i / 4] |= (uint8_t)(tags[i] << (2 * (i % 4)));
    *slot_out = next;
    goto out;
io:
    snprintf(err, errlen, "%s: %s", path, strerror(errno));
out:
    secret_free(fns, slot_bytes);
    free(tags);
    if (fd >= 0)
        close(fd);
    free(path);
    return sig;
}

int uss_sig_parse(const uint8_t *sig, size_t siglen, uint8_t set_id[GRP_ID_LEN], int *signer, int *N, uint32_t *slot,
                  uint32_t *k)
{
    if (siglen < USS_SIG_HDR || memcmp(sig, MAGIC_SIG, 8) != 0)
        return -1;
    memcpy(set_id, sig + 8, GRP_ID_LEN);
    *signer = sig[24], *N = sig[25];
    *slot = get32(sig + 28), *k = get32(sig + 32);
    if (*N < 2 || *k == 0 || *k > 100000 || siglen != uss_sig_len(*N, *k))
        return -1;
    return 0;
}

static int sused_path(const struct grp *g, const struct grp_set *s, int j, char **path)
{
    char name[32];
    snprintf(name, sizeof name, "sused.%d", j + 1);
    *path = grp_set_path(g, s, name);
    return *path ? 0 : -1;
}

int uss_sused_create(const struct grp *g, const struct grp_set *s, int j, char *err, size_t errlen)
{
    char *path;
    if (sused_path(g, s, j, &path) < 0)
        return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    uint8_t h[16] = {0};
    memcpy(h, MAGIC_SUSED, 8);
    int ok = fd >= 0 && pwrite(fd, h, 16, 0) == 16 && ftruncate(fd, 16 + (off_t)s->slots * 32) == 0 && fsync(fd) == 0;
    if (!ok)
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
    if (fd >= 0)
        close(fd);
    grp_touch(g, path);
    free(path);
    return ok ? 0 : -1;
}

int uss_verify(struct grp *g, const uint8_t *sig, size_t siglen, uint64_t len, uss_read_fn rd, void *ctx,
               int record, struct uss_result *res, char *err, size_t errlen)
{
    memset(res, 0, sizeof *res);
    res->level = -2;
    int signer, N;
    uint32_t slot, k;
    if (uss_sig_parse(sig, siglen, res->set_id, &signer, &N, &slot, &k) < 0) {
        snprintf(err, errlen, "not a pnp signature, or a damaged one");
        return -1;
    }
    res->signer = signer, res->slot = slot;
    struct grp_set *s = grp_find_set(g, res->set_id);
    if (!s || s->k == 0) {
        snprintf(err, errlen, "this signature isn't from a key set of this group");
        return -1;
    }
    if (N != g->n - 1 || k != s->k || signer >= g->n || slot >= s->slots) {
        snprintf(err, errlen, "this signature doesn't fit its key set (damaged or altered)");
        return -1;
    }
    if (signer == g->me) {
        snprintf(err, errlen, "that's your own signature: only the other members can check it");
        return -1;
    }
    char name[32];
    snprintf(name, sizeof name, "verify.%d", signer + 1);
    char *path = grp_set_path(g, s, name);
    int fd = path ? grp_open_read(path) : -1, ret = -1;
    uint64_t nf = (uint64_t)N * k, bytes = nf * USS_SPLIT_LEN;
    uint8_t h[USS_VERIFY_HDR], *fns = NULL, *tags = NULL;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || pread_all(fd, h, sizeof h, 0) < 0) {
        snprintf(err, errlen, "no verify keys for this signer in this key set (%s)",
                 errno == ENOENT ? "wiped after the dispute period, or never imported" : strerror(errno));
        goto out;
    }
    if (memcmp(h, MAGIC_VERIFY, 8) != 0 || memcmp(h + 8, s->id, GRP_ID_LEN) != 0 || h[24] != signer ||
        h[25] != g->me || h[26] != N || get32(h + 28) != k || get32(h + 32) != s->slots ||
        (uint64_t)st.st_size != uss_verify_len(N, k, s->slots)) {
        snprintf(err, errlen, "%s isn't the verify file for this signer, or it's damaged", path);
        goto out;
    }
    fns = secret_alloc(bytes);
    tags = calloc(nf ? nf : 1, 1);
    if (!fns || !tags || pread_all(fd, fns, bytes, USS_VERIFY_HDR + (uint64_t)slot * bytes) < 0) {
        snprintf(err, errlen, "%s: %s", path, errno ? strerror(errno) : "out of memory");
        goto out;
    }
    uint64_t total = (uint64_t)N * N * k;
    for (uint64_t i = 0; i < nf; i++)
        if (get32(fns + i * USS_SPLIT_LEN) >= total || !fn_ok(fns + i * USS_SPLIT_LEN + 4)) {
            snprintf(err, errlen, "%s: slot %u is damaged", path, slot + 1);
            goto out;
        }
    struct uss_eval *e = uss_eval_new(fns + 4, USS_SPLIT_LEN, (size_t)nf);
    if (!e) {
        snprintf(err, errlen, "out of memory");
        goto out;
    }
    uint8_t frame[USS_FRAME_LEN], digest[32];
    uss_frame(frame, s->id, signer, slot, len);
    struct pnp_blake2b hb;
    pnp_blake2b_init(&hb, 32);
    int fr = feed_message(e, &hb, frame, len, rd, ctx);
    uss_eval_finish(e, tags);
    pnp_blake2b_final(&hb, digest);
    if (fr < 0) {
        snprintf(err, errlen, "the file changed size or couldn't be read while it was being checked");
        goto out;
    }
    /* mismatches per set (set b holds functions b·k .. (b+1)·k - 1) */
    uint32_t *mm = calloc((size_t)N, sizeof *mm);
    if (!mm)
        goto out;
    res->exact = 1;
    for (uint64_t i = 0; i < nf; i++) {
        uint32_t pos = get32(fns + i * USS_SPLIT_LEN);
        int t = (sig[USS_SIG_HDR + pos / 4] >> (2 * (pos % 4))) & 3;
        if (t != tags[i]) {
            mm[i / k]++;
            res->exact = 0;
        }
    }
    for (int l = g->lmax; l >= -1; l--) {
        int passed = 0;
        for (int b = 0; b < N; b++)
            passed += uss_set_passes(mm[b], k, l, g->lmax);
        if (uss_accepts(passed, N, l, g->omega)) {
            res->level = l;
            res->passed = passed;
            break;
        }
    }
    free(mm);
    /* a slot is good for one message: remember what this one signed, and say if it signed something else before
     * (the BLAKE2b digest only tells messages apart; the signature's security doesn't depend on it) */
    char *sp;
    if (res->level >= -1 && sused_path(g, s, signer, &sp) == 0) {
        int ufd = open_rw(sp);
        uint8_t was[32], h16[16];
        static const uint8_t zero[32];
        if (ufd >= 0 && pread_all(ufd, h16, 16, 0) == 0 && memcmp(h16, MAGIC_SUSED, 8) == 0 &&
            pread_all(ufd, was, 32, 16 + (uint64_t)slot * 32) == 0) {
            if (memcmp(was, zero, 32) != 0 && memcmp(was, digest, 32) != 0)
                res->reused = 1;
            else if (record && memcmp(was, zero, 32) == 0 && pwrite(ufd, digest, 32, 16 + (off_t)slot * 32) == 32) {
                fsync(ufd);
                grp_touch(g, sp);
            }
        }
        if (ufd >= 0)
            close(ufd);
        free(sp);
    }
    ret = 0;
out:
    secret_free(fns, bytes);
    free(tags);
    if (fd >= 0)
        close(fd);
    free(path);
    return ret;
}

int uss_wipe_unused(const struct grp *g, const struct grp_set *s)
{
    int N = g->n - 1;
    char *path = grp_set_path(g, s, "sign");
    int fd = path ? open_rw(path) : -1, ret = -1;
    uint8_t h[USS_SIGN_HDR];
    if (fd >= 0 && pread_all(fd, h, sizeof h, 0) == 0 && memcmp(h, MAGIC_SIGN, 8) == 0 &&
        get32(h + 32) == s->slots && get32(h + 36) <= s->slots) {
        uint64_t slot_bytes = (uint64_t)N * N * s->k * USS_FN_LEN, next = get32(h + 36);
        ret = write_zeros(fd, USS_SIGN_HDR + next * slot_bytes, (s->slots - next) * slot_bytes) == 0 && fsync(fd) == 0
                  ? 0 : -1;
        grp_touch(g, path);
    }
    if (fd >= 0)
        close(fd);
    free(path);
    return ret;
}
