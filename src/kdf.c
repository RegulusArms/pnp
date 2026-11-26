/* Memory-hard password hashing for --protect (see protect.c for how the two are chained).
 *
 * Both functions make every passphrase guess cost a lot of memory and time, so an attacker can't try guesses quickly
 * on GPUs or custom chips (memory, unlike arithmetic, doesn't get cheap in bulk). They're computationally secure
 * only: P = NP would break them. pnp runs both, one after the other, as a hedge: if a shortcut is found for one (a
 * way to compute it with much less memory), every guess still costs the other in full.
 *
 * Balloon (Boneh, Corrigan-Gibbs, Schechter, "Balloon Hashing", ASIACRYPT 2016, Algorithm 1): proven memory-hard in
 * the random-oracle model. Argon2id (RFC 9106): the Password Hashing Competition winner and the most analysed.
 * Both are checked against independent implementations in tests/test_kdf.c. */
#define _GNU_SOURCE
#include "kdf.h"
#include "blake2b.h"

#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static pnp_kdf_progress_fn progress_fn;

void pnp_kdf_set_progress(pnp_kdf_progress_fn fn) { progress_fn = fn; }

static void report(const char *phase, uint64_t done, uint64_t total)
{
    if (progress_fn)
        progress_fn(phase, done, total);
}

static int strict;
void pnp_kdf_set_strict(int on) { strict = on; }

/* The big buffers: mmap'd (so they go back to the system at once), kept out of core dumps, wiped in a child if
 * anything ever forked, wiped when done. Locked in RAM when the limit allows: what they hold is derived from the
 * passphrase, and on swap it would outlive the run. The default limit (8 MiB) is far below the default 1 GiB, so
 * usually they aren't; --strict (pnp_kdf_set_strict) makes that a failure instead. */
static void *big_alloc(size_t n)
{
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    madvise(p, n, MADV_DONTDUMP);
#ifdef MADV_WIPEONFORK
    madvise(p, n, MADV_WIPEONFORK);
#endif
    if (mlock(p, n) < 0 && strict) {
        munmap(p, n);
        return NULL;
    }
    return p;
}

static void big_free(void *p, size_t n)
{
    explicit_bzero(p, n);
    munmap(p, n); /* unlocks it too */
}

static void le32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

static void le64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

/* ---- Balloon ----
 * hash(cnt, x, y) = BLAKE2b-512(LE64(cnt) || x || y), cnt counting every hash. With s blocks of 64 bytes:
 *   expand:  buf[0] = hash(cnt++, passwd, salt); buf[m] = hash(cnt++, buf[m-1])
 *   mix, t_cost times, for each m: buf[m] = hash(cnt++, buf[m-1 mod s], buf[m]), then 3 times (delta = 3):
 *            other = hash(cnt++, salt, LE64(t) || LE64(m) || LE64(i)) as a little-endian integer, mod s
 *            buf[m] = hash(cnt++, buf[m], buf[other])
 *   result:  buf[s-1]
 * Which blocks are read depends only on the salt, never on the passphrase, so the timing reveals nothing about it. */
static void bhash(uint8_t *out, uint64_t cnt, const uint8_t *x, size_t xn, const uint8_t *y, size_t yn)
{
    struct pnp_blake2b s;
    uint8_t c[8];
    le64(c, cnt);
    pnp_blake2b_init(&s, PNP_BALLOON_BLOCK);
    pnp_blake2b_update(&s, c, sizeof c);
    pnp_blake2b_update(&s, x, xn);
    pnp_blake2b_update(&s, y, yn);
    pnp_blake2b_final(&s, out); /* out may be x or y: they're read before it's written */
}

int pnp_balloon(uint8_t out[PNP_BALLOON_BLOCK], const uint8_t *pwd, size_t pwdlen, const uint8_t *salt,
                size_t saltlen, uint64_t s_cost, uint32_t t_cost)
{
    /* s_cost < 2^40 keeps the mod below exact in 64 bits (r * 256 + 255 < 2^64) */
    if (s_cost < 2 || s_cost > ((uint64_t)1 << 40) || t_cost < 1 || saltlen > 64)
        return -1;
    size_t len = (size_t)s_cost * PNP_BALLOON_BLOCK;
    uint8_t *buf = big_alloc(len);
    if (!buf)
        return -1;
#define BLK(i) (buf + (size_t)(i) * PNP_BALLOON_BLOCK)
    uint64_t cnt = 0;
    uint8_t idx_in[64 + 24], idx[PNP_BALLOON_BLOCK];
    memcpy(idx_in, salt, saltlen);
    /* progress in block steps: s_cost to expand, then s_cost per round */
    uint64_t steps = s_cost * (1 + (uint64_t)t_cost);
    report("Balloon", 0, steps);
    bhash(BLK(0), cnt++, pwd, pwdlen, salt, saltlen);
    for (uint64_t m = 1; m < s_cost; m++) {
        bhash(BLK(m), cnt++, BLK(m - 1), PNP_BALLOON_BLOCK, NULL, 0);
        if (m % 4096 == 0)
            report("Balloon", m, steps);
    }
    for (uint32_t t = 0; t < t_cost; t++) {
        for (uint64_t m = 0; m < s_cost; m++) {
            if (m % 4096 == 0)
                report("Balloon", s_cost * (1 + (uint64_t)t) + m, steps);
            bhash(BLK(m), cnt++, BLK((m + s_cost - 1) % s_cost), PNP_BALLOON_BLOCK, BLK(m), PNP_BALLOON_BLOCK);
            for (uint64_t i = 0; i < 3; i++) {
                le64(idx_in + saltlen, t);
                le64(idx_in + saltlen + 8, m);
                le64(idx_in + saltlen + 16, i);
                bhash(idx, cnt++, idx_in, saltlen + 24, NULL, 0);
                uint64_t other = 0;
                for (int j = PNP_BALLOON_BLOCK - 1; j >= 0; j--)
                    other = (other * 256 + idx[j]) % s_cost;
                bhash(BLK(m), cnt++, BLK(m), PNP_BALLOON_BLOCK, BLK(other), PNP_BALLOON_BLOCK);
            }
        }
    }
    report("Balloon", steps, steps);
    memcpy(out, BLK(s_cost - 1), PNP_BALLOON_BLOCK);
#undef BLK
    big_free(buf, len);
    return 0;
}

/* ---- Argon2id (RFC 9106, sections 3.1-3.6) ---- */

#define BLOCK_WORDS 128 /* a 1 KiB block as 64-bit words */

struct block {
    uint64_t v[BLOCK_WORDS];
};

/* H'^T(X), the variable-length hash (section 3.3), written as H'(LE32(T) || X) built from BLAKE2b-512 */
static void hprime(uint8_t *out, uint32_t T, const uint8_t *x, size_t xn)
{
    struct pnp_blake2b s;
    uint8_t t4[4], v[64];
    le32(t4, T);
    pnp_blake2b_init(&s, T <= 64 ? T : 64);
    pnp_blake2b_update(&s, t4, 4);
    pnp_blake2b_update(&s, x, xn);
    if (T <= 64) {
        pnp_blake2b_final(&s, out);
        return;
    }
    pnp_blake2b_final(&s, v); /* V_1 */
    uint32_t r = (T + 31) / 32 - 2;
    for (uint32_t i = 1; i < r; i++) {
        memcpy(out, v, 32);
        out += 32;
        pnp_blake2b(v, 64, v, 64); /* V_(i+1) */
    }
    memcpy(out, v, 32);
    out += 32;
    pnp_blake2b(out, T - 32 * r, v, 64); /* V_(r+1), the last T - 32r bytes */
    explicit_bzero(v, sizeof v);
}

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

/* BlaMka: BLAKE2b's G with each addition a + b replaced by a + b + 2 * lo32(a) * lo32(b) (section 3.6) */
static uint64_t fbl(uint64_t a, uint64_t b) { return a + b + 2 * (uint64_t)(uint32_t)a * (uint32_t)b; }

#define GB(a, b, c, d)                                                                                                \
    do {                                                                                                              \
        a = fbl(a, b);                                                                                                \
        d = rotr64(d ^ a, 32);                                                                                        \
        c = fbl(c, d);                                                                                                \
        b = rotr64(b ^ c, 24);                                                                                        \
        a = fbl(a, b);                                                                                                \
        d = rotr64(d ^ a, 16);                                                                                        \
        c = fbl(c, d);                                                                                                \
        b = rotr64(b ^ c, 63);                                                                                        \
    } while (0)

/* the permutation P on 16 words (section 3.6) */
#define PERM(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)                                   \
    do {                                                                                                              \
        GB(v0, v4, v8, v12);                                                                                          \
        GB(v1, v5, v9, v13);                                                                                          \
        GB(v2, v6, v10, v14);                                                                                         \
        GB(v3, v7, v11, v15);                                                                                         \
        GB(v0, v5, v10, v15);                                                                                         \
        GB(v1, v6, v11, v12);                                                                                         \
        GB(v2, v7, v8, v13);                                                                                          \
        GB(v3, v4, v9, v14);                                                                                          \
    } while (0)

/* next = G(prev, ref), or (with_xor, passes after the first) next ^= G(prev, ref). G: R = X ^ Y; P on each row of
 * R (8 rows of 16 words), then on each column (8 columns of 16 words, two adjacent words from each row); then Z ^ R.
 * next may be ref (making the address blocks). */
static void fill_block(const struct block *prev, const struct block *ref, struct block *next, int with_xor)
{
    struct block r, z;
    for (int i = 0; i < BLOCK_WORDS; i++)
        r.v[i] = z.v[i] = prev->v[i] ^ ref->v[i];
    uint64_t *v = z.v;
    for (int i = 0; i < 8; i++) {
        uint64_t *w = v + 16 * i;
        PERM(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);
    }
    for (int i = 0; i < 8; i++) {
        uint64_t *w = v + 2 * i;
        PERM(w[0], w[1], w[16], w[17], w[32], w[33], w[48], w[49], w[64], w[65], w[80], w[81], w[96], w[97], w[112],
             w[113]);
    }
    for (int i = 0; i < BLOCK_WORDS; i++)
        next->v[i] = (with_xor ? next->v[i] : 0) ^ z.v[i] ^ r.v[i];
}

static void load_block(struct block *b, const uint8_t *in)
{
    for (int i = 0; i < BLOCK_WORDS; i++) {
        uint64_t w = 0;
        for (int j = 7; j >= 0; j--)
            w = (w << 8) | in[8 * i + j];
        b->v[i] = w;
    }
}

struct argon2 {
    struct block *mem;
    uint32_t lanes, q, seg, passes, mprime; /* q: blocks per lane; seg: blocks per segment (q / 4) */
};

/* which block of the reference lane to use (section 3.4.2): one already computed and not being computed in
 * parallel, chosen non-uniformly (biased towards recent blocks) from J1 */
static uint32_t ref_index(const struct argon2 *a, uint32_t pass, uint32_t slice, uint32_t index, uint32_t j1,
                          int same_lane)
{
    uint64_t area; /* how many blocks may be referenced */
    if (pass == 0) {
        if (slice == 0)
            area = index - 1; /* only this lane's blocks so far, less the previous one */
        else
            area = (uint64_t)slice * a->seg + (same_lane ? (uint64_t)index - 1 : index == 0 ? (uint64_t)-1 : 0);
    } else {
        area = (uint64_t)a->q - a->seg + (same_lane ? (uint64_t)index - 1 : index == 0 ? (uint64_t)-1 : 0);
    }
    uint64_t x = ((uint64_t)j1 * j1) >> 32;
    uint64_t rel = area - 1 - ((area * x) >> 32);
    uint64_t start = pass != 0 && slice != 3 ? (uint64_t)(slice + 1) * a->seg : 0;
    return (uint32_t)((start + rel) % a->q);
}

/* the next 128 data-independent pseudo-random values: G(0, G(0, input)) with the input's counter incremented */
static void next_addresses(struct block *addr, struct block *in, const struct block *zero)
{
    in->v[6]++;
    fill_block(zero, in, addr, 0);
    fill_block(zero, addr, addr, 0);
}

/* report: lane 0, on the calling thread, stands for every lane's progress (they run in step) */
static void fill_segment(const struct argon2 *a, uint32_t pass, uint32_t lane, uint32_t slice, int report_it)
{
    /* Argon2id: the first half of the first pass picks blocks independently of the data (as Argon2i, resisting
     * side channels), the rest from the data (as Argon2d, resisting time-memory trade-offs) */
    int indep = pass == 0 && slice < 2;
    struct block in, addr, zero;
    memset(&in, 0, sizeof in);
    memset(&addr, 0, sizeof addr);
    memset(&zero, 0, sizeof zero);
    uint32_t start = pass == 0 && slice == 0 ? 2 : 0; /* blocks 0 and 1 of each lane come from H0 */
    if (indep) {
        in.v[0] = pass;
        in.v[1] = lane;
        in.v[2] = slice;
        in.v[3] = a->mprime;
        in.v[4] = a->passes;
        in.v[5] = 2; /* the type: Argon2id */
        if (start)
            next_addresses(&addr, &in, &zero);
    }
    uint32_t cur = lane * a->q + slice * a->seg + start;
    uint32_t prev = cur % a->q == 0 ? cur + a->q - 1 : cur - 1;
    for (uint32_t i = start; i < a->seg; i++, cur++, prev++) {
        if (cur % a->q == 1)
            prev = cur - 1;
        uint64_t rnd;
        if (indep) {
            if (i % BLOCK_WORDS == 0)
                next_addresses(&addr, &in, &zero);
            rnd = addr.v[i % BLOCK_WORDS];
        } else {
            rnd = a->mem[prev].v[0];
        }
        uint32_t ref_lane = pass == 0 && slice == 0 ? lane : (uint32_t)((rnd >> 32) % a->lanes);
        uint32_t idx = ref_index(a, pass, slice, i, (uint32_t)rnd, ref_lane == lane);
        if (report_it && i % 4096 == 0)
            report("Argon2id", ((uint64_t)pass * 4 + slice) * a->seg + i, (uint64_t)a->passes * 4 * a->seg);
        fill_block(&a->mem[prev], &a->mem[(size_t)ref_lane * a->q + idx], &a->mem[cur], pass != 0);
    }
    explicit_bzero(&addr, sizeof addr);
}

/* one thread's share of a slice: lanes first, first + step, first + 2 step... */
struct lanes_job {
    const struct argon2 *a;
    uint32_t pass, slice, first, step;
};

static void *run_lanes(void *arg)
{
    const struct lanes_job *j = arg;
    for (uint32_t l = j->first; l < j->a->lanes; l += j->step)
        fill_segment(j->a, j->pass, l, j->slice, l == 0);
    return NULL;
}

int pnp_argon2id(uint8_t *out, size_t outlen, const uint8_t *pwd, size_t pwdlen, const uint8_t *salt, size_t saltlen,
                 const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen, uint32_t m_kib, uint32_t t,
                 uint32_t lanes)
{
    if (outlen < 4 || outlen > 1024 || lanes < 1 || lanes > 255 || t < 1 || m_kib < 8 * lanes || saltlen < 8 ||
        pwdlen > UINT32_MAX || saltlen > UINT32_MAX || secretlen > 32 || adlen > UINT32_MAX)
        return -1;
    struct argon2 a;
    a.lanes = lanes;
    a.passes = t;
    a.mprime = 4 * lanes * (m_kib / (4 * lanes));
    a.q = a.mprime / lanes;
    a.seg = a.q / 4;
    size_t len = (size_t)a.mprime * sizeof(struct block);
    a.mem = big_alloc(len);
    if (!a.mem)
        return -1;

    /* H0 = H^64(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) || each of P, S, K, X with its
     * LE32 length) (section 3.2) */
    uint8_t h0[64 + 8], w[4], blk[1024];
    struct pnp_blake2b s;
    pnp_blake2b_init(&s, 64);
    const uint32_t head[6] = {lanes, (uint32_t)outlen, m_kib, t, 0x13, 2};
    for (int i = 0; i < 6; i++) {
        le32(w, head[i]);
        pnp_blake2b_update(&s, w, 4);
    }
    const uint8_t *part[4] = {pwd, salt, secret, ad};
    const size_t plen[4] = {pwdlen, saltlen, secretlen, adlen};
    for (int i = 0; i < 4; i++) {
        le32(w, (uint32_t)plen[i]);
        pnp_blake2b_update(&s, w, 4);
        if (plen[i])
            pnp_blake2b_update(&s, part[i], plen[i]);
    }
    pnp_blake2b_final(&s, h0);

    /* the first two blocks of each lane: H'^1024(H0 || LE32(0 or 1) || LE32(lane)) */
    for (uint32_t l = 0; l < lanes; l++) {
        for (uint32_t j = 0; j < 2; j++) {
            le32(h0 + 64, j);
            le32(h0 + 68, l);
            hprime(blk, 1024, h0, sizeof h0);
            load_block(&a.mem[(size_t)l * a.q + j], blk);
        }
    }
    /* Within a slice the lanes are independent (each only references other lanes' finished slices), so they run in
     * parallel: thread i takes lanes i, i + n, i + 2n... Every thread finishes the slice before the next starts. */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t nth = cpus < 1 ? 1 : (uint32_t)cpus < lanes ? (uint32_t)cpus : lanes;
    struct lanes_job job[255];
    pthread_t th[255];
    for (uint32_t pass = 0; pass < t; pass++) {
        for (uint32_t slice = 0; slice < 4; slice++) {
            int started[255] = {0};
            for (uint32_t i = 0; i < nth; i++)
                job[i] = (struct lanes_job){&a, pass, slice, i, nth};
            for (uint32_t i = 1; i < nth; i++)
                started[i] = pthread_create(&th[i], NULL, run_lanes, &job[i]) == 0;
            run_lanes(&job[0]);
            for (uint32_t i = 1; i < nth; i++) {
                if (started[i])
                    pthread_join(th[i], NULL);
                else
                    run_lanes(&job[i]); /* no thread could be made: do its lanes here */
            }
        }
    }

    /* C = XOR of each lane's last block; tag = H'^T(C) */
    struct block c = a.mem[a.q - 1];
    for (uint32_t l = 1; l < lanes; l++)
        for (int i = 0; i < BLOCK_WORDS; i++)
            c.v[i] ^= a.mem[(size_t)l * a.q + a.q - 1].v[i];
    for (int i = 0; i < BLOCK_WORDS; i++)
        le64(blk + 8 * i, c.v[i]);
    hprime(out, (uint32_t)outlen, blk, sizeof blk);
    report("Argon2id", (uint64_t)t * 4 * a.seg, (uint64_t)t * 4 * a.seg);

    explicit_bzero(h0, sizeof h0);
    explicit_bzero(blk, sizeof blk);
    explicit_bzero(&c, sizeof c);
    big_free(a.mem, len);
    return 0;
}
