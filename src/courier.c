/* Courier sticks, self sticks and kill cards (courier.h).
 *
 * A store is a raw partition (or, in tests, a file) with no filesystem: nothing mounts it, so no kernel ever parses
 * a filesystem shaped by someone else's laptop, and pnp reads it with this small parser alone (fuzzed by
 * tests/fuzz/fuzz_courier.c).
 *
 *   header (64 bytes):  0 8 "PNPCR001"; 8 role (0 courier, 1 self, 2 kill card); 9 owner; 10 visiting; 11 round;
 *                       12 done (the visited member has finished); 13 3 zero; 16 16 group ID; 32 4 generation; 36 4 zero; 40 8 records' end; 48 8 capacity;
 *                       56 8 zero
 *   records:            16-byte header (type, from, to, signer, 2-byte key set index, 2 zero, 8-byte length),
 *                       the data, then a 32-byte BLAKE2b of header and data
 *
 * The checksum catches a bad stick or a bad copy. It isn't what keeps the contents secret or genuine: that is
 * custody (a courier only ever passes between its owner and one other member at a time) and being there in person.
 * A hostile laptop can write anything here; it only ever reaches pnp's bounds-checked parser. */
#define _GNU_SOURCE
#include "courier.h"
#include "blake2b.h"
#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char MAGIC_CS[8] = {'P', 'N', 'P', 'C', 'R', '0', '0', '1'};

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

static int pwrite_all(int fd, const void *buf, size_t n, uint64_t off)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = pwrite(fd, p, n, (off_t)off);
        if (r <= 0)
            return -1;
        p += r, n -= (size_t)r, off += (uint64_t)r;
    }
    return 0;
}

static uint64_t store_size(int fd)
{
    struct stat st;
    if (fstat(fd, &st) < 0)
        return 0;
    if (S_ISBLK(st.st_mode)) {
        uint64_t size = 0;
        return ioctl(fd, BLKGETSIZE64, &size) == 0 ? size : 0;
    }
    return (uint64_t)st.st_size;
}

static int save_header(struct cstore *c)
{
    uint8_t h[CS_HDR_LEN] = {0};
    memcpy(h, MAGIC_CS, 8);
    h[8] = (uint8_t)c->role, h[9] = (uint8_t)c->owner, h[10] = (uint8_t)c->visiting, h[11] = (uint8_t)c->round;
    h[12] = (uint8_t)c->done;
    memcpy(h + 16, c->group, GRP_ID_LEN);
    put32(h + 32, c->gen);
    put64(h + 40, c->end);
    put64(h + 48, c->capacity);
    if (pwrite_all(c->fd, h, sizeof h, 0) < 0)
        return -1;
    return fsync(c->fd);
}

int cs_create(struct cstore *c, const char *path, int role, int owner, const uint8_t group[GRP_ID_LEN],
              uint32_t gen, uint64_t capacity, char *err, size_t errlen)
{
    memset(c, 0, sizeof *c);
    c->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    c->path = strdup(path);
    struct stat st;
    if (c->fd < 0 || !c->path || fstat(c->fd, &st) < 0)
        goto fail;
    if (S_ISREG(st.st_mode) && capacity && ftruncate(c->fd, (off_t)capacity) < 0)
        goto fail;
    c->capacity = S_ISREG(st.st_mode) && capacity ? capacity : store_size(c->fd);
    c->role = role, c->owner = owner, c->visiting = owner;
    memcpy(c->group, group, GRP_ID_LEN);
    c->gen = gen;
    c->end = CS_HDR_LEN;
    if (c->capacity < CS_HDR_LEN) {
        snprintf(err, errlen, "%s is too small to be a pnp drive", path);
        cs_close(c);
        return -1;
    }
    if (save_header(c) < 0)
        goto fail;
    return 0;
fail:
    snprintf(err, errlen, "%s: %s", path, strerror(errno));
    cs_close(c);
    return -1;
}

int cs_open(struct cstore *c, const char *path, char *err, size_t errlen)
{
    memset(c, 0, sizeof *c);
    c->fd = open(path, O_RDWR | O_CLOEXEC);
    c->path = strdup(path);
    uint8_t h[CS_HDR_LEN];
    if (c->fd < 0 || !c->path || pread_all(c->fd, h, sizeof h, 0) < 0) {
        snprintf(err, errlen, "%s: %s", path, errno ? strerror(errno) : "too short");
        cs_close(c);
        return -1;
    }
    c->role = h[8], c->owner = h[9], c->visiting = h[10], c->round = h[11], c->done = h[12] == 1;
    memcpy(c->group, h + 16, GRP_ID_LEN);
    c->gen = get32(h + 32);
    c->end = get64(h + 40);
    c->capacity = get64(h + 48);
    uint64_t real = store_size(c->fd);
    if (memcmp(h, MAGIC_CS, 8) != 0 || c->role > CS_KILLCARD || c->end < CS_HDR_LEN || c->end > c->capacity ||
        c->capacity > real) {
        snprintf(err, errlen, "%s isn't a pnp courier, self drive or kill card (or it's damaged)", path);
        cs_close(c);
        return -1;
    }
    return 0;
}

void cs_close(struct cstore *c)
{
    if (c->fd >= 0 && c->path)
        close(c->fd);
    free(c->path);
    c->path = NULL;
    c->fd = -1;
}

int cs_done(struct cstore *c, char *err, size_t errlen)
{
    c->done = 1;
    if (save_header(c) < 0) {
        snprintf(err, errlen, "%s: %s", c->path, strerror(errno));
        return -1;
    }
    return 0;
}

int cs_set_group(struct cstore *c, const uint8_t group[GRP_ID_LEN], uint32_t gen, char *err, size_t errlen)
{
    memcpy(c->group, group, GRP_ID_LEN);
    c->gen = gen;
    if (save_header(c) < 0) {
        snprintf(err, errlen, "%s: %s", c->path, strerror(errno));
        return -1;
    }
    return 0;
}

int cs_address(struct cstore *c, int visiting, int round, char *err, size_t errlen)
{
    c->visiting = visiting, c->round = round, c->done = 0;
    if (save_header(c) < 0) {
        snprintf(err, errlen, "%s: %s", c->path, strerror(errno));
        return -1;
    }
    return 0;
}

static void rec_hdr(uint8_t h[CS_REC_HDR], const struct crec *r)
{
    memset(h, 0, CS_REC_HDR);
    h[0] = (uint8_t)r->type, h[1] = (uint8_t)r->from, h[2] = (uint8_t)r->to, h[3] = (uint8_t)r->signer;
    h[4] = (uint8_t)r->set, h[5] = (uint8_t)(r->set >> 8);
    put64(h + 8, r->len);
}

int cs_begin(struct cstore *c, struct cwriter *w, const struct crec *r, char *err, size_t errlen)
{
    memset(w, 0, sizeof *w);
    if (r->len > c->capacity || c->end + CS_REC_HDR + CS_SUM_LEN > c->capacity - r->len) {
        snprintf(err, errlen, "%s is too small for this meeting's key material", c->path);
        return -1;
    }
    w->c = c, w->start = c->end, w->len = r->len;
    rec_hdr(w->hdr, r);
    w->hash = malloc(sizeof(struct pnp_blake2b));
    if (!w->hash || pwrite_all(c->fd, w->hdr, CS_REC_HDR, w->start) < 0) {
        snprintf(err, errlen, "%s: %s", c->path, errno ? strerror(errno) : "out of memory");
        free(w->hash);
        w->hash = NULL;
        return -1;
    }
    pnp_blake2b_init(w->hash, CS_SUM_LEN);
    pnp_blake2b_update(w->hash, w->hdr, CS_REC_HDR);
    return 0;
}

int cs_write(struct cwriter *w, const void *buf, size_t n)
{
    if (n > w->len - w->done || pwrite_all(w->c->fd, buf, n, w->start + CS_REC_HDR + w->done) < 0)
        return -1;
    pnp_blake2b_update(w->hash, buf, n);
    w->done += n;
    return 0;
}

int cs_end(struct cwriter *w, char *err, size_t errlen)
{
    uint8_t sum[CS_SUM_LEN];
    int ok = w->done == w->len;
    pnp_blake2b_final(w->hash, sum);
    free(w->hash);
    w->hash = NULL;
    uint64_t at = w->start + CS_REC_HDR + w->len;
    if (!ok || pwrite_all(w->c->fd, sum, sizeof sum, at) < 0) {
        snprintf(err, errlen, "%s: %s", w->c->path, ok ? strerror(errno) : "record length mismatch");
        return -1;
    }
    w->c->end = at + CS_SUM_LEN;
    if (save_header(w->c) < 0) {
        snprintf(err, errlen, "%s: %s", w->c->path, strerror(errno));
        return -1;
    }
    return 0;
}

int cs_record(struct cstore *c, uint64_t *pos, struct crec *r)
{
    if (*pos == 0)
        *pos = CS_HDR_LEN;
    if (*pos >= c->end)
        return 1;
    uint8_t h[CS_REC_HDR];
    if (c->end - *pos < CS_REC_HDR + CS_SUM_LEN || pread_all(c->fd, h, sizeof h, *pos) < 0)
        return -1;
    memset(r, 0, sizeof *r);
    r->type = h[0], r->from = h[1], r->to = h[2], r->signer = h[3], r->set = h[4] | h[5] << 8;
    r->len = get64(h + 8);
    if (r->len > c->end - *pos - CS_REC_HDR - CS_SUM_LEN)
        return -1;
    r->data = *pos + CS_REC_HDR;
    *pos = r->data + r->len + CS_SUM_LEN;
    return 0;
}

int cs_read(struct cstore *c, const struct crec *r, uint64_t off, void *buf, size_t n)
{
    if (off > r->len || n > r->len - off)
        return -1;
    return pread_all(c->fd, buf, n, r->data + off);
}

static int check_sum(struct cstore *c, const struct crec *r)
{
    struct pnp_blake2b s;
    uint8_t h[CS_REC_HDR], buf[65536], sum[CS_SUM_LEN], want[CS_SUM_LEN];
    pnp_blake2b_init(&s, CS_SUM_LEN);
    rec_hdr(h, r);
    pnp_blake2b_update(&s, h, sizeof h);
    for (uint64_t off = 0; off < r->len;) {
        size_t n = r->len - off < sizeof buf ? (size_t)(r->len - off) : sizeof buf;
        if (pread_all(c->fd, buf, n, r->data + off) < 0)
            return -1;
        pnp_blake2b_update(&s, buf, n);
        off += n;
    }
    pnp_blake2b_final(&s, sum);
    if (pread_all(c->fd, want, sizeof want, r->data + r->len) < 0)
        return -1;
    explicit_bzero(buf, sizeof buf);
    return memcmp(sum, want, sizeof sum) == 0 ? 0 : -1;
}

int cs_verify(struct cstore *c, char *err, size_t errlen)
{
    uint64_t pos = 0;
    struct crec r;
    int st, i = 0;
    while ((st = cs_record(c, &pos, &r)) == 0) {
        if (check_sum(c, &r) < 0) {
            snprintf(err, errlen, "%s: record %d is damaged (bad drive or bad copy): redo this transfer", c->path,
                     i + 1);
            return -1;
        }
        i++;
    }
    if (st < 0) {
        snprintf(err, errlen, "%s: its records are damaged: redo this transfer", c->path);
        return -1;
    }
    return 0;
}

int cs_find(struct cstore *c, int type, int from, int to, int signer, int set, struct crec *r)
{
    uint64_t pos = 0;
    while (cs_record(c, &pos, r) == 0)
        if (r->type == type && (from < 0 || r->from == from) && (to < 0 || r->to == to) &&
            (signer < 0 || r->signer == signer) && (set < 0 || r->set == set))
            return 0;
    return -1;
}

int cs_copy_all(struct cstore *src, struct cstore *dst, char *err, size_t errlen)
{
    if (cs_verify(src, err, errlen) < 0)
        return -1;
    uint64_t pos = 0;
    struct crec r;
    static uint8_t buf[1 << 16];
    while (cs_record(src, &pos, &r) == 0) {
        struct cwriter w;
        if (cs_begin(dst, &w, &r, err, errlen) < 0)
            return -1;
        for (uint64_t off = 0; off < r.len;) {
            size_t n = r.len - off < sizeof buf ? (size_t)(r.len - off) : sizeof buf;
            if (cs_read(src, &r, off, buf, n) < 0 || cs_write(&w, buf, n) < 0) {
                snprintf(err, errlen, "%s: %s", src->path, strerror(errno));
                return -1;
            }
            off += n;
        }
        explicit_bzero(buf, sizeof buf);
        if (cs_end(&w, err, errlen) < 0)
            return -1;
    }
    return 0;
}

/* writes for cs_overwrite; the test build can make the "drive" lie (PNP_TEST_COURIER_LIE=drop: writes are
 * ignored; =wrap: it holds only half what it claims and wraps around) */
static int overwrite_write(int fd, const void *buf, size_t n, uint64_t off, uint64_t capacity)
{
#ifdef PNP_TEST
    const char *lie = getenv("PNP_TEST_COURIER_LIE");
    if (lie && strcmp(lie, "drop") == 0)
        return 0;
    if (lie && strcmp(lie, "wrap") == 0) /* a drive that really holds only 4 KiB */
        off %= 4096;
#endif
    (void)capacity;
    return pwrite_all(fd, buf, n, off);
}

int cs_overwrite(struct cstore *c, char *err, size_t errlen)
{
    uint64_t len = c->end;
    uint8_t buf[65536], back[65536], seed[32];
    struct pnp_blake2b wrote, read;
    if (getrandom(seed, sizeof seed, 0) != (ssize_t)sizeof seed)
        goto io;
    pnp_blake2b_init(&wrote, 32);
    /* the bytes written are a keystream from a fresh seed: each chunk is BLAKE2b(seed || chunk number), so the read
     * back can be checked chunk by chunk without keeping a copy */
    for (uint64_t off = 0, i = 0; off < len; off += sizeof buf, i++) {
        size_t n = len - off < sizeof buf ? (size_t)(len - off) : sizeof buf;
        for (size_t j = 0; j < n; j += 64) {
            uint8_t in[48];
            memcpy(in, seed, 32), put64(in + 32, i), put64(in + 40, j);
            uint8_t out[64];
            pnp_blake2b(out, 64, in, sizeof in);
            memcpy(buf + j, out, n - j < 64 ? n - j : 64);
        }
        if (overwrite_write(c->fd, buf, n, off, c->capacity) < 0)
            goto io;
        pnp_blake2b_update(&wrote, buf, n);
    }
    if (fsync(c->fd) < 0)
        goto io;
    /* read it all back: the bytes must be exactly those written */
    posix_fadvise(c->fd, 0, (off_t)len, POSIX_FADV_DONTNEED);
    pnp_blake2b_init(&read, 32);
    for (uint64_t off = 0; off < len; off += sizeof back) {
        size_t n = len - off < sizeof back ? (size_t)(len - off) : sizeof back;
        if (pread_all(c->fd, back, n, off) < 0)
            goto io;
        pnp_blake2b_update(&read, back, n);
    }
    uint8_t a[32], b[32];
    pnp_blake2b_final(&wrote, a);
    pnp_blake2b_final(&read, b);
    if (memcmp(a, b, sizeof a) != 0) {
        snprintf(err, errlen,
                 "%s didn't keep what was written over it (it ignores writes or isn't as big as it claims): don't use "
                 "this drive; destroy it, and use another one", c->path);
        return -1;
    }
    c->end = CS_HDR_LEN;
    c->visiting = c->owner, c->done = 0;
    if (save_header(c) < 0)
        goto io;
    return 0;
io:
    snprintf(err, errlen, "%s: %s", c->path, strerror(errno));
    return -1;
}

/* ---- finding sticks ---- */
/* whether the block device with this major:minor is a partition of pnp's type (udev's record of it) */
static int is_pnp_partition(unsigned maj, unsigned min)
{
    char path[64], line[256];
    snprintf(path, sizeof path, "/run/udev/data/b%u:%u", maj, min);
    FILE *f = fopen(path, "re");
    int yes = 0;
    while (f && !yes && fgets(line, sizeof line, f))
        yes = strncmp(line, "E:ID_PART_ENTRY_TYPE=" CS_PART_TYPE, 21 + 36) == 0;
    if (f)
        fclose(f);
    return yes;
}

int cs_find_devices(const char *dir, char **paths, int max)
{
    int n = 0;
    DIR *d = opendir(dir ? dir : "/dev/disk/by-partuuid");
    struct dirent *e;
    while (d && n < max && (e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        char *p = NULL, *real = NULL;
        if (asprintf(&p, "%s/%s", dir ? dir : "/dev/disk/by-partuuid", e->d_name) < 0)
            continue;
        struct stat st;
        if (dir) {
            if (stat(p, &st) == 0 && S_ISREG(st.st_mode))
                paths[n++] = p, p = NULL;
        } else if ((real = realpath(p, NULL)) && stat(real, &st) == 0 && S_ISBLK(st.st_mode) &&
                   is_pnp_partition(major(st.st_rdev), minor(st.st_rdev))) {
            paths[n++] = real, real = NULL;
        }
        free(p), free(real);
    }
    if (d)
        closedir(d);
    return n;
}

int cs_capacity_check(const char *path, char *err, size_t errlen)
{
    struct cstore c;
    memset(&c, 0, sizeof c);
    c.fd = open(path, O_RDWR | O_CLOEXEC);
    c.path = strdup(path);
    if (c.fd < 0 || !c.path) {
        snprintf(err, errlen, "%s: %s%s", path, strerror(errno),
                 errno == EACCES ? " (is it a pnp drive? Run sudo pnp-courier-setup on it, and join the pnp group)" : "");
        cs_close(&c);
        return -1;
    }
    c.capacity = c.end = store_size(c.fd);
    c.role = CS_COURIER;
    int r = c.capacity < CS_HDR_LEN ? -1 : cs_overwrite(&c, err, errlen);
    if (c.capacity < CS_HDR_LEN)
        snprintf(err, errlen, "%s is too small", path);
    static const uint8_t zero[CS_HDR_LEN];
    if (r == 0 && (pwrite_all(c.fd, zero, sizeof zero, 0) < 0 || fsync(c.fd) < 0)) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        r = -1;
    }
    cs_close(&c);
    return r;
}
