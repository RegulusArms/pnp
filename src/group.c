/* Pairs and groups: storage (see group.h).
 *
 * A group lives in one folder on a code cylinder, "pnp-group-<ID in hex>", made at import after a meeting:
 *
 *   group                  the roster, settings and key sets (grp_parse / grp_serialise; rewritten atomically)
 *   names.local            optional private nicknames (anonymous groups), never shared
 *   set-<ID>/pool.<a>-<b>  the pad from member a to member b, for seals and messages: a 64-byte header, then one
 *                          24-byte locator entry per seal or message, then the pad bytes
 *   set-<ID>/recv.<a>      what has arrived from a: locators seen and pad ranges used
 *   set-<ID>/sign, verify.<a>, sused.<a>   group signatures (uss.c)
 *   kills/                 kill and leave notices received (kill.c)
 *
 * Every file is 0600 in 0700 folders. Nothing records when anything was done: after every write the file's and its
 * folder's mtime and atime are reset to one fixed time (grp_touch), and reads use O_NOATIME, so the timestamps don't
 * become an activity log. (ctime can't be reset without root; docs/group.md says so.)
 *
 * Every byte read from a group file is checked before use: the files sit on a removable drive that anyone holding
 * it could alter. tests/fuzz/fuzz_group.c runs the parser on arbitrary bytes. */
#define _GNU_SOURCE
#include "group.h"
#include "fileio.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char MAGIC_GROUP[8] = {'P', 'N', 'P', 'G', 'R', '0', '0', '1'};
static const char MAGIC_POOL[8] = {'P', 'N', 'P', 'P', 'L', '0', '0', '1'};
static const char MAGIC_RECV[8] = {'P', 'N', 'P', 'R', 'V', '0', '0', '1'};

#define GRP_FILE_MAX (GRP_HDR_LEN + GRP_MAX_MEMBERS * GRP_MEMBER_LEN + 64 + GRP_MAX_SETS * GRP_SET_LEN)
#define MAX_NLOC (1u << 24)            /* seals + messages per pool direction */
#define MAX_POOL ((uint64_t)1 << 44)   /* 16 TiB per direction */

static void put16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v, b[1] = (uint8_t)(v >> 8); }
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
static uint16_t get16(const uint8_t *b) { return (uint16_t)(b[0] | b[1] << 8); }
static uint32_t get32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static uint64_t get64(const uint8_t *b) { return (uint64_t)get32(b) | (uint64_t)get32(b + 4) << 32; }

/* ---- the group file ----
 *   0  8  "PNPGR001"          36  2  time zone (minutes east of UTC, signed)
 *   8 16  group ID            38  2  key sets
 *  24  4  generation          40  4  dispute period (days; 0 = keep verify keys)
 *  28  1  members (2..255)    44  4  clock guard day (signed)
 *  29  1  me                  48  4  creation day (signed)
 *  30  1  ω  31 1 l_max       52 12  zero
 *  32  1  kill threshold      64 64  group name (NUL-terminated)
 *  33  1  grace days         128     members × 32 (names, NUL-terminated), the left and expelled bitmaps (32 each),
 *  34  1  flags (1 anonymous, 2 signed by default)          then the key sets, 64 bytes each:
 *  35  1  zero
 *   key set:  0 16 ID; 16 kind; 17 state; 18 reason; 19 zero; 20 4 start day; 24 4 end day; 28 4 signatures per
 *             member; 32 4 k; 36 4 locators per direction; 40 8 pad bytes per direction; 48 4 suspect day;
 *             52 suspect member; 53 3 zero; 56 4 suspect slot; 60 4 zero */
size_t grp_file_len(int n, int nsets)
{
    return GRP_HDR_LEN + (size_t)n * GRP_MEMBER_LEN + 64 + (size_t)nsets * GRP_SET_LEN;
}

static int terminated(const uint8_t *b, size_t len) { return memchr(b, 0, len) != NULL; }
static int all_zero(const uint8_t *b, size_t len)
{
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++)
        d |= b[i];
    return d == 0;
}

int grp_parse(const uint8_t *b, size_t len, struct grp *g)
{
    memset(g, 0, sizeof *g);
    if (len < GRP_HDR_LEN || memcmp(b, MAGIC_GROUP, 8) != 0)
        return -1;
    memcpy(g->id, b + 8, GRP_ID_LEN);
    g->gen = get32(b + 24);
    g->n = b[28], g->me = b[29], g->omega = b[30], g->lmax = b[31], g->threshold = b[32], g->grace = b[33];
    g->anon = b[34] & 1, g->signed_default = (b[34] >> 1) & 1;
    g->tz_min = (int16_t)get16(b + 36);
    g->nsets = get16(b + 38);
    g->dispute_days = get32(b + 40);
    g->guard_day = (int32_t)get32(b + 44);
    g->created_day = (int32_t)get32(b + 48);
    if (g->n < 2 || g->me >= g->n || b[34] > 3 || g->grace > 30 || g->tz_min < -720 || g->tz_min > 840 ||
        g->nsets > GRP_MAX_SETS || g->threshold < 1 || g->threshold > g->n || g->lmax > 8 ||
        (g->n >= 3 && (g->omega < 1 || 2 * g->omega >= g->n)) || g->dispute_days > 36500)
        return -1;
    if (len != grp_file_len(g->n, g->nsets) || !terminated(b + 64, GRP_NAME_LEN) || b[35] != 0 ||
        !all_zero(b + 52, 12))
        return -1; /* the zero bytes must be zero: one file, one way to write it */
    memcpy(g->name, b + 64, GRP_NAME_LEN);
    const uint8_t *p = b + GRP_HDR_LEN;
    for (int i = 0; i < g->n; i++, p += GRP_MEMBER_LEN) {
        if (!terminated(p, GRP_MEMBER_LEN))
            return -1;
        memcpy(g->member[i], p, GRP_MEMBER_LEN);
    }
    memcpy(g->left, p, 32), memcpy(g->expelled, p + 32, 32);
    p += 64;
    g->sets = calloc(g->nsets ? (size_t)g->nsets : 1, sizeof *g->sets);
    if (!g->sets)
        return -1;
    for (int i = 0; i < g->nsets; i++, p += GRP_SET_LEN) {
        struct grp_set *s = &g->sets[i];
        memcpy(s->id, p, GRP_ID_LEN);
        s->kind = p[16], s->state = p[17], s->reason = p[18];
        s->start_day = (int32_t)get32(p + 20), s->end_day = (int32_t)get32(p + 24);
        s->slots = get32(p + 28), s->k = get32(p + 32), s->nloc = get32(p + 36), s->pool_bytes = get64(p + 40);
        s->suspect_day = (int32_t)get32(p + 48), s->suspect_member = p[52], s->suspect_slot = get32(p + 56);
        if (p[19] != 0 || !all_zero(p + 53, 3) || !all_zero(p + 60, 4) || s->kind > GRP_SET_EMERGENCY ||
            s->state > GRP_CLOSED || s->reason > GRP_R_ENDED ||
            s->start_day > s->end_day || s->nloc > MAX_NLOC || s->pool_bytes > MAX_POOL || s->slots > 1000000 ||
            s->k > 100000 || (g->n >= 3 && s->slots && s->k == 0) || s->suspect_member >= g->n) {
            free(g->sets);
            g->sets = NULL;
            return -1;
        }
    }
    return 0;
}

void grp_serialise(const struct grp *g, uint8_t *buf)
{
    memset(buf, 0, grp_file_len(g->n, g->nsets));
    memcpy(buf, MAGIC_GROUP, 8);
    memcpy(buf + 8, g->id, GRP_ID_LEN);
    put32(buf + 24, g->gen);
    buf[28] = (uint8_t)g->n, buf[29] = (uint8_t)g->me, buf[30] = (uint8_t)g->omega, buf[31] = (uint8_t)g->lmax;
    buf[32] = (uint8_t)g->threshold, buf[33] = (uint8_t)g->grace;
    buf[34] = (uint8_t)(g->anon | g->signed_default << 1);
    put16(buf + 36, (uint16_t)(int16_t)g->tz_min);
    put16(buf + 38, (uint16_t)g->nsets);
    put32(buf + 40, g->dispute_days);
    put32(buf + 44, (uint32_t)g->guard_day);
    put32(buf + 48, (uint32_t)g->created_day);
    memcpy(buf + 64, g->name, GRP_NAME_LEN - 1);
    uint8_t *p = buf + GRP_HDR_LEN;
    for (int i = 0; i < g->n; i++, p += GRP_MEMBER_LEN)
        memcpy(p, g->member[i], GRP_MEMBER_LEN - 1);
    memcpy(p, g->left, 32), memcpy(p + 32, g->expelled, 32);
    p += 64;
    for (int i = 0; i < g->nsets; i++, p += GRP_SET_LEN) {
        const struct grp_set *s = &g->sets[i];
        memcpy(p, s->id, GRP_ID_LEN);
        p[16] = s->kind, p[17] = s->state, p[18] = s->reason;
        put32(p + 20, (uint32_t)s->start_day), put32(p + 24, (uint32_t)s->end_day);
        put32(p + 28, s->slots), put32(p + 32, s->k), put32(p + 36, s->nloc), put64(p + 40, s->pool_bytes);
        put32(p + 48, (uint32_t)s->suspect_day), p[52] = s->suspect_member, put32(p + 56, s->suspect_slot);
    }
}

void grp_free(struct grp *g)
{
    free(g->sets);
    free(g->dir);
    g->sets = NULL, g->dir = NULL;
}

int grp_open_read(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM) /* O_NOATIME needs the file's owner: someone else's file is read normally */
        fd = open(path, O_RDONLY | O_CLOEXEC);
    return fd;
}

struct __dirstream *grp_opendir(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM)
        fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    DIR *d = fdopendir(fd);
    if (!d)
        close(fd);
    return d;
}

/* reads a whole small file (at most max bytes) */
static uint8_t *read_file(const char *path, size_t max, size_t *len)
{
    int fd = grp_open_read(path);
    if (fd < 0)
        return NULL;
    struct stat st;
    uint8_t *b = NULL;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_size <= max) {
        b = malloc(st.st_size ? (size_t)st.st_size : 1);
        if (b && pread(fd, b, (size_t)st.st_size, 0) != st.st_size) {
            free(b);
            b = NULL;
        }
        *len = (size_t)st.st_size;
    }
    close(fd);
    return b;
}

int grp_load(const char *dir, struct grp *g, char *err, size_t errlen)
{
    memset(g, 0, sizeof *g);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/group", dir);
    size_t len = 0;
    uint8_t *b = read_file(path, GRP_FILE_MAX, &len);
    if (!b) {
        snprintf(err, errlen, "%s: %s", path, errno ? strerror(errno) : "too large to be a group file");
        return -1;
    }
    int r = grp_parse(b, len, g);
    free(b);
    if (r < 0) {
        snprintf(err, errlen, "%s isn't a pnp group file, or it's damaged", path);
        return -1;
    }
    g->dir = strdup(dir);
    return g->dir ? 0 : -1;
}

/* writes a whole file atomically (part file, fsync, rename), then resets the timestamps */
static int save_file(const struct grp *g, const char *path, const uint8_t *buf, size_t len, char *err,
                     size_t errlen)
{
    struct pnp_out o;
    if (pnp_out_open(&o, path, 0600, err, errlen) < 0)
        return -1;
    if (pnp_write_all(o.fd, buf, len) < 0) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        pnp_out_discard(&o);
        return -1;
    }
    if (pnp_out_commit(&o, 1, err, errlen) < 0) {
        pnp_out_discard(&o);
        return -1;
    }
    pnp_out_discard(&o);
    pnp_sync_dir(path);
    grp_touch(g, path);
    char *d = pnp_dir_of(path);
    if (d)
        grp_touch(g, d);
    free(d);
    return 0;
}

int grp_save(struct grp *g, char *err, size_t errlen)
{
    size_t len = grp_file_len(g->n, g->nsets);
    uint8_t *b = malloc(len);
    if (!b) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    grp_serialise(g, b);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/group", g->dir);
    int r = save_file(g, path, b, len, err, errlen);
    free(b);
    return r;
}

/* ---- names and paths ---- */
void grp_hex(const uint8_t id[GRP_ID_LEN], char out[2 * GRP_ID_LEN + 1])
{
    for (int i = 0; i < GRP_ID_LEN; i++)
        snprintf(out + 2 * i, 3, "%02x", id[i]);
}

int grp_unhex(const char *s, uint8_t id[GRP_ID_LEN])
{
    if (strlen(s) != 2 * GRP_ID_LEN)
        return -1;
    for (int i = 0; i < GRP_ID_LEN; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return -1;
        id[i] = (uint8_t)v;
    }
    return 0;
}

char *grp_set_path(const struct grp *g, const struct grp_set *s, const char *file)
{
    char hex[2 * GRP_ID_LEN + 1], *p = NULL;
    grp_hex(s->id, hex);
    if (asprintf(&p, "%s/set-%s%s%s", g->dir, hex, file ? "/" : "", file ? file : "") < 0)
        return NULL;
    return p;
}

const char *grp_member_name(const struct grp *g, int i, char *buf, size_t len)
{
    if (g->anon || !g->member[i][0])
        snprintf(buf, len, "member %d", i + 1);
    else
        snprintf(buf, len, "%s", g->member[i]);
    return buf;
}

int grp_find_member(const struct grp *g, const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*s && !*end && v >= 1 && v <= g->n)
        return (int)v - 1;
    for (int i = 0; i < g->n; i++)
        if (!g->anon && strcasecmp(g->member[i], s) == 0)
            return i;
    return -1;
}

int grp_bit(const uint8_t *map, int i) { return (map[i / 8] >> (i % 8)) & 1; }
void grp_set_bit(uint8_t *map, int i) { map[i / 8] |= (uint8_t)(1 << (i % 8)); }

struct grp_set *grp_find_set(struct grp *g, const uint8_t id[GRP_ID_LEN])
{
    for (int i = 0; i < g->nsets; i++)
        if (memcmp(g->sets[i].id, id, GRP_ID_LEN) == 0)
            return &g->sets[i];
    return NULL;
}

/* ---- the clock ---- */
/* days since 1970-01-01 of a civil date (proleptic Gregorian), and back (H. Hinnant's algorithms) */
static int32_t days_from_civil(int y, int m, int d)
{
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    int yoe = y - era * 400;
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

void grp_day_str(int32_t day, char out[16])
{
    if (day == GRP_INDEFINITE_START || day == GRP_INDEFINITE_END) {
        snprintf(out, 16, "-");
        return;
    }
    int32_t z = day + 719468;
    int32_t era = (z >= 0 ? z : z - 146096) / 146097;
    int32_t doe = z - era * 146097;
    int32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int32_t y = yoe + era * 400, doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int32_t mp = (5 * doy + 2) / 153, d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    snprintf(out, 16, "%04u-%02u-%02u", (unsigned)(y + (m <= 2)) % 10000u, (unsigned)m % 100u, (unsigned)d % 100u);
}

int grp_parse_day(const char *s, int32_t *day)
{
    int y, m, d;
    char end;
    if (sscanf(s, "%4d-%2d-%2d%c", &y, &m, &d, &end) != 3 || y < 1970 || y > 9999 || m < 1 || m > 12 || d < 1 ||
        d > 31)
        return -1;
    *day = days_from_civil(y, m, d);
    char back[16];
    grp_day_str(*day, back); /* 2030-02-31 isn't a day */
    return strncmp(back, s, 10) == 0 ? 0 : -1;
}

int32_t grp_today(int tz_min)
{
#ifdef PNP_TEST
    /* test hook: today's date in the group's time zone */
    const char *now = getenv("PNP_TEST_NOW");
    int32_t day;
    if (now && grp_parse_day(now, &day) == 0)
        return day;
#endif
    time_t t = time(NULL) + (time_t)tz_min * 60;
    return (int32_t)(t >= 0 ? t / 86400 : (t - 86399) / 86400);
}

int grp_clock_guard(struct grp *g, int confirmed, char *err, size_t errlen)
{
    int32_t today = grp_today(g->tz_min);
    if (today < g->guard_day && !confirmed) {
        char a[16], b[16];
        grp_day_str(today, a);
        grp_day_str(g->guard_day, b);
        snprintf(err, errlen,
                 "the clock says %s, but pnp has already seen %s with this group: the clock may be wrong. Check it "
                 "(validity windows depend on it); to go on anyway, add --clock-ok", a, b);
        return -1;
    }
    if (today > g->guard_day) {
        g->guard_day = today;
        return 1;
    }
    return 0;
}

int grp_can_send(const struct grp_set *s, int32_t today)
{
    return s->state == GRP_ACTIVE && today >= s->start_day && today <= s->end_day;
}

int grp_can_receive(const struct grp *g, const struct grp_set *s, int32_t today)
{
    int64_t last = s->end_day == GRP_INDEFINITE_END ? INT64_MAX : (int64_t)s->end_day + g->grace;
    return (s->state == GRP_ACTIVE || s->state == GRP_REPLACED) && today >= s->start_day && today <= last;
}

struct grp_set *grp_current_set(struct grp *g, int32_t today)
{
    struct grp_set *best = NULL;
    for (int i = 0; i < g->nsets; i++) {
        struct grp_set *s = &g->sets[i];
        if (s->kind == GRP_SET_NORMAL && grp_can_send(s, today) && (!best || s->start_day > best->start_day))
            best = s;
    }
    return best;
}

/* ---- timestamps ---- */
void grp_touch(const struct grp *g, const char *path)
{
    time_t t = g->anon ? GRP_ANON_TIME : (time_t)g->created_day * 86400;
    struct timespec ts[2] = {{t, 0}, {t, 0}};
    utimensat(AT_FDCWD, path, ts, 0);
}

/* ---- pools ----
 *   0  8 "PNPPL001"   24 from   32 4 locators     40 8 pad bytes      56 8 zero
 *   8 16 key set ID   25 to     36 4 next locator 48 8 next offset
 *  then locators × 24 bytes (16-byte locator, 8-byte offset mask), then the pad bytes. */
int pool_open(const struct grp *g, const struct grp_set *s, int from, int to, struct pool *p, char *err, size_t errlen)
{
    memset(p, 0, sizeof *p);
    p->fd = -1;
    char name[32];
    snprintf(name, sizeof name, "pool.%d-%d", from + 1, to + 1);
    p->path = grp_set_path(g, s, name);
    if (!p->path)
        return -1;
    p->fd = open(p->path, O_RDWR | O_CLOEXEC | O_NOATIME);
    if (p->fd < 0 && errno == EPERM)
        p->fd = open(p->path, O_RDWR | O_CLOEXEC);
    uint8_t h[POOL_HDR_LEN];
    struct stat st;
    if (p->fd < 0 || fstat(p->fd, &st) < 0 || pread(p->fd, h, sizeof h, 0) != (ssize_t)sizeof h) {
        snprintf(err, errlen, "%s: %s", p->path, errno ? strerror(errno) : "too short");
        pool_close(p);
        return -1;
    }
    memcpy(p->set_id, h + 8, GRP_ID_LEN);
    p->from = h[24], p->to = h[25];
    p->nloc = get32(h + 32), p->next_loc = get32(h + 36);
    p->bytes = get64(h + 40), p->next_off = get64(h + 48);
    if (memcmp(h, MAGIC_POOL, 8) != 0 || memcmp(p->set_id, s->id, GRP_ID_LEN) != 0 || p->from != from ||
        p->to != to || p->nloc > MAX_NLOC || p->bytes > MAX_POOL || p->next_loc > p->nloc ||
        p->next_off > p->bytes ||
        (uint64_t)st.st_size != POOL_HDR_LEN + (uint64_t)p->nloc * GRP_LOC_ENTRY + p->bytes) {
        snprintf(err, errlen, "%s isn't a pnp pool for this key set, or it's damaged", p->path);
        pool_close(p);
        return -1;
    }
    return 0;
}

void pool_close(struct pool *p)
{
    if (p->fd >= 0)
        close(p->fd);
    free(p->path);
    p->fd = -1, p->path = NULL;
}

static uint64_t pad_start(const struct pool *p) { return POOL_HDR_LEN + (uint64_t)p->nloc * GRP_LOC_ENTRY; }

int pool_reserve(struct pool *p, uint64_t len, uint32_t *loc_i, uint8_t entry[GRP_LOC_ENTRY], uint64_t *off,
                 char *err, size_t errlen)
{
    if (p->next_loc >= p->nloc || len > p->bytes - p->next_off) {
        snprintf(err, errlen, "%s", p->next_loc >= p->nloc ? "no seals or messages left in this pool: meet again"
                                                            : "not enough pad left in this pool: meet again");
        return -1;
    }
    *loc_i = p->next_loc;
    *off = p->next_off;
    if (pread(p->fd, entry, GRP_LOC_ENTRY, POOL_HDR_LEN + (off_t)p->next_loc * GRP_LOC_ENTRY) != GRP_LOC_ENTRY)
        goto io;
    /* reserved before anything is read or released: a crash after this can only waste them, never reuse them */
    p->next_loc++;
    p->next_off += len;
    uint8_t c[16];
    put32(c, p->nloc), put32(c + 4, p->next_loc), put64(c + 8, p->bytes);
    uint8_t o[8];
    put64(o, p->next_off);
    if (pwrite(p->fd, c + 4, 4, 36) != 4 || pwrite(p->fd, o, 8, 48) != 8)
        goto io;
    pnp_crash_point("pool reserve");
    if (fsync(p->fd) < 0)
        goto io;
    return 0;
io:
    snprintf(err, errlen, "%s: %s", p->path, strerror(errno));
    return -1;
}

int pool_read(struct pool *p, uint64_t off, uint8_t *buf, size_t len)
{
    if (off > p->bytes || len > p->bytes - off)
        return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(p->fd, buf + done, len - done, (off_t)(pad_start(p) + off + done));
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

int pool_wipe(struct pool *p, uint64_t off, uint64_t len)
{
    static const uint8_t zero[65536];
    if (off > p->bytes || len > p->bytes - off)
        return -1;
    while (len) {
        size_t n = len < sizeof zero ? (size_t)len : sizeof zero;
        if (pwrite(p->fd, zero, n, (off_t)(pad_start(p) + off)) != (ssize_t)n)
            return -1;
        off += n, len -= n;
    }
    return 0;
}

int pool_wipe_loc(struct pool *p, uint32_t i)
{
    static const uint8_t zero[GRP_LOC_ENTRY];
    if (i >= p->nloc)
        return -1;
    return pwrite(p->fd, zero, GRP_LOC_ENTRY, POOL_HDR_LEN + (off_t)i * GRP_LOC_ENTRY) == GRP_LOC_ENTRY ? 0 : -1;
}

int pool_sync(struct pool *p) { return fsync(p->fd); }

void pool_header(uint8_t h[POOL_HDR_LEN], const uint8_t set_id[GRP_ID_LEN], int from, int to, uint32_t nloc,
                 uint32_t next_loc, uint64_t bytes, uint64_t next_off)
{
    memset(h, 0, POOL_HDR_LEN);
    memcpy(h, MAGIC_POOL, 8);
    memcpy(h + 8, set_id, GRP_ID_LEN);
    h[24] = (uint8_t)from, h[25] = (uint8_t)to;
    put32(h + 32, nloc), put32(h + 36, next_loc);
    put64(h + 40, bytes), put64(h + 48, next_off);
}

/* ---- receiving: recv.<from> ----
 *   0 8 "PNPRV001"  8 4 locators  12 4 ranges  then the seen bitmap (locators/8 rounded up), then ranges × 16 */
int recv_load(const struct grp *g, const struct grp_set *s, int from, struct recv_state *r, uint32_t nloc)
{
    memset(r, 0, sizeof *r);
    r->nloc = nloc;
    size_t bm = (nloc + 7) / 8;
    r->seen = calloc(bm ? bm : 1, 1);
    if (!r->seen)
        return -1;
    char name[32];
    snprintf(name, sizeof name, "recv.%d", from + 1);
    char *path = grp_set_path(g, s, name);
    if (!path)
        return -1;
    size_t len = 0;
    errno = 0;
    uint8_t *b = read_file(path, 16 + bm + (uint64_t)MAX_NLOC * 16, &len);
    int e = errno;
    free(path);
    if (!b)
        return e == ENOENT ? 0 : -1; /* nothing received yet */
    int ok = len >= 16 && memcmp(b, MAGIC_RECV, 8) == 0 && get32(b + 8) == nloc;
    uint32_t nr = ok ? get32(b + 12) : 0;
    ok = ok && nr <= nloc && len == 16 + bm + (size_t)nr * 16;
    if (ok && nr) {
        r->ranges = malloc((size_t)nr * sizeof *r->ranges);
        ok = r->ranges != NULL;
    }
    if (ok) {
        memcpy(r->seen, b + 16, bm);
        for (uint32_t i = 0; i < nr; i++)
            r->ranges[i][0] = get64(b + 16 + bm + 16 * i), r->ranges[i][1] = get64(b + 24 + bm + 16 * i);
        r->nranges = nr;
    }
    free(b);
    return ok ? 0 : -1;
}

int recv_save(const struct grp *g, const struct grp_set *s, int from, const struct recv_state *r, char *err,
              size_t errlen)
{
    size_t bm = (r->nloc + 7) / 8, len = 16 + bm + (size_t)r->nranges * 16;
    uint8_t *b = calloc(len, 1);
    char name[32];
    snprintf(name, sizeof name, "recv.%d", from + 1);
    char *path = grp_set_path(g, s, name);
    if (!b || !path) {
        free(b), free(path);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    memcpy(b, MAGIC_RECV, 8);
    put32(b + 8, r->nloc), put32(b + 12, r->nranges);
    memcpy(b + 16, r->seen, bm);
    for (uint32_t i = 0; i < r->nranges; i++)
        put64(b + 16 + bm + 16 * i, r->ranges[i][0]), put64(b + 24 + bm + 16 * i, r->ranges[i][1]);
    int ret = save_file(g, path, b, len, err, errlen);
    free(b), free(path);
    return ret;
}

void recv_free(struct recv_state *r)
{
    free(r->seen), free(r->ranges);
    memset(r, 0, sizeof *r);
}

uint32_t recv_next(const struct recv_state *r)
{
    uint32_t i = 0;
    while (i < r->nloc && grp_bit(r->seen, (int)i))
        i++;
    return i;
}

int recv_overlaps(const struct recv_state *r, uint64_t off, uint64_t len)
{
    for (uint32_t i = 0; i < r->nranges; i++) {
        uint64_t a = r->ranges[i][0], l = r->ranges[i][1];
        if (off < a + l && a < off + len)
            return 1;
    }
    return 0;
}

int recv_add(struct recv_state *r, uint32_t loc, uint64_t off, uint64_t len)
{
    if (loc >= r->nloc || r->nranges >= r->nloc)
        return -1;
    uint64_t(*nr)[2] = realloc(r->ranges, (r->nranges + 1) * sizeof *r->ranges);
    if (!nr)
        return -1;
    r->ranges = nr;
    r->ranges[r->nranges][0] = off, r->ranges[r->nranges][1] = len;
    r->nranges++;
    r->seen[loc / 8] |= (uint8_t)(1 << (loc % 8));
    return 0;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int grp_lookup(struct grp *g, const uint8_t loc[GRP_LOC_LEN], int lookahead, struct grp_set **set, int *from,
               uint32_t *loc_i, uint64_t *off)
{
    static const uint8_t zero[GRP_LOC_LEN];
    if (ct_equal(loc, zero, GRP_LOC_LEN)) /* used entries are wiped to zeros: never match one */
        return -1;
    for (int si = 0; si < g->nsets; si++) {
        struct grp_set *s = &g->sets[si];
        for (int o = 0; o < g->n; o++) {
            if (o == g->me)
                continue;
            struct pool p;
            char err[256];
            if (pool_open(g, s, o, g->me, &p, err, sizeof err) < 0)
                continue;
            struct recv_state r;
            if (recv_load(g, s, o, &r, p.nloc) < 0) {
                recv_free(&r);
                pool_close(&p);
                continue;
            }
            int tried = 0;
            for (uint32_t i = recv_next(&r); i < p.nloc && tried < lookahead; i++) {
                if (grp_bit(r.seen, (int)i))
                    continue;
                tried++;
                uint8_t e[GRP_LOC_ENTRY];
                if (pread(p.fd, e, sizeof e, POOL_HDR_LEN + (off_t)i * GRP_LOC_ENTRY) != (ssize_t)sizeof e)
                    break;
                if (ct_equal(e, loc, GRP_LOC_LEN)) {
                    *set = s, *from = o, *loc_i = i;
                    *off = get64(loc + GRP_LOC_LEN) ^ get64(e + GRP_LOC_LEN);
                    recv_free(&r);
                    pool_close(&p);
                    return 0;
                }
            }
            recv_free(&r);
            pool_close(&p);
        }
    }
    return -1;
}

/* ---- finding groups ---- */
static int is_group_dir(const char *dir)
{
    char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof path, "%s/group", dir);
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void add_under(const char *root, char **dirs, int *n, int max)
{
    const char *base = strrchr(root, '/');
    base = base ? base + 1 : root;
    if (strncmp(base, "pnp-group-", 10) == 0 && is_group_dir(root)) {
        if (*n < max && (dirs[*n] = strdup(root)))
            (*n)++;
        return;
    }
    DIR *d = opendir(root);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) && *n < max) {
        if (strncmp(e->d_name, "pnp-group-", 10) != 0)
            continue;
        char *p = NULL;
        if (asprintf(&p, "%s/%s", root, e->d_name) < 0)
            continue;
        if (is_group_dir(p))
            dirs[(*n)++] = p;
        else
            free(p);
    }
    closedir(d);
}

int grp_find_all(const char *root, char **dirs, int max)
{
    int n = 0;
    if (root) {
        add_under(root, dirs, &n, max);
        return n;
    }
    const char *env = getenv("PNP_GROUPS");
    if (env && *env) {
        char *copy = strdup(env), *save = NULL;
        for (char *t = copy ? strtok_r(copy, ":", &save) : NULL; t; t = strtok_r(NULL, ":", &save))
            add_under(t, dirs, &n, max);
        free(copy);
    }
    const char *user = getenv("USER");
    const char *media[2] = {"/media", "/run/media"};
    for (int m = 0; user && m < 2; m++) {
        char base[PATH_MAX];
        snprintf(base, sizeof base, "%s/%s", media[m], user);
        DIR *d = opendir(base);
        if (!d)
            continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.')
                continue;
            char *p = NULL;
            if (asprintf(&p, "%s/%s", base, e->d_name) < 0)
                continue;
            add_under(p, dirs, &n, max);
            free(p);
        }
        closedir(d);
    }
    return n;
}

int grp_mkdirs(const struct grp *g, char *err, size_t errlen)
{
    if (mkdir(g->dir, 0700) < 0 && errno != EEXIST)
        goto fail;
    char kills[PATH_MAX];
    snprintf(kills, sizeof kills, "%s/kills", g->dir);
    if (mkdir(kills, 0700) < 0 && errno != EEXIST)
        goto fail;
    for (int i = 0; i < g->nsets; i++) {
        char *p = grp_set_path(g, &g->sets[i], NULL);
        int r = p ? mkdir(p, 0700) : -1;
        if (r < 0 && errno != EEXIST) {
            free(p);
            goto fail;
        }
        free(p);
    }
    return 0;
fail:
    snprintf(err, errlen, "%s: %s", g->dir, strerror(errno));
    return -1;
}
