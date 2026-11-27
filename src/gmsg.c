/* Seals and messages on a pairwise pool (gmsg.h; docs/group.md "Pairs", "Encrypted messages").
 *
 * Every seal or message takes the next item of the sender's pool to the recipient: one locator entry and a run of
 * pad bytes, the first 32 of which are a one-time MAC key (mac.c). Both are reserved and fsynced before anything is
 * read (pool_reserve), and wiped as they're used, so they can never be used twice and leave nothing behind.
 *
 *   seal:     locator (16) | offset xor mask (8) | tag (16)
 *             tag = MAC over "PNPSE001" | key set ID | from | to | item | u64 length | the file
 *   message:  locator (16) | offset xor mask (8) | frame xor pad (L bytes) | tag (16)
 *             tag = MAC over "PNPGM001" | key set ID | from | to | item | u64 L | the frame
 *   frame:    "PNPGF001" | group ID | generation (4) | from | count | to... | message ID (16) | flags (1: signed) |
 *             u32 length + kill notices | u16 length + file name | u64 length + content | [u32 length + signature]
 *
 * The header outside the encryption is a one-time locator and a masked offset: random bytes that name no group,
 * pair or key set and link no two messages. The sender's and recipients' names are inside both the signature and the
 * encryption (Davis 2001, §1.1, §3.2): a recipient can't re-encrypt a signed message to someone else and pass it off
 * as sent to them. A signature always covers the plaintext, never the ciphertext: with a one-time pad, a ciphertext
 * can be "opened" to any text by whoever invents the pad. */
#define _GNU_SOURCE
#include "gmsg.h"
#include "fileio.h"
#include "kill.h"
#include "mac.h"
#include "uss.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK 65536
static const char FRAME_MAGIC[8] = {'P', 'N', 'P', 'G', 'F', '0', '0', '1'};

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
static uint32_t get32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static uint64_t get64(const uint8_t *b) { return (uint64_t)get32(b) | (uint64_t)get32(b + 4) << 32; }

static int read_at(int fd, void *buf, size_t n, uint64_t off)
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

/* the MAC's prefix: what binds the tag to the key set, the pair and the item */
static void mac_prefix(struct pnp_mac *m, const char *magic, const uint8_t set_id[GRP_ID_LEN], int from, int to,
                       uint32_t item, uint64_t len)
{
    uint8_t p[8 + GRP_ID_LEN + 2 + 4 + 8];
    memcpy(p, magic, 8);
    memcpy(p + 8, set_id, GRP_ID_LEN);
    p[24] = (uint8_t)from, p[25] = (uint8_t)to;
    put32(p + 26, item);
    put64(p + 30, len);
    pnp_mac_feed(m, p, sizeof p);
}

/* takes the next item of my pool to `to`: reserves it, reads its key, wipes the key and the locator entry */
static int take_item(struct grp *g, struct grp_set *s, int to, uint64_t len, struct pool *p, uint32_t *item,
                     uint8_t hdr[GRP_LOC_LEN + 8], uint64_t *off, uint8_t key[GRP_KEY_LEN], char *err, size_t errlen)
{
    if (pool_open(g, s, g->me, to, p, err, errlen) < 0)
        return -1;
    for (;;) {
        uint8_t entry[GRP_LOC_ENTRY];
        if (pool_reserve(p, GRP_KEY_LEN + len, item, entry, off, err, errlen) < 0)
            goto fail;
        int ok = pool_read(p, *off, key, GRP_KEY_LEN) == 0;
        ok = ok && pool_wipe(p, *off, GRP_KEY_LEN) == 0 && pool_wipe_loc(p, *item) == 0 && pool_sync(p) == 0;
        if (!ok) {
            snprintf(err, errlen, "%s: %s", p->path, strerror(errno));
            goto fail;
        }
        memcpy(hdr, entry, GRP_LOC_LEN);
        put64(hdr + GRP_LOC_LEN, *off ^ get64(entry + GRP_LOC_LEN));
        explicit_bzero(entry, sizeof entry);
        if (pnp_mac_key_fix(key) == 0)
            return 0;
        /* the key came out as p itself (chance 2^-126): this item is spent; the receiver refuses it too */
    }
fail:
    pool_close(p);
    return -1;
}

static int write_output(const char *path, const void *a, size_t alen, int force, struct pnp_out *o, char *err,
                        size_t errlen)
{
    struct stat st;
    if (!force && lstat(path, &st) == 0) {
        snprintf(err, errlen, "%s already exists (use -f to replace it)", path);
        return -1;
    }
    if (pnp_out_open(o, path, 0644, err, errlen) < 0)
        return -1;
    if (a && pnp_write_all(o->fd, a, alen) < 0) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        pnp_out_discard(o);
        return -1;
    }
    return 0;
}

/* ---- seals ---- */
/* what a seal covers: a file, or bytes in memory */
struct body {
    const char *path;
    const uint8_t *mem;
    uint64_t len;
};

static int body_len(struct body *b, char *err, size_t errlen)
{
    if (!b->path)
        return 0;
    struct stat st;
    if (stat(b->path, &st) < 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errlen, "%s: %s", b->path, errno ? strerror(errno) : "not a regular file");
        return -1;
    }
    b->len = (uint64_t)st.st_size;
    return 0;
}

static int body_feed(struct pnp_mac *m, const struct body *b, char *err, size_t errlen)
{
    if (!b->path) {
        pnp_mac_feed(m, b->mem, (size_t)b->len);
        return 0;
    }
    int fd = open(b->path, O_RDONLY | O_CLOEXEC);
    uint8_t buf[CHUNK];
    uint64_t got = 0;
    ssize_t r;
    while (fd >= 0 && (r = read(fd, buf, sizeof buf)) > 0) {
        pnp_mac_feed(m, buf, (size_t)r);
        got += (uint64_t)r;
    }
    if (fd >= 0)
        close(fd);
    if (fd < 0 || got != b->len) {
        snprintf(err, errlen, "%s changed or couldn't be read", b->path);
        return -1;
    }
    return 0;
}

static int seal_body(struct grp *g, struct grp_set *s, int to, struct body *b, uint8_t seal[SEAL_LEN], char *err,
                     size_t errlen)
{
    uint64_t off;
    uint32_t item;
    uint8_t key[GRP_KEY_LEN];
    struct pool p;
    struct pnp_mac m;
    if (body_len(b, err, errlen) < 0 || take_item(g, s, to, 0, &p, &item, seal, &off, key, err, errlen) < 0)
        return -1;
    grp_touch(g, p.path);
    pool_close(&p);
    pnp_mac_init(&m, key);
    explicit_bzero(key, sizeof key);
    mac_prefix(&m, "PNPSE001", s->id, g->me, to, item, b->len);
    if (body_feed(&m, b, err, errlen) < 0) {
        explicit_bzero(&m, sizeof m);
        return -1;
    }
    pnp_mac_final(&m, seal + GRP_LOC_LEN + 8);
    return 0;
}

int seal_make(struct grp *g, struct grp_set *s, int to, const char *path, uint8_t seal[SEAL_LEN], char *err,
              size_t errlen)
{
    struct body b = {path, NULL, 0};
    return seal_body(g, s, to, &b, seal, err, errlen);
}

int seal_make_mem(struct grp *g, struct grp_set *s, int to, const uint8_t *buf, size_t len, uint8_t seal[SEAL_LEN],
                  char *err, size_t errlen)
{
    struct body b = {NULL, buf, len};
    return seal_body(g, s, to, &b, seal, err, errlen);
}

/* the receiving side of an item: checks it can be taken, and reads its key */
static int recv_item(struct grp *g, const uint8_t hdr[GRP_LOC_LEN + 8], uint64_t len, int lookahead,
                     struct grp_set **set, int *from, uint32_t *item, uint64_t *off, uint8_t key[GRP_KEY_LEN],
                     char *err, size_t errlen)
{
    if (grp_lookup(g, hdr, lookahead, set, from, item, off) < 0)
        return 0;
    /* the offset field was masked: put the real one back */
    struct grp_set *s = *set;
    int32_t today = grp_today(g->tz_min);
    char who[48];
    grp_member_name(g, *from, who, sizeof who);
    if (s->state == GRP_KILLED || s->state == GRP_CLOSED) {
        snprintf(err, errlen, "this is from %s, on a key set that has been %s: it's refused", who,
                 s->state == GRP_KILLED ? "killed" : "closed");
        return -1;
    }
    if (!grp_can_receive(g, s, today)) {
        char a[16], b[16];
        grp_day_str(s->start_day, a), grp_day_str(s->end_day, b);
        snprintf(err, errlen, "this is from %s, on key set %s → %s (+%d days): today is outside that window, so "
                 "it's refused", who, a, b, g->grace);
        return -1;
    }
    if (grp_bit(g->left, *from) || grp_bit(g->expelled, *from)) {
        snprintf(err, errlen, "this is from %s, who %s the group: it's refused", who,
                 grp_bit(g->left, *from) ? "left" : "was removed from");
        return -1;
    }
    struct pool p;
    if (pool_open(g, s, *from, g->me, &p, err, errlen) < 0)
        return -1;
    struct recv_state r;
    int ret = -1;
    if (recv_load(g, s, *from, &r, p.nloc) < 0) {
        snprintf(err, errlen, "the record of what has arrived from %s is damaged", who);
        pool_close(&p);
        return -1;
    }
    if (*off > p.bytes || GRP_KEY_LEN + len > p.bytes - *off || recv_overlaps(&r, *off, GRP_KEY_LEN + len)) {
        snprintf(err, errlen, "this item from %s claims pad that's already used or doesn't exist: it's refused "
                 "(a replay, or the sender reused pad)", who);
        goto out;
    }
    if (pool_read(&p, *off, key, GRP_KEY_LEN) < 0) {
        snprintf(err, errlen, "%s: %s", p.path, strerror(errno));
        goto out;
    }
    if (pnp_mac_key_fix(key) < 0) {
        snprintf(err, errlen, "this item's key is unusable (it was spent by the sender)");
        goto out;
    }
    ret = 1;
out:
    recv_free(&r);
    pool_close(&p);
    return ret;
}

/* after an item checked: record it, wipe its pad and locator */
static int recv_done(struct grp *g, struct grp_set *s, int from, uint32_t item, uint64_t off, uint64_t len, char *err,
                     size_t errlen)
{
    struct pool p;
    struct recv_state r;
    if (pool_open(g, s, from, g->me, &p, err, errlen) < 0)
        return -1;
    int ok = recv_load(g, s, from, &r, p.nloc) == 0 && recv_add(&r, item, off, len) == 0 &&
             recv_save(g, s, from, &r, err, errlen) == 0;
    ok = ok && pool_wipe(&p, off, len) == 0 && pool_wipe_loc(&p, item) == 0 && pool_sync(&p) == 0;
    recv_free(&r);
    grp_touch(g, p.path);
    pool_close(&p);
    if (!ok && !*err)
        snprintf(err, errlen, "couldn't record what arrived: %s", strerror(errno));
    return ok ? 0 : -1;
}

static int check_body(struct grp *g, struct body *b, const uint8_t seal[SEAL_LEN], int lookahead,
                      struct seal_result *res, char *err, size_t errlen)
{
    uint64_t off;
    uint32_t item;
    uint8_t key[GRP_KEY_LEN], tag[16];
    struct pnp_mac m;
    err[0] = 0;
    if (body_len(b, err, errlen) < 0)
        return -1;
    int r = recv_item(g, seal, 0, lookahead, &res->set, &res->from, &item, &off, key, err, errlen);
    if (r <= 0)
        return r;
    pnp_mac_init(&m, key);
    explicit_bzero(key, sizeof key);
    mac_prefix(&m, "PNPSE001", res->set->id, res->from, g->me, item, b->len);
    if (body_feed(&m, b, err, errlen) < 0) {
        explicit_bzero(&m, sizeof m);
        return -1;
    }
    pnp_mac_final(&m, tag);
    if (pnp_mac_tag_cmp(tag, seal + GRP_LOC_LEN + 8) != 0)
        return 0; /* not recorded: the real seal for this item can still arrive */
    return recv_done(g, res->set, res->from, item, off, GRP_KEY_LEN, err, errlen) < 0 ? -1 : 1;
}

int seal_check(struct grp *g, const char *path, const uint8_t seal[SEAL_LEN], int lookahead, struct seal_result *res,
               char *err, size_t errlen)
{
    struct body b = {path, NULL, 0};
    return check_body(g, &b, seal, lookahead, res, err, errlen);
}

int seal_check_mem(struct grp *g, const uint8_t *buf, size_t len, const uint8_t seal[SEAL_LEN], int lookahead,
                   struct seal_result *res, char *err, size_t errlen)
{
    struct body b = {NULL, buf, len};
    return check_body(g, &b, seal, lookahead, res, err, errlen);
}

/* ---- messages ---- */
/* the plaintext, as a stream: the frame's header, the file, then the signature trailer */
struct src {
    const uint8_t *head;
    size_t head_len;
    int fd;
    uint64_t file_len, file_done;
    const uint8_t *tail;
    size_t tail_len;
    uint64_t pos;
    int failed;
};

static long src_read(void *ctx, uint8_t *buf, size_t n)
{
    struct src *s = ctx;
    size_t done = 0;
    while (done < n) {
        if (s->pos < s->head_len) {
            size_t t = s->head_len - (size_t)s->pos < n - done ? s->head_len - (size_t)s->pos : n - done;
            memcpy(buf + done, s->head + s->pos, t);
            done += t, s->pos += t;
        } else if (s->file_done < s->file_len) {
            uint64_t left = s->file_len - s->file_done;
            size_t want = left < n - done ? (size_t)left : n - done;
            ssize_t r = pread(s->fd, buf + done, want, (off_t)s->file_done);
            if (r <= 0) {
                s->failed = 1;
                return -1;
            }
            done += (size_t)r, s->file_done += (uint64_t)r, s->pos += (uint64_t)r;
        } else {
            uint64_t into = s->pos - s->head_len - s->file_len;
            if (into >= s->tail_len)
                break;
            size_t t = s->tail_len - (size_t)into < n - done ? s->tail_len - (size_t)into : n - done;
            memcpy(buf + done, s->tail + into, t);
            done += t, s->pos += t;
        }
    }
    return (long)done;
}

static void src_rewind(struct src *s)
{
    s->pos = 0, s->file_done = 0;
}

static const char *base_name(const char *path)
{
    const char *b = strrchr(path, '/');
    return b ? b + 1 : path;
}

int msg_send(struct grp *g, struct grp_set *s, int to, const char *in_path, const char *out_path, int sign, int force,
             char *err, size_t errlen)
{
    int fd = open(in_path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errlen, "%s: %s", in_path, fd < 0 ? strerror(errno) : "not a regular file");
        if (fd >= 0)
            close(fd);
        return -1;
    }
    uint8_t *kills = NULL, *head = NULL, *sig = NULL, *tail = NULL;
    size_t klen = 0, siglen = 0;
    int ret = -1;
    if (kill_bundle(g, &kills, &klen) < 0)
        klen = 0;
    const char *name = base_name(in_path);
    size_t nlen = strlen(name) > 255 ? 255 : strlen(name);
    size_t hlen = 8 + GRP_ID_LEN + 4 + 2 + 1 + 16 + 1 + 4 + klen + 2 + nlen + 8;
    head = malloc(hlen);
    if (!head)
        goto out;
    uint8_t *h = head;
    memcpy(h, FRAME_MAGIC, 8), h += 8;
    memcpy(h, g->id, GRP_ID_LEN), h += GRP_ID_LEN;
    put32(h, g->gen), h += 4;
    *h++ = (uint8_t)g->me, *h++ = 1, *h++ = (uint8_t)to;
    if (getrandom(h, 16, 0) != 16)
        goto out;
    h += 16;
    *h++ = sign ? 1 : 0;
    put32(h, (uint32_t)klen), h += 4;
    if (klen)
        memcpy(h, kills, klen), h += klen;
    put16(h, (uint16_t)nlen), h += 2;
    memcpy(h, name, nlen), h += nlen;
    put64(h, (uint64_t)st.st_size), h += 8;
    struct src sr = {head, hlen, fd, (uint64_t)st.st_size, 0, NULL, 0, 0, 0};
    {
        /* room in the pool first: a send that can't happen mustn't use up a signing slot */
        struct pool p;
        uint64_t need = GRP_KEY_LEN + hlen + (uint64_t)st.st_size + (sign ? 4 + uss_sig_len(g->n - 1, s->k) : 0);
        if (pool_open(g, s, g->me, to, &p, err, errlen) < 0)
            goto out;
        int room = p.next_loc < p.nloc && need <= p.bytes - p.next_off;
        pool_close(&p);
        if (!room) {
            snprintf(err, errlen, "not enough pad left in the pool for this message: meet again");
            goto out;
        }
    }
    if (sign) {
        uint32_t slot;
        uint64_t plen = hlen + (uint64_t)st.st_size;
        sig = uss_sign(g, s, plen, src_read, &sr, &siglen, &slot, err, errlen);
        if (!sig)
            goto out;
        tail = malloc(4 + siglen);
        if (!tail)
            goto out;
        put32(tail, (uint32_t)siglen);
        memcpy(tail + 4, sig, siglen);
        sr.tail = tail, sr.tail_len = 4 + siglen;
        src_rewind(&sr);
    }
    uint64_t L = hlen + (uint64_t)st.st_size + sr.tail_len, off;
    uint32_t item;
    uint8_t lochdr[GRP_LOC_LEN + 8], key[GRP_KEY_LEN];
    struct pool p;
    struct pnp_out o;
    if (write_output(out_path, NULL, 0, force, &o, err, errlen) < 0)
        goto out;
    if (take_item(g, s, to, L, &p, &item, lochdr, &off, key, err, errlen) < 0) {
        pnp_out_discard(&o);
        goto out;
    }
    struct pnp_mac m;
    pnp_mac_init(&m, key);
    explicit_bzero(key, sizeof key);
    mac_prefix(&m, "PNPGM001", s->id, g->me, to, item, L);
    uint8_t buf[CHUNK], pad[CHUNK], tag[16];
    int ok = pnp_write_all(o.fd, lochdr, sizeof lochdr) == 0;
    for (uint64_t done = 0; ok && done < L;) {
        size_t n = L - done < CHUNK ? (size_t)(L - done) : CHUNK;
        long r = src_read(&sr, buf, n);
        ok = r == (long)n && pool_read(&p, off + GRP_KEY_LEN + done, pad, n) == 0;
        if (!ok)
            break;
        pnp_mac_feed(&m, buf, n);
        for (size_t i = 0; i < n; i++)
            buf[i] ^= pad[i];
        ok = pnp_write_all(o.fd, buf, n) == 0 && pool_wipe(&p, off + GRP_KEY_LEN + done, n) == 0;
        done += n;
    }
    pnp_mac_final(&m, tag);
    explicit_bzero(pad, sizeof pad), explicit_bzero(buf, sizeof buf);
    ok = ok && pnp_write_all(o.fd, tag, sizeof tag) == 0 && pool_sync(&p) == 0;
    grp_touch(g, p.path);
    pool_close(&p);
    if (!ok) {
        snprintf(err, errlen, "%s", sr.failed ? "the file changed while it was being sent" : strerror(errno));
        pnp_out_discard(&o);
        goto out;
    }
    if (pnp_out_commit(&o, force, err, errlen) < 0) {
        pnp_out_discard(&o);
        goto out;
    }
    pnp_out_discard(&o);
    ret = 0;
out:
    close(fd);
    free(head), free(sig), free(tail), free(kills);
    return ret;
}

/* parsing a decrypted frame held in fd (len bytes) */
struct frame {
    int from, nto, to_me, is_signed;
    int to[GRP_MAX_MEMBERS];
    uint64_t kills_at, kills_len, name_at, content_at, content_len, signed_len, sig_at, sig_len;
    char name[256];
};

static int parse_frame(int fd, uint64_t len, const struct grp *g, struct frame *f)
{
    memset(f, 0, sizeof *f);
    uint8_t h[8 + GRP_ID_LEN + 4 + 2 + 255];
    if (len < 8 + GRP_ID_LEN + 4 + 2 || read_at(fd, h, 8 + GRP_ID_LEN + 4 + 2, 0) < 0 ||
        memcmp(h, FRAME_MAGIC, 8) != 0 || memcmp(h + 8, g->id, GRP_ID_LEN) != 0)
        return -1;
    f->from = h[28], f->nto = h[29];
    uint64_t at = 30;
    if (f->nto < 1 || at + (uint64_t)f->nto > len || read_at(fd, h, (size_t)f->nto, at) < 0)
        return -1;
    for (int i = 0; i < f->nto; i++) {
        f->to[i] = h[i];
        if (h[i] == g->me)
            f->to_me = 1;
    }
    at += (uint64_t)f->nto + 16; /* the message ID */
    uint8_t b[8];
    if (at + 1 + 4 > len || read_at(fd, b, 5, at) < 0 || b[0] > 1)
        return -1;
    f->is_signed = b[0];
    f->kills_len = get32(b + 1);
    f->kills_at = at + 5;
    at = f->kills_at + f->kills_len;
    if (f->kills_len > len || at + 2 > len || read_at(fd, b, 2, at) < 0)
        return -1;
    size_t nl = (size_t)(b[0] | b[1] << 8);
    f->name_at = at + 2;
    if (nl > 255 || f->name_at + nl + 8 > len || read_at(fd, f->name, nl, f->name_at) < 0)
        return -1;
    f->name[nl] = 0;
    at = f->name_at + nl;
    if (read_at(fd, b, 8, at) < 0)
        return -1;
    f->content_len = get64(b);
    f->content_at = at + 8;
    if (f->content_len > len - f->content_at)
        return -1;
    f->signed_len = f->content_at + f->content_len;
    if (f->is_signed) {
        if (f->signed_len + 4 > len || read_at(fd, b, 4, f->signed_len) < 0)
            return -1;
        f->sig_len = get32(b);
        f->sig_at = f->signed_len + 4;
        if (f->sig_len != len - f->sig_at || f->sig_len > (64u << 20))
            return -1;
    } else if (f->signed_len != len) {
        return -1;
    }
    /* a received file's name never leads out of its folder */
    if (!f->name[0] || strchr(f->name, '/') || !strcmp(f->name, ".") || !strcmp(f->name, ".."))
        snprintf(f->name, sizeof f->name, "message");
    return 0;
}

/* a range of an fd as a uss_read_fn source */
struct fd_src {
    int fd;
    uint64_t at, left;
};
static long fd_read(void *ctx, uint8_t *buf, size_t n)
{
    struct fd_src *s = ctx;
    size_t want = s->left < n ? (size_t)s->left : n;
    if (!want)
        return 0;
    ssize_t r = pread(s->fd, buf, want, (off_t)s->at);
    if (r <= 0)
        return -1;
    s->at += (uint64_t)r, s->left -= (uint64_t)r;
    return (long)r;
}

static int check_signature(struct grp *g, int fd, const struct frame *f, struct msg_result *res, int record, char *err,
                           size_t errlen)
{
    uint8_t *sig = malloc(f->sig_len ? (size_t)f->sig_len : 1);
    struct uss_result ur;
    struct fd_src fs = {fd, 0, f->signed_len};
    int ok = sig && read_at(fd, sig, (size_t)f->sig_len, f->sig_at) == 0 &&
             uss_verify(g, sig, (size_t)f->sig_len, f->signed_len, fd_read, &fs, record, &ur, err, errlen) == 0;
    free(sig);
    if (!ok)
        return -1;
    if (ur.signer != f->from) {
        snprintf(err, errlen, "the signature inside is from a different member than the sender: refused");
        return -1;
    }
    res->sig_level = ur.level, res->sig_exact = ur.exact, res->sig_reused = ur.reused;
    return 0;
}

static int tmp_in_dir(const char *path)
{
    char *dir = pnp_dir_of(path);
    int fd = dir ? open(dir, O_RDWR | O_TMPFILE | O_CLOEXEC, 0600) : -1;
    if (fd < 0 && dir) { /* no O_TMPFILE on this filesystem: a hidden file, removed at once */
        char *t = NULL;
        if (asprintf(&t, "%s/.pnp-msg-XXXXXX", dir) >= 0) {
            fd = mkstemp(t);
            if (fd >= 0)
                unlink(t);
            free(t);
        }
    }
    free(dir);
    return fd;
}

static int copy_range(int from, uint64_t at, uint64_t len, int to)
{
    uint8_t buf[CHUNK];
    while (len) {
        size_t n = len < CHUNK ? (size_t)len : CHUNK;
        if (read_at(from, buf, n, at) < 0 || pnp_write_all(to, buf, n) < 0)
            return -1;
        at += n, len -= n;
    }
    return 0;
}

int msg_receive(struct grp *g, const char *in_path, const char *out_path, int force, int lookahead,
                struct msg_result *res, char *err, size_t errlen)
{
    memset(res, 0, sizeof *res);
    err[0] = 0;
    int fd = open(in_path, O_RDONLY | O_CLOEXEC), tmp = -1, ret = -1;
    struct stat st;
    uint8_t lochdr[GRP_LOC_LEN + 8], key[GRP_KEY_LEN];
    if (fd < 0 || fstat(fd, &st) < 0) {
        snprintf(err, errlen, "%s: %s", in_path, strerror(errno));
        goto out;
    }
    if ((uint64_t)st.st_size < MSG_OVERHEAD || read_at(fd, lochdr, sizeof lochdr, 0) < 0) {
        ret = 0;
        goto out;
    }
    uint64_t L = (uint64_t)st.st_size - MSG_OVERHEAD, off;
    uint32_t item;
    int r = recv_item(g, lochdr, L, lookahead, &res->set, &res->from, &item, &off, key, err, errlen);
    if (r <= 0) {
        ret = r;
        goto out;
    }
    struct grp_set *s = res->set;
    struct pool p;
    if (pool_open(g, s, res->from, g->me, &p, err, errlen) < 0)
        goto out;
    /* decrypt into an unnamed file beside the output, checking the MAC as it goes */
    char *outp = NULL;
    if (out_path)
        outp = strdup(out_path);
    else
        outp = pnp_dir_of(in_path);
    tmp = outp ? tmp_in_dir(out_path ? out_path : in_path) : -1;
    struct pnp_mac m;
    pnp_mac_init(&m, key);
    explicit_bzero(key, sizeof key);
    mac_prefix(&m, "PNPGM001", s->id, res->from, g->me, item, L);
    uint8_t buf[CHUNK], pad[CHUNK], tag[16], want[16];
    int ok = tmp >= 0;
    for (uint64_t done = 0; ok && done < L;) {
        size_t n = L - done < CHUNK ? (size_t)(L - done) : CHUNK;
        ok = read_at(fd, buf, n, sizeof lochdr + done) == 0 && pool_read(&p, off + GRP_KEY_LEN + done, pad, n) == 0;
        for (size_t i = 0; ok && i < n; i++)
            buf[i] ^= pad[i];
        if (ok)
            pnp_mac_feed(&m, buf, n);
        ok = ok && pnp_write_all(tmp, buf, n) == 0;
        done += n;
    }
    pnp_mac_final(&m, tag);
    explicit_bzero(pad, sizeof pad), explicit_bzero(buf, sizeof buf);
    pool_close(&p);
    if (!ok || read_at(fd, want, sizeof want, sizeof lochdr + L) < 0) {
        snprintf(err, errlen, "couldn't read or decrypt %s: %s", in_path, strerror(errno));
        free(outp);
        goto out;
    }
    if (pnp_mac_tag_cmp(tag, want) != 0) {
        snprintf(err, errlen, "the integrity check failed: %s was altered or damaged; nothing was written", in_path);
        free(outp);
        ret = 0;
        goto out;
    }
    struct frame f;
    if (parse_frame(tmp, L, g, &f) < 0 || f.from != res->from || !f.to_me) {
        snprintf(err, errlen, "%s checks, but its inside doesn't match who sent it to whom: refused", in_path);
        free(outp);
        goto out;
    }
    res->is_signed = f.is_signed;
    snprintf(res->name, sizeof res->name, "%s", f.name);
    if (!f.is_signed && g->signed_default && g->n >= 3) {
        snprintf(err, errlen, "this group signs every message, and this one isn't signed: refused");
        free(outp);
        goto out;
    }
    if (f.is_signed && check_signature(g, tmp, &f, res, 1, err, errlen) < 0) {
        free(outp);
        goto out;
    }
    if (f.is_signed && res->sig_level < -1) {
        snprintf(err, errlen, "the signature inside doesn't check: refused");
        free(outp);
        goto out;
    }
    res->pending_warning = kill_pending_for(g, s);
    /* where it goes: -o, or the sender's file name beside the message */
    char *final = NULL;
    if (out_path)
        final = outp, outp = NULL;
    else if (asprintf(&final, "%s/%s", outp, f.name) < 0)
        final = NULL;
    free(outp);
    struct pnp_out o, ev;
    if (!final || write_output(final, NULL, 0, force, &o, err, errlen) < 0) {
        free(final);
        goto out;
    }
    ok = copy_range(tmp, f.content_at, f.content_len, o.fd) == 0;
    char *evp = NULL;
    int have_ev = 0;
    if (ok && f.is_signed && asprintf(&evp, "%s.pnp-signed", final) >= 0) {
        have_ev = write_output(evp, NULL, 0, force, &ev, err, errlen) == 0;
        ok = have_ev && copy_range(tmp, 0, L, ev.fd) == 0;
    }
    /* the message checked: record it and wipe its pad before anything is placed */
    if (ok)
        ok = recv_done(g, s, res->from, item, off, GRP_KEY_LEN + L, err, errlen) == 0;
    if (ok && f.kills_len) {
        uint8_t *kb = malloc((size_t)f.kills_len);
        if (kb && read_at(tmp, kb, (size_t)f.kills_len, f.kills_at) == 0)
            kill_absorb(g, kb, (size_t)f.kills_len, NULL);
        free(kb);
    }
    ok = ok && pnp_out_commit(&o, force, err, errlen) == 0 && (!have_ev || pnp_out_commit(&ev, force, err, errlen) == 0);
    if (!ok && !err[0])
        snprintf(err, errlen, "%s: %s", final, strerror(errno));
    pnp_out_discard(&o);
    if (have_ev)
        pnp_out_discard(&ev);
    free(evp);
    free(final);
    ret = ok ? 1 : -1;
out:
    if (fd >= 0)
        close(fd);
    if (tmp >= 0)
        close(tmp);
    return ret;
}

int msg_verify_evidence(struct grp *g, const char *path, struct msg_result *res, char *err, size_t errlen)
{
    memset(res, 0, sizeof *res);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    struct frame f;
    if (fd < 0 || fstat(fd, &st) < 0) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    int ret = -1;
    if (parse_frame(fd, (uint64_t)st.st_size, g, &f) < 0 || !f.is_signed) {
        snprintf(err, errlen, "%s isn't a signed message kept from this group", path);
        goto out;
    }
    res->from = f.from, res->is_signed = 1;
    res->nto = f.nto;
    memcpy(res->to, f.to, sizeof res->to);
    snprintf(res->name, sizeof res->name, "%s", f.name);
    if (check_signature(g, fd, &f, res, 0, err, errlen) == 0)
        ret = 0;
out:
    close(fd);
    return ret;
}
