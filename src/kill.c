/* Kill and leave notices (kill.h; docs/group.md "Kill notices", "Leaving a group").
 *
 *   notice:  0 8 "PNPKL001"; 8 16 group ID; 24 16 notice ID; 40 scope; 41 member; 42 reason; 43 key sets (n);
 *            44 4 suspect day; 48 suspect member; 49 3 zero; 52 4 suspect slot; 56 n × 16 key set IDs
 *            -- each signature covers everything above --
 *            then: signatures (1 byte), and each: signer, kind (1 group signature, 2 seal), u32 length, the bytes
 *
 * Signatures come from the emergency key set (groups) or the emergency pool (pairs), which have no window, so a
 * notice can be made at any time even when the keys it reports are the compromised ones. A notice signed by fewer
 * members than the threshold only warns; reaching it kills, for good. A leave notice needs only the leaver.
 *
 * Received notices are kept in the group's kills/ folder as <notice ID>.pnp-kill, with <notice ID>.state beside it:
 * which signers have been checked (a seal can only be checked once: checking uses it up) and whether it's applied.
 * Notices also travel inside every message (kill_bundle / kill_absorb), so a kill spreads with ordinary traffic. */
#define _GNU_SOURCE
#include "kill.h"
#include "fileio.h"
#include "gmsg.h"
#include "uss.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

static const char MAGIC_KILL[8] = {'P', 'N', 'P', 'K', 'L', '0', '0', '1'};
static const char MAGIC_STATE[8] = {'P', 'N', 'P', 'K', 'S', '0', '0', '1'};
#define KILL_FILE_MAX (64u << 20)
#define STATE_LEN (8 + 1 + 32)

static void put32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* appends a copy of a signature: the bytes are copied, stored and counted in one step (0, or -1 when out of room
 * or memory), so every allocation is always reachable through k->nsig */
static int add_sig(struct kill_notice *k, int signer, int kind, const uint8_t *data, size_t len)
{
    if (k->nsig >= GRP_MAX_MEMBERS)
        return -1;
    if (!k->sig && !(k->sig = calloc(GRP_MAX_MEMBERS, sizeof *k->sig))) /* room for every member, once */
        return -1;
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy)
        return -1;
    memcpy(copy, data, len);
    k->sig[k->nsig].signer = signer, k->sig[k->nsig].kind = kind, k->sig[k->nsig].len = len;
    k->sig[k->nsig].data = copy;
    k->nsig++;
    return 0;
}

int kill_parse(const uint8_t *b, size_t len, struct kill_notice *k)
{
    memset(k, 0, sizeof *k);
    if (len < 56 || memcmp(b, MAGIC_KILL, 8) != 0)
        return -1;
    memcpy(k->group, b + 8, GRP_ID_LEN);
    memcpy(k->id, b + 24, GRP_ID_LEN);
    k->scope = b[40], k->member = b[41], k->reason = b[42], k->nsets = b[43];
    k->suspect_day = (int32_t)get32(b + 44), k->suspect_member = b[48], k->suspect_slot = get32(b + 52);
    if (k->scope < KS_SETS || k->scope > KS_LEAVE || k->reason < GRP_R_COMPROMISED || k->reason > GRP_R_ENDED ||
        k->nsets > KILL_MAX_SETS || (k->scope == KS_SETS) != (k->nsets > 0))
        return -1;
    k->frame_len = 56 + (size_t)k->nsets * GRP_ID_LEN;
    if (len < k->frame_len + 1)
        return -1;
    memcpy(k->sets, b + 56, (size_t)k->nsets * GRP_ID_LEN);
    size_t at = k->frame_len;
    int n = b[at++];
    for (int i = 0; i < n; i++) {
        if (len - at < 6)
            goto bad;
        int signer = b[at], kind = b[at + 1];
        size_t slen = get32(b + at + 2);
        at += 6;
        if ((kind != 1 && kind != 2) || slen > len - at)
            goto bad;
        for (int j = 0; j < k->nsig; j++)
            if (k->sig[j].signer == signer)
                goto bad; /* one signature per member */
        if (add_sig(k, signer, kind, b + at, slen) < 0)
            goto bad;
        at += slen;
    }
    if (at != len)
        goto bad;
    return 0;
bad:
    kill_free(k);
    return -1;
}

void kill_free(struct kill_notice *k)
{
    for (int i = 0; i < k->nsig; i++)
        free(k->sig[i].data);
    free(k->sig);
    k->sig = NULL;
    k->nsig = 0;
}

static uint8_t *serialise(const struct kill_notice *k, size_t *len)
{
    size_t n = k->frame_len + 1;
    for (int i = 0; i < k->nsig; i++)
        n += 6 + k->sig[i].len;
    uint8_t *b = calloc(n, 1);
    if (!b)
        return NULL;
    memcpy(b, MAGIC_KILL, 8);
    memcpy(b + 8, k->group, GRP_ID_LEN);
    memcpy(b + 24, k->id, GRP_ID_LEN);
    b[40] = (uint8_t)k->scope, b[41] = (uint8_t)k->member, b[42] = (uint8_t)k->reason, b[43] = (uint8_t)k->nsets;
    put32(b + 44, (uint32_t)k->suspect_day), b[48] = (uint8_t)k->suspect_member, put32(b + 52, k->suspect_slot);
    memcpy(b + 56, k->sets, (size_t)k->nsets * GRP_ID_LEN);
    size_t at = k->frame_len;
    b[at++] = (uint8_t)k->nsig;
    for (int i = 0; i < k->nsig; i++) {
        b[at] = (uint8_t)k->sig[i].signer, b[at + 1] = (uint8_t)k->sig[i].kind;
        put32(b + at + 2, (uint32_t)k->sig[i].len);
        memcpy(b + at + 6, k->sig[i].data, k->sig[i].len);
        at += 6 + k->sig[i].len;
    }
    *len = n;
    return b;
}

static struct grp_set *emergency_set(struct grp *g)
{
    for (int i = 0; i < g->nsets; i++)
        if (g->sets[i].kind == GRP_SET_EMERGENCY && g->sets[i].state != GRP_REPLACED)
            return &g->sets[i];
    return NULL;
}

struct mem_src {
    const uint8_t *p;
    size_t n, at;
};
static long mem_read(void *ctx, uint8_t *buf, size_t n)
{
    struct mem_src *m = ctx;
    size_t take = m->n - m->at < n ? m->n - m->at : n;
    memcpy(buf, m->p + m->at, take);
    m->at += take;
    return (long)take;
}

/* my signature over the notice's frame, from the emergency key set (groups) or pool (pairs) */
static int sign_frame(struct grp *g, const uint8_t *frame, size_t flen, struct kill_sig *s, char *err, size_t errlen)
{
    struct grp_set *e = emergency_set(g);
    if (!e) {
        snprintf(err, errlen, "this group has no emergency keys left: meet again");
        return -1;
    }
    s->signer = g->me;
    if (g->n == 2) {
        s->kind = 2, s->len = SEAL_LEN;
        s->data = malloc(SEAL_LEN);
        return s->data && seal_make_mem(g, e, 1 - g->me, frame, flen, s->data, err, errlen) == 0 ? 0 : -1;
    }
    struct mem_src src = {frame, flen, 0};
    uint32_t slot;
    s->kind = 1;
    s->data = uss_sign(g, e, flen, mem_read, &src, &s->len, &slot, err, errlen);
    return s->data ? 0 : -1;
}

/* ---- the kills/ folder ---- */
static char *kills_path(const struct grp *g, const uint8_t id[GRP_ID_LEN], const char *ext)
{
    char hex[2 * GRP_ID_LEN + 1], *p = NULL;
    grp_hex(id, hex);
    if (asprintf(&p, "%s/kills/%s%s", g->dir, hex, ext) < 0)
        return NULL;
    return p;
}

static uint8_t *read_small(const char *path, size_t max, size_t *len)
{
    int fd = grp_open_read(path);
    struct stat st;
    uint8_t *b = NULL;
    if (fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_size <= max) {
        b = malloc(st.st_size ? (size_t)st.st_size : 1);
        if (b && pread(fd, b, (size_t)st.st_size, 0) != st.st_size) {
            free(b);
            b = NULL;
        }
        *len = (size_t)st.st_size;
    }
    if (fd >= 0)
        close(fd);
    return b;
}

static int write_whole(const struct grp *g, const char *path, const uint8_t *b, size_t len, char *err, size_t errlen)
{
    struct pnp_out o;
    if (pnp_out_open(&o, path, 0600, err, errlen) < 0)
        return -1;
    int ok = pnp_write_all(o.fd, b, len) == 0 && pnp_out_commit(&o, 1, err, errlen) == 0;
    if (!ok && !err[0])
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
    pnp_out_discard(&o);
    if (ok) {
        pnp_sync_dir(path);
        grp_touch(g, path);
        char *d = pnp_dir_of(path);
        if (d)
            grp_touch(g, d);
        free(d);
    }
    return ok ? 0 : -1;
}

struct kstate {
    int applied;
    uint8_t checked[32]; /* signers whose signature has been checked */
};

static void state_load(const struct grp *g, const uint8_t id[GRP_ID_LEN], struct kstate *st)
{
    memset(st, 0, sizeof *st);
    char *p = kills_path(g, id, ".state");
    size_t len = 0;
    uint8_t *b = p ? read_small(p, STATE_LEN, &len) : NULL;
    if (b && len == STATE_LEN && memcmp(b, MAGIC_STATE, 8) == 0) {
        st->applied = b[8] == 1;
        memcpy(st->checked, b + 9, 32);
    }
    free(b), free(p);
}

static int state_save(const struct grp *g, const uint8_t id[GRP_ID_LEN], const struct kstate *st)
{
    uint8_t b[STATE_LEN];
    memcpy(b, MAGIC_STATE, 8);
    b[8] = (uint8_t)st->applied;
    memcpy(b + 9, st->checked, 32);
    char *p = kills_path(g, id, ".state"), err[256] = "";
    int r = p ? write_whole(g, p, b, sizeof b, err, sizeof err) : -1;
    free(p);
    return r;
}

/* stores a notice in kills/, merging its signatures with a copy already there; 0 */
static int store_notice(struct grp *g, const struct kill_notice *in)
{
    char *p = kills_path(g, in->id, ".pnp-kill");
    if (!p)
        return -1;
    size_t len = 0;
    uint8_t *b = read_small(p, KILL_FILE_MAX, &len);
    /* the notice to keep: the one arriving (with its own copies of the signatures), plus any signatures the copy
     * already stored has that it lacks */
    struct kill_notice fresh, have;
    memcpy(&fresh, in, sizeof fresh);
    fresh.sig = NULL;
    fresh.nsig = 0;
    for (int i = 0; i < in->nsig; i++)
        add_sig(&fresh, in->sig[i].signer, in->sig[i].kind, in->sig[i].data, in->sig[i].len);
    int changed = 1, ret = 0;
    if (b && kill_parse(b, len, &have) == 0) {
        if (memcmp(have.group, in->group, GRP_ID_LEN) == 0 && have.frame_len == in->frame_len) {
            for (int j = 0; j < have.nsig; j++) {
                int known = 0;
                for (int i = 0; i < fresh.nsig; i++)
                    known |= fresh.sig[i].signer == have.sig[j].signer;
                if (!known)
                    add_sig(&fresh, have.sig[j].signer, have.sig[j].kind, have.sig[j].data, have.sig[j].len);
            }
            changed = fresh.nsig > have.nsig; /* nothing new: leave the stored copy as it is */
        }
        kill_free(&have);
    }
    struct kill_notice *keep = &fresh;
    free(b);
    if (changed) {
        size_t n;
        uint8_t *out = serialise(keep, &n);
        char err[256] = "";
        ret = out ? write_whole(g, p, out, n, err, sizeof err) : -1;
        free(out);
    }
    kill_free(keep);
    free(p);
    return ret;
}

int kill_tolerance_left(const struct grp *g)
{
    int gone = 0;
    for (int i = 0; i < g->n; i++)
        gone += grp_bit(g->left, i) | grp_bit(g->expelled, i);
    return g->omega - gone;
}

static int covers(const struct kill_notice *k, const struct grp_set *s)
{
    if (k->scope == KS_GROUP || k->scope == KS_MEMBER)
        return 1;
    for (int i = 0; i < k->nsets; i++)
        if (memcmp(k->sets[i], s->id, GRP_ID_LEN) == 0)
            return 1;
    return 0;
}

static int needed(const struct grp *g, const struct kill_notice *k)
{
    return k->scope == KS_LEAVE || g->n == 2 ? 1 : g->threshold;
}

/* wipes what's left of my pools with member o in set s (both directions) */
static void wipe_pools_with(struct grp *g, struct grp_set *s, int o)
{
    for (int d = 0; d < 2; d++) {
        struct pool p;
        char err[256];
        if (pool_open(g, s, d ? o : g->me, d ? g->me : o, &p, err, sizeof err) < 0)
            continue;
        pool_wipe(&p, p.next_off, p.bytes - p.next_off);
        for (uint32_t i = p.next_loc; i < p.nloc; i++)
            pool_wipe_loc(&p, i);
        if (d) /* incoming: everything not yet received goes; what's received is wiped already */
            pool_wipe(&p, 0, p.bytes);
        pool_sync(&p);
        grp_touch(g, p.path);
        pool_close(&p);
    }
}

static void kill_set(struct grp *g, struct grp_set *s, const struct kill_notice *k)
{
    if (s->state == GRP_KILLED)
        return;
    s->state = GRP_KILLED;
    s->reason = (uint8_t)k->reason;
    s->suspect_day = k->suspect_day, s->suspect_member = (uint8_t)k->suspect_member, s->suspect_slot = k->suspect_slot;
    for (int o = 0; o < g->n; o++)
        if (o != g->me)
            wipe_pools_with(g, s, o);
    if (g->n >= 3 && s->slots)
        uss_wipe_unused(g, s);
}

static void apply(struct grp *g, const struct kill_notice *k, void (*say)(const char *fmt, ...))
{
    char who[48];
    switch (k->scope) {
    case KS_LEAVE:
    case KS_MEMBER: {
        int m = k->member;
        if (k->scope == KS_LEAVE)
            grp_set_bit(g->left, m);
        else
            grp_set_bit(g->expelled, m);
        for (int si = 0; si < g->nsets; si++)
            if (g->sets[si].kind == GRP_SET_NORMAL)
                wipe_pools_with(g, &g->sets[si], m);
        if (m == g->me)
            for (int si = 0; si < g->nsets; si++)
                kill_set(g, &g->sets[si], k);
        if (say)
            say("%s %s the group%s", grp_member_name(g, m, who, sizeof who),
                k->scope == KS_LEAVE ? "left" : "was removed from",
                k->reason == GRP_R_COMPROMISED ? " (their keys were reported compromised)" : "");
        break;
    }
    default:
        for (int si = 0; si < g->nsets; si++)
            if (g->sets[si].kind == GRP_SET_NORMAL && covers(k, &g->sets[si]))
                kill_set(g, &g->sets[si], k);
        if (say)
            say("%s killed (%s): they can't be used any more", k->scope == KS_GROUP ? "every key set of this group was"
                                                               : "key sets were",
                k->reason == GRP_R_ENDED ? "ended" : "reported compromised");
    }
}

static int check_sig(struct grp *g, const uint8_t *frame, size_t flen, const struct kill_sig *s)
{
    char err[256];
    if (s->signer >= g->n || s->signer == g->me)
        return 0;
    if (g->n == 2) {
        struct seal_result r;
        return s->kind == 2 && s->len == SEAL_LEN &&
               seal_check_mem(g, frame, flen, s->data, 64, &r, err, sizeof err) == 1 && r.from == s->signer &&
               r.set->kind == GRP_SET_EMERGENCY;
    }
    struct uss_result r;
    struct mem_src src = {frame, flen, 0};
    if (s->kind != 1 || uss_verify(g, s->data, s->len, flen, mem_read, &src, 1, &r, err, sizeof err) < 0)
        return 0;
    struct grp_set *e = grp_find_set(g, r.set_id);
    return r.level >= 0 && r.signer == s->signer && e && e->kind == GRP_SET_EMERGENCY;
}

/* checks and, at the threshold, applies one stored notice; 1 if it's pending (below the threshold) */
static int process_one(struct grp *g, const uint8_t *b, size_t len, void (*say)(const char *fmt, ...))
{
    struct kill_notice k;
    if (kill_parse(b, len, &k) < 0 || memcmp(k.group, g->id, GRP_ID_LEN) != 0)
        return 0;
    struct kstate st;
    state_load(g, k.id, &st);
    int changed = 0;
    for (int i = 0; i < k.nsig; i++) {
        int sg = k.sig[i].signer;
        if (sg < g->n && !grp_bit(st.checked, sg) && check_sig(g, b, k.frame_len, &k.sig[i])) {
            grp_set_bit(st.checked, sg);
            changed = 1;
        }
    }
    int count = 0;
    for (int i = 0; i < g->n; i++)
        count += grp_bit(st.checked, i);
    if (k.scope == KS_LEAVE && !grp_bit(st.checked, k.member))
        count = 0; /* only the leaver can leave */
    int pending = 0;
    if (!st.applied && count >= needed(g, &k)) {
        apply(g, &k, say);
        st.applied = 1;
        changed = 1;
        char err[256];
        grp_save(g, err, sizeof err);
    } else if (!st.applied && count > 0 && k.scope != KS_LEAVE) {
        pending = 1;
        if (say) {
            char who[48];
            int first = 0;
            while (first < g->n && !grp_bit(st.checked, first))
                first++;
            say("WARNING: %s reports %s compromised; waiting for %d more member%s to confirm",
                grp_member_name(g, first < g->n ? first : 0, who, sizeof who),
                k.scope == KS_GROUP ? "the whole group" : k.scope == KS_MEMBER ? "a member's keys" : "key sets",
                needed(g, &k) - count, needed(g, &k) - count == 1 ? "" : "s");
        }
    }
    if (changed)
        state_save(g, k.id, &st);
    kill_free(&k);
    return pending;
}

static int is_notice_name(const char *n)
{
    size_t l = strlen(n);
    return l > 9 && strcmp(n + l - 9, ".pnp-kill") == 0 && n[0] != '.';
}

int kill_process(struct grp *g, const char *extra_dir, void (*say)(const char *fmt, ...))
{
    /* notices lying in the current folder (or wherever the user points) are taken into kills/ first */
    if (extra_dir) {
        DIR *d = opendir(extra_dir);
        struct dirent *e;
        while (d && (e = readdir(d))) {
            if (!is_notice_name(e->d_name))
                continue;
            char *p = NULL;
            if (asprintf(&p, "%s/%s", extra_dir, e->d_name) < 0)
                continue;
            size_t len = 0;
            uint8_t *b = read_small(p, KILL_FILE_MAX, &len);
            struct kill_notice k;
            if (b && kill_parse(b, len, &k) == 0) {
                if (memcmp(k.group, g->id, GRP_ID_LEN) == 0)
                    store_notice(g, &k);
                kill_free(&k);
            }
            free(b), free(p);
        }
        if (d)
            closedir(d);
    }
    char *kd = NULL;
    if (asprintf(&kd, "%s/kills", g->dir) < 0)
        return 0;
    DIR *d = grp_opendir(kd);
    int pending = 0;
    struct dirent *e;
    while (d && (e = readdir(d))) {
        if (!is_notice_name(e->d_name))
            continue;
        char *p = NULL;
        if (asprintf(&p, "%s/%s", kd, e->d_name) < 0)
            continue;
        size_t len = 0;
        uint8_t *b = read_small(p, KILL_FILE_MAX, &len);
        if (b)
            pending += process_one(g, b, len, say);
        free(b), free(p);
    }
    if (d)
        closedir(d);
    free(kd);
    return pending;
}

int kill_pending_for(struct grp *g, const struct grp_set *s)
{
    char *kd = NULL;
    if (asprintf(&kd, "%s/kills", g->dir) < 0)
        return 0;
    DIR *d = grp_opendir(kd);
    int pending = 0;
    struct dirent *e;
    while (d && !pending && (e = readdir(d))) {
        if (!is_notice_name(e->d_name))
            continue;
        char *p = NULL;
        if (asprintf(&p, "%s/%s", kd, e->d_name) < 0)
            continue;
        size_t len = 0;
        uint8_t *b = read_small(p, KILL_FILE_MAX, &len);
        struct kill_notice k;
        if (b && kill_parse(b, len, &k) == 0) {
            struct kstate st;
            state_load(g, k.id, &st);
            int count = 0;
            for (int i = 0; i < g->n; i++)
                count += grp_bit(st.checked, i);
            pending = !st.applied && count > 0 && k.scope != KS_LEAVE && covers(&k, s);
            kill_free(&k);
        }
        free(b), free(p);
    }
    if (d)
        closedir(d);
    free(kd);
    return pending;
}

int kill_bundle(struct grp *g, uint8_t **out, size_t *len)
{
    *out = NULL, *len = 0;
    char *kd = NULL;
    if (asprintf(&kd, "%s/kills", g->dir) < 0)
        return -1;
    DIR *d = grp_opendir(kd);
    struct dirent *e;
    while (d && (e = readdir(d))) {
        if (!is_notice_name(e->d_name))
            continue;
        char *p = NULL;
        if (asprintf(&p, "%s/%s", kd, e->d_name) < 0)
            continue;
        size_t n = 0;
        uint8_t *b = read_small(p, KILL_FILE_MAX, &n);
        uint8_t *grown = b ? realloc(*out, *len + 4 + n) : NULL;
        if (grown) {
            *out = grown;
            put32(*out + *len, (uint32_t)n);
            memcpy(*out + *len + 4, b, n);
            *len += 4 + n;
        }
        free(b), free(p);
    }
    if (d)
        closedir(d);
    free(kd);
    return 0;
}

void kill_absorb(struct grp *g, const uint8_t *b, size_t len, void (*say)(const char *fmt, ...))
{
    size_t at = 0;
    int any = 0;
    while (len - at >= 4) {
        uint32_t n = get32(b + at);
        at += 4;
        if (n > len - at)
            break;
        struct kill_notice k;
        if (kill_parse(b + at, n, &k) == 0) {
            if (memcmp(k.group, g->id, GRP_ID_LEN) == 0 && store_notice(g, &k) == 0)
                any = 1;
            kill_free(&k);
        }
        at += n;
    }
    if (any)
        kill_process(g, NULL, say);
}

int kill_make(struct grp *g, int scope, int member, const uint8_t (*sets)[GRP_ID_LEN], int nsets, int reason,
              int32_t suspect_day, int suspect_member, uint32_t suspect_slot, const char *out, char *err,
              size_t errlen)
{
    struct kill_notice k;
    memset(&k, 0, sizeof k);
    memcpy(k.group, g->id, GRP_ID_LEN);
    if (getrandom(k.id, GRP_ID_LEN, 0) != GRP_ID_LEN) {
        snprintf(err, errlen, "getrandom: %s", strerror(errno));
        return -1;
    }
    k.scope = scope, k.member = member, k.reason = reason, k.nsets = nsets;
    if (nsets)
        memcpy(k.sets, sets, (size_t)nsets * GRP_ID_LEN);
    k.suspect_day = suspect_day, k.suspect_member = suspect_member, k.suspect_slot = suspect_slot;
    k.frame_len = 56 + (size_t)nsets * GRP_ID_LEN;
    size_t flen;
    uint8_t *frame = serialise(&k, &flen); /* no signatures yet: the frame and a zero count */
    if (!frame)
        return -1;
    struct kill_sig mine = {0, 0, NULL, 0};
    int ok = sign_frame(g, frame, k.frame_len, &mine, err, errlen) == 0 &&
             add_sig(&k, mine.signer, mine.kind, mine.data, mine.len) == 0;
    free(frame);
    free(mine.data);
    if (!ok) {
        kill_free(&k);
        return -1;
    }
    size_t n;
    uint8_t *b = serialise(&k, &n);
    ok = b && write_whole(g, out, b, n, err, errlen) == 0;
    /* my own copy: my signature counts (I made it), then apply it to my side if that's enough */
    if (ok) {
        store_notice(g, &k);
        struct kstate st;
        memset(&st, 0, sizeof st);
        grp_set_bit(st.checked, g->me);
        state_save(g, k.id, &st);
        process_one(g, b, n, NULL);
    }
    free(b);
    kill_free(&k);
    return ok ? 0 : -1;
}

int kill_cosign(struct grp *g, const char *path, char *err, size_t errlen)
{
    size_t len = 0;
    uint8_t *b = read_small(path, KILL_FILE_MAX, &len);
    struct kill_notice k;
    int parsed = b && kill_parse(b, len, &k) == 0;
    if (!parsed || memcmp(k.group, g->id, GRP_ID_LEN) != 0) {
        snprintf(err, errlen, "%s isn't a kill notice for this group", path);
        if (parsed)
            kill_free(&k);
        free(b);
        return -1;
    }
    int ret = -1;
    for (int i = 0; i < k.nsig; i++)
        if (k.sig[i].signer == g->me) {
            snprintf(err, errlen, "you have already signed this notice");
            goto out;
        }
    if (k.scope == KS_LEAVE) {
        snprintf(err, errlen, "a leave notice is the leaver's alone: there's nothing to add");
        goto out;
    }
    if (k.nsig >= GRP_MAX_MEMBERS) {
        snprintf(err, errlen, "this notice already carries every signature it can");
        goto out;
    }
    store_notice(g, &k);
    kill_process(g, NULL, NULL); /* check the signatures already there first, while their items are fresh */
    struct kill_sig mine = {0, 0, NULL, 0};
    int signed_ok = sign_frame(g, b, k.frame_len, &mine, err, errlen) == 0 &&
                    add_sig(&k, mine.signer, mine.kind, mine.data, mine.len) == 0;
    free(mine.data);
    if (!signed_ok)
        goto out;
    size_t n;
    uint8_t *nb = serialise(&k, &n);
    if (nb && write_whole(g, path, nb, n, err, errlen) == 0) {
        store_notice(g, &k);
        struct kstate st;
        state_load(g, k.id, &st);
        grp_set_bit(st.checked, g->me);
        state_save(g, k.id, &st);
        process_one(g, nb, n, NULL);
        ret = 0;
    }
    free(nb);
out:
    kill_free(&k);
    free(b);
    return ret;
}
