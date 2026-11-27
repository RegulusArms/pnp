/* The command line for pairs and groups (gcli.h; docs/group.md).
 *
 * Every command loads the group from its cylinder, then, before doing anything:
 *   - the clock guard: a clock earlier than the latest day pnp has seen with this group stops it (--clock-ok);
 *   - closing: key sets whose window plus grace days has passed have their unused slots and pad wiped, and verify
 *     keys past the dispute period are deleted (after saying which signatures stop being checkable);
 *   - kill notices: those in the group's kills/ folder and beside the file being handled are checked and applied.
 * Results ("sealed by", "signed by") go to stdout; everything else to stderr, cleaned of control characters. */
#define _GNU_SOURCE
#include "gcli.h"
#include "courier.h"
#include "format.h"
#include "fileio.h"
#include "gmsg.h"
#include "group.h"
#include "kill.h"
#include "meeting.h"
#include "pnp.h"
#include "rng.h"
#include "sandbox.h"
#include "uss.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_GROUPS 64
#define DEFAULT_LOOKAHEAD 16

static int quiet;

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    pnp_clean(msg);
    fprintf(stderr, "pnp: %s\n", msg);
}

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void note(const char *fmt, ...)
{
    if (quiet)
        return;
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    pnp_clean(msg);
    fprintf(stderr, "pnp: %s\n", msg);
}

/* results: on stdout, cleaned like everything else */
static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    pnp_clean(msg);
    printf("%s\n", msg);
    fflush(stdout);
}

static const char *const COMMANDS[] = {"--seal", "--check-seal", "--sign", "--verify-sig", "--send", "--receive",
                                       "--kill", "--kill-sign", "--leave", "--info", "--meet", "--import", "--move",
                                       "--courier-check",
#ifdef PNP_TEST
                                       "--test-setup",
#endif
                                       NULL};

int pnp_is_group_command(const char *arg)
{
    for (int i = 0; COMMANDS[i]; i++)
        if (strcmp(arg, COMMANDS[i]) == 0)
            return 1;
    return 0;
}

struct opts {
    const char *groups, *group, *to, *out, *level, *reason, *since, *member, *sets;
    const char *self, *courier, *sticks, *card;
    const char *card_used; /* --kill with a card: the card, which must stay reachable to be written back */
    const char *from;      /* --meet --from GROUP-FOLDER: a re-meeting */
    int force, sign, clock_ok, despite, lookahead, wipe_verify;
};

#ifdef PNP_TEST
int pnp_test_setup(const char *spec, const char *dir);
#endif
int pnp_meet(const char *self_path, const char *courier_path, const char *sticks, const char *from);
int pnp_import_card(const char *self_path, const char *root, const char *card);
int pnp_move(const char *groups, const char *set_prefix, const char *dest_root);
int pnp_courier_check(const char *dev);
char *pnp_card_unpack(const char *card, char **tmp_out, char *err, size_t errlen);
int pnp_card_repack(const char *card, const char *gdir, char *tmp, char *err, size_t errlen);

/* ---- the fence: once the groups are loaded, nothing outside their folders, the files' folders and the current
 * folder can be touched (Landlock, sandbox.c) ---- */
static void fence(const struct grp *gs, int n, const char *a, const char *b, const char *c)
{
    char *dirs[MAX_GROUPS + 4];
    int nd = 0;
    for (int i = 0; i < n; i++)
        dirs[nd++] = gs[i].dir;
    char *da = a ? pnp_dir_of(a) : NULL, *db = b ? pnp_dir_of(b) : NULL;
    if (da)
        dirs[nd++] = da;
    if (db)
        dirs[nd++] = db;
    if (c)
        dirs[nd++] = (char *)c;
    dirs[nd++] = (char *)".";
    pnp_sandbox_dirs(dirs, nd);
    free(da), free(db);
#ifdef PNP_TEST
    /* test hook: what the fence lets through */
    const char *probe = getenv("PNP_TEST_PROBE");
    if (probe) {
        int fd = open(probe, O_RDONLY | O_CLOEXEC);
        fprintf(stderr, "probe read %s: %s\n", probe, fd >= 0 ? "allowed" : strerror(errno));
        if (fd >= 0)
            close(fd);
        char made[PATH_MAX];
        snprintf(made, sizeof made, "%s.made", probe);
        fd = open(made, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        fprintf(stderr, "probe create: %s\n", fd >= 0 ? "allowed" : strerror(errno));
        if (fd >= 0)
            close(fd);
    }
#endif
}

/* ---- finding and preparing a group ---- */
static int load_all(const struct opts *o, struct grp *gs, int max)
{
    char *dirs[MAX_GROUPS];
    int n = grp_find_all(o->groups, dirs, max < MAX_GROUPS ? max : MAX_GROUPS), got = 0;
    for (int i = 0; i < n; i++) {
        char err[512];
        if (grp_load(dirs[i], &gs[got], err, sizeof err) == 0)
            got++;
        else
            say("%s", err);
        free(dirs[i]);
    }
    return got;
}

static int matches(const struct grp *g, const char *sel)
{
    char hex[2 * GRP_ID_LEN + 1];
    grp_hex(g->id, hex);
    return strcasecmp(g->name, sel) == 0 || (strlen(sel) >= 4 && strncasecmp(hex, sel, strlen(sel)) == 0);
}

static void free_all(struct grp *gs, int n)
{
    for (int i = 0; i < n; i++)
        grp_free(&gs[i]);
}

/* wipes what a closed window leaves, and verify keys past the dispute period */
static int maintain(struct grp *g)
{
    int32_t today = grp_today(g->tz_min);
    int changed = 0;
    for (int si = 0; si < g->nsets; si++) {
        struct grp_set *s = &g->sets[si];
        if ((s->state == GRP_ACTIVE || s->state == GRP_REPLACED) && s->end_day != GRP_INDEFINITE_END &&
            (int64_t)today > (int64_t)s->end_day + g->grace) {
            for (int o = 0; o < g->n; o++) {
                if (o == g->me || !s->nloc)
                    continue;
                for (int d = 0; d < 2; d++) {
                    struct pool p;
                    char err[256];
                    if (pool_open(g, s, d ? o : g->me, d ? g->me : o, &p, err, sizeof err) < 0)
                        continue;
                    pool_wipe(&p, d ? 0 : p.next_off, d ? p.bytes : p.bytes - p.next_off);
                    for (uint32_t i = d ? 0 : p.next_loc; i < p.nloc; i++)
                        pool_wipe_loc(&p, i);
                    pool_sync(&p);
                    grp_touch(g, p.path);
                    pool_close(&p);
                }
            }
            if (g->n >= 3 && s->slots)
                uss_wipe_unused(g, s);
            s->state = GRP_CLOSED;
            changed = 1;
            char a[16];
            grp_day_str(s->end_day, a);
            note("key set ending %s has closed: its unused slots and pad were wiped", a);
        }
        if (g->dispute_days && g->n >= 3 && s->state != GRP_ACTIVE && s->end_day != GRP_INDEFINITE_END &&
            (int64_t)today > (int64_t)s->end_day + g->grace + g->dispute_days) {
            int any = 0;
            for (int j = 0; j < g->n; j++) {
                char name[32];
                snprintf(name, sizeof name, "verify.%d", j + 1);
                char *p = grp_set_path(g, s, name);
                struct stat st;
                if (p && stat(p, &st) == 0) {
                    if (!any) {
                        char a[16];
                        grp_day_str(s->end_day, a);
                        note("the dispute period of key set ending %s is over: signatures made with it can no longer "
                             "be checked here, and its verify keys are now wiped", a);
                    }
                    any = 1;
                    unlink(p);
                }
                free(p);
            }
        }
    }
    return changed;
}

static void say_cb(const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    say("%s", msg);
}

/* the checks every command makes first; extra: a folder to look for kill notices in */
static int prepare(struct grp *g, const struct opts *o, const char *extra)
{
    char err[512];
    int c = grp_clock_guard(g, o->clock_ok, err, sizeof err);
    if (c < 0) {
        say("%s", err);
        return -1;
    }
    int changed = maintain(g) || c > 0;
    if (changed && grp_save(g, err, sizeof err) < 0) {
        say("%s", err);
        return -1;
    }
    /* notices beside the file being handled, and in the current folder, are taken in first; warnings and what's
     * applied are said once, by the last pass */
    if (extra && strcmp(extra, ".") != 0)
        kill_process(g, extra, NULL);
    kill_process(g, ".", say_cb);
    if (g->n >= 3) {
        int gone = 0;
        char who[48];
        for (int i = 0; i < g->n; i++)
            if ((grp_bit(g->left, i) || grp_bit(g->expelled, i)) && i != g->me) {
                gone++;
                note("%s %s the group: meet again to make new key sets", grp_member_name(g, i, who, sizeof who),
                     grp_bit(g->left, i) ? "left" : "was removed from");
            }
        if (gone) {
            int t = kill_tolerance_left(g), active = g->n - gone;
            if (active <= 2)
                note("only two active members are left: signatures now prove no more than a pair's seal");
            else if (t <= 0)
                note("tolerance left: none. The signature guarantees no longer hold against a further cheater");
            else
                note("tolerance left: %d cheater%s", t, t == 1 ? "" : "s");
        }
    }
    return 0;
}

/* picks the one group a sending command uses */
static int pick_group(const struct opts *o, struct grp *gs, int n)
{
    int found = -1;
    for (int i = 0; i < n; i++) {
        if (o->group && !matches(&gs[i], o->group))
            continue;
        /* the same group in two generations (after a re-meeting): the newest one sends */
        if (found >= 0 && memcmp(gs[found].id, gs[i].id, GRP_ID_LEN) == 0) {
            if (gs[i].gen > gs[found].gen)
                found = i;
            continue;
        }
        if (found >= 0) {
            say("you're in more than one group here: choose one with --group NAME (or the start of its ID)");
            return -1;
        }
        found = i;
    }
    if (found < 0)
        say("%s", o->group ? "no group by that name or ID here (see pnp --info)"
                           : "no pnp group found: plug in your code cylinder, or give --groups FOLDER");
    return found;
}

static int not_me_or_gone(const struct grp *g, int m)
{
    if (m < 0) {
        say("there's no such member (give a name, or a number from 1 to %d)", g->n);
        return -1;
    }
    if (m == g->me) {
        say("that's you");
        return -1;
    }
    if (grp_bit(g->left, g->me) || grp_bit(g->expelled, g->me)) {
        say("you're no longer in this group");
        return -1;
    }
    if (grp_bit(g->left, m) || grp_bit(g->expelled, m)) {
        say("that member is no longer in the group");
        return -1;
    }
    return 0;
}

/* the key set for sending today, and the warning check */
static struct grp_set *sending_set(struct grp *g, const struct opts *o)
{
    int32_t today = grp_today(g->tz_min);
    struct grp_set *s = grp_current_set(g, today);
    if (!s) {
        int killed = 0;
        for (int i = 0; i < g->nsets; i++)
            killed |= g->sets[i].kind == GRP_SET_NORMAL && g->sets[i].state == GRP_KILLED &&
                      today >= g->sets[i].start_day && today <= g->sets[i].end_day;
        say("%s", killed ? "today's key set has been killed (see pnp --info): meet again"
                         : "no key set of this group is valid today (each has a window agreed at the meeting): "
                           "meet again");
        return NULL;
    }
    if (kill_pending_for(g, s) && !o->despite) {
        say("a member reports this key set compromised (not yet confirmed). Send anyway? Add --despite-warning");
        return NULL;
    }
    return s;
}

static char *with_suffix(const char *path, const char *suffix)
{
    char *p = NULL;
    return asprintf(&p, "%s%s", path, suffix) < 0 ? NULL : p;
}

static int read_whole(const char *path, uint8_t **b, size_t *len, size_t max)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || (uint64_t)st.st_size > max) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    *b = malloc(st.st_size ? (size_t)st.st_size : 1);
    *len = (size_t)st.st_size;
    int ok = *b && read(fd, *b, *len) == (ssize_t)*len;
    close(fd);
    return ok ? 0 : -1;
}

static int write_new(const char *path, const uint8_t *b, size_t len, int force)
{
    char err[512];
    struct stat st;
    if (!force && lstat(path, &st) == 0) {
        say("%s already exists (use -f to replace it)", path);
        return -1;
    }
    struct pnp_out o;
    if (pnp_out_open(&o, path, 0644, err, sizeof err) < 0) {
        say("%s", err);
        return -1;
    }
    int ok = pnp_write_all(o.fd, b, len) == 0 && pnp_out_commit(&o, force, err, sizeof err) == 0;
    if (!ok)
        say("%s: %s", path, err[0] ? err : strerror(errno));
    pnp_out_discard(&o);
    return ok ? 0 : -1;
}

static char *dir_of(const char *path) { return pnp_dir_of(path); }

/* ---- commands ---- */
static int cmd_seal(const struct opts *o, const char *file)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), i = pick_group(o, gs, n), ret = 1;
    fence(gs, n, file, o->out, NULL);
    if (i < 0)
        goto out;
    struct grp *g = &gs[i];
    char *d = dir_of(file);
    if (prepare(g, o, d) < 0) {
        free(d);
        goto out;
    }
    free(d);
    if (!o->to) {
        say("--seal needs --to MEMBER");
        goto out;
    }
    int to = grp_find_member(g, o->to);
    if (not_me_or_gone(g, to) < 0)
        goto out;
    struct grp_set *s = sending_set(g, o);
    if (!s)
        goto out;
    uint8_t seal[SEAL_LEN];
    char err[512];
    if (seal_make(g, s, to, file, seal, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    char *dest = o->out ? strdup(o->out) : with_suffix(file, ".pnp.seal");
    if (dest && write_new(dest, seal, sizeof seal, o->force) == 0) {
        char who[48];
        note("sealed for %s: %s (a seal proves who made it to the two of you only)",
             grp_member_name(g, to, who, sizeof who), dest);
        ret = 0;
    }
    free(dest);
out:
    free_all(gs, n);
    return ret;
}

static int cmd_check_seal(const struct opts *o, const char *file, const char *seal_path)
{
    char *sp = seal_path ? strdup(seal_path) : with_suffix(file, ".pnp.seal");
    uint8_t *b = NULL;
    size_t len = 0;
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), ret = 1;
    fence(gs, n, file, seal_path, NULL);
    if (!sp || read_whole(sp, &b, &len, SEAL_LEN) < 0 || len != SEAL_LEN) {
        say("%s isn't a pnp seal", sp ? sp : "the seal");
        goto out;
    }
    int any = 0;
    for (int i = 0; i < n && !any; i++) {
        struct grp *g = &gs[i];
        char *d = dir_of(file);
        int pr = prepare(g, o, d);
        free(d);
        if (pr < 0)
            continue;
        struct seal_result r;
        char err[512];
        int c = seal_check(g, file, b, o->lookahead, &r, err, sizeof err);
        if (c < 0) {
            say("%s", err);
            any = 1;
        } else if (c == 1) {
            char who[48];
            out("Sealed by %s. Only you and %s could have made this; it proves nothing to anyone else.",
                grp_member_name(g, r.from, who, sizeof who), who);
            ret = 0, any = 1;
        } else if (err[0]) {
            say("%s", err);
        }
    }
    if (!any)
        say("the seal doesn't check: %s was changed, or the seal isn't for you (or it's too far ahead: try "
            "--lookahead)", file);
out:
    free(sp), free(b);
    free_all(gs, n);
    return ret;
}

struct fsrc {
    int fd;
    uint64_t left;
};
static long fsrc_read(void *ctx, uint8_t *buf, size_t n)
{
    struct fsrc *s = ctx;
    size_t want = s->left < n ? (size_t)s->left : n;
    if (!want)
        return 0;
    ssize_t r = read(s->fd, buf, want);
    if (r <= 0)
        return -1;
    s->left -= (uint64_t)r;
    return (long)r;
}

static int cmd_sign(const struct opts *o, const char *file)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), i = pick_group(o, gs, n), ret = 1, fd = -1;
    fence(gs, n, file, o->out, NULL);
    if (i < 0)
        goto out;
    struct grp *g = &gs[i];
    char *d = dir_of(file);
    int pr = prepare(g, o, d);
    free(d);
    if (pr < 0)
        goto out;
    if (g->n < 3) {
        say("a pair has seals, not signatures: use --seal (a signature needs a group of 3 or more)");
        goto out;
    }
    if (grp_bit(g->left, g->me) || grp_bit(g->expelled, g->me)) {
        say("you're no longer in this group");
        goto out;
    }
    struct grp_set *s = sending_set(g, o);
    if (!s)
        goto out;
    struct stat st;
    fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        say("%s: %s", file, fd < 0 ? strerror(errno) : "not a regular file");
        goto out;
    }
    struct fsrc src = {fd, (uint64_t)st.st_size};
    size_t siglen;
    uint32_t slot;
    char err[512];
    uint8_t *sig = uss_sign(g, s, (uint64_t)st.st_size, fsrc_read, &src, &siglen, &slot, err, sizeof err);
    if (!sig) {
        say("%s", err);
        goto out;
    }
    char *dest = o->out ? strdup(o->out) : with_suffix(file, ".pnp.sig");
    if (dest && write_new(dest, sig, siglen, o->force) == 0) {
        note("signed: %s (slot %u of %u; checkable by every other member)", dest, slot + 1, s->slots);
        ret = 0;
    }
    free(dest), free(sig);
out:
    if (fd >= 0)
        close(fd);
    free_all(gs, n);
    return ret;
}

static const char *level_text(int level, char *buf, size_t len)
{
    if (level == -1)
        snprintf(buf, len, "at the dispute level only");
    else
        snprintf(buf, len, "at level %d", level);
    return buf;
}

static int report_sig(const struct grp *g, int signer, int level, int exact, int reused, int want_level,
                      const char *what)
{
    char who[48], lv[48];
    grp_member_name(g, signer, who, sizeof who);
    if (level < want_level) {
        out("The signature on %s doesn't check%s.", what, level >= -1 ? " at the level asked for" : "");
        return 1;
    }
    out("Signed by %s, accepted %s%s.", who, level_text(level, lv, sizeof lv),
        exact ? "" : ", but NOT EXACT: someone tampered with it (the signer or another member). Raise it with the group");
    if (reused)
        out("WARNING: %s used this signature's slot for a different message too: the signer misbehaved.", who);
    if (level == -1 && want_level == -1)
        out("(This is your vote in a dispute: the signature is valid if more than half the members accept it.)");
    return 0;
}

static int cmd_verify_sig(const struct opts *o, const char *file, const char *sig_path)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), ret = 1, want = 0;
    fence(gs, n, file, sig_path, NULL);
    if (o->level) {
        want = atoi(o->level);
        if (want < -1 || want > 8) {
            say("--level takes -1 (dispute) to 8");
            goto out0;
        }
    }
    size_t fl = strlen(file);
    int evidence = !sig_path && fl > 11 && strcmp(file + fl - 11, ".pnp-signed") == 0;
    char *sp = evidence ? NULL : sig_path ? strdup(sig_path) : with_suffix(file, ".pnp.sig");
    uint8_t *sig = NULL;
    size_t siglen = 0;
    uint8_t set_id[GRP_ID_LEN];
    int signer, N;
    uint32_t slot, k;
    if (!evidence && (!sp || read_whole(sp, &sig, &siglen, 64u << 20) < 0 ||
                      uss_sig_parse(sig, siglen, set_id, &signer, &N, &slot, &k) < 0)) {
        say("%s isn't a pnp signature", sp ? sp : "the signature");
        goto out;
    }
    int done = 0;
    for (int i = 0; i < n && !done; i++) {
        struct grp *g = &gs[i];
        if (!evidence && !grp_find_set(g, set_id))
            continue;
        char *d = dir_of(file);
        int pr = prepare(g, o, d);
        free(d);
        if (pr < 0) {
            done = 1;
            break;
        }
        char err[512];
        if (evidence) {
            struct msg_result r;
            if (msg_verify_evidence(g, file, &r, err, sizeof err) < 0)
                continue;
            ret = report_sig(g, r.from, r.sig_level, r.sig_exact, r.sig_reused, want, file);
            /* who it was sent to is part of what was signed: a signed message passed on to someone else says so */
            char list[1024] = "", who[48];
            for (int t = 0; t < r.nto; t++)
                snprintf(list + strlen(list), sizeof list - strlen(list), "%s%s", t ? ", " : "",
                         grp_member_name(g, r.to[t] < g->n ? r.to[t] : 0, who, sizeof who));
            if (!ret)
                out("It was sent to: %s.", list);
            done = 1;
            break;
        }
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) < 0) {
            say("%s: %s", file, strerror(errno));
            if (fd >= 0)
                close(fd);
            done = 1;
            break;
        }
        struct fsrc src = {fd, (uint64_t)st.st_size};
        struct uss_result r;
        int v = uss_verify(g, sig, siglen, (uint64_t)st.st_size, fsrc_read, &src, 1, &r, err, sizeof err);
        close(fd);
        if (v < 0)
            say("%s", err);
        else
            ret = report_sig(g, r.signer, r.level, r.exact, r.reused, want, file);
        done = 1;
    }
    if (!done)
        say("this signature isn't from a group on this cylinder");
out:
    free(sp), free(sig);
out0:
    free_all(gs, n);
    return ret;
}

static int cmd_send(const struct opts *o, const char *file)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), i = pick_group(o, gs, n), ret = 1;
    fence(gs, n, file, o->out, NULL);
    if (i < 0)
        goto out;
    struct grp *g = &gs[i];
    char *d = dir_of(file);
    int pr = prepare(g, o, d);
    free(d);
    if (pr < 0)
        goto out;
    if (!o->to) {
        say("--send needs --to MEMBER (several: --to 2,3; everyone: --to all)");
        goto out;
    }
    int sign = o->sign || (g->signed_default && g->n >= 3);
    if (sign && g->n < 3) {
        say("a pair's messages are already authenticated (and deniable); signatures need a group of 3 or more");
        goto out;
    }
    struct grp_set *s = sending_set(g, o);
    if (!s)
        goto out;
    int to[GRP_MAX_MEMBERS], nto = 0;
    if (strcmp(o->to, "all") == 0) {
        for (int m = 0; m < g->n; m++)
            if (m != g->me && !grp_bit(g->left, m) && !grp_bit(g->expelled, m))
                to[nto++] = m;
    } else {
        char *copy = strdup(o->to), *save = NULL;
        for (char *t = copy ? strtok_r(copy, ",", &save) : NULL; t && nto < GRP_MAX_MEMBERS;
             t = strtok_r(NULL, ",", &save)) {
            int m = grp_find_member(g, t);
            if (not_me_or_gone(g, m) < 0) {
                free(copy);
                goto out;
            }
            to[nto++] = m;
        }
        free(copy);
    }
    if (!nto) {
        say("nobody to send to");
        goto out;
    }
    if (nto > 1 && o->out) {
        say("-o names one output: with several recipients, each message is FILE.N.pnp");
        goto out;
    }
    ret = 0;
    for (int t = 0; t < nto; t++) {
        char *dest = NULL;
        if (o->out)
            dest = strdup(o->out);
        else if (nto == 1)
            dest = with_suffix(file, ".pnp");
        else if (asprintf(&dest, "%s.%d.pnp", file, to[t] + 1) < 0)
            dest = NULL;
        char err[512], who[48];
        if (!dest || msg_send(g, s, to[t], file, dest, sign, o->force, err, sizeof err) < 0) {
            say("%s", dest ? err : "out of memory");
            ret = 1;
        } else {
            note("%s for %s: %s", sign ? "signed and encrypted" : "encrypted", grp_member_name(g, to[t], who, sizeof who),
                 dest);
        }
        free(dest);
    }
out:
    free_all(gs, n);
    return ret;
}

static int cmd_receive(const struct opts *o, const char *file)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), ret = 1, done = 0;
    fence(gs, n, file, o->out, NULL);
    for (int i = 0; i < n && !done; i++) {
        struct grp *g = &gs[i];
        char *d = dir_of(file);
        int pr = prepare(g, o, d);
        free(d);
        if (pr < 0)
            break;
        struct msg_result r;
        char err[512];
        int c = msg_receive(g, file, o->out, o->force, o->lookahead, &r, err, sizeof err);
        if (c == 0 && err[0]) {
            say("%s", err);
            done = 1;
        } else if (c < 0) {
            say("%s", err);
            done = 1;
        } else if (c == 1) {
            char who[48], lv[48];
            grp_member_name(g, r.from, who, sizeof who);
            if (r.is_signed)
                out("From %s, signed (accepted %s%s): %s", who, level_text(r.sig_level, lv, sizeof lv),
                    r.sig_exact ? "" : ", NOT EXACT: raise it with the group", r.name);
            else
                out("From %s (deniable: it proves nothing to anyone else): %s", who, r.name);
            if (r.sig_reused)
                out("WARNING: %s used this signature's slot twice: the signer misbehaved.", who);
            if (r.pending_warning)
                out("WARNING: received while a compromise report about its key set was pending.");
            ret = 0, done = 1;
        }
    }
    if (!done)
        say("%s isn't a message for you from any group on this cylinder (or it's too far ahead: try --lookahead)",
            file);
    free_all(gs, n);
    return ret;
}

static int parse_reason(const char *s)
{
    if (!s || strcmp(s, "compromised") == 0)
        return GRP_R_COMPROMISED;
    if (strcmp(s, "ended") == 0)
        return GRP_R_ENDED;
    return -1;
}

static int cmd_kill(const struct opts *o, const char *scope);
/* --kill with --kill-card: the card's emergency keys, opened in memory, used, and written back */
static int cmd_kill_card(const struct opts *o, const char *scope)
{
    char err[512], *tmp = NULL;
    char *gdir = pnp_card_unpack(o->card, &tmp, err, sizeof err);
    if (!gdir) {
        say("%s", err);
        return 1;
    }
    struct opts oo = *o;
    oo.groups = gdir, oo.card = NULL, oo.group = NULL, oo.card_used = o->card;
    oo.clock_ok = 1; /* the card has no clock guard of its own */
    int ret = cmd_kill(&oo, scope);
    if (pnp_card_repack(o->card, gdir, tmp, err, sizeof err) < 0) {
        say("the notice is made, but the kill card couldn't be written back: %s. Don't use this card again", err);
        ret = 1;
    }
    free(gdir);
    return ret;
}

static int cmd_kill(const struct opts *o, const char *scope)
{
    if (o->card)
        return cmd_kill_card(o, scope);
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), i = pick_group(o, gs, n), ret = 1;
    fence(gs, n, o->out, o->card_used, NULL);
    if (i < 0)
        goto out;
    struct grp *g = &gs[i];
    if (prepare(g, o, ".") < 0)
        goto out;
    int reason = parse_reason(o->reason);
    if (reason < 0) {
        say("--reason is compromised or ended");
        goto out;
    }
    int sc, member = 0, nsets = 0;
    uint8_t sets[KILL_MAX_SETS][GRP_ID_LEN];
    if (strcmp(scope, "group") == 0) {
        sc = KS_GROUP;
    } else if (strncmp(scope, "member:", 7) == 0) {
        sc = KS_MEMBER;
        member = grp_find_member(g, scope + 7);
        if (member < 0) {
            say("no such member");
            goto out;
        }
    } else if (strncmp(scope, "sets:", 5) == 0) {
        sc = KS_SETS;
        char *copy = strdup(scope + 5), *save = NULL;
        for (char *t = copy ? strtok_r(copy, ",", &save) : NULL; t; t = strtok_r(NULL, ",", &save)) {
            int found = 0;
            for (int si = 0; si < g->nsets && nsets < KILL_MAX_SETS; si++) {
                char hex[2 * GRP_ID_LEN + 1];
                grp_hex(g->sets[si].id, hex);
                if (strlen(t) >= 4 && strncasecmp(hex, t, strlen(t)) == 0) {
                    memcpy(sets[nsets++], g->sets[si].id, GRP_ID_LEN);
                    found = 1;
                }
            }
            if (!found) {
                say("no key set starting %s (see pnp --info)", t);
                free(copy);
                goto out;
            }
        }
        free(copy);
    } else {
        say("--kill takes group, member:M or sets:ID,ID...");
        goto out;
    }
    int32_t sday = 0;
    int smember = 0;
    uint32_t sslot = 0;
    if (o->since) {
        unsigned sl;
        char who[64];
        if (grp_parse_day(o->since, &sday) == 0) {
        } else if (sscanf(o->since, "%63[^:]:%u", who, &sl) == 2 && grp_find_member(g, who) >= 0) {
            smember = grp_find_member(g, who), sslot = sl;
            sday = 1;
        } else {
            say("--since takes a date (YYYY-MM-DD) or MEMBER:SLOT");
            goto out;
        }
    }
    char *dest = NULL;
    if (o->out)
        dest = strdup(o->out);
    else if (asprintf(&dest, "kill-%u.pnp-kill", (unsigned)getpid()) < 0)
        dest = NULL;
    char err[512];
    if (!dest || kill_make(g, sc, member, (const uint8_t(*)[GRP_ID_LEN])sets, nsets, reason, sday, smember, sslot, dest, err, sizeof err) < 0) {
        say("%s", dest ? err : "out of memory");
    } else {
        int need = g->n == 2 ? 1 : g->threshold;
        note("kill notice written to %s%s", dest,
             need > 1 ? ": it takes effect when enough other members add their signature (pnp --kill-sign FILE)"
                      : ": send it to the other person");
        ret = 0;
    }
    free(dest);
out:
    free_all(gs, n);
    return ret;
}

static int cmd_kill_sign(const struct opts *o, const char *file)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), ret = 1, done = 0;
    fence(gs, n, file, NULL, NULL);
    uint8_t *b = NULL;
    size_t len;
    struct kill_notice k;
    if (read_whole(file, &b, &len, 64u << 20) < 0 || kill_parse(b, len, &k) < 0) {
        say("%s isn't a kill notice", file);
        goto out;
    }
    for (int i = 0; i < n && !done; i++) {
        struct grp *g = &gs[i];
        if (memcmp(g->id, k.group, GRP_ID_LEN) != 0)
            continue;
        done = 1;
        if (prepare(g, o, NULL) < 0)
            break;
        char err[512];
        if (kill_cosign(g, file, err, sizeof err) < 0) {
            say("%s", err);
        } else {
            note("signed: send %s to everyone in the group", file);
            ret = 0;
        }
    }
    kill_free(&k);
    if (!done)
        say("this notice is for a group that isn't on this cylinder");
out:
    free(b);
    free_all(gs, n);
    return ret;
}

static int cmd_leave(const struct opts *o)
{
    struct grp gs[MAX_GROUPS];
    int n = load_all(o, gs, MAX_GROUPS), i = pick_group(o, gs, n), ret = 1;
    fence(gs, n, o->out, NULL, NULL);
    if (i < 0)
        goto out;
    struct grp *g = &gs[i];
    if (prepare(g, o, ".") < 0)
        goto out;
    if (grp_bit(g->left, g->me)) {
        say("you have already left this group");
        goto out;
    }
    char *dest = NULL;
    if (o->out)
        dest = strdup(o->out);
    else if (asprintf(&dest, "leave-%u.pnp-kill", (unsigned)getpid()) < 0)
        dest = NULL;
    char err[512];
    int scope = g->n == 2 ? KS_GROUP : KS_LEAVE, reason = parse_reason(o->reason ? o->reason : "ended");
    if (!dest || kill_make(g, scope, g->me, NULL, 0, reason < 0 ? GRP_R_ENDED : reason, 0, 0, 0, dest, err,
                           sizeof err) < 0) {
        say("%s", dest ? err : "out of memory");
        free(dest);
        goto out;
    }
    /* my side, at once: my signing keys and every pool go; verify keys stay unless asked (proof of what I got) */
    for (int si = 0; si < g->nsets; si++) {
        struct grp_set *s = &g->sets[si];
        if (g->n >= 3 && s->slots)
            uss_wipe_unused(g, s);
        if (o->wipe_verify)
            for (int j = 0; j < g->n; j++) {
                char name[32];
                snprintf(name, sizeof name, "verify.%d", j + 1);
                char *p = grp_set_path(g, s, name);
                if (p)
                    unlink(p);
                free(p);
            }
    }
    note("%s written to %s: send it to %s. Your keys for this group are wiped%s. Anything already received "
         "stays with the others: leaving can't take it back",
         g->n == 2 ? "the end of this pair is" : "your leave notice is", dest,
         g->n == 2 ? "the other person" : "everyone in the group",
         o->wipe_verify || g->n == 2 ? "" : " (your verify keys are kept, so you can still check what you received)");
    free(dest);
    ret = 0;
out:
    free_all(gs, n);
    return ret;
}

/* ---- --info ---- */
static void info_group(struct grp *g)
{
    char hex[2 * GRP_ID_LEN + 1], who[48], a[16], b[16];
    grp_hex(g->id, hex);
    int32_t today = grp_today(g->tz_min);
    int pending = kill_process(g, NULL, NULL);
    out("%s \"%s\" (%s) · %d members · you: %s (%d) · generation %u", g->n == 2 ? "Pair" : "Group",
        g->anon ? "anonymous" : g->name, hex, g->n, grp_member_name(g, g->me, who, sizeof who), g->me + 1, g->gen);
    if (pending)
        out("!! %d compromise report%s waiting for confirmation (see the warnings above)", pending,
            pending == 1 ? "" : "s");
    if (g->n >= 3)
        out("Signatures: up to %d cheater%s tolerated, %d guaranteed hand-on%s · kill threshold %d · tolerance "
            "left %d", g->omega, g->omega == 1 ? "" : "s", g->lmax, g->lmax == 1 ? "" : "s", g->threshold,
            kill_tolerance_left(g));
    for (int i = 0; i < g->n; i++)
        if (grp_bit(g->left, i) || grp_bit(g->expelled, i))
            out("!! %s %s the group", grp_member_name(g, i, who, sizeof who),
                grp_bit(g->left, i) ? "left" : "was removed from");
    for (int si = 0; si < g->nsets; si++) {
        struct grp_set *s = &g->sets[si];
        grp_hex(s->id, hex);
        grp_day_str(s->start_day, a), grp_day_str(s->end_day, b);
        static const char *const st[] = {"active", "replaced", "KILLED", "closed"};
        char win[96];
        if (s->end_day == GRP_INDEFINITE_END)
            snprintf(win, sizeof win, "no time limit");
        else
            snprintf(win, sizeof win, "valid %s → %s (+%d days delivery)%s", a, b, g->grace,
                     today < s->start_day ? ", not valid yet" : today > s->end_day ? "" : "");
        char *sd = grp_set_path(g, s, NULL);
        struct stat sst;
        int here = sd && stat(sd, &sst) == 0;
        free(sd);
        out("%s %.8s  %s · %s%s%s", s->kind == GRP_SET_EMERGENCY ? "Emergency" : "Key set", hex, win,
            st[s->state], s->state == GRP_KILLED ? (s->reason == GRP_R_ENDED ? " (ended)" : " (compromised)") : "",
            here ? "" : " · not on this cylinder (vault?)");
        if (s->state != GRP_ACTIVE || !here)
            continue;
        if (today >= s->start_day && today <= s->end_day && s->end_day != GRP_INDEFINITE_END)
            out("  %d day%s left", s->end_day - today + 1, s->end_day - today + 1 == 1 ? "" : "s");
        if (g->n >= 3 && s->slots) {
            char *p = grp_set_path(g, s, "sign");
            int fd = p ? grp_open_read(p) : -1;
            uint8_t h[USS_SIGN_HDR];
            if (fd >= 0 && pread(fd, h, sizeof h, 0) == (ssize_t)sizeof h) {
                uint32_t next = (uint32_t)h[36] | (uint32_t)h[37] << 8 | (uint32_t)h[38] << 16 | (uint32_t)h[39] << 24;
                out("  Signing: %u of %u used (one was the meeting's test) · your signatures: checkable by all %d "
                    "others", next, s->slots, g->n - 1);
            }
            if (fd >= 0)
                close(fd);
            free(p);
        }
        for (int o = 0; o < g->n && s->nloc; o++) {
            if (o == g->me)
                continue;
            struct pool p;
            char err[256];
            if (pool_open(g, s, g->me, o, &p, err, sizeof err) < 0)
                continue;
            struct recv_state r;
            uint32_t got = 0;
            if (recv_load(g, s, o, &r, s->nloc) == 0) {
                for (uint32_t x = 0; x < r.nloc; x++)
                    got += (uint32_t)grp_bit(r.seen, (int)x);
                recv_free(&r);
            }
            out("  → %s: %u of %u items, %llu of %llu bytes used · ← %s: %u received · readable by you and %s only",
                grp_member_name(g, o, who, sizeof who), p.next_loc, p.nloc, (unsigned long long)p.next_off,
                (unsigned long long)p.bytes, who, got, who);
            pool_close(&p);
        }
    }
}

static int cmd_info(const struct opts *o, const char *path)
{
    struct grp gs[MAX_GROUPS];
    struct opts oo = *o;
    if (path) {
        /* a courier, self stick or kill card? */
        struct cstore c;
        char err[512];
        if (cs_open(&c, path, err, sizeof err) == 0) {
            static const char *const role[] = {"courier", "self stick", "kill card"};
            char hex[2 * GRP_ID_LEN + 1];
            grp_hex(c.group, hex);
            out("pnp %s of member %d · meeting %.8s, generation %u · visiting member %d, round %d · %llu bytes used",
                role[c.role], c.owner + 1, hex, c.gen, c.visiting + 1, c.round, (unsigned long long)c.end);
            uint64_t pos = 0;
            struct crec r;
            static const char *const type[] = {"?", "roster", "pool contribution", "signing functions",
                                               "signer block", "split", "test signature", "test seal",
                                               "emergency key file"};
            while (cs_record(&c, &pos, &r) == 0)
                out("  %s: from %d to %d (signer %d), key set %d, %llu bytes", r.type <= 8 ? type[r.type] : "?",
                    r.from + 1, r.to + 1, r.signer + 1, r.set + 1, (unsigned long long)r.len);
            cs_close(&c);
            return 0;
        }
        /* a ciphertext, key or share (format.h): its header only, never the key bytes */
        int fd = grp_open_read(path);
        struct stat st;
        uint8_t h[PNP_HDR_MAX];
        ssize_t got = -1;
        if (fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
            got = pread(fd, h, sizeof h, 0);
        if (fd >= 0)
            close(fd);
        struct pnp_hdr ph;
        if (got > 0 && pnp_hdr_parse(h, (size_t)got, (uint64_t)st.st_size, &ph) == PNP_HDR_OK) {
            char hex[2 * ID_LEN + 1];
            for (int i = 0; i < ID_LEN; i++)
                snprintf(hex + 2 * i, 3, "%02x", ph.id[i]);
            static const char *const kind[] = {"?", "ciphertext", "key", "key share"};
            out("pnp %s (format %03d) · ID %s · for %llu bytes of plaintext", kind[ph.kind], ph.version, hex,
                (unsigned long long)ph.body);
            if (ph.kind == PNP_H_SHARE)
                out("  share %d of %d: all %d are needed to decrypt", ph.num, ph.count, ph.count);
            if (ph.kind != PNP_H_CT)
                out("  %s", ph.prot ? "locked with a passphrase (--protect; computationally secure only)"
                                    : "not locked with a passphrase");
            if (ph.prot)
                out("  passphrase hashing: Argon2id %u MiB, %u lane%s, %u pass%s; Balloon %u KiB",
                    ph.pp.argon_kib / 1024, ph.pp.argon_lanes, ph.pp.argon_lanes == 1 ? "" : "s", ph.pp.argon_passes,
                    ph.pp.argon_passes == 1 ? "" : "es", ph.pp.balloon_blocks / 16);
            if (ph.version == 1)
                out("  format 001: no integrity check (still decrypts, never written any more)");
            return 0;
        }
        oo.groups = path;
    }
    int n = load_all(&oo, gs, MAX_GROUPS);
    if (!n) {
        say("no pnp group found%s", path ? " there" : ": plug in your code cylinder, or give a folder");
        return 1;
    }
    int ret = 0;
    for (int i = 0; i < n; i++) {
        if (o->group && !matches(&gs[i], o->group))
            continue;
        if (prepare(&gs[i], o, ".") == 0)
            info_group(&gs[i]);
        else
            ret = 1;
    }
    free_all(gs, n);
    return ret;
}


int pnp_group_cli(int argc, char **argv)
{
    enum {
        O_GROUPS = 300, O_GROUP, O_TO, O_SIGN, O_CLOCK, O_DESPITE, O_LOOK, O_LEVEL, O_REASON, O_SINCE, O_WIPEV,
        O_SELF, O_COURIER, O_STICKS, O_CARD, O_CCHECK, O_FROM,
    };
    static const struct option lo[] = {
        {"seal", no_argument, NULL, 'S'},         {"check-seal", no_argument, NULL, 'C'},
        {"sign", no_argument, NULL, O_SIGN},      {"verify-sig", no_argument, NULL, 'V'},
        {"send", no_argument, NULL, 's'},         {"receive", no_argument, NULL, 'r'},
        {"kill", no_argument, NULL, 'K'},         {"kill-sign", no_argument, NULL, 'k'},
        {"leave", no_argument, NULL, 'L'},        {"info", no_argument, NULL, 'I'},
        {"meet", no_argument, NULL, 'M'},         {"import", no_argument, NULL, 'i'},
        {"move", no_argument, NULL, 'm'},         {"test-setup", no_argument, NULL, 'T'},
        {"groups", required_argument, NULL, O_GROUPS}, {"group", required_argument, NULL, O_GROUP},
        {"to", required_argument, NULL, O_TO},    {"output", required_argument, NULL, 'o'},
        {"force", no_argument, NULL, 'f'},        {"quiet", no_argument, NULL, 'q'},
        {"clock-ok", no_argument, NULL, O_CLOCK}, {"despite-warning", no_argument, NULL, O_DESPITE},
        {"lookahead", required_argument, NULL, O_LOOK}, {"level", required_argument, NULL, O_LEVEL},
        {"reason", required_argument, NULL, O_REASON}, {"since", required_argument, NULL, O_SINCE},
        {"wipe-verify", no_argument, NULL, O_WIPEV},     {"self", required_argument, NULL, O_SELF},
        {"courier", required_argument, NULL, O_COURIER}, {"sticks", required_argument, NULL, O_STICKS},
        {"kill-card", required_argument, NULL, O_CARD},  {"courier-check", no_argument, NULL, O_CCHECK},
        {"from", required_argument, NULL, O_FROM},
        {NULL, 0, NULL, 0},
    };
    struct opts o = {0};
    o.lookahead = DEFAULT_LOOKAHEAD;
    /* the command is argv[1]; after it, --sign is the "sign this message too" flag of --send */
    int cmd = 0, c, first = 1;
    while ((c = getopt_long(argc, argv, "o:fq", lo, NULL)) != -1) {
        if (first) {
            first = 0;
            cmd = c;
            continue;
        }
        switch (c) {
        case O_GROUPS: o.groups = optarg; break;
        case O_GROUP: o.group = optarg; break;
        case O_TO: o.to = optarg; break;
        case O_SIGN: o.sign = 1; break;
        case 'o': o.out = optarg; break;
        case 'f': o.force = 1; break;
        case 'q': quiet = 1; break;
        case O_CLOCK: o.clock_ok = 1; break;
        case O_DESPITE: o.despite = 1; break;
        case O_LOOK: o.lookahead = atoi(optarg) > 0 ? atoi(optarg) : DEFAULT_LOOKAHEAD; break;
        case O_LEVEL: o.level = optarg; break;
        case O_REASON: o.reason = optarg; break;
        case O_SINCE: o.since = optarg; break;
        case O_WIPEV: o.wipe_verify = 1; break;
        case O_SELF: o.self = optarg; break;
        case O_COURIER: o.courier = optarg; break;
        case O_STICKS: o.sticks = optarg; break;
        case O_CARD: o.card = optarg; break;
        case O_FROM: o.from = optarg; break;
        default: return 2;
        }
    }
    int nargs = argc - optind;
    char **args = argv + optind;
    switch (cmd) {
    case 'S': return nargs == 1 ? cmd_seal(&o, args[0]) : (say("usage: pnp --seal FILE --to MEMBER"), 2);
    case 'C':
        return nargs == 1 || nargs == 2 ? cmd_check_seal(&o, args[0], nargs == 2 ? args[1] : NULL)
                                        : (say("usage: pnp --check-seal FILE [SEAL]"), 2);
    case O_SIGN: return nargs == 1 ? cmd_sign(&o, args[0]) : (say("usage: pnp --sign FILE"), 2);
    case 'V':
        return nargs == 1 || nargs == 2 ? cmd_verify_sig(&o, args[0], nargs == 2 ? args[1] : NULL)
                                        : (say("usage: pnp --verify-sig FILE [SIG]"), 2);
    case 's': return nargs == 1 ? cmd_send(&o, args[0]) : (say("usage: pnp --send FILE --to MEMBER"), 2);
    case 'r': return nargs == 1 ? cmd_receive(&o, args[0]) : (say("usage: pnp --receive FILE.pnp"), 2);
    case 'K':
        return nargs == 1 ? cmd_kill(&o, args[0])
                          : (say("usage: pnp --kill group|member:M|sets:ID,... [--reason compromised|ended] "
                                 "[--since DATE|MEMBER:SLOT]"), 2);
    case 'k': return nargs == 1 ? cmd_kill_sign(&o, args[0]) : (say("usage: pnp --kill-sign FILE.pnp-kill"), 2);
    case 'L': return nargs == 0 ? cmd_leave(&o) : (say("usage: pnp --leave [--group G] [--wipe-verify]"), 2);
    case 'I': return nargs <= 1 ? cmd_info(&o, nargs ? args[0] : NULL) : (say("usage: pnp --info [PATH]"), 2);
    case 'M':
        return nargs == 0 ? pnp_meet(o.self, o.courier, o.sticks, o.from)
                          : (say("usage: pnp --meet --self DEVICE --courier DEVICE"), 2);
    case 'i':
        return nargs == 2 ? pnp_import_card(args[0], args[1], o.card)
                          : (say("usage: pnp --import SELF-STICK CYLINDER-FOLDER [--kill-card DEVICE]"), 2);
    case 'm':
        return nargs == 1 && o.to ? pnp_move(o.groups, args[0], o.to)
                                  : (say("usage: pnp --move KEYSET --to CYLINDER-FOLDER [--groups FROM]"), 2);
    case O_CCHECK: return nargs == 1 ? pnp_courier_check(args[0]) : (say("usage: pnp --courier-check DEVICE"), 2);
#ifdef PNP_TEST
    case 'T': return nargs == 2 ? pnp_test_setup(args[0], args[1]) : 2;
#endif
    default: say("unknown command"); return 2;
    }
}
