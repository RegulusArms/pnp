/* Meetings from the command line (docs/group.md "The meeting wizard"): pnp --meet walks one member through a
 * meeting on their own laptop, pnp --import makes the group folder at home, and in the test build pnp --test-setup
 * runs a whole meeting in one process (every member's laptop, self stick and courier as files), through exactly
 * the same protocol steps (meeting.c). */
#define _GNU_SOURCE
#include "courier.h"
#include "group.h"
#include "meeting.h"
#include "pnp.h"
#include "rng.h"
#include "uss.h"
#include "blake2b.h"
#include "fileio.h"
#include "kill.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void msg(const char *fmt, ...)
{
    char m[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m, sizeof m, fmt, ap);
    va_end(ap);
    pnp_clean(m);
    fprintf(stderr, "pnp: %s\n", m);
}

/* a roster from settings (the wizard asks for them; the test setup reads them from the environment) */
struct roster_opts {
    int n, omega, lmax, threshold, grace, anon, signed_default, tz, periods, period_days, indefinite;
    uint32_t slots, nloc, dispute, emergency;
    uint64_t bytes;
    int32_t start;
    const char *name;
    const char *names[GRP_MAX_MEMBERS];
};

static int build_roster(const struct roster_opts *ro, struct grp *g, char *err, size_t errlen)
{
    memset(g, 0, sizeof *g);
    g->n = ro->n;
    g->gen = 1;
    if (ro->n >= 3) {
        g->omega = ro->omega, g->lmax = ro->lmax;
        if (!uss_valid(ro->n - 1, g->omega, g->lmax)) {
            snprintf(err, errlen, "%d cheaters with %d hand-ons isn't possible with %d members", g->omega, g->lmax,
                     ro->n);
            return -1;
        }
    }
    g->threshold = ro->n == 2 ? 1 : ro->threshold;
    if (ro->n >= 3 && (g->threshold < 2 || g->threshold > ro->n - g->omega)) {
        snprintf(err, errlen, "the kill threshold must be from 2 to %d (the honest members)", ro->n - g->omega);
        return -1;
    }
    g->grace = ro->grace, g->anon = ro->anon, g->signed_default = ro->signed_default, g->tz_min = ro->tz;
    g->dispute_days = ro->dispute;
    g->created_day = g->guard_day = grp_today(ro->tz);
    snprintf(g->name, sizeof g->name, "%s", ro->anon ? "" : ro->name ? ro->name : "");
    for (int i = 0; i < ro->n; i++)
        snprintf(g->member[i], GRP_MEMBER_LEN, "%s", ro->anon || !ro->names[i] ? "" : ro->names[i]);
    uint32_t k = ro->n >= 3 ? uss_k(ro->n - 1, g->omega, g->lmax) : 0;
    g->nsets = ro->periods + 1;
    g->sets = calloc((size_t)g->nsets, sizeof *g->sets);
    if (!g->sets)
        return -1;
    for (int i = 0; i < ro->periods; i++) {
        struct grp_set *s = &g->sets[i];
        s->kind = GRP_SET_NORMAL;
        if (ro->indefinite) {
            s->start_day = GRP_INDEFINITE_START, s->end_day = GRP_INDEFINITE_END;
        } else {
            s->start_day = ro->start + i * ro->period_days;
            s->end_day = s->start_day + ro->period_days - 1;
        }
        s->slots = ro->n >= 3 ? ro->slots + 1 : 0; /* + the meeting's test signature */
        s->k = k;
        s->nloc = ro->nloc + 1;                      /* + the meeting's test seal */
        s->pool_bytes = ro->bytes + GRP_KEY_LEN;
    }
    struct grp_set *e = &g->sets[ro->periods]; /* the emergency set: no window */
    e->kind = GRP_SET_EMERGENCY;
    e->start_day = GRP_INDEFINITE_START, e->end_day = GRP_INDEFINITE_END;
    if (ro->n >= 3) {
        e->slots = ro->emergency + 1, e->k = k;
    } else {
        e->nloc = ro->emergency + 1, e->pool_bytes = (uint64_t)(ro->emergency + 1) * GRP_KEY_LEN;
    }
    return 0;
}

#ifdef PNP_TEST
/* the test setup's settings: PNP_TEST_SETUP_OPTS="slots=3,nloc=8,bytes=65536,start=2030-05-01,days=31,..." */
static void test_opts(struct roster_opts *ro)
{
    static const char *const names[] = {"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan"};
    ro->slots = 10, ro->nloc = 8, ro->bytes = 1 << 16, ro->periods = 1, ro->period_days = 31, ro->grace = 3;
    ro->threshold = 2, ro->emergency = 8, ro->name = "test group";
    ro->start = grp_today(0);
    for (int i = 0; i < GRP_MAX_MEMBERS; i++)
        ro->names[i] = i < 9 ? names[i] : NULL;
    const char *env = getenv("PNP_TEST_SETUP_OPTS");
    char *copy = env ? strdup(env) : NULL, *save = NULL;
    for (char *t = copy ? strtok_r(copy, ",", &save) : NULL; t; t = strtok_r(NULL, ",", &save)) {
        char *v = strchr(t, '=');
        if (!v)
            continue;
        *v++ = 0;
        long x = strtol(v, NULL, 10);
        if (!strcmp(t, "slots")) ro->slots = (uint32_t)x;
        else if (!strcmp(t, "nloc")) ro->nloc = (uint32_t)x;
        else if (!strcmp(t, "bytes")) ro->bytes = (uint64_t)x;
        else if (!strcmp(t, "periods")) ro->periods = (int)x;
        else if (!strcmp(t, "days")) ro->period_days = (int)x;
        else if (!strcmp(t, "grace")) ro->grace = (int)x;
        else if (!strcmp(t, "threshold")) ro->threshold = (int)x;
        else if (!strcmp(t, "anon")) ro->anon = (int)x;
        else if (!strcmp(t, "signed")) ro->signed_default = (int)x;
        else if (!strcmp(t, "dispute")) ro->dispute = (uint32_t)x;
        else if (!strcmp(t, "indefinite")) ro->indefinite = (int)x;
        else if (!strcmp(t, "emergency")) ro->emergency = (uint32_t)x;
        else if (!strcmp(t, "omega")) ro->omega = (int)x;
        else if (!strcmp(t, "lmax")) ro->lmax = (int)x;
        else if (!strcmp(t, "start")) grp_parse_day(v, &ro->start);
    }
    free(copy);
}

/* pnp-test --test-setup pair|group:N DIR: a whole meeting in one process; member m's cylinder is DIR/mM */
int pnp_test_setup(const char *spec, const char *dir)
{
    struct roster_opts ro;
    memset(&ro, 0, sizeof ro);
    test_opts(&ro);
    int omega = ro.omega, lmax = ro.lmax;
    if (strcmp(spec, "pair") == 0)
        ro.n = 2;
    else if (sscanf(spec, "group:%d", &ro.n) != 1 || ro.n < 3 || ro.n > GRP_MAX_MEMBERS)
        return 2;
    if (ro.n >= 3) {
        int dw, dl;
        uss_defaults(ro.n, &dw, &dl);
        ro.omega = omega ? omega : dw, ro.lmax = omega ? lmax : dl;
    }
    struct grp g;
    char err[512];
    struct pnp_rng rng;
    pnp_rng_open(&rng);
    if (!rng.hardware_ok) {
        msg("no hardware source");
        return 1;
    }
    if (build_roster(&ro, &g, err, sizeof err) < 0 || meet_new_ids(&g, &rng, err, sizeof err) < 0) {
        msg("%s", err);
        return 1;
    }
    mkdir(dir, 0700);
    int n = g.n, ret = 1;
    struct cstore *self = calloc((size_t)n, sizeof *self), *cour = calloc((size_t)n, sizeof *cour);
    struct grp *ros = calloc((size_t)n, sizeof *ros);
    if (!self || !cour || !ros)
        goto out;
    for (int m = 0; m < n; m++) {
        char p[4096];
        ros[m] = g;
        ros[m].me = m;
        snprintf(p, sizeof p, "%s/self.%d", dir, m + 1);
        if (cs_create(&self[m], p, CS_SELF, m, g.id, g.gen, (uint64_t)16 << 30, err, sizeof err) < 0)
            goto fail;
        snprintf(p, sizeof p, "%s/courier.%d", dir, m + 1);
        if (cs_create(&cour[m], p, CS_COURIER, m, g.id, g.gen, (uint64_t)16 << 30, err, sizeof err) < 0)
            goto fail;
        if (meet_self_generate(&ros[m], &self[m], &rng, err, sizeof err) < 0)
            goto fail;
    }
    for (int round = 1; round <= 2; round++) {
        for (int o = 0; o < n; o++)
            for (int m = 0; m < n; m++) {
                if (m == o)
                    continue;
                if (cs_address(&cour[o], m, round, err, sizeof err) < 0 ||
                    (round == 1 ? meet_round1(&ros[m], &self[m], &cour[o], err, sizeof err)
                                : meet_round2(&ros[m], &self[m], &cour[o], err, sizeof err)) < 0 ||
                    meet_collect(&cour[o], &self[o], err, sizeof err) < 0)
                    goto fail;
            }
        if (round == 1)
            for (int m = 0; m < n; m++)
                if (meet_make_splits(&ros[m], &self[m], &rng, err, sizeof err) < 0)
                    goto fail;
    }
    for (int m = 0; m < n; m++) {
        char root[4096], *gd = NULL;
        snprintf(root, sizeof root, "%s/m%d", dir, m + 1);
        mkdir(root, 0700);
        if (meet_import(&self[m], root, &gd, err, sizeof err) < 0)
            goto fail;
        free(gd);
    }
    ret = 0;
    goto out;
fail:
    msg("%s", err);
out:
    for (int m = 0; self && cour && m < n; m++)
        cs_close(&self[m]), cs_close(&cour[m]);
    free(self), free(cour), free(ros);
    free(g.sets);
    pnp_rng_close(&rng);
    return ret;
}
#endif


/* ---- the meeting wizard: pnp --meet ----
 * Each member runs it on their own laptop with their courier and self stick. Every handoff is checked: the wizard
 * waits until the stick in front of it is the right one, addressed to this member, before touching it. On a terminal
 * it asks you to plug a stick in and press Enter; with no terminal (scripts, the tests) it waits for the stick. */
struct wiz {
    const char *self, *courier, *sticks; /* own self stick and courier; where to look for others' couriers */
    int tty;
    struct grp g;
};

static int ask(const char *prompt, char *buf, size_t len)
{
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (!fgets(buf, (int)len, stdin))
        return -1;
    buf[strcspn(buf, "\r\n")] = 0;
    return 0;
}

static long ask_num(const char *prompt, long lo, long hi, long dflt)
{
    char b[128];
    for (;;) {
        if (ask(prompt, b, sizeof b) < 0)
            return -1;
        if (!b[0] && dflt >= lo)
            return dflt;
        char *end;
        long v = strtol(b, &end, 10);
        if (b[0] && !*end && v >= lo && v <= hi)
            return v;
        fprintf(stderr, "  a number from %ld to %ld, please\n", lo, hi);
    }
}

static int ask_choice(const char *prompt, const char *choices)
{
    char b[64];
    for (;;) {
        if (ask(prompt, b, sizeof b) < 0)
            return -1;
        if (b[0] && !b[1] && strchr(choices, b[0]))
            return b[0];
        fprintf(stderr, "  one of: %s\n", choices);
    }
}

/* the code everyone reads aloud: the roster as agreed (BLAKE2b; it only catches typos and mix-ups) */
static void check_code(const struct grp *g, char out[16])
{
    size_t len = grp_file_len(g->n, g->nsets);
    uint8_t *b = malloc(len), h[4];
    if (!b) {
        snprintf(out, 16, "?");
        return;
    }
    grp_serialise(g, b);
    b[29] = 0; /* "me" differs per laptop */
    pnp_blake2b(h, sizeof h, b, len);
    free(b);
    snprintf(out, 16, "%02x%02x-%02x%02x", h[0], h[1], h[2], h[3]);
}

static double storage_gib(const struct grp *g)
{
    double total = 0;
    int N = g->n - 1;
    for (int i = 0; i < g->nsets; i++) {
        const struct grp_set *s = &g->sets[i];
        if (g->n >= 3 && s->slots)
            total += (double)uss_sign_len(N, s->k, s->slots) + (double)N * (double)uss_verify_len(N, s->k, s->slots);
        total += (double)N * 2 * ((double)s->nloc * GRP_LOC_ENTRY + (double)s->pool_bytes);
    }
    return total / (1 << 30);
}

static void show_roster(const struct grp *g)
{
    char who[48], code[16], a[16], b[16];
    fprintf(stderr, "\n%s \"%s\", %d members:\n", g->n == 2 ? "Pair" : "Group", g->anon ? "anonymous" : g->name,
            g->n);
    for (int i = 0; i < g->n; i++)
        fprintf(stderr, "  %d. %s%s\n", i + 1, grp_member_name(g, i, who, sizeof who), i == g->me ? "  (you)" : "");
    for (int i = 0; i < g->nsets; i++) {
        const struct grp_set *s = &g->sets[i];
        if (s->kind != GRP_SET_NORMAL)
            continue;
        grp_day_str(s->start_day, a), grp_day_str(s->end_day, b);
        fprintf(stderr, "  key set %d: %s%s%s\n", i + 1, s->end_day == GRP_INDEFINITE_END ? "no time limit" : a,
                s->end_day == GRP_INDEFINITE_END ? "" : " to ", s->end_day == GRP_INDEFINITE_END ? "" : b);
    }
    if (g->n >= 3)
        fprintf(stderr, "  signatures: %d cheater%s tolerated, %d hand-on%s; kill threshold %d\n", g->omega,
                g->omega == 1 ? "" : "s", g->lmax, g->lmax == 1 ? "" : "s", g->threshold);
    fprintf(stderr, "  storage per person: %.2f GiB\n", storage_gib(g));
    check_code(g, code);
    fprintf(stderr, "\nCheck code: %s   (everyone reads theirs aloud: they must all match)\n\n", code);
}

/* y-m-d plus k months, day clamped to the month */
static int32_t add_months(int32_t day, int k)
{
    char s[16];
    grp_day_str(day, s);
    int y, m, d;
    if (sscanf(s, "%d-%d-%d", &y, &m, &d) != 3)
        return day;
    int mm = m - 1 + k;
    y += mm / 12, m = mm % 12 + 1;
    for (; d >= 28; d--) {
        char t[32];
        int32_t r;
        snprintf(t, sizeof t, "%04d-%02d-%02d", y, m, d);
        if (grp_parse_day(t, &r) == 0)
            return r;
    }
    char t[32];
    int32_t r = day;
    snprintf(t, sizeof t, "%04d-%02d-%02d", y, m, d);
    grp_parse_day(t, &r);
    return r;
}

static int create_roster(struct grp *g, struct pnp_rng *rng, const struct grp *prev)
{
    struct roster_opts ro;
    memset(&ro, 0, sizeof ro);
    char b[256];
    static char names[GRP_MAX_MEMBERS][GRP_MEMBER_LEN], gname[GRP_NAME_LEN];
    int kept = 0;
    if (prev) { /* a re-meeting: the same group, without those who left or were removed */
        fprintf(stderr, "Re-meeting \"%s\" (generation %u). Staying:\n", prev->anon ? "anonymous" : prev->name,
                prev->gen + 1);
        for (int i = 0; i < prev->n; i++)
            if (!grp_bit(prev->left, i) && !grp_bit(prev->expelled, i)) {
                snprintf(names[kept], GRP_MEMBER_LEN, "%s", prev->member[i]);
                fprintf(stderr, "  %d. %s\n", kept + 1, prev->anon ? "(anonymous)" : names[kept]);
                kept++;
            }
        fprintf(stderr, "Those who left or were removed are out. Anyone new is added after them.\n");
        /* the creator's laptop is always member 1: put the creator first */
        long me = kept > 1 ? ask_num("Which number are you on this list? ", 1, kept, 1) : 1;
        if (me < 0)
            return -1;
        if (me > 1) {
            char t[GRP_MEMBER_LEN];
            memcpy(t, names[me - 1], GRP_MEMBER_LEN);
            memmove(names[1], names[0], (size_t)(me - 1) * GRP_MEMBER_LEN);
            memcpy(names[0], t, GRP_MEMBER_LEN);
        }
    }
    long n = ask_num(prev ? "How many people now, including new members? "
                          : "How many people? 2 is a pair; 3-9 a group; more: type the number: ",
                     prev ? (kept > 2 ? kept : 2) : 2, GRP_MAX_MEMBERS, prev ? kept : -1);
    if (n < 0)
        return -1;
    if (n > 9) {
        fprintf(stderr, "  Note: storage grows with the square of the group: with %ld people each person may need "
                        "tens of GiB per 1000 signatures, and each round takes %ld courier handoffs.\n", n, n * (n - 1));
        if (ask_choice("  Go ahead? (y/n) ", "yn") != 'y')
            return -1;
    }
    ro.n = (int)n;
    int c = prev ? (prev->anon ? 'a' : 'n')
                 : ask_choice("Named or anonymous? Anonymous: no real names on any key, members are numbers. (n/a) ", "na");
    if (c < 0)
        return -1;
    ro.anon = c == 'a';
    if (prev && !ro.anon) {
        snprintf(gname, sizeof gname, "%s", prev->name);
        ro.name = gname;
        for (int i = 0; i < kept && i < ro.n; i++)
            ro.names[i] = names[i];
    }
    if (!ro.anon) {
        if (!prev && ask("Group name: ", gname, sizeof gname) < 0)
            return -1;
        ro.name = gname;
        for (int i = prev ? kept : 0; i < ro.n; i++) {
            char p[64];
            snprintf(p, sizeof p, "Member %d%s: ", i + 1, i == 0 ? " (you)" : "");
            if (ask(p, names[i], sizeof names[i]) < 0)
                return -1;
            ro.names[i] = names[i];
        }
    }
    c = ask_choice("Key set periods: (w)eek, (m)onth, (q)uarter, (y)ear, or (i)ndefinite? ", "wmqyi");
    if (c < 0)
        return -1;
    ro.indefinite = c == 'i';
    ro.periods = ro.indefinite ? 1 : (int)ask_num("How many periods? ", 1, 520, -1);
    int32_t start = grp_today(0);
    if (!ro.indefinite) {
        for (;;) {
            if (ask("Starting on (YYYY-MM-DD, Enter for today): ", b, sizeof b) < 0)
                return -1;
            if (!b[0] || grp_parse_day(b, &start) == 0)
                break;
            fprintf(stderr, "  a date like 2030-05-01, please\n");
        }
    }
    double scale = c == 'w' ? 0.25 : c == 'q' ? 3 : c == 'y' ? 12 : 1;
    if (ro.n >= 3)
        ro.slots = (uint32_t)ask_num("Signatures each person expects to make per period: ", 1, 1000000,
                                     (long)(200 * scale));
    ro.nloc = (uint32_t)ask_num("Messages and seals each person sends each other member per period: ", 1, 1 << 22,
                                (long)(1000 * scale));
    ro.bytes = (uint64_t)ask_num("MiB of messages each person sends each other member per period: ", 0, 1 << 20,
                                 (long)(256 * scale)) << 20;
    ro.emergency = 8;
    if (ro.n >= 3) {
        int dw, dl;
        uss_defaults(ro.n, &dw, &dl);
        ro.omega = dw, ro.lmax = dl;
        fprintf(stderr, "Signatures: the default tolerates %d cheater%s with %d guaranteed hand-on%s.\n", dw,
                dw == 1 ? "" : "s", dl, dl == 1 ? "" : "s");
        if (dw > 1 && uss_valid(ro.n - 1, dw - 1, dl + 1)) {
            fprintf(stderr, "  Or: %d cheater%s with %d hand-ons (keys about 4x larger).\n", dw - 1, dw == 2 ? "" : "s",
                    dl + 1);
            if (ask_choice("  Use the default? (y/n) ", "yn") == 'n')
                ro.omega = dw - 1, ro.lmax = dl + 1;
        }
        ro.threshold = (int)ask_num("Kill threshold (members needed to kill keys; Enter for 2): ", 2,
                                    ro.n - ro.omega, 2);
        ro.signed_default = ask_choice("Sign every message by default? (suggested: n, deniable) (y/n) ", "yn") == 'y';
        ro.dispute = (uint32_t)ask_num("Days to keep verify keys after a window closes (Enter: keep them): ", 0,
                                       36500, 0);
    }
    ro.grace = (int)ask_num("Grace days for delivery after a window closes (Enter for 3): ", 0, 30, 3);
    struct tm tm;
    time_t now = time(NULL);
    localtime_r(&now, &tm);
    ro.tz = (int)ask_num("Time zone, minutes east of UTC (Enter for this laptop's): ", -720, 840, tm.tm_gmtoff / 60);
    ro.period_days = 7;
    ro.start = start;
    char err[512];
    if (build_roster(&ro, g, err, sizeof err) < 0) {
        msg("%s", err);
        return -1;
    }
    if (prev) { /* the same group: its ID stays, its generation goes up */
        memcpy(g->id, prev->id, GRP_ID_LEN);
        g->gen = prev->gen + 1;
    }
    for (int i = 0; !ro.indefinite && i < ro.periods; i++) { /* calendar periods */
        struct grp_set *s = &g->sets[i];
        int months = c == 'm' ? 1 : c == 'q' ? 3 : c == 'y' ? 12 : 0;
        if (months) {
            s->start_day = add_months(start, i * months);
            s->end_day = add_months(start, (i + 1) * months) - 1;
        }
    }
    uint8_t keep[GRP_ID_LEN];
    memcpy(keep, g->id, GRP_ID_LEN);
    if (meet_new_ids(g, rng, err, sizeof err) < 0)
        return -1;
    if (prev)
        memcpy(g->id, keep, GRP_ID_LEN); /* fresh key set IDs, the group's own ID kept */
    return 0;
}

/* finds a courier among the sticks plugged in matching what's expected; its path (malloc'd) or NULL */
static char *find_courier(const struct wiz *w, int owner, int visiting, int round, int done, const uint8_t *group)
{
    char *paths[64];
    int n = cs_find_devices(w->sticks, paths, 64);
    char *found = NULL;
    for (int i = 0; i < n; i++) {
        struct cstore c;
        char err[256];
        if (!found && (!w->self || strcmp(paths[i], w->self) != 0) && cs_open(&c, paths[i], err, sizeof err) == 0) {
            int ok = c.role == CS_COURIER && (owner < 0 || c.owner == owner) && c.visiting == visiting &&
                     c.round == round && c.done == done && (!group || memcmp(c.group, group, GRP_ID_LEN) == 0);
            cs_close(&c);
            if (ok) {
                found = paths[i];
                continue;
            }
        }
        free(paths[i]);
    }
    return found;
}

/* waits for the courier described; on a terminal by asking, otherwise by watching the sticks */
static char *wait_courier(const struct wiz *w, const char *what, int owner, int visiting, int round, int done,
                          const uint8_t *group)
{
    for (int tries = 0;; tries++) {
        char *p = find_courier(w, owner, visiting, round, done, group);
        if (p)
            return p;
        if (w->tty) {
            char b[16];
            fprintf(stderr, "%s %s, then press Enter. ", tries ? "That isn't it yet: plug in" : "Plug in", what);
            if (ask("", b, sizeof b) < 0)
                return NULL;
        } else {
            if (tries > 6000) /* ten minutes: the meeting has stalled */
                return NULL;
            struct timespec ts = {0, 100 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
}

static const char *nm(const struct grp *g, int i, char *buf, size_t len) { return grp_member_name(g, i, buf, len); }

static int rounds(struct wiz *w, struct pnp_rng *rng)
{
    struct grp *g = &w->g;
    int n = g->n, me = g->me;
    char err[512], a[48], b[48];
    struct cstore self;
    if (cs_open(&self, w->self, err, sizeof err) < 0)
        goto fail0;
    for (int round = 1; round <= 2; round++) {
        for (int t = 1; t < n; t++) {
            int to = (me + t) % n, from = (me - t + n) % n;
            struct cstore own;
            if (cs_open(&own, w->courier, err, sizeof err) < 0 || cs_address(&own, to, round, err, sizeof err) < 0)
                goto fail;
            cs_close(&own);
            fprintf(stderr, "Round %d, step %d of %d: give your courier to %s. You'll get %s's courier.\n", round, t,
                    n - 1, nm(g, to, a, sizeof a), nm(g, from, b, sizeof b));
            char what[96];
            snprintf(what, sizeof what, "%s's courier", b);
            char *p = wait_courier(w, what, from, me, round, 0, g->id);
            struct cstore in;
            if (!p || cs_open(&in, p, err, sizeof err) < 0) {
                snprintf(err, sizeof err, "the meeting stalled waiting for %s", what);
                free(p);
                goto fail;
            }
            free(p);
            int r = round == 1 ? meet_round1(g, &self, &in, err, sizeof err) : meet_round2(g, &self, &in, err, sizeof err);
            if (r < 0 || cs_done(&in, err, sizeof err) < 0) {
                cs_close(&in);
                goto fail;
            }
            cs_close(&in);
            fprintf(stderr, "  Done: give it back to %s.\n", b);
            snprintf(what, sizeof what, "your own courier (back from %s)", a);
            p = wait_courier(w, what, me, to, round, 1, g->id);
            if (!p || strcmp(p, w->courier) != 0 || cs_open(&own, p, err, sizeof err) < 0) {
                snprintf(err, sizeof err, "the meeting stalled waiting for your courier");
                free(p);
                goto fail;
            }
            free(p);
            if (meet_collect(&own, &self, err, sizeof err) < 0) {
                cs_close(&own);
                goto fail;
            }
            cs_close(&own);
            fprintf(stderr, "  Your courier is back, moved to your self drive and overwritten.\n");
        }
        if (round == 1 && meet_make_splits(g, &self, rng, err, sizeof err) < 0)
            goto fail;
    }
    cs_close(&self);
    return 0;
fail:
    cs_close(&self);
fail0:
    msg("%s", err);
    return -1;
}

/* the check at the meeting: a trial import into memory (the per-user runtime folder), then removed */
static int rm_rf(const char *path)
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
            rm_rf(p);
            free(p);
        }
    }
    closedir(d);
    return rmdir(path);
}

static int trial_import(const struct wiz *w)
{
    const char *run = getenv("XDG_RUNTIME_DIR");
    char *root = NULL, *dir = NULL, err[512];
    if (asprintf(&root, "%s/pnp-check-XXXXXX", run && *run ? run : "/dev/shm") < 0 || !mkdtemp(root)) {
        msg("no place in memory for the check (XDG_RUNTIME_DIR)");
        free(root);
        return -1;
    }
    struct cstore self;
    int r = cs_open(&self, w->self, err, sizeof err) == 0 ? meet_import(&self, root, &dir, err, sizeof err) : -1;
    if (r == 0)
        cs_close(&self);
    rm_rf(root);
    free(root), free(dir);
    char who[48];
    if (r < 0) {
        msg("the check failed: %s", err);
        return -1;
    }
    for (int i = 0; i < w->g.n; i++)
        if (i != w->g.me)
            fprintf(stderr, "  ✓ %s: test %s and test seal check, both ways\n", nm(&w->g, i, who, sizeof who),
                    w->g.n >= 3 ? "signature" : "item");
    return 0;
}

int pnp_meet(const char *self_path, const char *courier_path, const char *sticks, const char *from)
{
    struct wiz w;
    memset(&w, 0, sizeof w);
    w.self = self_path, w.courier = courier_path, w.sticks = sticks;
    w.tty = isatty(STDIN_FILENO);
    if (!self_path || !courier_path) {
        msg("--meet needs your drives: --self DEVICE --courier DEVICE (the two pnp drives you brought; see "
            "pnp-courier-setup)");
        return 2;
    }
    struct pnp_rng rng;
    pnp_rng_open(&rng);
    if (!rng.hardware_ok) {
        msg("no usable hardware random source on this laptop: it can't take part in a meeting");
        pnp_rng_close(&rng);
        return 1;
    }
    fprintf(stderr, "pnp meeting. Only your own laptop touches your self drive; your courier only ever goes to the "
                    "one member it's addressed to, and comes straight back.\n");
    int ret = 1, c = ask_choice("Are you (c)reating the group, or (j)oining it? ", "cj");
    char err[512], who[48];
    struct cstore cs, self;
    if (c == 'c') {
        struct grp prev;
        int have_prev = 0;
        if (from) {
            if (grp_load(from, &prev, err, sizeof err) < 0)
                goto fail;
            have_prev = 1;
        }
        int cr = create_roster(&w.g, &rng, have_prev ? &prev : NULL);
        if (have_prev)
            grp_free(&prev);
        if (cr < 0)
            goto out;
        show_roster(&w.g);
        if (cs_create(&cs, courier_path, CS_COURIER, 0, w.g.id, w.g.gen, 0, err, sizeof err) < 0)
            goto fail;
        cs_close(&cs);
        fprintf(stderr, "Each other member now gives you their courier, one at a time; your laptop writes the "
                        "roster onto it.\n");
        uint8_t zero[GRP_ID_LEN] = {0};
        for (int k = 1; k < w.g.n; k++) {
            char *p = wait_courier(&w, "another member's courier", -1, 0, 0, 0, zero);
            struct cstore jc;
            if (!p || cs_open(&jc, p, err, sizeof err) < 0) {
                free(p);
                snprintf(err, sizeof err, "the meeting stalled waiting for the members' couriers");
                goto fail;
            }
            free(p);
            struct grp r = w.g;
            r.me = jc.owner;
            size_t glen = grp_file_len(r.n, r.nsets);
            uint8_t *gb = malloc(glen);
            struct crec rec = {R_ROSTER, 0, jc.owner, 0, 0, glen, 0};
            struct cwriter cw;
            int ok = gb && jc.owner > 0 && jc.owner < w.g.n;
            if (ok)
                grp_serialise(&r, gb);
            ok = ok && cs_set_group(&jc, w.g.id, w.g.gen, err, sizeof err) == 0 &&
                 cs_begin(&jc, &cw, &rec, err, sizeof err) == 0 && cs_write(&cw, gb, glen) == 0 &&
                 cs_end(&cw, err, sizeof err) == 0 && cs_done(&jc, err, sizeof err) == 0;
            free(gb);
            fprintf(stderr, "  Roster written for %s: give the courier back.\n", nm(&w.g, jc.owner, who, sizeof who));
            cs_close(&jc);
            if (!ok)
                goto fail;
        }
    } else if (c == 'j') {
        long k = ask_num("Your number on the list the creator reads out (2 or more): ", 2, GRP_MAX_MEMBERS, -1);
        if (k < 0)
            goto out;
        uint8_t zero[GRP_ID_LEN] = {0};
        if (cs_create(&cs, courier_path, CS_COURIER, (int)k - 1, zero, 0, 0, err, sizeof err) < 0 ||
            cs_address(&cs, 0, 0, err, sizeof err) < 0)
            goto fail;
        cs_close(&cs);
        fprintf(stderr, "Give your courier to the creator (member 1).\n");
        char *p = wait_courier(&w, "your courier, back from the creator", (int)k - 1, 0, 0, 1, NULL);
        struct crec rec;
        uint8_t *gb = NULL;
        if (!p || cs_open(&cs, p, err, sizeof err) < 0) {
            free(p);
            snprintf(err, sizeof err, "the meeting stalled waiting for the roster");
            goto fail;
        }
        free(p);
        int ok = cs_verify(&cs, err, sizeof err) == 0 && cs_find(&cs, R_ROSTER, -1, -1, -1, -1, &rec) == 0 &&
                 rec.len < (1 << 20) && (gb = malloc((size_t)rec.len)) && cs_read(&cs, &rec, 0, gb, (size_t)rec.len) == 0 &&
                 grp_parse(gb, (size_t)rec.len, &w.g) == 0 && w.g.me == k - 1;
        free(gb);
        if (!ok) {
            cs_close(&cs);
            if (!err[0])
                snprintf(err, sizeof err, "the roster on your courier is damaged, or not for member %ld", k);
            goto fail;
        }
        int ow = cs_overwrite(&cs, err, sizeof err);
        cs_close(&cs);
        if (ow < 0)
            goto fail;
        show_roster(&w.g);
    } else {
        goto out;
    }
    if (ask_choice("Does everyone's check code match? (y/n) ", "yn") != 'y') {
        msg("stop here: someone typed the roster differently. Start again");
        goto out;
    }
    if (cs_create(&self, self_path, CS_SELF, w.g.me, w.g.id, w.g.gen, 0, err, sizeof err) < 0)
        goto fail;
    fprintf(stderr, "Making your keys from this laptop's hardware random sources...\n");
    int gr = meet_self_generate(&w.g, &self, &rng, err, sizeof err);
    cs_close(&self);
    if (gr < 0)
        goto fail;
    if (rounds(&w, &rng) < 0)
        goto out;
    fprintf(stderr, "Checking everything from every member (in memory)...\n");
    if (trial_import(&w) < 0)
        goto out;
    fprintf(stderr, "\nThe meeting is complete for you. Keep your self drive on you. At home, alone, on a machine you "
                    "fully control:\n  pnp --import %s YOUR-CYLINDER-FOLDER [--kill-card DEVICE]\n", self_path);
    ret = 0;
    goto out;
fail:
    msg("%s", err);
out:
    grp_free(&w.g);
    pnp_rng_close(&rng);
    return ret;
}

/* ---- kill cards: the emergency keys, apart from the cylinder ----
 * The card and the cylinder must never hold the same emergency slot (using both would use it twice), so the
 * emergency slots are split at import: the card keeps the first half, the cylinder the rest. */
#define R_FILE 8 /* a file of the card: u16 name length, the name (relative to the group folder), the bytes */

static int card_add(struct cstore *c, const char *gdir, const char *rel, char *err, size_t errlen)
{
    char *path = NULL;
    if (asprintf(&path, "%s/%s", gdir, rel) < 0)
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        free(path);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    size_t nl = strlen(rel);
    struct crec r = {R_FILE, c->owner, c->owner, 0, 0, 2 + nl + (uint64_t)st.st_size, 0};
    struct cwriter w;
    uint8_t h[2] = {(uint8_t)nl, (uint8_t)(nl >> 8)}, buf[65536];
    int ok = cs_begin(c, &w, &r, err, errlen) == 0 && cs_write(&w, h, 2) == 0 && cs_write(&w, rel, nl) == 0;
    ssize_t got;
    while (ok && (got = read(fd, buf, sizeof buf)) > 0)
        ok = cs_write(&w, buf, (size_t)got) == 0;
    explicit_bzero(buf, sizeof buf);
    ok = ok && cs_end(&w, err, errlen) == 0;
    close(fd);
    free(path);
    return ok ? 0 : -1;
}

/* wipes slots [from, to) of a signing file, and sets its next counter */
static int split_sign(const char *path, const struct grp *g, const struct grp_set *s, uint32_t from, uint32_t to,
                      uint32_t next)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    uint64_t slot = (uint64_t)(g->n - 1) * (g->n - 1) * s->k * USS_FN_LEN;
    static const uint8_t zero[65536];
    int ok = 1;
    for (uint64_t off = USS_SIGN_HDR + from * slot, end = USS_SIGN_HDR + to * slot; ok && off < end;) {
        size_t n = end - off < sizeof zero ? (size_t)(end - off) : sizeof zero;
        ok = pwrite(fd, zero, n, (off_t)off) == (ssize_t)n;
        off += n;
    }
    uint8_t c[4] = {(uint8_t)next, (uint8_t)(next >> 8), (uint8_t)(next >> 16), (uint8_t)(next >> 24)};
    ok = ok && pwrite(fd, c, 4, 36) == 4 && fsync(fd) == 0;
    close(fd);
    grp_touch(g, path);
    return ok ? 0 : -1;
}

/* the same for an emergency pool (pairs): items are 32 bytes each, so item i is at offset 32·i */
static int split_pool(struct grp *g, struct grp_set *s, int to, uint32_t from_i, uint32_t to_i, uint32_t next)
{
    struct pool p;
    char err[256];
    if (pool_open(g, s, g->me, to, &p, err, sizeof err) < 0)
        return -1;
    int ok = 1;
    for (uint32_t i = from_i; ok && i < to_i && i < p.nloc; i++)
        ok = pool_wipe_loc(&p, i) == 0 && pool_wipe(&p, (uint64_t)i * GRP_KEY_LEN, GRP_KEY_LEN) == 0;
    uint8_t c[16];
    for (int i = 0; i < 4; i++)
        c[i] = (uint8_t)(next >> (8 * i));
    uint64_t off = (uint64_t)next * GRP_KEY_LEN;
    for (int i = 0; i < 8; i++)
        c[4 + i] = (uint8_t)(off >> (8 * i));
    ok = ok && pwrite(p.fd, c, 4, 36) == 4 && pwrite(p.fd, c + 4, 8, 48) == 8 && pool_sync(&p) == 0;
    grp_touch(g, p.path);
    pool_close(&p);
    return ok ? 0 : -1;
}

static int make_kill_card(const char *gdir, const char *card, char *err, size_t errlen)
{
    struct grp g;
    if (grp_load(gdir, &g, err, errlen) < 0)
        return -1;
    struct grp_set *e = NULL;
    for (int i = 0; i < g.nsets; i++)
        if (g.sets[i].kind == GRP_SET_EMERGENCY)
            e = &g.sets[i];
    char *edir = e ? grp_set_path(&g, e, NULL) : NULL, *tmp = NULL;
    int ret = -1, other = 1 - g.me;
    if (!e || !edir)
        goto out;
    /* the card's copy is made in memory (the runtime folder), split, written to the card, then removed */
    const char *run = getenv("XDG_RUNTIME_DIR");
    if (asprintf(&tmp, "%s/pnp-card-XXXXXX", run && *run ? run : "/dev/shm") < 0 || !mkdtemp(tmp))
        goto out;
    uint32_t total = g.n >= 3 ? e->slots : e->nloc, half = 1 + (total - 1) / 2;
    char hex[2 * GRP_ID_LEN + 1], *rel = NULL;
    grp_hex(e->id, hex);
    if (asprintf(&rel, g.n >= 3 ? "set-%s/sign" : "set-%s/pool.%d-%d", hex, g.me + 1, other + 1) < 0)
        goto out;
    struct grp cg = g;
    cg.dir = tmp;
    char *src = NULL, *dst = NULL, *dd = NULL;
    int ok = asprintf(&src, "%s/%s", gdir, rel) >= 0 && asprintf(&dst, "%s/%s", tmp, rel) >= 0 &&
             asprintf(&dd, "%s/set-%s", tmp, hex) >= 0 && mkdir(dd, 0700) == 0;
    if (ok) { /* copy the emergency file into memory */
        int in = open(src, O_RDONLY | O_CLOEXEC), outfd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        uint8_t buf[65536];
        ssize_t got;
        ok = in >= 0 && outfd >= 0;
        while (ok && (got = read(in, buf, sizeof buf)) > 0)
            ok = pnp_write_all(outfd, buf, (size_t)got) == 0;
        explicit_bzero(buf, sizeof buf);
        if (in >= 0)
            close(in);
        if (outfd >= 0)
            close(outfd);
    }
    /* card: slots [1, half); cylinder: [half, total) */
    if (ok)
        ok = g.n >= 3 ? split_sign(dst, &g, e, half, total, 1) == 0 && split_sign(src, &g, e, 1, half, half) == 0
                      : split_pool(&cg, e, other, half, total, 1) == 0 && split_pool(&g, e, other, 1, half, half) == 0;
    struct cstore c;
    if (ok && cs_create(&c, card, CS_KILLCARD, g.me, g.id, g.gen, 0, err, errlen) == 0) {
        ok = card_add(&c, tmp, rel, err, errlen) == 0;
        char *gtmp = NULL;
        /* the group file too, so the card works alone */
        if (ok && asprintf(&gtmp, "%s/group", gdir) >= 0) {
            free(gtmp);
            ok = card_add(&c, gdir, "group", err, errlen) == 0;
        }
        cs_close(&c);
        ret = ok ? 0 : -1;
    } else if (!ok) {
        snprintf(err, errlen, "couldn't split the emergency keys: %s", strerror(errno));
    }
    free(src), free(dst), free(dd), free(rel);
out:
    if (tmp)
        rm_rf(tmp);
    free(tmp), free(edir);
    grp_free(&g);
    return ret;
}

/* Unpacks a kill card into memory (the runtime folder): its group folder's path, malloc'd. */
char *pnp_card_unpack(const char *card, char **tmp_out, char *err, size_t errlen)
{
    struct cstore c;
    if (cs_open(&c, card, err, errlen) < 0)
        return NULL;
    if (c.role != CS_KILLCARD || cs_verify(&c, err, errlen) < 0) {
        if (c.role != CS_KILLCARD)
            snprintf(err, errlen, "%s isn't a kill card", card);
        cs_close(&c);
        return NULL;
    }
    const char *run = getenv("XDG_RUNTIME_DIR");
    char hex[2 * GRP_ID_LEN + 1], *tmp = NULL, *gdir = NULL;
    grp_hex(c.group, hex);
    if (asprintf(&tmp, "%s/pnp-card-XXXXXX", run && *run ? run : "/dev/shm") < 0 || !mkdtemp(tmp) ||
        asprintf(&gdir, "%s/pnp-group-%s", tmp, hex) < 0 || mkdir(gdir, 0700) < 0) {
        snprintf(err, errlen, "no place in memory to open the card");
        cs_close(&c);
        free(tmp), free(gdir);
        return NULL;
    }
    char *kd = NULL;
    if (asprintf(&kd, "%s/kills", gdir) >= 0)
        mkdir(kd, 0700);
    free(kd);
    uint64_t pos = 0;
    struct crec r;
    int ok = 1;
    while (ok && cs_record(&c, &pos, &r) == 0) {
        uint8_t h[2];
        char name[256];
        if (r.type != R_FILE || cs_read(&c, &r, 0, h, 2) < 0 || (size_t)(h[0] | h[1] << 8) >= sizeof name)
            continue;
        size_t nl = (size_t)(h[0] | h[1] << 8);
        if (cs_read(&c, &r, 2, name, nl) < 0)
            break;
        name[nl] = 0;
        if (strstr(name, "..") || name[0] == '/')
            continue;
        char *p = NULL, *slash;
        if (asprintf(&p, "%s/%s", gdir, name) < 0)
            break;
        if ((slash = strrchr(p, '/')) && slash > p + strlen(gdir)) {
            *slash = 0;
            mkdir(p, 0700);
            *slash = '/';
        }
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        uint8_t buf[65536];
        for (uint64_t off = 2 + nl; fd >= 0 && ok && off < r.len;) {
            size_t n = r.len - off < sizeof buf ? (size_t)(r.len - off) : sizeof buf;
            ok = cs_read(&c, &r, off, buf, n) == 0 && pnp_write_all(fd, buf, n) == 0;
            off += n;
        }
        explicit_bzero(buf, sizeof buf);
        if (fd >= 0)
            close(fd);
        free(p);
    }
    cs_close(&c);
    *tmp_out = tmp;
    return gdir;
}

/* Writes the card back from its unpacked folder (an emergency slot was used), then removes the folder. */
int pnp_card_repack(const char *card, const char *gdir, char *tmp, char *err, size_t errlen)
{
    struct grp g;
    int ret = -1;
    if (grp_load(gdir, &g, err, errlen) == 0) {
        struct grp_set *e = NULL;
        for (int i = 0; i < g.nsets; i++)
            if (g.sets[i].kind == GRP_SET_EMERGENCY)
                e = &g.sets[i];
        char hex[2 * GRP_ID_LEN + 1], *rel = NULL;
        struct cstore c;
        if (e) {
            grp_hex(e->id, hex);
            if (asprintf(&rel, g.n >= 3 ? "set-%s/sign" : "set-%s/pool.%d-%d", hex, g.me + 1, 2 - g.me) >= 0 &&
                cs_create(&c, card, CS_KILLCARD, g.me, g.id, g.gen, 0, err, errlen) == 0) {
                ret = card_add(&c, gdir, rel, err, errlen) == 0 && card_add(&c, gdir, "group", err, errlen) == 0 ? 0 : -1;
                cs_close(&c);
            }
        }
        free(rel);
        grp_free(&g);
    }
    rm_rf(tmp);
    free(tmp);
    return ret;
}

int pnp_import_card(const char *self_path, const char *root, const char *card)
{
    struct cstore self;
    char err[512], *dir = NULL;
    if (cs_open(&self, self_path, err, sizeof err) < 0) {
        msg("%s", err);
        return 1;
    }
    int r = meet_import(&self, root, &dir, err, sizeof err);
    cs_close(&self);
    if (r < 0) {
        msg("%s", err);
        return 1;
    }
    if (card && make_kill_card(dir, card, err, sizeof err) < 0) {
        msg("imported to %s, but the kill card couldn't be made: %s", dir, err);
        free(dir);
        return 1;
    }
    msg("imported: %s. Every test signature and seal from the meeting checked.%s Now overwrite the self drive and "
        "couriers, or keep them with your vault", dir,
        card ? " The kill card holds half of your emergency keys: keep it apart from your cylinder." : "");
    free(dir);
    return 0;
}

/* ---- moving a key set to another cylinder (the vault, or back) ---- */
int pnp_move(const char *groups, const char *set_prefix, const char *dest_root)
{
    char *dirs[16], err[512];
    int n = grp_find_all(groups, dirs, 16), ret = 1;
    for (int i = 0; i < n; i++) {
        struct grp g;
        if (ret == 1 && grp_load(dirs[i], &g, err, sizeof err) == 0) {
            for (int si = 0; si < g.nsets && ret == 1; si++) {
                char hex[2 * GRP_ID_LEN + 1];
                grp_hex(g.sets[si].id, hex);
                if (strlen(set_prefix) < 4 || strncasecmp(hex, set_prefix, strlen(set_prefix)) != 0)
                    continue;
                if (g.sets[si].state == GRP_KILLED) {
                    msg("that key set has been killed: it isn't moved");
                    ret = 2;
                    break;
                }
                char *src = grp_set_path(&g, &g.sets[si], NULL), *gh = NULL, *dgd = NULL, *dsd = NULL;
                char ghex[2 * GRP_ID_LEN + 1];
                grp_hex(g.id, ghex);
                int ok = src && asprintf(&dgd, "%s/pnp-group-%s", dest_root, ghex) >= 0 &&
                         asprintf(&dsd, "%s/set-%s", dgd, hex) >= 0;
                struct stat st;
                if (ok && stat(dgd, &st) < 0) { /* the group's folder on the destination: its group file */
                    struct grp d = g;
                    d.dir = dgd;
                    ok = grp_mkdirs(&d, err, sizeof err) == 0 && grp_save(&d, err, sizeof err) == 0;
                    /* grp_mkdirs made every set's folder: keep only the one moving */
                    for (int sj = 0; ok && sj < g.nsets; sj++) {
                        char *p = grp_set_path(&d, &g.sets[sj], NULL);
                        if (p && sj != si)
                            rmdir(p);
                        free(p);
                    }
                }
                ok = ok && (mkdir(dsd, 0700) == 0 || errno == EEXIST);
                DIR *dd = ok ? opendir(src) : NULL;
                struct dirent *e;
                while (dd && ok && (e = readdir(dd))) {
                    if (e->d_name[0] == '.')
                        continue;
                    char *a = NULL, *b = NULL;
                    ok = asprintf(&a, "%s/%s", src, e->d_name) >= 0 && asprintf(&b, "%s/%s", dsd, e->d_name) >= 0;
                    int in = ok ? open(a, O_RDONLY | O_CLOEXEC) : -1;
                    int out = ok ? open(b, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600) : -1;
                    uint8_t buf[65536];
                    ssize_t got;
                    ok = in >= 0 && out >= 0;
                    while (ok && (got = read(in, buf, sizeof buf)) > 0)
                        ok = pnp_write_all(out, buf, (size_t)got) == 0;
                    ok = ok && fsync(out) == 0;
                    explicit_bzero(buf, sizeof buf);
                    if (in >= 0)
                        close(in);
                    if (out >= 0)
                        close(out);
                    if (ok)
                        grp_touch(&g, b);
                    free(a), free(b);
                }
                if (dd)
                    closedir(dd);
                if (ok) { /* copied and synced: now remove the source (its files are key material: overwritten first) */
                    pnp_sync_dir(dsd);
                    dd = opendir(src);
                    while (dd && (e = readdir(dd))) {
                        if (e->d_name[0] == '.')
                            continue;
                        char *a = NULL;
                        if (asprintf(&a, "%s/%s", src, e->d_name) >= 0) {
                            int fd = open(a, O_WRONLY | O_CLOEXEC);
                            struct stat fs;
                            static const uint8_t zero[65536];
                            if (fd >= 0 && fstat(fd, &fs) == 0)
                                for (off_t off = 0; off < fs.st_size; off += (off_t)sizeof zero)
                                    if (pwrite(fd, zero, sizeof zero, off) < 0)
                                        break;
                            if (fd >= 0) {
                                fsync(fd);
                                close(fd);
                            }
                            unlink(a);
                        }
                        free(a);
                    }
                    if (dd)
                        closedir(dd);
                    rmdir(src);
                    grp_touch(&g, dsd);
                    msg("moved key set %.8s to %s", hex, dgd);
                    ret = 0;
                } else {
                    msg("couldn't move it: %s", err[0] ? err : strerror(errno));
                    ret = 2;
                }
                free(src), free(gh), free(dgd), free(dsd);
            }
            grp_free(&g);
        }
        free(dirs[i]);
    }
    if (ret == 1)
        msg("no key set starting %s here (see pnp --info)", set_prefix);
    return ret ? 1 : 0;
}

int pnp_courier_check(const char *dev)
{
    char err[512];
    fprintf(stderr, "Writing the whole drive and reading it back (this takes a while on a big drive)...\n");
    if (cs_capacity_check(dev, err, sizeof err) < 0) {
        msg("%s", err);
        return 1;
    }
    msg("%s holds what it claims and keeps what's written: ready for a meeting", dev);
    return 0;
}
