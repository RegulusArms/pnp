/* pnp: one-time pad file encryption that stays secure even if P = NP.
 *
 *   pnp FILE            FILE -> FILE.pnp (ciphertext) + FILE.pnp.key (the pad)
 *   pnp -d FILE.pnp     FILE.pnp + FILE.pnp.key -> FILE
 *
 * The file formats are in docs/format.md: a 24-byte header (magic, then a 16-byte ID shared by a ciphertext and its
 * key, so a mismatched key is refused), then the body. ciphertext body = plaintext XOR pad; key body = pad.
 *
 * --key-out writes the key straight into another folder (a USB stick, say), so it never touches the internal disk.
 * --shares N writes the key as N shares instead of one key file: shares 1..N-1 are fresh hardware-random pads and
 * share N is pad XOR all of them. Any N-1 shares are uniformly random whatever the pad is, so they reveal nothing
 * (information-theoretically, like the pad itself); all N XORed together give the pad back. */
#define _GNU_SOURCE
#include "fileio.h"
#include "rng.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PNP_VERSION
#define PNP_VERSION "unknown"
#endif

#define MAGIC_LEN 8
#define ID_LEN 16
#define HEADER_LEN (MAGIC_LEN + ID_LEN)       /* ciphertext and whole key */
#define SHARE_HEADER_LEN (HEADER_LEN + 2)     /* a key share: then its number (1..count) and the count */
static const char MAGIC_CT[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '1'};
static const char MAGIC_KEY[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '1'};
static const char MAGIC_SHARE[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'H', '0', '0', '1'};

#define MAX_SHARES 16 /* also the most key files decrypting takes */

#define CHUNK 65536

extern volatile sig_atomic_t pnp_stop;

/* plaintext, pad, output and share buffers: locked in RAM where allowed (never swapped) and wiped after use */
static uint8_t buf_in[CHUNK], buf_pad[CHUNK], buf_out[CHUNK], buf_share[CHUNK];

static int quiet;

static void wipe_buffers(void)
{
    explicit_bzero(buf_in, sizeof buf_in);
    explicit_bzero(buf_pad, sizeof buf_pad);
    explicit_bzero(buf_out, sizeof buf_out);
    explicit_bzero(buf_share, sizeof buf_share);
}

static void on_signal(int sig) { pnp_stop = sig; }

static void setup_process(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal; /* no SA_RESTART: a blocking read returns EINTR and the run stops */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    /* no core dumps: they'd write pad and plaintext bytes to disk */
    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_CORE, &none);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    mlock(buf_in, sizeof buf_in);
    mlock(buf_pad, sizeof buf_pad);
    mlock(buf_out, sizeof buf_out);
    mlock(buf_share, sizeof buf_share);
}

/* after cleaning up, die of the signal that stopped us, so the shell sees it */
static void exit_for_signal(void)
{
    if (pnp_stop) {
        int sig = pnp_stop;
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("pnp: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void usage(FILE *f)
{
    fprintf(f,
            "usage: pnp [-f] [-q] [-o OUT] [--key-out PATH] [--shares N] FILE\n"
            "                                    encrypt FILE to FILE.pnp and its key FILE.pnp.key\n"
            "       pnp -d [-f] [-q] [-k KEY]... [-o OUT] FILE.pnp\n"
            "                                    decrypt FILE.pnp with FILE.pnp.key (or its shares) to FILE\n"
            "       pnp --sources                list the hardware random sources and whether they're usable\n"
            "\n"
            "  -d, --decrypt   decrypt instead of encrypting\n"
            "  -k, --key KEY   the key file to decrypt with (default: FILE.pnp.key, or FILE.pnp.key.1, .2...);\n"
            "                  give -k once per share for a key split with --shares\n"
            "  -o, --output OUT  where to write: the ciphertext when encrypting (its key goes to OUT.key),\n"
            "                  the plaintext when decrypting\n"
            "      --key-out PATH  write the key straight into this folder (or to this file name) instead of\n"
            "                  beside the ciphertext; with --shares, once for all shares or once per share\n"
            "      --shares N  split the key into N shares (2-16), all of them needed to decrypt\n"
            "  -f, --force     replace output files that already exist\n"
            "  -q, --quiet     don't print which random sources made the pad\n"
            "  -v, --verbose   print every random source and its state\n"
            "  -V, --version   print the version\n"
            "  -h, --help      print this help\n"
            "\n"
            "Keep the key secret, away from the ciphertext, and never use it for anything else.\n");
}

/* How to fix /dev/hwrng being unreadable, for this user's situation. */
static void explain_denied(void)
{
    struct group *g = getgrnam("pnp");
    if (!g) {
        say("/dev/hwrng is there but only root can read it, and the pnp group doesn't exist: pnp's udev rule "
            "isn't installed. Install the pnp package, or from the source folder run: sudo make install-udev");
        return;
    }
    gid_t groups[256];
    int n = getgroups(256, groups);
    for (int i = 0; i < n; i++) {
        if (groups[i] == g->gr_gid) {
            say("you're in the pnp group but /dev/hwrng isn't readable by it yet. Apply pnp's udev rule: "
                "sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=misc "
                "--sysname-match=hw_random");
            return;
        }
    }
    const char *user = getenv("USER");
    for (char **m = g->gr_mem; user && *m; m++) {
        if (strcmp(*m, user) == 0) {
            say("you've joined the pnp group, but this session started before that: log out and back in "
                "(or run: newgrp pnp)");
            return;
        }
    }
    say("to let pnp read /dev/hwrng, join the pnp group: sudo usermod -aG pnp $USER, then log out and back in");
}

static const char *state_text(enum pnp_source_state s)
{
    switch (s) {
    case PNP_SRC_OK: return "in use";
    case PNP_SRC_ABSENT: return "not available";
    case PNP_SRC_DENIED: return "not usable";
    case PNP_SRC_FAILED: return "not usable";
    }
    return "?";
}

static void list_sources(const struct pnp_rng *rng, FILE *f)
{
    for (int i = 0; i < rng->count; i++) {
        const struct pnp_source *s = &rng->src[i];
        fprintf(f, "  %-11s %s%s%s%s\n", s->name, state_text(s->state), s->detail[0] ? " (" : "", s->detail,
                s->detail[0] ? ")" : "");
    }
    fprintf(f, "  %-11s always mixed in (software, not counted as a hardware source)\n", "getrandom");
}

static int hwrng_denied(const struct pnp_rng *rng)
{
    for (int i = 0; i < rng->count; i++)
        if (rng->src[i].state == PNP_SRC_DENIED)
            return 1;
    return 0;
}

/* opens the hardware sources; returns -1 (after explaining) if none can be used */
static int open_sources(struct pnp_rng *rng, int verbose)
{
    pnp_rng_open(rng);
    if (verbose) {
        fprintf(stderr, "pnp: random sources:\n");
        list_sources(rng, stderr);
    }
    if (rng->hardware_ok == 0) {
        say("no usable hardware random source, so pnp won't encrypt: a one-time pad from software randomness "
            "alone isn't safe if P = NP.");
        if (!verbose)
            list_sources(rng, stderr);
        if (hwrng_denied(rng))
            explain_denied();
        return -1;
    }
    if (!quiet) {
        char desc[256];
        pnp_rng_describe(rng, desc, sizeof desc);
        say("pad from %s", desc);
        if (hwrng_denied(rng)) {
            say("note: /dev/hwrng isn't used (permission denied)");
            explain_denied();
        }
    }
    return 0;
}

static int exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int same_file(const char *path, const struct stat *st)
{
    struct stat o;
    return stat(path, &o) == 0 && o.st_dev == st->st_dev && o.st_ino == st->st_ino;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && strcmp(s + a - b, suffix) == 0;
}

/* reads up to n bytes, fewer only at the end of the file; -1 on error */
static ssize_t read_some(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR && !pnp_stop)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int open_input(const char *path, struct stat *st)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        say("can't open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, st) < 0 || !S_ISREG(st->st_mode)) {
        say("%s isn't a regular file", path);
        close(fd);
        return -1;
    }
    return fd;
}

/* path with its folder resolved, to tell whether two outputs would be the same file (malloc'd; the path itself if
 * the folder can't be resolved, which pnp_out_open then reports) */
static char *target_of(const char *path)
{
    char *dir = pnp_dir_of(path), *base = pnp_base_of(path), *real = dir ? realpath(dir, NULL) : NULL, *t = NULL;
    if (real && base) {
        if (asprintf(&t, "%s/%s", real, base) < 0)
            t = NULL;
    } else {
        t = strdup(path);
    }
    free(dir);
    free(base);
    free(real);
    return t;
}

/* Where the key goes, or each share: beside the ciphertext as CT.key (shares CT.key.1, CT.key.2...), or with
 * --key-out into the folder given (same names) or to the file name given. --key-out is given once, or once per
 * share. Fills paths[0..nkeys-1]; -1 after saying why. */
static int make_key_paths(const char *ct_path, char *const *outs, int nouts, int shares, char **paths)
{
    int nkeys = shares ? shares : 1, ret = -1;
    char *base = pnp_base_of(ct_path);
    if (!base) {
        say("out of memory");
        return -1;
    }
    if (nouts > 1 && nouts != nkeys) {
        if (shares)
            say("give --key-out once, or once for each of the %d shares", nkeys);
        else
            say("give --key-out once (several are for --shares)");
        goto out;
    }
    for (int i = 0; i < nkeys; i++) {
        const char *o = nouts ? outs[nouts == 1 ? 0 : i] : NULL;
        char num[8] = "";
        struct stat s;
        int r;
        if (shares)
            snprintf(num, sizeof num, ".%d", i + 1);
        if (!o) {
            r = asprintf(&paths[i], "%s.key%s", ct_path, num);
        } else if (stat(o, &s) == 0 && S_ISDIR(s.st_mode)) {
            r = asprintf(&paths[i], "%s%s%s.key%s", o, ends_with(o, "/") ? "" : "/", base, num);
        } else if (ends_with(o, "/")) {
            say("--key-out %s: there's no such folder", o);
            goto out;
        } else if (shares && nouts == 1) {
            say("--key-out %s isn't a folder: with --shares, give a folder, or one file name per share", o);
            goto out;
        } else {
            r = asprintf(&paths[i], "%s", o);
        }
        if (r < 0) {
            paths[i] = NULL;
            say("out of memory");
            goto out;
        }
    }
    ret = 0;
out:
    free(base);
    return ret;
}

/* No output may be the input, another output, or (without -f) an existing file. -1 after saying why. */
static int check_outputs(char *const *paths, int n, const struct stat *in_st, int force)
{
    char *t[MAX_SHARES + 1] = {0};
    int ret = -1;
    for (int i = 0; i < n; i++) {
        if (same_file(paths[i], in_st)) {
            say("the output would overwrite the file being encrypted");
            goto out;
        }
        if (!(t[i] = target_of(paths[i]))) {
            say("out of memory");
            goto out;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(t[i], t[j]) == 0) {
                say("%s would be written twice", paths[i]);
                goto out;
            }
        }
        if (!force && exists(paths[i])) {
            say("%s already exists (use -f to replace it)", paths[i]);
            goto out;
        }
    }
    ret = 0;
out:
    for (int i = 0; i < n; i++)
        free(t[i]);
    return ret;
}

static int encrypt(const char *in_path, const char *out_opt, char *const *key_outs, int n_key_outs, int shares,
                   int force, int verbose)
{
    int nkeys = shares ? shares : 1; /* key files: the key, or its shares */
    char *ct_path = NULL, *key_path[MAX_SHARES] = {0};
    const char *failed = NULL; /* the output a write failed on */
    struct pnp_out ct, key[MAX_SHARES];
    struct pnp_rng rng;
    char err[512];
    int ret = 1, in = -1;
    struct stat st;

    memset(&ct, 0, sizeof ct);
    memset(key, 0, sizeof key);
    ct.fd = -1;
    for (int i = 0; i < nkeys; i++)
        key[i].fd = -1;
    memset(&rng, 0, sizeof rng);

    if ((in = open_input(in_path, &st)) < 0)
        goto out;
    if (out_opt ? asprintf(&ct_path, "%s", out_opt) < 0 : asprintf(&ct_path, "%s.pnp", in_path) < 0) {
        ct_path = NULL;
        say("out of memory");
        goto out;
    }
    if (make_key_paths(ct_path, key_outs, n_key_outs, shares, key_path) < 0)
        goto out;
    char *all[MAX_SHARES + 1];
    all[0] = ct_path;
    memcpy(all + 1, key_path, (size_t)nkeys * sizeof *all);
    if (check_outputs(all, nkeys + 1, &st, force) < 0)
        goto out;
    if (open_sources(&rng, verbose) < 0)
        goto out;

    uint8_t header[SHARE_HEADER_LEN];
    if (getrandom(header + MAGIC_LEN, ID_LEN, 0) != ID_LEN) {
        say("getrandom: %s", strerror(errno));
        goto out;
    }
    /* each key file is created in its own folder, so with --key-out the key never touches the ciphertext's disk */
    for (int i = 0; i < nkeys; i++) {
        if (pnp_out_open(&key[i], key_path[i], 0600, err, sizeof err) < 0) {
            say("%s", err);
            goto out;
        }
    }
    if (pnp_out_open(&ct, ct_path, 0666, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    for (int i = 0; i < nkeys; i++) {
        memcpy(header, shares ? MAGIC_SHARE : MAGIC_KEY, MAGIC_LEN);
        header[HEADER_LEN] = (uint8_t)(i + 1);
        header[HEADER_LEN + 1] = (uint8_t)nkeys;
        if (pnp_write_all(key[i].fd, header, shares ? SHARE_HEADER_LEN : HEADER_LEN) < 0) {
            failed = key_path[i];
            goto write_failed;
        }
    }
    memcpy(header, MAGIC_CT, MAGIC_LEN);
    if (pnp_write_all(ct.fd, header, HEADER_LEN) < 0) {
        failed = ct_path;
        goto write_failed;
    }

    for (;;) {
        if (pnp_stop)
            goto out;
        ssize_t n = read_some(in, buf_in, CHUNK);
        if (n < 0) {
            if (!pnp_stop)
                say("can't read %s: %s", in_path, strerror(errno));
            goto out;
        }
        if (n == 0)
            break;
        if (pnp_rng_fill(&rng, buf_pad, (size_t)n, err, sizeof err) < 0)
            goto rng_failed;
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (pnp_write_all(ct.fd, buf_out, (size_t)n) < 0) {
            failed = ct_path;
            goto write_failed;
        }
        /* shares 1..N-1: fresh pads from the same sources; share N (or the whole key): the pad XOR all of them */
        for (int k = 0; k < nkeys - 1; k++) {
            if (pnp_rng_fill(&rng, buf_share, (size_t)n, err, sizeof err) < 0)
                goto rng_failed;
            if (pnp_write_all(key[k].fd, buf_share, (size_t)n) < 0) {
                failed = key_path[k];
                goto write_failed;
            }
            for (ssize_t i = 0; i < n; i++)
                buf_pad[i] ^= buf_share[i];
        }
        if (pnp_write_all(key[nkeys - 1].fd, buf_pad, (size_t)n) < 0) {
            failed = key_path[nkeys - 1];
            goto write_failed;
        }
    }
    /* the key first: a ciphertext without its key would be lost data, a stray key is only noise */
    for (int i = 0; i < nkeys; i++) {
        if (pnp_out_commit(&key[i], force, err, sizeof err) < 0) {
            say("%s", err);
            goto unplace;
        }
    }
    if (pnp_out_commit(&ct, force, err, sizeof err) < 0) {
        say("%s", err);
        goto unplace; /* with -f, a replaced old key is gone by now: rare, and said in pnp.1 */
    }
    pnp_sync_dir(ct_path);
    for (int i = 0; i < nkeys; i++)
        pnp_sync_dir(key_path[i]);
    if (!quiet && !shares) {
        say("wrote %s and %s. Keep the key secret and apart from the .pnp file.", ct_path, key_path[0]);
    } else if (!quiet) {
        say("wrote %s, and its key as %d shares. All of them are needed to decrypt: keep them in different places.",
            ct_path, nkeys);
        for (int i = 0; i < nkeys; i++)
            fprintf(stderr, "  %s\n", key_path[i]);
    }
    ret = 0;
    goto out;

unplace:
    for (int i = 0; i < nkeys; i++)
        pnp_out_unplace(&key[i]);
    goto out;
rng_failed:
    if (!pnp_stop)
        say("%s. Nothing was written.", err);
    goto out;
write_failed:
    say("can't write %s: %s", failed, strerror(errno));
out:
    wipe_buffers();
    explicit_bzero(&rng, sizeof rng);
    pnp_rng_close(&rng);
    for (int i = 0; i < nkeys; i++) {
        pnp_out_discard(&key[i]);
        free(key_path[i]);
    }
    pnp_out_discard(&ct);
    if (in >= 0)
        close(in);
    free(ct_path);
    return ret;
}

enum pnp_kind { KIND_CT, KIND_KEY, KIND_SHARE };

struct pnp_file {
    int fd;
    enum pnp_kind kind;
    uint8_t id[ID_LEN];
    int num, count; /* a share: its number (1..count) and how many there are */
    off_t body;     /* bytes after the header */
};

/* Opens a ciphertext (want KIND_CT) or a key or share (want KIND_KEY) and reads its header. Returns 0, or -1 after
 * saying why (f->fd is then -1). */
static int open_pnp_file(const char *path, enum pnp_kind want, struct pnp_file *f)
{
    struct stat st;
    uint8_t h[SHARE_HEADER_LEN];
    f->fd = open_input(path, &st);
    if (f->fd < 0)
        return -1;
    ssize_t n = read_some(f->fd, h, HEADER_LEN);
    int ct = n == HEADER_LEN && memcmp(h, MAGIC_CT, MAGIC_LEN) == 0;
    int key = n == HEADER_LEN && memcmp(h, MAGIC_KEY, MAGIC_LEN) == 0;
    int share = n == HEADER_LEN && memcmp(h, MAGIC_SHARE, MAGIC_LEN) == 0;
    if (want == KIND_CT && (key || share)) {
        say("%s is a pnp %s, not a ciphertext", path, key ? "key" : "key share");
        goto fail;
    }
    if (want == KIND_KEY && ct) {
        say("%s is a pnp ciphertext, not a key", path);
        goto fail;
    }
    if (!ct && !key && !share) {
        say("%s isn't a pnp %s (or it's from a newer version of pnp)", path, want == KIND_CT ? "ciphertext" : "key");
        goto fail;
    }
    f->kind = ct ? KIND_CT : key ? KIND_KEY : KIND_SHARE;
    memcpy(f->id, h + MAGIC_LEN, ID_LEN);
    f->num = f->count = 0;
    f->body = st.st_size - HEADER_LEN;
    if (share) {
        if (read_some(f->fd, h + HEADER_LEN, 2) != 2 || h[HEADER_LEN + 1] < 2 || h[HEADER_LEN] < 1 ||
            h[HEADER_LEN] > h[HEADER_LEN + 1]) {
            say("%s is a damaged key share", path);
            goto fail;
        }
        f->num = h[HEADER_LEN];
        f->count = h[HEADER_LEN + 1];
        f->body -= 2;
    }
    return 0;
fail:
    close(f->fd);
    f->fd = -1;
    return -1;
}

/* The key files must be one whole key, or every share of one key, all from this ciphertext's encryption and all as
 * long as it. -1 after saying why. */
static int check_keys(const char *ct_path, const struct pnp_file *ct, char *const *kp, const struct pnp_file *kf,
                      int nk)
{
    for (int k = 0; k < nk; k++) {
        if (memcmp(kf[k].id, ct->id, ID_LEN) != 0) {
            say("%s isn't the key for %s (they're from different encryptions)", kp[k], ct_path);
            return -1;
        }
    }
    for (int k = 0; k < nk; k++) {
        if (kf[k].body != ct->body) {
            say("%s and %s have different sizes: one of them is damaged or incomplete", ct_path, kp[k]);
            return -1;
        }
    }
    if (nk == 1 && kf[0].kind == KIND_KEY)
        return 0;
    const char *seen[MAX_SHARES + 1] = {0};
    for (int k = 0; k < nk; k++) {
        if (kf[k].kind == KIND_KEY) {
            say("%s is a whole key: give either one key, or all the shares of one", kp[k]);
            return -1;
        }
        if (kf[k].count != kf[0].count || kf[k].count > MAX_SHARES) {
            say("%s is a damaged key share", kp[k]);
            return -1;
        }
        if (seen[kf[k].num]) {
            say("%s and %s are the same share (number %d)", seen[kf[k].num], kp[k], kf[k].num);
            return -1;
        }
        seen[kf[k].num] = kp[k];
    }
    if (nk != kf[0].count) {
        char missing[64] = "";
        for (int s = 1; s <= kf[0].count; s++)
            if (!seen[s])
                snprintf(missing + strlen(missing), sizeof missing - strlen(missing), "%s%d", missing[0] ? ", " : "",
                         s);
        say("only %d of the key's %d shares were given (missing: %s). All of them are needed to decrypt.", nk,
            kf[0].count, missing);
        return -1;
    }
    return 0;
}

static int decrypt(const char *ct_path, char *const *key_opts, int n_key_opts, const char *out_opt, int force)
{
    char *kp[MAX_SHARES] = {0}, *out_path = NULL;
    struct pnp_file ct, kf[MAX_SHARES];
    struct pnp_out out;
    char err[512];
    int ret = 1, nk = 0, find_shares = 0;
    struct stat st;

    memset(&out, 0, sizeof out);
    out.fd = -1;
    ct.fd = -1;
    for (int k = 0; k < MAX_SHARES; k++)
        kf[k].fd = -1;

    if (out_opt) {
        out_path = strdup(out_opt);
    } else if (ends_with(ct_path, ".pnp") && strlen(ct_path) > 4) {
        out_path = strndup(ct_path, strlen(ct_path) - 4);
    } else {
        say("%s doesn't end in .pnp, so say where to write the decrypted file with -o", ct_path);
        ret = 2;
        goto out;
    }
    if (!out_path)
        goto oom;
    if (n_key_opts) {
        for (nk = 0; nk < n_key_opts; nk++)
            if (!(kp[nk] = strdup(key_opts[nk])))
                goto oom;
    } else {
        /* FILE.pnp.key, or else the shares FILE.pnp.key.1, .2... (share 1 says how many) */
        if (asprintf(&kp[0], "%s.key", ct_path) < 0) {
            kp[0] = NULL;
            goto oom;
        }
        nk = 1;
        char *first = NULL;
        if (!exists(kp[0]) && asprintf(&first, "%s.1", kp[0]) >= 0) {
            if (exists(first)) {
                free(kp[0]);
                kp[0] = first;
                find_shares = 1;
            } else {
                free(first);
            }
        }
    }
    if (open_pnp_file(ct_path, KIND_CT, &ct) < 0)
        goto out;
    for (int k = 0; k < nk; k++)
        if (open_pnp_file(kp[k], KIND_KEY, &kf[k]) < 0)
            goto out;
    if (find_shares && kf[0].kind == KIND_SHARE && kf[0].count <= MAX_SHARES) {
        for (; nk < kf[0].count; nk++) {
            if (asprintf(&kp[nk], "%s.key.%d", ct_path, nk + 1) < 0) {
                kp[nk] = NULL;
                goto oom;
            }
            if (open_pnp_file(kp[nk], KIND_KEY, &kf[nk]) < 0) {
                say("all %d shares of the key are needed to decrypt (name them with -k if they're elsewhere)",
                    kf[0].count);
                goto out;
            }
        }
    }
    if (check_keys(ct_path, &ct, kp, kf, nk) < 0)
        goto out;
    if (fstat(ct.fd, &st) == 0 && same_file(out_path, &st)) {
        say("the output would overwrite the ciphertext or the key");
        goto out;
    }
    for (int k = 0; k < nk; k++) {
        if (fstat(kf[k].fd, &st) == 0 && same_file(out_path, &st)) {
            say("the output would overwrite the ciphertext or the key");
            goto out;
        }
    }
    if (!force && exists(out_path)) {
        say("%s already exists (use -f to replace it)", out_path);
        goto out;
    }
    if (pnp_out_open(&out, out_path, 0600, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    off_t total = 0;
    for (;;) {
        if (pnp_stop)
            goto out;
        ssize_t n = read_some(ct.fd, buf_in, CHUNK);
        if (n < 0) {
            if (!pnp_stop)
                say("can't read %s: %s", ct_path, strerror(errno));
            goto out;
        }
        if (n == 0)
            break;
        /* the pad: the key, or every share XORed together (in any order) */
        for (int k = 0; k < nk; k++) {
            if (read_some(kf[k].fd, k ? buf_share : buf_pad, (size_t)n) != n) {
                if (!pnp_stop)
                    say("%s ended early or can't be read", kp[k]);
                goto out;
            }
            for (ssize_t i = 0; k && i < n; i++)
                buf_pad[i] ^= buf_share[i];
        }
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (pnp_write_all(out.fd, buf_out, (size_t)n) < 0) {
            say("can't write %s: %s", out_path, strerror(errno));
            goto out;
        }
        total += n;
    }
    for (int k = 0; k < nk; k++) {
        if (total != ct.body || read_some(kf[k].fd, buf_pad, 1) != 0) {
            say("%s or %s changed while pnp was reading them", ct_path, kp[k]);
            goto out;
        }
    }
    if (pnp_out_commit(&out, force, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    pnp_sync_dir(out_path);
    if (!quiet)
        say("wrote %s", out_path);
    ret = 0;
    goto out;
oom:
    say("out of memory");
out:
    wipe_buffers();
    pnp_out_discard(&out);
    if (ct.fd >= 0)
        close(ct.fd);
    for (int k = 0; k < MAX_SHARES; k++) {
        if (kf[k].fd >= 0)
            close(kf[k].fd);
        free(kp[k]);
    }
    free(out_path);
    return ret;
}

int main(int argc, char **argv)
{
    enum { OPT_SOURCES = 256, OPT_KEY_OUT, OPT_SHARES };
    static const struct option opts[] = {
        {"decrypt", no_argument, NULL, 'd'},         {"key", required_argument, NULL, 'k'},
        {"output", required_argument, NULL, 'o'},    {"force", no_argument, NULL, 'f'},
        {"quiet", no_argument, NULL, 'q'},           {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},         {"help", no_argument, NULL, 'h'},
        {"sources", no_argument, NULL, OPT_SOURCES}, {"key-out", required_argument, NULL, OPT_KEY_OUT},
        {"shares", required_argument, NULL, OPT_SHARES}, {NULL, 0, NULL, 0},
    };
    int dec = 0, force = 0, verbose = 0, sources = 0, shares = 0, nkeys = 0, nkey_outs = 0, c;
    char *keys[MAX_SHARES], *key_outs[MAX_SHARES];
    const char *out_opt = NULL;

    while ((c = getopt_long(argc, argv, "dk:o:fqvVh", opts, NULL)) != -1) {
        switch (c) {
        case 'd': dec = 1; break;
        case 'k':
            if (nkeys == MAX_SHARES) {
                say("too many -k (at most %d)", MAX_SHARES);
                return 2;
            }
            keys[nkeys++] = optarg;
            break;
        case OPT_KEY_OUT:
            if (nkey_outs == MAX_SHARES) {
                say("too many --key-out (at most %d)", MAX_SHARES);
                return 2;
            }
            key_outs[nkey_outs++] = optarg;
            break;
        case OPT_SHARES: {
            char *end;
            errno = 0;
            long v = strtol(optarg, &end, 10);
            if (errno || *end || end == optarg || v < 2 || v > MAX_SHARES) {
                say("--shares takes a number from 2 to %d", MAX_SHARES);
                return 2;
            }
            shares = (int)v;
            break;
        }
        case 'o': out_opt = optarg; break;
        case 'f': force = 1; break;
        case 'q': quiet = 1; break;
        case 'v': verbose = 1; break;
        case OPT_SOURCES: sources = 1; break;
        case 'V': printf("pnp %s\n", PNP_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    setup_process();
    if (sources) {
        struct pnp_rng rng;
        pnp_rng_open(&rng);
        printf("Hardware random sources:\n");
        list_sources(&rng, stdout);
        int ok = rng.hardware_ok;
        fflush(stdout);
        if (hwrng_denied(&rng))
            explain_denied();
        pnp_rng_close(&rng);
        if (!ok)
            printf("No usable hardware source: pnp can decrypt here but won't encrypt.\n");
        return ok ? 0 : 1;
    }
    if (optind != argc - 1) {
        usage(stderr);
        return 2;
    }
    if (nkeys && !dec) {
        say("-k is for decrypting (to choose where the key is written, use --key-out)");
        return 2;
    }
    if (dec && (nkey_outs || shares)) {
        say("--key-out and --shares are for encrypting (to name the key or its shares when decrypting, use -k)");
        return 2;
    }
    int ret = dec ? decrypt(argv[optind], keys, nkeys, out_opt, force)
                  : encrypt(argv[optind], out_opt, key_outs, nkey_outs, shares, force, verbose);
    exit_for_signal();
    return ret;
}
