/* pnp: one-time pad file encryption that stays secure even if P = NP.
 *
 *   pnp FILE            FILE -> FILE.pnp (ciphertext) + FILE.pnp.key (the pad)
 *   pnp -d FILE.pnp     FILE.pnp + FILE.pnp.key -> FILE
 *
 * The file formats are in docs/format.md: a 24-byte header (magic, then a 16-byte ID shared by a ciphertext and its
 * key, so a mismatched key is refused), then the body. ciphertext body = plaintext XOR pad; key body = pad. */
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
#define HEADER_LEN (MAGIC_LEN + ID_LEN)
static const char MAGIC_CT[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '1'};
static const char MAGIC_KEY[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '1'};

#define CHUNK 65536

extern volatile sig_atomic_t pnp_stop;

/* plaintext, pad and output buffers: locked in RAM where allowed (never swapped) and wiped after use */
static uint8_t buf_in[CHUNK], buf_pad[CHUNK], buf_out[CHUNK];

static int quiet;

static void wipe_buffers(void)
{
    explicit_bzero(buf_in, sizeof buf_in);
    explicit_bzero(buf_pad, sizeof buf_pad);
    explicit_bzero(buf_out, sizeof buf_out);
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
            "usage: pnp [-f] [-q] [-o OUT] FILE           encrypt FILE to FILE.pnp and its key FILE.pnp.key\n"
            "       pnp -d [-f] [-q] [-k KEY] [-o OUT] FILE.pnp   decrypt FILE.pnp with FILE.pnp.key to FILE\n"
            "       pnp --sources                       list the hardware random sources and whether they're usable\n"
            "\n"
            "  -d, --decrypt   decrypt instead of encrypting\n"
            "  -k, --key KEY   the key file to decrypt with (default: FILE.pnp.key)\n"
            "  -o, --output OUT  where to write: the ciphertext when encrypting (its key goes to OUT.key),\n"
            "                  the plaintext when decrypting\n"
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

static int encrypt(const char *in_path, const char *out_opt, int force, int verbose)
{
    char *ct_path = NULL, *key_path = NULL;
    struct pnp_out ct, key;
    struct pnp_rng rng;
    char err[512];
    int ret = 1, in = -1;
    struct stat st;

    memset(&ct, 0, sizeof ct);
    memset(&key, 0, sizeof key);
    ct.fd = key.fd = -1;
    memset(&rng, 0, sizeof rng);

    if ((in = open_input(in_path, &st)) < 0)
        goto out;
    if (out_opt ? asprintf(&ct_path, "%s", out_opt) < 0 : asprintf(&ct_path, "%s.pnp", in_path) < 0) {
        ct_path = NULL;
        goto oom;
    }
    if (asprintf(&key_path, "%s.key", ct_path) < 0) {
        key_path = NULL;
        goto oom;
    }
    if (same_file(ct_path, &st) || same_file(key_path, &st)) {
        say("the output would overwrite the file being encrypted");
        goto out;
    }
    if (!force) {
        if (exists(ct_path)) {
            say("%s already exists (use -f to replace it)", ct_path);
            goto out;
        }
        if (exists(key_path)) {
            say("%s already exists (use -f to replace it)", key_path);
            goto out;
        }
    }
    if (open_sources(&rng, verbose) < 0)
        goto out;

    uint8_t header[HEADER_LEN];
    memcpy(header, MAGIC_KEY, MAGIC_LEN);
    if (getrandom(header + MAGIC_LEN, ID_LEN, 0) != ID_LEN) {
        say("getrandom: %s", strerror(errno));
        goto out;
    }
    if (pnp_out_open(&key, key_path, 0600, err, sizeof err) < 0 ||
        pnp_out_open(&ct, ct_path, 0666, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    if (pnp_write_all(key.fd, header, HEADER_LEN) < 0)
        goto write_failed_key;
    memcpy(header, MAGIC_CT, MAGIC_LEN);
    if (pnp_write_all(ct.fd, header, HEADER_LEN) < 0)
        goto write_failed_ct;

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
        if (pnp_rng_fill(&rng, buf_pad, (size_t)n, err, sizeof err) < 0) {
            if (!pnp_stop)
                say("%s. Nothing was written.", err);
            goto out;
        }
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (pnp_write_all(key.fd, buf_pad, (size_t)n) < 0)
            goto write_failed_key;
        if (pnp_write_all(ct.fd, buf_out, (size_t)n) < 0)
            goto write_failed_ct;
    }
    /* the key first: a ciphertext without its key would be lost data, a stray key is only noise */
    if (pnp_out_commit(&key, force, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    if (pnp_out_commit(&ct, force, err, sizeof err) < 0) {
        say("%s", err);
        pnp_out_unplace(&key); /* with -f, a replaced old key is gone by now: rare, and said in pnp.1 */
        goto out;
    }
    pnp_sync_dir(ct_path);
    pnp_sync_dir(key_path);
    if (!quiet)
        say("wrote %s and %s. Keep the key secret and apart from the .pnp file.", ct_path, key_path);
    ret = 0;
    goto out;

write_failed_key:
    say("can't write %s: %s", key_path, strerror(errno));
    goto out;
write_failed_ct:
    say("can't write %s: %s", ct_path, strerror(errno));
    goto out;
oom:
    say("out of memory");
out:
    wipe_buffers();
    explicit_bzero(&rng, sizeof rng);
    pnp_rng_close(&rng);
    pnp_out_discard(&key);
    pnp_out_discard(&ct);
    if (in >= 0)
        close(in);
    free(ct_path);
    free(key_path);
    return ret;
}

/* opens a ciphertext or key file and checks its header; fills id */
static int open_pnp_file(const char *path, const char magic[MAGIC_LEN], const char *what, uint8_t id[ID_LEN],
                         struct stat *st)
{
    int fd = open_input(path, st);
    if (fd < 0)
        return -1;
    uint8_t header[HEADER_LEN];
    ssize_t n = read_some(fd, header, HEADER_LEN);
    if (n != HEADER_LEN || memcmp(header, magic, MAGIC_LEN) != 0) {
        if (n == HEADER_LEN && memcmp(header, magic == MAGIC_CT ? MAGIC_KEY : MAGIC_CT, MAGIC_LEN) == 0)
            say("%s is a pnp %s, not a %s", path, magic == MAGIC_CT ? "key" : "ciphertext", what);
        else
            say("%s isn't a pnp %s (or it's from a newer version of pnp)", path, what);
        close(fd);
        return -1;
    }
    memcpy(id, header + MAGIC_LEN, ID_LEN);
    return fd;
}

static int decrypt(const char *ct_path, const char *key_opt, const char *out_opt, int force)
{
    char *key_path = NULL, *out_path = NULL;
    struct pnp_out out;
    char err[512];
    int ret = 1, ct = -1, key = -1;
    struct stat ct_st, key_st;
    uint8_t ct_id[ID_LEN], key_id[ID_LEN];

    memset(&out, 0, sizeof out);
    out.fd = -1;

    if (out_opt) {
        out_path = strdup(out_opt);
    } else if (ends_with(ct_path, ".pnp") && strlen(ct_path) > 4) {
        out_path = strndup(ct_path, strlen(ct_path) - 4);
    } else {
        say("%s doesn't end in .pnp, so say where to write the decrypted file with -o", ct_path);
        ret = 2;
        goto out;
    }
    if (key_opt ? asprintf(&key_path, "%s", key_opt) < 0 : asprintf(&key_path, "%s.key", ct_path) < 0) {
        key_path = NULL;
        say("out of memory");
        goto out;
    }
    if (!out_path) {
        say("out of memory");
        goto out;
    }
    if ((ct = open_pnp_file(ct_path, MAGIC_CT, "ciphertext", ct_id, &ct_st)) < 0)
        goto out;
    if ((key = open_pnp_file(key_path, MAGIC_KEY, "key", key_id, &key_st)) < 0)
        goto out;
    if (memcmp(ct_id, key_id, ID_LEN) != 0) {
        say("%s isn't the key for %s (they're from different encryptions)", key_path, ct_path);
        goto out;
    }
    if (ct_st.st_size != key_st.st_size) {
        say("%s and %s have different sizes: one of them is damaged or incomplete", ct_path, key_path);
        goto out;
    }
    if (same_file(out_path, &ct_st) || same_file(out_path, &key_st)) {
        say("the output would overwrite the ciphertext or the key");
        goto out;
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
        ssize_t n = read_some(ct, buf_in, CHUNK);
        if (n < 0) {
            if (!pnp_stop)
                say("can't read %s: %s", ct_path, strerror(errno));
            goto out;
        }
        if (n == 0)
            break;
        ssize_t k = read_some(key, buf_pad, (size_t)n);
        if (k != n) {
            if (!pnp_stop)
                say("%s ended early or can't be read", key_path);
            goto out;
        }
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (pnp_write_all(out.fd, buf_out, (size_t)n) < 0) {
            say("can't write %s: %s", out_path, strerror(errno));
            goto out;
        }
        total += n;
    }
    if (total + HEADER_LEN != ct_st.st_size || read_some(key, buf_pad, 1) != 0) {
        say("%s or %s changed while pnp was reading them", ct_path, key_path);
        goto out;
    }
    if (pnp_out_commit(&out, force, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    pnp_sync_dir(out_path);
    if (!quiet)
        say("wrote %s", out_path);
    ret = 0;
out:
    wipe_buffers();
    pnp_out_discard(&out);
    if (ct >= 0)
        close(ct);
    if (key >= 0)
        close(key);
    free(key_path);
    free(out_path);
    return ret;
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"decrypt", no_argument, NULL, 'd'}, {"key", required_argument, NULL, 'k'},
        {"output", required_argument, NULL, 'o'}, {"force", no_argument, NULL, 'f'},
        {"quiet", no_argument, NULL, 'q'}, {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'}, {"help", no_argument, NULL, 'h'},
        {"sources", no_argument, NULL, 'S'}, {NULL, 0, NULL, 0},
    };
    int dec = 0, force = 0, verbose = 0, sources = 0, c;
    const char *key_opt = NULL, *out_opt = NULL;

    while ((c = getopt_long(argc, argv, "dk:o:fqvVh", opts, NULL)) != -1) {
        switch (c) {
        case 'd': dec = 1; break;
        case 'k': key_opt = optarg; break;
        case 'o': out_opt = optarg; break;
        case 'f': force = 1; break;
        case 'q': quiet = 1; break;
        case 'v': verbose = 1; break;
        case 'S': sources = 1; break;
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
    if (key_opt && !dec) {
        say("-k is for decrypting (the key is always written beside the ciphertext as OUT.key)");
        return 2;
    }
    int ret = dec ? decrypt(argv[optind], key_opt, out_opt, force) : encrypt(argv[optind], out_opt, force, verbose);
    exit_for_signal();
    return ret;
}
