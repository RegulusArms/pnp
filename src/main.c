/* pnp: one-time pad file encryption that stays secure even if P = NP.
 *
 *   pnp FILE            FILE -> FILE.pnp (ciphertext) + FILE.pnp.key (the pad)
 *   pnp -d FILE.pnp     FILE.pnp + FILE.pnp.key -> FILE
 *   pnp                 alone, in a terminal: the interactive mode (tui.c), which calls pnp_encrypt / pnp_decrypt
 *
 * The file formats are in docs/format.md and format.h: a 24-byte header (magic, then a 16-byte ID shared by a
 * ciphertext and its key, so a mismatched key is refused), then the body. ciphertext body = plaintext XOR pad; key body = pad.
 * The integrity check (mac.c): a one-time MAC of ID || plaintext, keyed by 32 more hardware-random bytes at the start
 * of the key's body; its tag ends the ciphertext. Decrypting renames the output into place only if the tag matches.
 *
 * --key-out writes the key straight into another folder (a USB stick, say), so it never touches the internal disk.
 * --shares N writes the key as N shares instead of one key file: shares 1..N-1 are fresh hardware-random pads and
 * share N is pad XOR all of them. Any N-1 shares are uniformly random whatever the pad is, so they reveal nothing
 * (information-theoretically, like the pad itself); all N XORed together give the pad back.
 * --protect also encrypts the key (or each share) under a passphrase (protect.c): only computationally secure, an
 * extra hurdle for whoever steals a key file, not part of the P = NP guarantee. --gen-passphrase makes a passphrase
 * of words from the EFF large word list, chosen with the same random sources as the pad. */
#define _GNU_SOURCE
#include "fileio.h"
#include "kdf.h"
#include "mac.h"
#include "pnp.h"
#include "progress.h"
#include "protect.h"
#include "rng.h"
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PNP_VERSION
#define PNP_VERSION "unknown"
#endif

#include "format.h"



#define CHUNK 65536

extern volatile sig_atomic_t pnp_stop;

/* Every buffer that holds secrets lives in one region (secure_setup): plaintext, pad, output and share chunks, the
 * passphrase, a passphrase given in advance (pnp_preset_passphrase), and two scratch passphrase buffers for the
 * interactive mode and --gen-passphrase (pnp_secure_buf). The region is locked in RAM where the limit allows (never
 * swapped), left out of core dumps, wiped in any child if something ever forked (MADV_WIPEONFORK), and wiped
 * after use. */
static uint8_t *buf_in, *buf_pad, *buf_out, *buf_share;
static char *pass, *preset, *scratch[2];
#define SECURE_LEN (4 * CHUNK + 4 * PNP_PASS_MAX)
static int mlock_failed; /* the region or the stack window couldn't be locked: said once, or refused with --strict */
static int strict;       /* --strict: refuse to work with secrets that can't be locked in memory */

static int quiet;
static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int sandbox_early;  /* the early seccomp filter is on (sandbox.c) */
static int sandbox_cli;    /* a command-line run: fence pnp in once its files are open (not the interactive mode) */
static int sandbox_say;    /* -v: say what the sandbox could do */

static void wipe_buffers(void)
{
    explicit_bzero(buf_in, CHUNK);
    explicit_bzero(buf_pad, CHUNK);
    explicit_bzero(buf_out, CHUNK);
    explicit_bzero(buf_share, CHUNK);
    explicit_bzero(pass, PNP_PASS_MAX);
}

char *pnp_secure_buf(int which) { return scratch[which & 1]; }

static void on_signal(int sig) { pnp_stop = sig; }

/* The main thread's stack, where short-lived secrets sit in local variables: the MAC key, the key a passphrase
 * makes, the passphrase typed a second time, the hashes' last blocks. A window of it below main() is touched (so
 * the pages exist) and locked, which covers every deeper call frame within it. 256 KiB is far more than pnp's
 * calls go down, and well inside the usual 8 MiB limit. The threads Argon2id starts have stacks of their own,
 * which this doesn't cover: they hold blocks of the hash's memory, which is locked only when the limit allows
 * (kdf.c). */
#define STACK_LOCK (256 * 1024)
static __attribute__((noinline)) int lock_stack(void)
{
    volatile uint8_t window[STACK_LOCK];
    for (size_t i = 0; i < sizeof window; i += 4096)
        window[i] = 0;
    uintptr_t lo = (uintptr_t)window & ~(uintptr_t)4095, hi = (uintptr_t)window + sizeof window;
    return mlock((void *)lo, hi - lo);
}

/* the secure region (see the top of this file), with the stack window */
static void secure_setup(void)
{
    uint8_t *r = mmap(NULL, SECURE_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED) {
        fprintf(stderr, "pnp: out of memory\n");
        exit(1);
    }
    madvise(r, SECURE_LEN, MADV_DONTDUMP);
#ifdef MADV_WIPEONFORK
    madvise(r, SECURE_LEN, MADV_WIPEONFORK); /* pnp never forks; this is for anything that ever might */
#endif
    buf_in = r, buf_pad = r + CHUNK, buf_out = r + 2 * CHUNK, buf_share = r + 3 * CHUNK;
    pass = (char *)r + 4 * CHUNK, preset = pass + PNP_PASS_MAX;
    scratch[0] = preset + PNP_PASS_MAX, scratch[1] = scratch[0] + PNP_PASS_MAX;
    /* kept out of swap, where pad, plaintext or passphrase bytes would outlive the run. The limit (ulimit -l) is
     * usually 8 MiB, plenty for these; if it's lower, pnp says so (note_unlocked), or with --strict refuses. */
    mlock_failed = mlock(r, SECURE_LEN) < 0;
    mlock_failed |= lock_stack() < 0;
}

/* whether len more bytes could be locked: the limit, less what's locked already and some room */
static int can_lock(uint64_t len)
{
    struct rlimit rl;
    if (geteuid() == 0 || (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY))
        return 1;
    return getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur >= len + SECURE_LEN + STACK_LOCK + (1 << 20);
}

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
    secure_setup();
    sandbox_early = pnp_sandbox_early() == 0;
}

/* Once every file a command-line run reads is open and every output's part file exists, the rest of the run
 * needs only those folders and a few system calls: pnp_sandbox_work fences it in (sandbox.c). The interactive mode
 * goes on to other files afterwards, so it keeps only the early filter. */
static void fence_in(char *const *paths, int n)
{
    if (!sandbox_cli)
        return;
    char *dirs[MAX_SHARES + 1] = {0};
    int nd = 0;
    for (int i = 0; i < n; i++)
        if ((dirs[nd] = pnp_dir_of(paths[i])))
            nd++;
    struct pnp_sandbox_state st;
    pnp_sandbox_work(dirs, nd, &st);
    for (int i = 0; i < nd; i++)
        free(dirs[i]);
    if (sandbox_say) {
        char ll[64] = "not available in this kernel";
        if (st.landlock_abi > 0)
            snprintf(ll, sizeof ll, "on (ABI %d)", st.landlock_abi);
        say("sandbox: no new privileges; seccomp %s, %s; Landlock %s", sandbox_early ? "on" : "off",
            st.seccomp ? "work filter on" : "work filter off", ll);
    }
#ifdef PNP_TEST
    /* test hook: what the sandbox lets through now */
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
        char *pdir = pnp_dir_of(probe); /* what pnp_sync_dir does after saving: must pass */
        fd = pdir ? open(pdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
        fprintf(stderr, "probe folder: %s\n", fd >= 0 ? "allowed" : strerror(errno));
        if (fd >= 0)
            close(fd);
        free(pdir);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        fprintf(stderr, "probe socket: %s\n", fd >= 0 ? "allowed" : strerror(errno));
        if (getenv("PNP_TEST_PROBE_EXEC"))
            execl("/bin/true", "true", (char *)NULL); /* must kill the process */
    }
#endif
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

/* File names come from disk and can hold anything, including escape sequences that would move the cursor, retitle
 * the window or worse when printed. Every message goes through this: control characters (C0, DEL, and C1 as UTF-8)
 * become "?". */
void pnp_clean(char *s)
{
    for (unsigned char *p = (unsigned char *)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            *p = '?';
        else if (p[0] == 0xc2 && p[1] >= 0x80 && p[1] < 0xa0)
            p[0] = '?', p[1] = '?';
    }
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    pnp_clean(msg);
#ifdef PNP_FUZZ
    return; /* tests/fuzz: formatted and cleaned (so that's fuzzed too), but stderr is left to the fuzzer */
#endif
    pnp_progress_interrupt(); /* a progress line on the screen is wiped first */
    fprintf(stderr, "pnp: %s\n", msg);
}

static void usage(FILE *f)
{
    fprintf(f,
            "usage: pnp [-f] [-q] [-o OUT] [--key-out PATH] [--shares N]\n"
            "           [--protect [--kdf-memory MIB] [--passphrase-file FILE]] FILE\n"
            "                                    encrypt FILE to FILE.pnp and its key FILE.pnp.key\n"
            "       pnp -d [-f] [-q] [-k KEY]... [-o OUT] [--passphrase-file FILE] FILE.pnp\n"
            "                                    decrypt FILE.pnp with FILE.pnp.key (or its shares) to FILE\n"
            "       pnp --verify [-q] [-k KEY]... [--passphrase-file FILE] FILE.pnp\n"
            "                                    check FILE.pnp against its key or shares (IDs, sizes and the\n"
            "                                    integrity check) without writing anything\n"
            "       pnp [--strict]               (alone, in a terminal) browse files and encrypt or decrypt them\n"
            "       pnp --sources                list the hardware random sources and whether they're usable\n"
            "       pnp --gen-passphrase[=WORDS] print a random passphrase (7 words unless WORDS, 5-20;\n"
            "                                    each is 12.9 bits: 7 about 90, 10 about 128, 20 about 256)\n"
            "\n"
            "  -d, --decrypt   decrypt instead of encrypting\n"
            "  -k, --key KEY   the key file to decrypt with (default: FILE.pnp.key, or FILE.pnp.key.1, .2...);\n"
            "                  give -k once per share for a key split with --shares\n"
            "  -o, --output OUT  where to write: the ciphertext when encrypting (its key goes to OUT.key),\n"
            "                  the plaintext when decrypting\n"
            "      --key-out PATH  write the key straight into this folder (or to this file name) instead of\n"
            "                  beside the ciphertext; with --shares, once for all shares or once per share\n"
            "      --shares N  split the key into N shares (2-16), all of them needed to decrypt\n"
            "      --protect   also encrypt the key (or each share) under a passphrase, so a stolen key file\n"
            "                  is slow to use. Computationally secure only: not part of pnp's P = NP guarantee\n"
            "      --kdf-memory MIB  memory each passphrase guess costs, for --protect (default %d, %d-%d)\n"
            "      --passphrase-file FILE  read the passphrase from FILE's first line instead of the terminal\n"
            "  -f, --force     replace output files that already exist\n"
            "      --strict    refuse to run if pad, file or passphrase bytes can't be locked in memory (kept\n"
            "                  out of swap), instead of only warning; with --protect, the hashes' memory too\n"
            "  -q, --quiet     don't print which random sources made the pad, notes, or progress\n"
            "  -v, --verbose   print every random source and its state\n"
            "  -V, --version   print the version\n"
            "  -h, --help      print this help\n"
            "\n"
            "Keep the key secret, away from the ciphertext, and never use it for anything else.\n",
            PNP_PROTECT_MIB, PNP_PROTECT_MIB_MIN, PNP_PROTECT_MIB_MAX);
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

/* -1 (after saying why) when --strict and the buffers aren't locked; otherwise a note, once */
static int check_locked(void)
{
    static int said;
    if (mlock_failed && strict) {
        say("--strict: pnp couldn't lock its buffers in memory (the limit, ulimit -l, is too low), so it stops "
            "rather than risk pad, file or passphrase bytes reaching swap. Raise the limit (ulimit -l 8192) or "
            "leave out --strict.");
        return -1;
    }
    if (mlock_failed && !quiet && !said++)
        say("note: pnp couldn't lock its buffers in memory (the limit, ulimit -l, is too low), so pad and file "
            "bytes could be written to swap. Raise the limit or turn swap off (or use --strict to stop instead).");
    return 0;
}

/* --strict and --protect: the passphrase hashes' memory must be lockable too (kdf.c locks it when it can) */
static int check_kdf_lockable(const struct pnp_protect *p)
{
    uint64_t need = (uint64_t)pnp_protect_need_mib(p) << 20;
    pnp_kdf_set_strict(strict);
    if (strict && !can_lock(need)) {
        say("--strict: the passphrase hashes need %u MiB locked in memory, more than the limit (ulimit -l) allows. "
            "Raise it (ulimit -l %llu, or memlock in /etc/security/limits.conf), choose less with --kdf-memory when "
            "encrypting, or leave out --strict.",
            pnp_protect_need_mib(p), (unsigned long long)((need + SECURE_LEN + STACK_LOCK + (2 << 20)) >> 10));
        return -1;
    }
    return 0;
}

/* a virtual machine's host can see everything: said before making a pad or passphrase there */
static void note_vm(void)
{
    char vm[64];
    if (pnp_in_vm(vm, sizeof vm))
        say("note: this is a virtual machine (%s). Its host can read the pad and your file from memory, and can "
            "decide what RDSEED and /dev/hwrng return: encrypt on a physical machine unless you trust the host.",
            vm);
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

/* opens the hardware sources for making what (a pad, a passphrase); returns -1 (after explaining) if none can be
 * used */
static int open_sources(struct pnp_rng *rng, int verbose, const char *what)
{
    pnp_rng_open(rng);
    if (verbose) {
        fprintf(stderr, "pnp: random sources:\n");
        list_sources(rng, stderr);
    }
    if (rng->hardware_ok == 0) {
        say("no usable hardware random source, so pnp won't make a %s: a one-time pad from software randomness "
            "alone isn't safe if P = NP.",
            what);
        if (!verbose)
            list_sources(rng, stderr);
        if (hwrng_denied(rng))
            explain_denied();
        return -1;
    }
    if (!quiet) {
        char desc[256];
        pnp_rng_describe(rng, desc, sizeof desc);
        say("%s from %s", what, desc);
        note_vm();
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
        char num[16] = "";
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

/* A run killed or cut off by a power loss partway leaves hidden files behind (fileio.c): parts of outputs that
 * were never finished, and, with -f, old files moved aside that were never put back. Said before writing into a
 * folder that holds any, with what to do (docs/recovery.md). Nothing is deleted or renamed automatically: only
 * the user can tell which copy they want. */
struct leftovers {
    int total, here; /* found in all folders, and in this one */
};

static void leftover_found(const char *dir, const char *entry, const char *name, int old, void *ctx)
{
    struct leftovers *n = ctx;
    n->total++;
    if (n->here++ == 0) /* a heading for each folder: the key's may be on another drive */
        say("note: %s holds files left by a pnp run that was interrupted (a crash, a kill or a power cut):", dir);
    char line[1024];
    if (old)
        snprintf(line, sizeof line, "  %s: the old %s, moved aside by pnp -f to be replaced. To undo that run, put "
                 "back every .pnp-old file it left (ciphertext and key together): mv -f '%s/%s' '%s/%s'", entry, name,
                 dir, entry, dir, name);
    else
        snprintf(line, sizeof line, "  %s: an unfinished %s (it may hold pad or plaintext bytes). Delete it, and run "
                 "pnp again if %s is missing", entry, name, name);
    pnp_clean(line);
    fprintf(stderr, "%s\n", line);
}

static void note_leftovers(char *const *paths, int n)
{
    char *seen[MAX_SHARES + 2] = {0};
    if (n > MAX_SHARES + 2)
        n = MAX_SHARES + 2;
    struct leftovers found = {0, 0};
    for (int i = 0; i < n && !quiet; i++) {
        char *dir = pnp_dir_of(paths[i]), *real = dir ? realpath(dir, NULL) : NULL;
        int dup = !real;
        for (int j = 0; real && j < i; j++)
            dup |= seen[j] && strcmp(seen[j], real) == 0;
        found.here = 0;
        if (!dup)
            pnp_find_leftovers(dir, leftover_found, &found);
        seen[i] = real;
        free(dir);
    }
    if (found.total)
        fprintf(stderr, "  (more in docs/recovery.md, or man pnp under RECOVERY)\n");
    for (int i = 0; i < n; i++)
        free(seen[i]);
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

/* Writes n bytes of key material (the pad, or the MAC key) to the key files: all to the key, or split into shares:
 * shares 1..N-1 get fresh bytes from the sources, share N the material XOR all of them (buf is changed). With
 * --protect (wrap not NULL), each file's bytes are XORed with its ChaCha20 keystream as they're written. Returns 0,
 * or -1 with *failed set to the file a write failed on, or left NULL when the sources failed (message in err). */
static int write_key_material(struct pnp_out *key, char *const *key_path, int nkeys, struct pnp_rng *rng,
                              struct pnp_chacha20 *wrap, uint8_t *buf, size_t n, const char **failed, char *err,
                              size_t errlen)
{
    for (int k = 0; k < nkeys - 1; k++) {
        if (pnp_rng_fill(rng, buf_share, n, err, errlen) < 0)
            return -1;
        for (size_t i = 0; i < n; i++)
            buf[i] ^= buf_share[i];
        if (wrap)
            pnp_chacha20_xor(&wrap[k], buf_share, n);
        if (pnp_write_all(key[k].fd, buf_share, n) < 0) {
            *failed = key_path[k];
            return -1;
        }
    }
    if (wrap)
        pnp_chacha20_xor(&wrap[nkeys - 1], buf, n);
    if (pnp_write_all(key[nkeys - 1].fd, buf, n) < 0) {
        *failed = key_path[nkeys - 1];
        return -1;
    }
    return 0;
}

/* A passphrase given in advance (the interactive mode asks once for a whole batch of files): used instead of
 * asking, until cleared. Locked in RAM and wiped like the rest. */
static long preset_len = -1;

void pnp_preset_passphrase(const char *p, size_t len)
{
    if (len >= PNP_PASS_MAX)
        len = PNP_PASS_MAX - 1;
    memcpy(preset, p, len);
    preset[len] = 0;
    preset_len = (long)len;
}

void pnp_clear_passphrase(void)
{
    explicit_bzero(preset, PNP_PASS_MAX);
    preset_len = -1;
}

/* the passphrase into pass: the preset one, or else from file or the terminal */
static long get_passphrase(const char *file, int confirm, char *err, size_t errlen)
{
    if (preset_len >= 0) {
        memcpy(pass, preset, (size_t)preset_len + 1);
        return preset_len;
    }
    return pnp_read_passphrase(file, confirm, pass, PNP_PASS_MAX, err, errlen);
}

/* A progress line for the passphrase hashes (kdf.c reports Balloon, then Argon2id): one line per phase. */
static struct pnp_progress kdf_prog;
static const char *kdf_phase;

static void kdf_progress(const char *phase, uint64_t done, uint64_t total)
{
    if (phase != kdf_phase) {
        pnp_progress_end(&kdf_prog);
        kdf_phase = phase;
        pnp_progress_start_steps(&kdf_prog, "hashing passphrase:", phase, total, !quiet);
    }
    pnp_progress_set(&kdf_prog, done);
}

static void kdf_progress_on(void)
{
    kdf_phase = NULL;
    pnp_kdf_set_progress(kdf_progress);
}

static void kdf_progress_off(void)
{
    pnp_kdf_set_progress(NULL);
    pnp_progress_end(&kdf_prog);
    kdf_phase = NULL;
}

/* the memory the passphrase hashing takes, for messages */
static uint32_t kdf_mib(const struct pnp_protect *p) { return p->argon_kib / 1024; }

/* the free memory hashing with p needs, or -1 if there's less than that (how much is free then in *avail) */
static int memory_short(const struct pnp_protect *p, long *avail)
{
    *avail = pnp_mem_available_mib();
    return *avail >= 0 && *avail < (long)pnp_protect_need_mib(p) ? -1 : 0;
}

int pnp_encrypt(const char *in_path, const char *out_opt, char *const *key_outs, int n_key_outs, int shares,
                int force, int verbose, const struct protect_opts *po)
{
    int nkeys = shares >= 2 && shares <= MAX_SHARES ? shares : 1; /* key files: the key, or its shares */
    if (shares && nkeys != shares) { /* callers check this; here so the arrays below can't overflow */
        say("--shares takes a number from 2 to %d", MAX_SHARES);
        return 2;
    }
    char *ct_path = NULL, *key_path[MAX_SHARES] = {0};
    const char *failed = NULL; /* the output a write failed on */
    struct pnp_out ct, key[MAX_SHARES];
    struct pnp_rng rng;
    struct pnp_mac mac;
    struct pnp_protect prot;
    struct pnp_chacha20 wrap[MAX_SHARES];
    uint8_t mackey[PNP_MAC_KEY_LEN], tag[PNP_MAC_TAG_LEN], wkey[32], pblock[PNP_PROTECT_LEN];
    char err[512];
    int ret = 1, in = -1;
    struct stat st;

    struct pnp_progress prog;
    memset(&prog, 0, sizeof prog);
    memset(&mac, 0, sizeof mac);
    memset(wrap, 0, sizeof wrap);
    memset(&ct, 0, sizeof ct);
    memset(key, 0, sizeof key);
    ct.fd = -1;
    for (int i = 0; i < nkeys; i++)
        key[i].fd = -1;
    memset(&rng, 0, sizeof rng);

    if (check_locked() < 0 || (in = open_input(in_path, &st)) < 0)
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
    note_leftovers(all, nkeys + 1);
    if (open_sources(&rng, verbose, "pad") < 0)
        goto out;
    if (po->on) {
        if ((uint64_t)st.st_size + PNP_MAC_KEY_LEN > PNP_PROTECT_MAX_BYTES) {
            say("--protect works for files up to 256 GiB");
            goto out;
        }
        long plen = get_passphrase(po->passfile, !po->passfile, err, sizeof err);
        if (plen < 0) {
            if (!pnp_stop)
                say("%s", err);
            goto out;
        }
        if (!quiet && plen < 20)
            say("note: a short passphrase can be guessed however slow each guess is; for a strong one, run: pnp "
                "--gen-passphrase");
        if (pnp_protect_new(&prot, po->mib) < 0) {
            say("getrandom: %s", strerror(errno));
            goto out;
        }
        long avail;
        if (check_kdf_lockable(&prot) < 0)
            goto out;
        if (memory_short(&prot, &avail) < 0) {
            say("--protect needs about %u MiB of free memory here (and again on the computer that decrypts), but "
                "only %ld MiB is available: choose less with --kdf-memory, or close other programs",
                pnp_protect_need_mib(&prot), avail);
            goto out;
        }
        if (!quiet)
            say("protecting the key with the passphrase (Balloon and Argon2id, %u MiB, %u lanes)...", kdf_mib(&prot),
                prot.argon_lanes);
        kdf_progress_on();
        int locked = pnp_protect_lock(&prot, pass, (size_t)plen, wkey);
        kdf_progress_off();
        if (locked < 0) {
            say("can't get%s the %u MiB of memory --protect needs (choose less with --kdf-memory)",
                strict ? " and lock" : "", kdf_mib(&prot));
            goto out;
        }
        explicit_bzero(pass, PNP_PASS_MAX);
        pnp_protect_encode(&prot, pblock);
        for (int i = 0; i < nkeys; i++)
            pnp_protect_stream(&wrap[i], wkey, shares ? i + 1 : 0);
        explicit_bzero(wkey, sizeof wkey);
    }

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
    fence_in(all, nkeys + 1);
    for (int i = 0; i < nkeys; i++) {
        memcpy(header, shares ? (po->on ? MAGIC_SHARE_P : MAGIC_SHARE) : po->on ? MAGIC_KEY_P : MAGIC_KEY, MAGIC_LEN);
        header[HEADER_LEN] = (uint8_t)(i + 1);
        header[HEADER_LEN + 1] = (uint8_t)nkeys;
        if (pnp_write_all(key[i].fd, header, shares ? SHARE_HEADER_LEN : HEADER_LEN) < 0 ||
            (po->on && pnp_write_all(key[i].fd, pblock, sizeof pblock) < 0)) {
            failed = key_path[i];
            goto write_failed;
        }
    }
    memcpy(header, MAGIC_CT, MAGIC_LEN);
    if (pnp_write_all(ct.fd, header, HEADER_LEN) < 0) {
        failed = ct_path;
        goto write_failed;
    }
    /* the integrity check's one-time key: fresh from the sources, first in the key's body (split like the pad) */
    do {
        if (pnp_rng_fill(&rng, mackey, sizeof mackey, err, sizeof err) < 0)
            goto rng_failed;
    } while (pnp_mac_key_fix(mackey) < 0);
    pnp_mac_init(&mac, mackey);
    pnp_mac_feed(&mac, header + MAGIC_LEN, ID_LEN);
    if (write_key_material(key, key_path, nkeys, &rng, po->on ? wrap : NULL, mackey, sizeof mackey, &failed, err,
                           sizeof err) < 0)
        goto material_failed;

    pnp_progress_start(&prog, "encrypting", in_path, (uint64_t)st.st_size, !quiet);
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
        pnp_mac_feed(&mac, buf_in, (size_t)n);
        if (pnp_rng_fill(&rng, buf_pad, (size_t)n, err, sizeof err) < 0)
            goto rng_failed;
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (pnp_write_all(ct.fd, buf_out, (size_t)n) < 0) {
            failed = ct_path;
            goto write_failed;
        }
        if (write_key_material(key, key_path, nkeys, &rng, po->on ? wrap : NULL, buf_pad, (size_t)n, &failed, err,
                               sizeof err) < 0)
            goto material_failed;
        pnp_progress_add(&prog, (uint64_t)n);
    }
    pnp_progress_end(&prog);
    pnp_mac_final(&mac, tag);
    if (pnp_write_all(ct.fd, tag, sizeof tag) < 0) {
        failed = ct_path;
        goto write_failed;
    }
    /* With -f, the files being replaced are moved aside first, and deleted only once every new file is in place:
     * if anything below fails, discarding puts them back (fileio.c). So an old key is never lost. */
    if (force) {
        for (int i = 0; i < nkeys; i++) {
            if (pnp_out_aside(&key[i], err, sizeof err) < 0) {
                say("%s", err);
                goto out;
            }
        }
        if (pnp_out_aside(&ct, err, sizeof err) < 0) {
            say("%s", err);
            goto out;
        }
    }
    /* the key first: a ciphertext without its key would be lost data, a stray key is only noise */
    for (int i = 0; i < nkeys; i++) {
        if (pnp_out_commit(&key[i], 0, err, sizeof err) < 0) {
            say("%s", err);
            goto unplace;
        }
    }
    if (pnp_out_commit(&ct, 0, err, sizeof err) < 0) {
        say("%s", err);
        goto unplace;
    }
    pnp_sync_dir(ct_path);
    for (int i = 0; i < nkeys; i++)
        pnp_sync_dir(key_path[i]);
    pnp_out_drop_old(&ct);
    for (int i = 0; i < nkeys; i++)
        pnp_out_drop_old(&key[i]);
    if (!quiet && !shares) {
        say("wrote %s and %s%s. Keep the key secret and apart from the .pnp file.", ct_path, key_path[0],
            po->on ? " (protected with the passphrase)" : "");
    } else if (!quiet) {
        say("wrote %s, and its key as %d shares%s. All of them are needed to decrypt: keep them in different places.",
            ct_path, nkeys, po->on ? " (each protected with the passphrase)" : "");
        for (int i = 0; i < nkeys; i++)
        {
            char line[PATH_MAX];
            snprintf(line, sizeof line, "%s", key_path[i]);
            pnp_clean(line);
            fprintf(stderr, "  %s\n", line);
        }
    }
    ret = 0;
    goto out;

unplace:
    for (int i = 0; i < nkeys; i++)
        pnp_out_unplace(&key[i]);
    goto out;
material_failed:
    if (failed)
        goto write_failed;
rng_failed:
    if (!pnp_stop)
        say("%s. Nothing was written.", err);
    goto out;
write_failed:
    say("can't write %s: %s", failed, strerror(errno));
out:
    pnp_progress_end(&prog);
    wipe_buffers();
    explicit_bzero(&mac, sizeof mac);
    explicit_bzero(mackey, sizeof mackey);
    explicit_bzero(wkey, sizeof wkey);
    explicit_bzero(wrap, sizeof wrap);
    pnp_rng_close(&rng); /* closes the sources (it needs rng's count) and wipes rng */
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

enum pnp_kind { KIND_CT = PNP_H_CT, KIND_KEY = PNP_H_KEY, KIND_SHARE = PNP_H_SHARE };

struct pnp_file {
    int fd;
    enum pnp_kind kind;
    uint8_t id[ID_LEN];
    int version;    /* 1 (no integrity check) or 2 */
    int num, count; /* a share: its number (1..count) and how many there are */
    off_t body;     /* the length of the plaintext it's for: its size less its header, MAC key or tag */
    int prot;       /* protected with a passphrase (--protect): pp holds its settings */
    struct pnp_protect pp;
};

/* Opens a ciphertext (want KIND_CT) or a key or share (want KIND_KEY) and reads its header (pnp_hdr_parse, the
 * same parser the interactive mode uses), leaving the file at the start of its body. Returns 0, or -1 after saying
 * why (f->fd is then -1). */
static int open_pnp_file(const char *path, enum pnp_kind want, struct pnp_file *f)
{
    struct stat st;
    struct pnp_hdr h;
    uint8_t b[PNP_HDR_MAX];
    f->fd = open_input(path, &st);
    if (f->fd < 0)
        return -1;
    ssize_t n = read_some(f->fd, b, sizeof b);
    int r = n < 0 ? PNP_HDR_NOT_PNP : pnp_hdr_parse(b, (size_t)n, (uint64_t)st.st_size, &h);
    if (n < 0) {
        say("can't read %s: %s", path, strerror(errno));
        goto fail;
    }
    if (want == KIND_CT && (h.kind == PNP_H_KEY || h.kind == PNP_H_SHARE)) {
        say("%s is a pnp %s, not a ciphertext", path, h.kind == PNP_H_KEY ? "key" : "key share");
        goto fail;
    }
    if (want == KIND_KEY && h.kind == PNP_H_CT) {
        say("%s is a pnp ciphertext, not a key", path);
        goto fail;
    }
    switch (r) {
    case PNP_HDR_OK: break;
    case PNP_HDR_NOT_PNP:
        say("%s isn't a pnp %s (or it's from a newer version of pnp)", path, want == KIND_CT ? "ciphertext" : "key");
        goto fail;
    case PNP_HDR_BAD_SHARE: say("%s is a damaged key share", path); goto fail;
    case PNP_HDR_BAD_PROTECT:
        say("%s asks for passphrase settings pnp doesn't accept: it's damaged, or from a newer version of pnp", path);
        goto fail;
    default: say("%s is too short: it's damaged or incomplete", path); goto fail;
    }
    /* the body starts right after the header; a file larger than off_t can hold can't exist here */
    if (lseek(f->fd, (off_t)h.len, SEEK_SET) < 0) {
        say("can't read %s: %s", path, strerror(errno));
        goto fail;
    }
    f->kind = (enum pnp_kind)h.kind;
    memcpy(f->id, h.id, ID_LEN);
    f->version = h.version;
    f->num = h.num;
    f->count = h.count;
    f->body = (off_t)h.body;
    f->prot = h.prot;
    f->pp = h.pp;
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
        if (memcmp(kf[k].id, ct->id, ID_LEN) != 0 || kf[k].version != ct->version) {
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

/* For keys protected with --protect: asks for the passphrase once, unlocks each (once for all the shares of one
 * encryption: they share their settings and salt) and starts its keystream in wrap[k]. -1 after saying why. */
static int unlock_keys(char *const *kp, const struct pnp_file *kf, int nk, const char *passfile,
                       struct pnp_chacha20 *wrap)
{
    uint8_t wkey[32];
    char err[512];
    const struct pnp_protect *done = NULL; /* the settings wkey was made from */
    long plen = -1;
    int ret = -1;
    for (int k = 0; k < nk; k++) {
        if (!kf[k].prot)
            continue;
        if (plen < 0 && (plen = get_passphrase(passfile, 0, err, sizeof err)) < 0) {
            if (!pnp_stop)
                say("%s", err);
            goto out;
        }
        if (!done || memcmp(&kf[k].pp, done, sizeof *done) != 0) {
            long avail;
            if (check_kdf_lockable(&kf[k].pp) < 0)
                goto out;
            if (memory_short(&kf[k].pp, &avail) < 0) {
                say("unlocking %s needs about %u MiB of free memory, but only %ld MiB is available: close other "
                    "programs, or decrypt on a computer with more memory",
                    kp[k], pnp_protect_need_mib(&kf[k].pp), avail);
                goto out;
            }
            if (!quiet)
                say("unlocking the key with the passphrase (Balloon and Argon2id, %u MiB)...", kdf_mib(&kf[k].pp));
            kdf_progress_on();
            int r = pnp_protect_unlock(&kf[k].pp, pass, (size_t)plen, wkey);
            kdf_progress_off();
            if (r == -1) {
                say("can't get%s the %u MiB of memory unlocking %s needs", strict ? " and lock" : "",
                    kdf_mib(&kf[k].pp), kp[k]);
                goto out;
            }
            if (r == -2) {
                say("wrong passphrase for %s (or the key is damaged). Nothing was written.", kp[k]);
                goto out;
            }
            done = &kf[k].pp;
        }
        pnp_protect_stream(&wrap[k], wkey, kf[k].kind == KIND_SHARE ? kf[k].num : 0);
    }
    ret = 0;
out:
    explicit_bzero(pass, PNP_PASS_MAX);
    explicit_bzero(wkey, sizeof wkey);
    return ret;
}

int pnp_decrypt(const char *ct_path, char *const *key_opts, int n_key_opts, const char *out_opt, int force,
                const char *passfile, int verify)
{
    char *kp[MAX_SHARES] = {0}, *out_path = NULL;
    struct pnp_file ct, kf[MAX_SHARES];
    struct pnp_out out;
    struct pnp_mac mac;
    struct pnp_chacha20 wrap[MAX_SHARES];
    uint8_t mackey[PNP_MAC_KEY_LEN] = {0}, tag[PNP_MAC_TAG_LEN], want[PNP_MAC_TAG_LEN];
    char err[512];
    int ret = 1, nk = 0, find_shares = 0;
    struct stat st;

    struct pnp_progress prog;
    memset(&prog, 0, sizeof prog);
    memset(&mac, 0, sizeof mac);
    memset(wrap, 0, sizeof wrap);
    memset(&out, 0, sizeof out);
    out.fd = -1;
    ct.fd = -1;
    for (int k = 0; k < MAX_SHARES; k++)
        kf[k].fd = -1;

    if (check_locked() < 0)
        goto out;
    if (verify) {
        out_path = strdup("(none)"); /* --verify writes nothing */
    } else if (out_opt) {
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
    if (verify) {
        /* nothing is written, so no output to check */
    } else if (fstat(ct.fd, &st) == 0 && same_file(out_path, &st)) {
        say("the output would overwrite the ciphertext or the key");
        goto out;
    }
    for (int k = 0; k < nk && !verify; k++) {
        if (fstat(kf[k].fd, &st) == 0 && same_file(out_path, &st)) {
            say("the output would overwrite the ciphertext or the key");
            goto out;
        }
    }
    if (!verify && !force && exists(out_path)) {
        say("%s already exists (use -f to replace it)", out_path);
        goto out;
    }
    /* where this run writes, and where the ciphertext and keys were written by the run that made them */
    char *dirs_to_check[MAX_SHARES + 2];
    int ndc = 0;
    if (!verify)
        dirs_to_check[ndc++] = out_path;
    dirs_to_check[ndc++] = (char *)ct_path;
    for (int k = 0; k < nk; k++)
        dirs_to_check[ndc++] = kp[k];
    note_leftovers(dirs_to_check, ndc);
    if (unlock_keys(kp, kf, nk, passfile, wrap) < 0)
        goto out;
    int checked = ct.version >= 2;
    if (checked) {
        /* the MAC key: the start of the key's body, or of every share's, XORed together */
        for (int k = 0; k < nk; k++) {
            if (read_some(kf[k].fd, k ? buf_share : mackey, sizeof mackey) != (ssize_t)sizeof mackey) {
                say("%s ended early or can't be read", kp[k]);
                goto out;
            }
            if (kf[k].prot)
                pnp_chacha20_xor(&wrap[k], k ? buf_share : mackey, sizeof mackey);
            for (size_t i = 0; k && i < sizeof mackey; i++)
                mackey[i] ^= buf_share[i];
        }
        if (pnp_mac_init(&mac, mackey) < 0) {
            say("the key for %s is damaged (its integrity check key isn't valid)", ct_path);
            goto out;
        }
        pnp_mac_feed(&mac, ct.id, ID_LEN);
    } else {
        say("note: %s is in pnp's old format (version 001, from pnp 0.1.0-alpha.2 or older), which has no integrity "
            "check: changes to it can't be detected",
            ct_path);
    }
    if (!verify && pnp_out_open(&out, out_path, 0600, err, sizeof err) < 0) {
        say("%s", err);
        goto out;
    }
    fence_in(&out_path, verify ? 0 : 1);
    pnp_progress_start(&prog, verify ? "verifying" : "decrypting", ct_path, (uint64_t)ct.body, !quiet);
    for (off_t left = ct.body; left > 0;) {
        if (pnp_stop)
            goto out;
        size_t chunk = left < CHUNK ? (size_t)left : CHUNK;
        ssize_t n = read_some(ct.fd, buf_in, chunk);
        if (n != (ssize_t)chunk) {
            if (!pnp_stop)
                say(n < 0 ? "can't read %s" : "%s ended early or changed while pnp was reading it", ct_path);
            goto out;
        }
        /* the pad: the key, or every share XORed together (in any order) */
        for (int k = 0; k < nk; k++) {
            if (read_some(kf[k].fd, k ? buf_share : buf_pad, (size_t)n) != n) {
                if (!pnp_stop)
                    say("%s ended early or can't be read", kp[k]);
                goto out;
            }
            if (kf[k].prot)
                pnp_chacha20_xor(&wrap[k], k ? buf_share : buf_pad, (size_t)n);
            for (ssize_t i = 0; k && i < n; i++)
                buf_pad[i] ^= buf_share[i];
        }
        for (ssize_t i = 0; i < n; i++)
            buf_out[i] = buf_in[i] ^ buf_pad[i];
        if (checked)
            pnp_mac_feed(&mac, buf_out, (size_t)n);
        if (!verify && pnp_write_all(out.fd, buf_out, (size_t)n) < 0) {
            say("can't write %s: %s", out_path, strerror(errno));
            goto out;
        }
        left -= n;
        pnp_progress_add(&prog, (uint64_t)n);
    }
    pnp_progress_end(&prog);
    if (checked && read_some(ct.fd, want, sizeof want) != (ssize_t)sizeof want) {
        say("%s ended early or changed while pnp was reading it", ct_path);
        goto out;
    }
    for (int k = -1; k < nk; k++) {
        if (read_some(k < 0 ? ct.fd : kf[k].fd, buf_pad, 1) != 0) {
            say("%s changed while pnp was reading it", k < 0 ? ct_path : kp[k]);
            goto out;
        }
    }
    /* the output is still a hidden part file: it takes its real name only if the integrity check passes */
    if (checked) {
        pnp_mac_final(&mac, tag);
        if (pnp_mac_tag_cmp(tag, want) != 0) {
            say("%s or its key has been changed or damaged: the integrity check failed.%s", ct_path,
                verify ? "" : " Nothing was written.");
            goto out;
        }
    }
    if (verify) {
        /* with -q, the exit status is the answer */
        if (quiet)
            ;
        else if (checked)
            say("%s is whole: its key %s, its size and its integrity check are right (%lld bytes; nothing written)",
                ct_path, nk > 1 ? "shares match it" : "matches it", (long long)ct.body);
        else
            say("%s matches its key and size, but it's in the old format without an integrity check, so its "
                "contents can't be checked",
                ct_path);
        ret = 0;
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
    goto out;
oom:
    say("out of memory");
out:
    pnp_progress_end(&prog);
    wipe_buffers();
    explicit_bzero(&mac, sizeof mac);
    explicit_bzero(mackey, sizeof mackey);
    explicit_bzero(wrap, sizeof wrap);
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

/* The EFF large word list (data/eff_large_wordlist.txt, CC BY 3.0 US), made into "word", lines by the Makefile:
 * 7776 = 6^5 words, so each is log2(7776) = 12.9 bits. */
static const char *const WORDS[] = {
#include "wordlist.h"
};
#define NWORDS 7776
_Static_assert(sizeof WORDS / sizeof *WORDS == NWORDS, "the EFF large word list has 7776 words");

/* n words into buf (space-separated), each chosen uniformly from the sources the pad would come from */
int pnp_make_passphrase(int n, char *buf, size_t len, int verbose)
{
    struct pnp_rng rng;
    char err[512];
    int ret = -1;
    size_t used = 0;
    memset(&rng, 0, sizeof rng);
    buf[0] = 0;
    if (check_locked() < 0 || open_sources(&rng, verbose, "passphrase") < 0)
        goto out;
    for (int i = 0; i < n; i++) {
        uint8_t b[2];
        unsigned v;
        do { /* uniform: 2 random bytes, redrawn above the largest multiple of 7776 (62208) */
            if (pnp_rng_fill(&rng, b, sizeof b, err, sizeof err) < 0) {
                say("%s", err);
                goto out;
            }
            v = (unsigned)b[0] << 8 | b[1];
        } while (v >= 65536 / NWORDS * NWORDS);
        int w = snprintf(buf + used, len - used, "%s%s", i ? " " : "", WORDS[v % NWORDS]);
        if (w < 0 || (size_t)w >= len - used) {
            say("passphrase buffer too small");
            goto out;
        }
        used += (size_t)w;
    }
    ret = 0;
out:
    if (ret < 0)
        explicit_bzero(buf, len);
    pnp_rng_close(&rng); /* closes the sources (it needs rng's count) and wipes rng */
    return ret;
}

/* --gen-passphrase: prints n words */
static int gen_passphrase(int n, int verbose)
{
    char *words = pnp_secure_buf(0);
    if (pnp_make_passphrase(n, words, PNP_PASS_MAX, verbose) < 0)
        return 1;
    printf("%s\n", words);
    fflush(stdout);
    explicit_bzero(words, PNP_PASS_MAX);
    if (!quiet)
        say("%d words from a list of %d: about %d bits. Write it down somewhere safe, away from the key.", n, NWORDS,
            n * 1292 / 100);
    return 0;
}

#ifdef PNP_FUZZ
/* tests/fuzz/fuzz_verify.c: what main() would set up, without options, signals or the sandbox */
void pnp_fuzz_init(void);
void pnp_fuzz_init(void)
{
    secure_setup();
    quiet = 1;
}
#endif

static int parse_int(const char *opt, const char *s, long lo, long hi, long *v)
{
    char *end;
    errno = 0;
    *v = strtol(s, &end, 10);
    if (errno || *end || end == s || *v < lo || *v > hi) {
        say("%s takes a number from %ld to %ld", opt, lo, hi);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    enum { OPT_SOURCES = 256, OPT_KEY_OUT, OPT_SHARES, OPT_PROTECT, OPT_KDF_MEMORY, OPT_PASSFILE, OPT_GEN, OPT_VERIFY, OPT_STRICT };
    static const struct option opts[] = {
        {"decrypt", no_argument, NULL, 'd'},         {"key", required_argument, NULL, 'k'},
        {"output", required_argument, NULL, 'o'},    {"force", no_argument, NULL, 'f'},
        {"quiet", no_argument, NULL, 'q'},           {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},         {"help", no_argument, NULL, 'h'},
        {"sources", no_argument, NULL, OPT_SOURCES}, {"key-out", required_argument, NULL, OPT_KEY_OUT},
        {"shares", required_argument, NULL, OPT_SHARES}, {"protect", no_argument, NULL, OPT_PROTECT},
        {"kdf-memory", required_argument, NULL, OPT_KDF_MEMORY},
        {"passphrase-file", required_argument, NULL, OPT_PASSFILE},
        {"gen-passphrase", optional_argument, NULL, OPT_GEN}, {"verify", no_argument, NULL, OPT_VERIFY},
        {"strict", no_argument, NULL, OPT_STRICT},
        {NULL, 0, NULL, 0},
    };
    int dec = 0, verify = 0, force = 0, verbose = 0, sources = 0, shares = 0, nkeys = 0, nkey_outs = 0, gen = 0, kdf_set = 0, c;
    struct protect_opts po = {0, PNP_PROTECT_MIB, NULL};
    long v;
    char *keys[MAX_SHARES], *key_outs[MAX_SHARES];
    const char *out_opt = NULL;

    while ((c = getopt_long(argc, argv, "dk:o:fqvVh", opts, NULL)) != -1) {
        switch (c) {
        case 'd': dec = 1; break;
        case OPT_VERIFY: verify = dec = 1; break;
        case OPT_STRICT: strict = 1; break;
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
        case OPT_SHARES:
            if (parse_int("--shares", optarg, 2, MAX_SHARES, &v) < 0)
                return 2;
            shares = (int)v;
            break;
        case OPT_PROTECT: po.on = 1; break;
        case OPT_KDF_MEMORY:
            if (parse_int("--kdf-memory", optarg, PNP_PROTECT_MIB_MIN, PNP_PROTECT_MIB_MAX, &v) < 0)
                return 2;
            po.mib = (uint32_t)v;
            kdf_set = 1;
            break;
        case OPT_PASSFILE: po.passfile = optarg; break;
        case OPT_GEN:
            if (parse_int("--gen-passphrase", optarg ? optarg : "7", 5, 20, &v) < 0)
                return 2;
            gen = (int)v;
            break;
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
#ifdef PNP_TEST
    /* test hook: one source's raw bytes to stdout, for tests/entropy/assess.sh */
    const char *dump = getenv("PNP_TEST_DUMP");
    if (dump) {
        const char *bytes = getenv("PNP_TEST_DUMP_BYTES");
        return pnp_rng_dump(dump, bytes ? strtoull(bytes, NULL, 10) : 1000000, STDOUT_FILENO) < 0 ? 1 : 0;
    }
#endif
    if (gen) {
        if (optind != argc) {
            usage(stderr);
            return 2;
        }
        int ret = gen_passphrase(gen, verbose);
        exit_for_signal();
        return ret;
    }
    if (sources) {
        struct pnp_rng rng;
        pnp_rng_open(&rng);
        printf("Hardware random sources:\n");
        list_sources(&rng, stdout);
        char vm[64];
        if (pnp_in_vm(vm, sizeof vm))
            printf("This is a virtual machine (%s): its host can read pnp's memory and decide what these sources "
                   "return.\n", vm);
        int ok = rng.hardware_ok;
        fflush(stdout);
        if (hwrng_denied(&rng))
            explain_denied();
        pnp_rng_close(&rng);
        if (!ok)
            printf("No usable hardware source: pnp can decrypt here but won't encrypt.\n");
        return ok ? 0 : 1;
    }
    /* just "pnp", in a terminal: the interactive mode (tui.c) */
    const char *term = getenv("TERM");
    if (argc == 1 + strict && optind == argc && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) && term &&
        strcmp(term, "dumb") != 0) {
        int ret = pnp_tui();
        pnp_clear_passphrase();
        exit_for_signal();
        return ret;
    }
    if (optind != argc - 1) {
        usage(stderr);
        return 2;
    }
    if (verify && (out_opt || force)) {
        say("--verify writes nothing, so -o and -f don't go with it");
        return 2;
    }
    if (nkeys && !dec) {
        say("-k is for decrypting (to choose where the key is written, use --key-out)");
        return 2;
    }
    if (dec && (nkey_outs || shares || po.on || kdf_set)) {
        say("--key-out, --shares, --protect and --kdf-memory are for encrypting (decrypting finds out from the key "
            "whether it's protected; to name the key or its shares, use -k)");
        return 2;
    }
    if (!dec && !po.on && (kdf_set || po.passfile)) {
        say("--kdf-memory and --passphrase-file go with --protect");
        return 2;
    }
    sandbox_cli = 1;
    sandbox_say = verbose;
    int ret = dec ? pnp_decrypt(argv[optind], keys, nkeys, out_opt, force, po.passfile, verify)
                  : pnp_encrypt(argv[optind], out_opt, key_outs, nkey_outs, shares, force, verbose, &po);
    exit_for_signal();
    return ret;
}
