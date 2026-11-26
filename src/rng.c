/* The pad's random bytes.
 *
 * A one-time pad is only unbreakable (even if P = NP) when its bytes are truly random. The kernel's getrandom() is
 * a ChaCha20 generator: excellent, but only computationally secure. So pnp reads hardware random sources directly:
 *   /dev/hwrng  the kernel's hardware RNG device (a chip on the board or CPU, a TPM, a USB TRNG); readable by the
 *               pnp group through the package's udev rule (data/60-pnp-hwrng.rules)
 *   RDSEED      the x86 CPU instruction giving its entropy source's conditioned output (not RDRAND, which is the
 *               output of a deterministic generator)
 * Each source's raw bytes go through SP 800-90B start-up and continuous health tests. A source failing at start-up
 * isn't used; a source failing while the pad is made stops the whole run (the caller deletes what it wrote). These
 * tests detect failures (stuck, repeating, badly biased output); no test can prove a source is unpredictable, so
 * the guarantee still rests on at least one source being a real random source.
 * The pad is the XOR of every source in use and getrandom(): as long as the sources are independent, the result is
 * at least as unpredictable as the best of them, so one weak or backdoored source can't make it worse.
 * With no healthy hardware source, the caller refuses to encrypt: getrandom() alone is never enough. */
#define _GNU_SOURCE
#include "rng.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define PNP_HAVE_X86 1
#endif

/* set by main's signal handler: blocking reads give up instead of retrying */
volatile sig_atomic_t pnp_stop;

#define HWRNG_PATH "/dev/hwrng"
#define HWRNG_CURRENT "/sys/class/misc/hw_random/rng_current"

/* Test builds only (make test builds build/pnp-test with -DPNP_TEST): tests point /dev/hwrng at a file or FIFO and
 * turn off RDSEED, so they run the same on every machine. The shipped binary has none of this (make test checks). */
#ifdef PNP_TEST
static const char *hwrng_path(void)
{
    const char *p = getenv("PNP_TEST_HWRNG");
    return p ? p : HWRNG_PATH;
}
static int rdseed_disabled(void) { return getenv("PNP_TEST_NO_RDSEED") != NULL; }
#else
static const char *hwrng_path(void) { return HWRNG_PATH; }
static int rdseed_disabled(void) { return 0; }
#endif

void pnp_health_init(struct pnp_health *h) { memset(h, 0, sizeof *h); }

int pnp_health_feed(struct pnp_health *h, const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t b = buf[i];
        /* Repetition Count Test */
        if (h->rct_run && b == h->rct_last) {
            if (++h->rct_run >= PNP_RCT_CUTOFF)
                return -1;
        } else {
            h->rct_last = b;
            h->rct_run = 1;
        }
        /* Adaptive Proportion Test: counts the window's first sample within the window */
        if (h->apt_seen == 0) {
            h->apt_first = b;
            h->apt_count = 1;
        } else if (b == h->apt_first) {
            if (++h->apt_count >= PNP_APT_CUTOFF)
                return -1;
        }
        if (++h->apt_seen == PNP_APT_WINDOW)
            h->apt_seen = 0;
    }
    return 0;
}

/* Reads exactly n bytes. Returns 0, or -1 with errno (EIO when the source ends, EINTR when pnp_stop is set). */
static int read_full(int fd, uint8_t *buf, size_t n)
{
    while (n) {
        ssize_t r = read(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR && !pnp_stop)
                continue;
            return -1;
        }
        if (r == 0) {
            errno = EIO;
            return -1;
        }
        buf += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Whether pnp is running in a virtual machine: the CPUID "hypervisor present" bit (with the hypervisor's vendor
 * string), or a virtio hwrng (fed by the host). Writes a name into what. A virtual machine's host can read its
 * memory and decide what RDSEED and /dev/hwrng return, so the pad is only as secret as the host is honest. */
int pnp_in_vm(char *what, size_t len)
{
#ifdef PNP_TEST
    if (getenv("PNP_TEST_VM")) { /* test hook: "" for a physical machine, else the hypervisor's name */
        snprintf(what, len, "%s", getenv("PNP_TEST_VM"));
        return what[0] != 0;
    }
#endif
#ifdef PNP_HAVE_X86
    unsigned a, b, c, d;
    if (__get_cpuid(1, &a, &b, &c, &d) && (c >> 31) & 1) {
        unsigned r[3];
        char v[13];
        __cpuid(0x40000000, a, r[0], r[1], r[2]);
        memcpy(v, r, 12);
        v[12] = 0;
        for (int i = 0; i < 12; i++)
            if (v[i] && (v[i] < 0x20 || v[i] > 0x7e))
                v[i] = '?';
        snprintf(what, len, "%s", v[0] ? v : "unknown hypervisor");
        return 1;
    }
#endif
    char cur[64] = "";
    FILE *f = fopen(HWRNG_CURRENT, "re");
    if (f) {
        if (!fgets(cur, sizeof cur, f))
            cur[0] = 0;
        fclose(f);
    }
    if (strstr(cur, "virtio")) {
        snprintf(what, len, "virtio-rng");
        return 1;
    }
    return 0;
}

#ifdef PNP_HAVE_X86
static int rdseed_supported(void)
{
    unsigned a, b, c, d;
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d))
        return 0;
    return (b >> 18) & 1; /* CPUID.(EAX=7,ECX=0):EBX.RDSEED[bit 18] */
}

/* One RDSEED word. The instruction may say "not ready" (carry clear) when its entropy source is drained; Intel's
 * guidance is to retry with a pause. Returns -1 if it stays not ready. The native-width form is used: AMD reported
 * (AMD-SB-7055) that RDSEED's 16- and 32-bit forms on some Zen 5 CPUs can return 0 while saying it's valid. */
static int rdseed_word(unsigned long *out)
{
    for (int i = 0; i < 100000; i++) {
        unsigned long v;
        unsigned char ok;
        __asm__ volatile("rdseed %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) {
            *out = v;
            return 0;
        }
        __asm__ volatile("pause");
    }
    return -1;
}
#endif

static int rdseed_read(uint8_t *buf, size_t n)
{
#ifdef PNP_HAVE_X86
    while (n) {
        unsigned long v;
        if (rdseed_word(&v) < 0) {
            errno = EIO;
            return -1;
        }
        size_t k = n < sizeof v ? n : sizeof v;
        memcpy(buf, &v, k);
        v = 0;
        buf += k;
        n -= k;
    }
    return 0;
#else
    (void)buf;
    (void)n;
    errno = ENODEV;
    return -1;
#endif
}

static int source_read(struct pnp_source *s, uint8_t *buf, size_t n)
{
    return s->fd >= 0 ? read_full(s->fd, buf, n) : rdseed_read(buf, n);
}

/* Reads PNP_STARTUP_BYTES, health-tests them and throws them away. */
static void startup_test(struct pnp_source *s)
{
    uint8_t sample[PNP_STARTUP_BYTES];
    pnp_health_init(&s->health);
    if (source_read(s, sample, sizeof sample) < 0) {
        s->state = errno == ENODEV ? PNP_SRC_ABSENT : PNP_SRC_FAILED;
        snprintf(s->detail, sizeof s->detail, "can't read it: %s", strerror(errno));
    } else if (pnp_health_feed(&s->health, sample, sizeof sample) < 0) {
        s->state = PNP_SRC_FAILED;
        snprintf(s->detail, sizeof s->detail, "failed its start-up health test");
    } else {
        s->state = PNP_SRC_OK;
    }
    explicit_bzero(sample, sizeof sample);
}

static void open_hwrng(struct pnp_source *s)
{
    s->name = HWRNG_PATH;
    s->fd = -1;
    s->detail[0] = 0;
#ifdef PNP_TEST
    int real = getenv("PNP_TEST_HWRNG") == NULL;
#else
    int real = 1;
#endif
    if (real) {
        /* the driver behind it, for the summary; "none" means no hardware RNG driver is loaded */
        FILE *f = fopen(HWRNG_CURRENT, "re");
        if (f) {
            if (fgets(s->detail, sizeof s->detail, f))
                s->detail[strcspn(s->detail, "\n")] = 0;
            fclose(f);
        }
        if (strcmp(s->detail, "none") == 0) {
            s->state = PNP_SRC_ABSENT;
            snprintf(s->detail, sizeof s->detail, "no hardware RNG driver loaded");
            return;
        }
    }
    s->fd = open(hwrng_path(), O_RDONLY | O_CLOEXEC);
    if (s->fd < 0) {
        int e = errno;
        if (e == ENOENT || e == ENODEV || e == ENXIO) {
            s->state = PNP_SRC_ABSENT;
            snprintf(s->detail, sizeof s->detail, "not on this machine");
        } else if (e == EACCES || e == EPERM) {
            s->state = PNP_SRC_DENIED;
            snprintf(s->detail, sizeof s->detail, "permission denied");
        } else {
            s->state = PNP_SRC_FAILED;
            snprintf(s->detail, sizeof s->detail, "can't open it: %s", strerror(e));
        }
        return;
    }
    startup_test(s);
}

static void open_rdseed(struct pnp_source *s)
{
    s->name = "RDSEED";
    s->fd = -1;
    s->detail[0] = 0;
#ifdef PNP_HAVE_X86
    if (!rdseed_disabled() && rdseed_supported()) {
        startup_test(s);
        return;
    }
#endif
    s->state = PNP_SRC_ABSENT;
    snprintf(s->detail, sizeof s->detail, "not supported by this CPU");
}

void pnp_rng_open(struct pnp_rng *rng)
{
    memset(rng, 0, sizeof *rng);
    open_hwrng(&rng->src[0]);
    open_rdseed(&rng->src[1]);
    rng->count = 2;
    for (int i = 0; i < rng->count; i++) {
        struct pnp_source *s = &rng->src[i];
        if (s->state == PNP_SRC_OK)
            rng->hardware_ok++;
        else if (s->fd >= 0) {
            close(s->fd);
            s->fd = -1;
        }
    }
}

int pnp_rng_fill(struct pnp_rng *rng, uint8_t *buf, size_t n, char *err, size_t errlen)
{
    static uint8_t tmp[65536];
    int ret = -1;

    if (rng->hardware_ok == 0) {
        snprintf(err, errlen, "no hardware random source");
        errno = EIO;
        return -1;
    }
    for (size_t done = 0; done < n;) {
        ssize_t r = getrandom(buf + done, n - done, 0);
        if (r < 0) {
            if (errno == EINTR && !pnp_stop)
                continue;
            snprintf(err, errlen, "getrandom: %s", strerror(errno));
            return -1;
        }
        done += (size_t)r;
    }
    for (int i = 0; i < rng->count; i++) {
        struct pnp_source *s = &rng->src[i];
        if (s->state != PNP_SRC_OK)
            continue;
        for (size_t off = 0; off < n;) {
            size_t k = n - off < sizeof tmp ? n - off : sizeof tmp;
            if (source_read(s, tmp, k) < 0) {
                int e = errno;
                if (e == EINTR)
                    snprintf(err, errlen, "interrupted");
                else
                    snprintf(err, errlen, "%s stopped working: %s", s->name, strerror(e));
                errno = e == EINTR ? EINTR : EIO;
                goto out;
            }
            if (pnp_health_feed(&s->health, tmp, k) < 0) {
                snprintf(err, errlen, "%s failed a health test (its output stopped looking random)", s->name);
                errno = EIO;
                goto out;
            }
            for (size_t j = 0; j < k; j++)
                buf[off + j] ^= tmp[j];
            off += k;
        }
    }
    ret = 0;
out:
    explicit_bzero(tmp, sizeof tmp);
    return ret;
}

void pnp_rng_close(struct pnp_rng *rng)
{
    for (int i = 0; i < rng->count; i++)
        if (rng->src[i].fd >= 0)
            close(rng->src[i].fd);
    memset(rng, 0, sizeof *rng);
}

void pnp_rng_describe(const struct pnp_rng *rng, char *out, size_t outlen)
{
    size_t len = 0;
    out[0] = 0;
    for (int i = 0; i < rng->count; i++) {
        const struct pnp_source *s = &rng->src[i];
        if (s->state != PNP_SRC_OK)
            continue;
        int w = s->detail[0] ? snprintf(out + len, outlen - len, "%s (%s) + ", s->name, s->detail)
                             : snprintf(out + len, outlen - len, "%s + ", s->name);
        if (w < 0 || (size_t)w >= outlen - len)
            return;
        len += (size_t)w;
    }
    snprintf(out + len, outlen - len, "getrandom");
}
