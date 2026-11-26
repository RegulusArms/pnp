/* --protect: the key (or each share) encrypted under a passphrase.
 *
 * What it's for: a stolen key file alone shouldn't be enough for a casual attacker. With --protect, they also need
 * the passphrase, and every guess costs about a gigabyte of memory and seconds of computing. What it isn't: part of
 * pnp's P = NP guarantee. ChaCha20, Balloon and Argon2id are only computationally secure. If they were broken, the
 * attacker would be back to holding the plain key file, exactly as without --protect: the pad inside is unchanged.
 *
 *   b   = Balloon-BLAKE2b(passphrase, salt)                 (kdf.c; 16 MiB, 2 rounds by default)
 *   a   = Argon2id(password b, salt) -> 64 bytes            (kdf.c; 1 GiB, 2 passes, one lane per CPU by default)
 *   key = a[0..31], check = a[32..47]
 *   key file body = key material XOR ChaCha20(key, nonce = LE32(share number, 0 for a whole key) || 8 zero bytes)
 *
 * The two hashes run one after the other, so each guess costs both: a shortcut found for one still leaves the
 * other. The salt is random for each encryption (all its shares share it, the nonce tells them apart), so a key
 * and a nonce are never used twice. The check value lets pnp say "wrong passphrase" at once instead of decrypting
 * the whole file first; it gives an attacker nothing they couldn't get by trying to decrypt, and it covers the
 * parameters and salt (a changed one gives another key). Damage to the wrapped body is caught by the integrity check
 * (mac.c), as for an unprotected key. */
#define _GNU_SOURCE
#include "protect.h"
#include "kdf.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>

extern volatile sig_atomic_t pnp_stop;

#define BALLOON_MAX_BLOCKS ((uint32_t)1 << 24) /* 1 GiB */
#define MAX_ROUNDS 16                           /* passes or rounds a key may ask for */
#define MAX_LANES 64                            /* Argon2id lanes pnp makes and accepts */

static void le32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get32(const uint8_t *b) { return (uint32_t)b[0] | b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }

int pnp_protect_new(struct pnp_protect *p, uint32_t argon_mib)
{
    memset(p, 0, sizeof *p);
    p->argon_kib = argon_mib * 1024;
    p->argon_passes = 2;
    /* One lane per CPU, so encrypting and decrypting here use every core. The lanes don't change the work an
     * attacker must do per guess (the same memory filled the same number of times), only how much of it can run
     * at once. A machine with fewer cores still decrypts, just more slowly. */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    p->argon_lanes = cpus < 1 ? 1 : cpus > MAX_LANES ? MAX_LANES : (uint32_t)cpus;
    /* Balloon is much slower per byte, so it gets 1/64 of the memory, at most 16 MiB (about 2.5 s) */
    p->balloon_blocks = (argon_mib < 1024 ? argon_mib : 1024) * 256;
    p->balloon_rounds = 2;
    return getrandom(p->salt, sizeof p->salt, 0) == (ssize_t)sizeof p->salt ? 0 : -1;
}

void pnp_protect_encode(const struct pnp_protect *p, uint8_t out[PNP_PROTECT_LEN])
{
    le32(out, p->balloon_blocks);
    le32(out + 4, p->balloon_rounds);
    le32(out + 8, p->argon_kib);
    le32(out + 12, p->argon_passes);
    le32(out + 16, p->argon_lanes);
    memcpy(out + 20, p->salt, PNP_PROTECT_SALT);
    memcpy(out + 36, p->check, PNP_PROTECT_CHECK);
}

int pnp_protect_decode(struct pnp_protect *p, const uint8_t in[PNP_PROTECT_LEN])
{
    p->balloon_blocks = get32(in);
    p->balloon_rounds = get32(in + 4);
    p->argon_kib = get32(in + 8);
    p->argon_passes = get32(in + 12);
    p->argon_lanes = get32(in + 16);
    memcpy(p->salt, in + 20, PNP_PROTECT_SALT);
    memcpy(p->check, in + 36, PNP_PROTECT_CHECK);
    /* bounds, so a damaged or hostile key can't ask for terabytes or hours */
    if (p->balloon_blocks < 2 || p->balloon_blocks > BALLOON_MAX_BLOCKS || p->balloon_rounds < 1 ||
        p->balloon_rounds > MAX_ROUNDS || p->argon_kib < PNP_PROTECT_MIB_MIN * 1024 ||
        p->argon_kib > (uint32_t)PNP_PROTECT_MIB_MAX * 1024 || p->argon_passes < 1 || p->argon_passes > MAX_ROUNDS ||
        p->argon_lanes < 1 || p->argon_lanes > MAX_LANES)
        return -1;
    return 0;
}

static int derive(const struct pnp_protect *p, const char *pass, size_t passlen, uint8_t key[32],
                  uint8_t check[PNP_PROTECT_CHECK])
{
    uint8_t b[PNP_BALLOON_BLOCK], a[64];
    int ret = -1;
    if (pnp_balloon(b, (const uint8_t *)pass, passlen, p->salt, sizeof p->salt, p->balloon_blocks,
                    p->balloon_rounds) == 0 &&
        pnp_argon2id(a, sizeof a, b, sizeof b, p->salt, sizeof p->salt, NULL, 0, NULL, 0, p->argon_kib,
                     p->argon_passes, p->argon_lanes) == 0) {
        memcpy(key, a, 32);
        memcpy(check, a + 32, PNP_PROTECT_CHECK);
        ret = 0;
    }
    explicit_bzero(b, sizeof b);
    explicit_bzero(a, sizeof a);
    return ret;
}

int pnp_protect_lock(struct pnp_protect *p, const char *pass, size_t passlen, uint8_t key[32])
{
    return derive(p, pass, passlen, key, p->check);
}

int pnp_protect_unlock(const struct pnp_protect *p, const char *pass, size_t passlen, uint8_t key[32])
{
    uint8_t check[PNP_PROTECT_CHECK], d = 0;
    if (derive(p, pass, passlen, key, check) < 0)
        return -1;
    for (int i = 0; i < PNP_PROTECT_CHECK; i++) /* constant time */
        d |= (uint8_t)(check[i] ^ p->check[i]);
    if (d) {
        explicit_bzero(key, 32);
        return -2;
    }
    return 0;
}

uint32_t pnp_protect_need_mib(const struct pnp_protect *p)
{
    /* Balloon's buffer is freed before Argon2id's is made, so the peak is the larger, plus a little for the rest */
    uint32_t balloon = (uint32_t)(((uint64_t)p->balloon_blocks * PNP_BALLOON_BLOCK) >> 20);
    uint32_t argon = p->argon_kib / 1024;
    return (argon > balloon ? argon : balloon) + 16;
}

/* Checked before hashing, so too little memory gives a clear message instead of the machine swapping for hours
 * (Argon2id reads its memory in a random order, which is hopeless on swap) or the kernel killing pnp. */
long pnp_mem_available_mib(void)
{
    const char *path = "/proc/meminfo";
#ifdef PNP_TEST
    const char *fake = getenv("PNP_TEST_MEMINFO");
    if (fake) /* test hook: another file in /proc/meminfo's format */
        path = fake;
#endif
    FILE *f = fopen(path, "re");
    if (!f)
        return -1;
    char line[128];
    long kib = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "MemAvailable: %ld kB", &kib) == 1)
            break;
    fclose(f);
    return kib < 0 ? -1 : kib / 1024;
}

void pnp_protect_stream(struct pnp_chacha20 *c, const uint8_t key[32], int share)
{
    uint8_t nonce[12] = {0};
    le32(nonce, (uint32_t)share);
    pnp_chacha20_init(c, key, nonce);
}

/* one line into buf (without its "\n" or "\r\n"): its length, -1 on a read error, -2 if it doesn't fit */
static long read_line(int fd, char *buf, size_t buflen)
{
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR && !pnp_stop)
                continue;
            return -1;
        }
        if (r == 0 || c == '\n')
            break;
        if (n + 1 >= buflen)
            return -2;
        buf[n++] = c;
    }
    if (n && buf[n - 1] == '\r')
        n--;
    buf[n] = 0;
    return (long)n;
}

static long ask(int fd, const char *prompt, char *buf, size_t buflen)
{
    if (write(fd, prompt, strlen(prompt)) < 0)
        return -1;
    long n = read_line(fd, buf, buflen);
    if (write(fd, "\n", 1) < 0) /* the Enter wasn't echoed */
        n = n < 0 ? n : -1;
    return n;
}

long pnp_read_passphrase(const char *file, int confirm, char *buf, size_t buflen, char *err, size_t errlen)
{
    long n;
    if (file) {
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            snprintf(err, errlen, "can't open %s: %s", file, strerror(errno));
            return -1;
        }
        n = read_line(fd, buf, buflen);
        close(fd);
        if (n == -1)
            snprintf(err, errlen, "can't read %s", file);
    } else {
        int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
        struct termios old, quiet_tty;
        if (fd < 0 || tcgetattr(fd, &old) < 0) {
            snprintf(err, errlen, "there's no terminal to ask for the passphrase on: give it with --passphrase-file");
            if (fd >= 0)
                close(fd);
            return -1;
        }
        quiet_tty = old;
        quiet_tty.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(fd, TCSAFLUSH, &quiet_tty);
        n = ask(fd, confirm ? "New passphrase for the key: " : "Passphrase for the key: ", buf, buflen);
        if (n >= 0 && confirm) {
            char again[PNP_PASS_MAX];
            long m = ask(fd, "Same passphrase again: ", again, sizeof again);
            if (m >= 0 && (m != n || memcmp(again, buf, (size_t)n) != 0)) {
                snprintf(err, errlen, "the two passphrases are different");
                n = -3;
            } else if (m < 0) {
                n = m;
            }
            explicit_bzero(again, sizeof again);
        }
        tcsetattr(fd, TCSAFLUSH, &old);
        close(fd);
        if (n == -1)
            snprintf(err, errlen, pnp_stop ? "stopped" : "can't read the passphrase from the terminal");
    }
    if (n == -2)
        snprintf(err, errlen, "the passphrase is too long (at most %zu bytes)", buflen - 1);
    if (n == 0) {
        snprintf(err, errlen, "the passphrase is empty");
        n = -1;
    }
    if (n < 0)
        explicit_bzero(buf, buflen);
    return n < 0 ? -1 : n;
}
