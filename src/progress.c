/* A progress line for encrypting and decrypting:
 *
 *   pnp: encrypting photo.jpg  [=========>          ]  47%  141.0 MiB of 300.0 MiB  1.2 MiB/s  2m 13s left
 *
 * A hardware random source can be slow (an AMD CCP gives about 56 KB/s), so a large file can take hours: this says
 * how far along it is. It's drawn on stderr, only when stderr is a terminal (never into logs or pipes) and not with
 * -q, redrawn at most ten times a second, and only once a file has taken half a second (small files don't flash
 * a bar). The line is wiped when the file is done, and before any message pnp prints. The passphrase hashes of
 * --protect (Balloon, then Argon2id) get the same line, counted in steps rather than bytes. */
#define _GNU_SOURCE
#include "progress.h"
#include "pnp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DELAY_MS 500  /* nothing shown before a file has taken this long */
#define EVERY_MS 100  /* at most this often */

static struct pnp_progress *active; /* the line on the screen, for pnp_progress_interrupt */

static long ms_since(const struct timespec *t)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t->tv_sec) * 1000 + (now.tv_nsec - t->tv_nsec) / 1000000;
}

/* bytes in binary units, as the rest of pnp uses (KiB, MiB, GiB) */
static void size_text(double n, char *b, size_t len)
{
    static const char *const unit[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int u = 0;
    while (n >= 1024 && u < 4)
        n /= 1024, u++;
    snprintf(b, len, u ? "%.1f %s" : "%.0f %s", n, unit[u]);
}

static void time_text(double s, char *b, size_t len)
{
    long t = (long)(s + 0.5);
    if (t >= 3600)
        snprintf(b, len, "%ldh %02ldm", t / 3600, t / 60 % 60);
    else if (t >= 60)
        snprintf(b, len, "%ldm %02lds", t / 60, t % 60);
    else
        snprintf(b, len, "%lds", t);
}

static void draw(struct pnp_progress *p)
{
    struct winsize w;
    int cols = ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col ? w.ws_col : 80;
    double secs = (double)ms_since(&p->start) / 1000.0, rate = secs > 0 ? (double)p->done / secs : 0;
    char done[32], total[32], speed[32], left[32] = "", right[160], line[1024];
    size_text((double)p->done, done, sizeof done);
    size_text((double)p->total, total, sizeof total);
    size_text(rate, speed, sizeof speed);
    if (secs < 0.25) /* too early for a meaningful speed */
        rate = 0;
    if (rate > 0 && p->done < p->total) {
        char t[24];
        time_text((double)(p->total - p->done) / rate, t, sizeof t);
        snprintf(left, sizeof left, "  %s left", t);
    }
    int pct = p->total ? (int)(p->done * 100 / p->total) : 100;
    if (!p->bytes)
        snprintf(right, sizeof right, "%3d%%%s", pct, left);
    else if (rate > 0)
        snprintf(right, sizeof right, "%3d%%  %s of %s  %s/s%s", pct, done, total, speed, left);
    else
        snprintf(right, sizeof right, "%3d%%  %s of %s", pct, done, total);

    /* "pnp: VERB NAME  [bar]  RIGHT", fitted to the width: the name is shortened first, then the bar dropped */
    int fixed = (int)(strlen("pnp: ") + strlen(p->verb) + 1 + 2 + strlen(right));
    int namew = (int)strlen(p->name), barw = cols - 1 - fixed - namew - 4;
    if (barw < 10 && namew > 20) {
        namew = 20;
        barw = cols - 1 - fixed - namew - 4;
    }
    int n = snprintf(line, sizeof line, "\r\033[Kpnp: %s %.*s%s  ", p->verb, namew, p->name,
                     namew < (int)strlen(p->name) ? "~" : "");
    if (barw >= 10 && barw < (int)sizeof line - n - (int)strlen(right) - 8) {
        int fill = p->total ? (int)((double)p->done / (double)p->total * barw) : barw;
        line[n++] = '[';
        for (int i = 0; i < barw; i++)
            line[n++] = i < fill ? '=' : i == fill ? '>' : ' ';
        line[n++] = ']';
        line[n++] = ' ';
        line[n++] = ' ';
    }
    n += snprintf(line + n, sizeof line - (size_t)n, "%s", right);
    if (n > 0 && write(STDERR_FILENO, line, (size_t)n) < 0) {
        /* nothing to do: the line is only a courtesy */
    }
    p->drawn = 1;
    active = p;
    clock_gettime(CLOCK_MONOTONIC, &p->last);
}

void pnp_progress_start(struct pnp_progress *p, const char *verb, const char *name, uint64_t total, int enabled)
{
    memset(p, 0, sizeof *p);
    p->on = enabled && total > 0 && isatty(STDERR_FILENO);
    p->verb = verb;
    p->total = total;
    p->bytes = 1;
    snprintf(p->name, sizeof p->name, "%s", name);
    pnp_clean(p->name);
    clock_gettime(CLOCK_MONOTONIC, &p->start);
    p->last = p->start;
}

void pnp_progress_start_steps(struct pnp_progress *p, const char *verb, const char *name, uint64_t total,
                              int enabled)
{
    pnp_progress_start(p, verb, name, total, enabled);
    p->bytes = 0;
}

void pnp_progress_add(struct pnp_progress *p, uint64_t n) { pnp_progress_set(p, p->done + n); }

void pnp_progress_set(struct pnp_progress *p, uint64_t done)
{
    if (!p->on)
        return;
    p->done = done;
    long delay = DELAY_MS;
#ifdef PNP_TEST
    if (getenv("PNP_TEST_PROGRESS")) /* test hook: draw from the start, every update */
        delay = 0;
#endif
    if (ms_since(&p->start) < delay)
        return;
    if (!p->drawn || p->done >= p->total || ms_since(&p->last) >= EVERY_MS || delay == 0)
        draw(p);
}

void pnp_progress_end(struct pnp_progress *p)
{
    if (p->drawn && write(STDERR_FILENO, "\r\033[K", 4) < 0) {
        /* as above */
    }
    p->drawn = 0;
    p->on = 0;
    if (active == p)
        active = NULL;
}

void pnp_progress_interrupt(void)
{
    if (active && active->drawn) {
        if (write(STDERR_FILENO, "\r\033[K", 4) < 0) {
            /* as above */
        }
        active->drawn = 0; /* the next update draws it again */
    }
}
