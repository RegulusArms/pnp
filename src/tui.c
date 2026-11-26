/* The interactive mode: "pnp" alone in a terminal.
 *
 * A file browser for the current folder: move with the arrow keys, select files with Space, press Enter, and pnp
 * shows what it will do before doing it: which ciphertext and key files encrypting writes and where (the code
 * cylinder: a key drive, see docs/code-cylinder.md), or which key decrypting will use. Then it runs the same
 * pnp_encrypt() / pnp_decrypt() as the command line (main.c), so the files and checks are exactly the same.
 *
 * Plain libc: termios for raw keyboard input and ANSI escape sequences for the screen (no curses, to keep pnp
 * dependency-free). Nothing here touches pad or key bytes: it only reads the 26-byte headers of .pnp and key files
 * (format.h) to tell them apart and to match each ciphertext with its key by their shared ID.
 *
 * The code cylinder is looked for among the mounted drives in /media/$USER and /run/media/$USER (one labelled KEYS
 * is preferred, the name docs/code-cylinder.md uses), or any folder the user types. Keys are looked for at the top of
 * each of those and beside the ciphertext. */
#define _GNU_SOURCE
#include "format.h"
#include "pnp.h"
#include "protect.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifndef PNP_VERSION
#define PNP_VERSION "unknown"
#endif

extern volatile sig_atomic_t pnp_stop;
static volatile sig_atomic_t resized;

static const char *const BANNER[] = {
    "    ____  _   ______ ",
    "   / __ \\/ | / / __ \\",
    "  / /_/ /  |/ / /_/ /",
    " / ____/ /|  / ____/ ",
    "/_/   /_/ |_/_/      ",
};
#define BANNER_LINES 5
static const char TAGLINE[] = "p = np. now what?";

/* ---------------------------------------------------------------- the terminal */

static struct termios saved_tty;
static int raw_on, rows = 24, cols = 80, color = 1;

/* the screen is built in this buffer and written in one go, so it doesn't flicker */
static char *scr;
static size_t scr_len, scr_cap;

static void add(const char *s, size_t n)
{
    if (scr_len + n + 1 > scr_cap) {
        size_t cap = scr_cap ? scr_cap * 2 : 65536;
        while (cap < scr_len + n + 1)
            cap *= 2;
        char *p = realloc(scr, cap);
        if (!p)
            return; /* drop output rather than crash; the next draw tries again */
        scr = p;
        scr_cap = cap;
    }
    memcpy(scr + scr_len, s, n);
    scr_len += n;
}

static void adds(const char *s) { add(s, strlen(s)); }

static void flush_screen(void)
{
    for (size_t off = 0; off < scr_len;) {
        ssize_t w = write(STDOUT_FILENO, scr + off, scr_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        off += (size_t)w;
    }
    scr_len = 0;
}

static void get_size(void)
{
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row && w.ws_col) {
        rows = w.ws_row;
        cols = w.ws_col;
    }
}

static void on_winch(int sig)
{
    (void)sig;
    resized = 1;
}

/* raw input (each key as it's pressed, no echo, Ctrl-C as a key), the alternate screen, no cursor */
static void term_enter(void)
{
    if (raw_on || tcgetattr(STDIN_FILENO, &saved_tty) < 0)
        return;
    struct termios t = saved_tty;
    t.c_lflag &= (tcflag_t) ~(ECHO | ICANON | ISIG | IEXTEN);
    t.c_iflag &= (tcflag_t) ~(IXON | ICRNL | INLCR);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSADRAIN, &t); /* not FLUSH: keys typed ahead are kept */
    raw_on = 1;
    adds("\033[?1049h\033[?25l");
    flush_screen();
    get_size();
}

static void term_leave(void)
{
    if (!raw_on)
        return;
    adds("\033[0m\033[?25h\033[?1049l");
    flush_screen();
    tcsetattr(STDIN_FILENO, TCSADRAIN, &saved_tty);
    raw_on = 0;
}

/* styles; colours are left out with NO_COLOR set (https://no-color.org) */
#define S_RESET "\033[0m"
#define S_BOLD "\033[1m"
#define S_DIM "\033[2m"
#define S_REV "\033[7m"
static const char *c_green(void) { return color ? "\033[32m" : ""; }
static const char *c_yellow(void) { return color ? "\033[33m" : ""; }
static const char *c_red(void) { return color ? "\033[31m" : ""; }
static const char *c_cyan(void) { return color ? "\033[36m" : ""; }

/* ---- writing lines: each a row of cells, clipped to the terminal's width */

static int row, col; /* where the next cell goes */

/* Appends text in a cell of width columns (-1: the rest of the line), padded with spaces, or cut short with "~".
 * File names come from disk and could hold escape sequences, so control characters (C0, DEL, and C1 written in
 * UTF-8) are shown as "?": a file name can never move the cursor or change the terminal. UTF-8 sequences count as
 * one column each. */
static void cell(const char *style, const char *text, int width)
{
    if (row >= rows)
        return;
    if (width < 0 || width > cols - col)
        width = cols - col;
    if (width <= 0)
        return;
    /* first pass: the width of the clean text */
    int len = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p;) {
        int n = *p < 0x80 ? 1 : *p >= 0xf0 ? 4 : *p >= 0xe0 ? 3 : *p >= 0xc0 ? 2 : 1;
        for (int i = 1; i < n; i++)
            if ((p[i] & 0xc0) != 0x80)
                n = 1;
        p += n;
        len++;
    }
    int room = len > width ? width - 1 : width; /* columns for text; the last one gets "~" if cut */
    if (style)
        adds(style);
    int used = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p && used < room; used++) {
        int n = *p < 0x80 ? 1 : *p >= 0xf0 ? 4 : *p >= 0xe0 ? 3 : *p >= 0xc0 ? 2 : 1;
        for (int i = 1; i < n; i++)
            if ((p[i] & 0xc0) != 0x80)
                n = 1;
        if (*p < 0x20 || *p == 0x7f || (n == 1 && *p >= 0x80) || (n == 2 && p[0] == 0xc2 && p[1] < 0xa0))
            add("?", 1);
        else
            add((const char *)p, (size_t)n);
        p += n;
    }
    if (len > width)
        add("~", 1), used++;
    for (; used < width; used++)
        add(" ", 1);
    if (style)
        adds(S_RESET);
    col += width;
}

/* a path: if it's too long, its start is cut ("~" + the end), since the end (the drive, the file) matters most */
static void cellp(const char *style, const char *path, int width)
{
    if (width < 0 || width > cols - col)
        width = cols - col;
    int len = 0;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        len += (*p & 0xc0) != 0x80;
    const char *s = path;
    if (len > width && width > 1) {
        for (int skip = len - width + 1; skip > 0 && *s; skip--)
            do
                s++;
            while ((*(const unsigned char *)s & 0xc0) == 0x80);
        char buf[PATH_MAX + 2];
        snprintf(buf, sizeof buf, "~%s", s);
        cell(style, buf, width);
        return;
    }
    cell(style, path, width);
}

static void cellf(const char *style, int width, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void cellf(const char *style, int width, const char *fmt, ...)
{
    char buf[PATH_MAX + 512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    cell(style, buf, width);
}

static void endl(void)
{
    if (row >= rows)
        return;
    adds(S_RESET "\033[K");
    if (row < rows - 1)
        adds("\r\n");
    row++;
    col = 0;
}

static void begin_screen(void)
{
    get_size();
    resized = 0;
    adds("\033[H");
    row = col = 0;
}

static void end_screen(void)
{
    while (row < rows)
        endl();
    flush_screen();
}

static void rule(void)
{
    char line[1024];
    int n = cols < (int)sizeof line - 1 ? cols : (int)sizeof line - 1;
    memset(line, '-', (size_t)n);
    line[n] = 0;
    cell(S_DIM, line, -1);
    endl();
}

/* ---- the keyboard */

enum {
    K_NONE = 1000, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN, K_HOME, K_END, K_ENTER, K_ESC, K_BKSP, K_QUIT
};

/* the next key, or K_NONE when interrupted (a resize, or a signal: check pnp_stop) */
static int read_key(void)
{
    unsigned char c;
    ssize_t r = read(STDIN_FILENO, &c, 1);
    if (r < 0 && errno == EINTR)
        return K_NONE;
    if (r <= 0)
        return K_QUIT; /* the terminal went away */
    if (c == '\r' || c == '\n')
        return K_ENTER;
    if (c == 127 || c == 8)
        return K_BKSP;
    if (c == 3 || c == 4) /* Ctrl-C, Ctrl-D */
        return K_QUIT;
    if (c != 27)
        return c;
    /* Esc alone, or the start of an arrow key's sequence (Esc [ A, Esc O A, Esc [ 5 ~ ...): wait briefly for more */
    struct pollfd pf = {STDIN_FILENO, POLLIN, 0};
    unsigned char s[4];
    if (poll(&pf, 1, 50) <= 0 || read(STDIN_FILENO, &s[0], 1) != 1)
        return K_ESC;
    if (s[0] != '[' && s[0] != 'O')
        return K_ESC;
    if (read(STDIN_FILENO, &s[1], 1) != 1)
        return K_ESC;
    switch (s[1]) {
    case 'A': return K_UP;
    case 'B': return K_DOWN;
    case 'C': return K_RIGHT;
    case 'D': return K_LEFT;
    case 'H': return K_HOME;
    case 'F': return K_END;
    }
    if (s[1] >= '0' && s[1] <= '9') {
        int n = s[1] - '0';
        while (read(STDIN_FILENO, &s[2], 1) == 1 && s[2] >= '0' && s[2] <= '9')
            n = n * 10 + (s[2] - '0');
        switch (n) {
        case 1: case 7: return K_HOME;
        case 4: case 8: return K_END;
        case 5: return K_PGUP;
        case 6: return K_PGDN;
        }
    }
    return K_NONE;
}

/* ---------------------------------------------------------------- headers, drives and keys */

enum { H_NONE, H_CT, H_KEY, H_SHARE };

struct hdr {
    int kind, prot, num, count;
    uint8_t id[ID_LEN];
};

/* Reads a file's header without blocking (a FIFO or device is skipped) and says what it is. */
static void peek(const char *path, struct hdr *h)
{
    memset(h, 0, sizeof *h);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return;
    struct stat st;
    uint8_t b[SHARE_HEADER_LEN];
    ssize_t n = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) ? read(fd, b, sizeof b) : -1;
    close(fd);
    if (n < HEADER_LEN)
        return;
    if (!memcmp(b, MAGIC_CT, MAGIC_LEN) || !memcmp(b, MAGIC_CT_V1, MAGIC_LEN))
        h->kind = H_CT;
    else if (!memcmp(b, MAGIC_KEY, MAGIC_LEN) || !memcmp(b, MAGIC_KEY_V1, MAGIC_LEN))
        h->kind = H_KEY;
    else if (!memcmp(b, MAGIC_KEY_P, MAGIC_LEN))
        h->kind = H_KEY, h->prot = 1;
    else if ((!memcmp(b, MAGIC_SHARE, MAGIC_LEN) || !memcmp(b, MAGIC_SHARE_P, MAGIC_LEN)) && n == SHARE_HEADER_LEN &&
             b[25] >= 2 && b[25] <= MAX_SHARES && b[24] >= 1 && b[24] <= b[25]) {
        h->kind = H_SHARE;
        h->prot = !memcmp(b, MAGIC_SHARE_P, MAGIC_LEN);
        h->num = b[24];
        h->count = b[25];
    }
    memcpy(h->id, b + MAGIC_LEN, ID_LEN);
}

/* ---- where keys can go: [0] beside the file, then the drives found, then folders the user typed */

#define MAX_DEST 32
struct dest {
    char path[PATH_MAX];
    char name[256];
    int manual;
};
static struct dest dest[MAX_DEST];
static int ndest, cyl; /* cyl: the code cylinder in use (an index into dest) */
static char cyl_path[PATH_MAX]; /* remembered across rescans */

static void add_dest(const char *path, const char *name, int manual)
{
    if (ndest == MAX_DEST)
        return;
    for (int i = 1; i < ndest; i++)
        if (strcmp(dest[i].path, path) == 0)
            return;
    snprintf(dest[ndest].path, sizeof dest[ndest].path, "%s", path);
    snprintf(dest[ndest].name, sizeof dest[ndest].name, "%s", name);
    dest[ndest].manual = manual;
    ndest++;
}

static void scan_dests(void)
{
    struct dest manual[MAX_DEST];
    int nmanual = 0;
    for (int i = 1; i < ndest; i++)
        if (dest[i].manual)
            manual[nmanual++] = dest[i];
    ndest = 1;
    snprintf(dest[0].path, sizeof dest[0].path, ".");
    snprintf(dest[0].name, sizeof dest[0].name, "beside the file");
    const char *user = getenv("USER");
    struct passwd *pw = user ? NULL : getpwuid(getuid());
    if (!user && pw)
        user = pw->pw_name;
    char bases[2][PATH_MAX];
    int nbases = 0;
#ifdef PNP_TEST
    if (getenv("PNP_TEST_MEDIA")) /* test hook: a folder standing in for /media/$USER */
        snprintf(bases[nbases++], PATH_MAX, "%s", getenv("PNP_TEST_MEDIA"));
    else
#endif
        if (user) {
        snprintf(bases[nbases++], PATH_MAX, "/media/%s", user);
        snprintf(bases[nbases++], PATH_MAX, "/run/media/%s", user);
    }
    for (int b = 0; b < nbases; b++) {
        DIR *d = opendir(bases[b]);
        if (!d)
            continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            char p[PATH_MAX];
            struct stat st;
            if (e->d_name[0] == '.' || snprintf(p, sizeof p, "%s/%s", bases[b], e->d_name) >= (int)sizeof p)
                continue;
            if (stat(p, &st) == 0 && S_ISDIR(st.st_mode))
                add_dest(p, e->d_name, 0);
        }
        closedir(d);
    }
    for (int i = 0; i < nmanual; i++)
        add_dest(manual[i].path, manual[i].name, 1);
    /* the cylinder: the one chosen before if it's still there, else a drive called KEYS, else the only drive */
    cyl = 0;
    for (int i = 1; i < ndest; i++)
        if (cyl_path[0] && strcmp(dest[i].path, cyl_path) == 0)
            cyl = i;
    for (int i = 1; i < ndest && !cyl; i++)
        if (strcasecmp(dest[i].name, "KEYS") == 0)
            cyl = i;
    if (!cyl && ndest == 2)
        cyl = 1;
}

static const char *dest_label(int i, char *buf, size_t len)
{
    if (i == 0)
        snprintf(buf, len, "beside the file (not on a code cylinder)");
    else
        snprintf(buf, len, "%s%s", dest[i].path, i == cyl ? "  (code cylinder)" : "");
    return buf;
}

/* ---- every key and share found on the drives and here */

struct keyfile {
    char path[PATH_MAX];
    struct hdr h;
    dev_t dev;
    ino_t ino;
};
static struct keyfile *keys;
static int nkeys, cap_keys;

static void index_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        char p[PATH_MAX];
        struct stat st;
        if (!strstr(e->d_name, ".key") || snprintf(p, sizeof p, "%s/%s", dir, e->d_name) >= (int)sizeof p ||
            stat(p, &st) < 0 || !S_ISREG(st.st_mode))
            continue;
        int dup = 0;
        for (int i = 0; i < nkeys && !dup; i++)
            dup = keys[i].dev == st.st_dev && keys[i].ino == st.st_ino;
        struct hdr h;
        if (dup || (peek(p, &h), h.kind != H_KEY && h.kind != H_SHARE))
            continue;
        if (nkeys == cap_keys) {
            int cap = cap_keys ? cap_keys * 2 : 64;
            struct keyfile *k = realloc(keys, (size_t)cap * sizeof *k);
            if (!k)
                break;
            keys = k;
            cap_keys = cap;
        }
        snprintf(keys[nkeys].path, sizeof keys[nkeys].path, "%s", strncmp(p, "./", 2) == 0 ? p + 2 : p);
        keys[nkeys].h = h;
        keys[nkeys].dev = st.st_dev;
        keys[nkeys].ino = st.st_ino;
        nkeys++;
    }
    closedir(d);
}

/* drives first, so a key on the code cylinder is preferred to a copy beside the file */
static void scan_keys(void)
{
    nkeys = 0;
    for (int i = 1; i < ndest; i++)
        index_dir(dest[i].path);
    index_dir(".");
}

struct match {
    int whole;              /* the whole key (an index into keys), or -1 */
    int count, found;       /* shares: how many there are, and how many were found */
    int share[MAX_SHARES + 1]; /* by share number: an index into keys, or -1 */
    int prot;               /* a passphrase will be needed */
};

static void find_key(const uint8_t id[ID_LEN], struct match *m)
{
    m->whole = -1;
    m->count = m->found = m->prot = 0;
    for (int i = 0; i <= MAX_SHARES; i++)
        m->share[i] = -1;
    for (int i = 0; i < nkeys; i++) {
        const struct hdr *h = &keys[i].h;
        if (memcmp(h->id, id, ID_LEN) != 0)
            continue;
        if (h->kind == H_KEY && m->whole < 0) {
            m->whole = i;
        } else if (h->kind == H_SHARE && m->share[h->num] < 0 && (!m->count || m->count == h->count)) {
            m->count = h->count;
            m->share[h->num] = i;
            m->found++;
        }
    }
    if (m->whole >= 0)
        m->prot = keys[m->whole].h.prot;
    else
        for (int s = 1; s <= m->count; s++)
            if (m->share[s] >= 0 && keys[m->share[s]].h.prot)
                m->prot = 1;
}

static int match_ok(const struct match *m) { return m->whole >= 0 || (m->count && m->found == m->count); }

/* the key files a match decrypts with, for pnp_decrypt; returns how many */
static int match_paths(const struct match *m, char **out)
{
    if (m->whole >= 0) {
        out[0] = keys[m->whole].path;
        return 1;
    }
    int n = 0;
    for (int s = 1; s <= m->count; s++)
        if (m->share[s] >= 0)
            out[n++] = keys[m->share[s]].path;
    return n;
}

/* ---------------------------------------------------------------- the folder */

struct entry {
    char name[256];
    int dir, sel;
    off_t size;
    struct hdr h;
};
static struct entry *ents;
static int nents, cap_ents, cur, top, show_hidden;
static char status[512];
static const char *status_style;

static void set_status(const char *style, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_status(const char *style, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(status, sizeof status, fmt, ap);
    va_end(ap);
    status_style = style;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && strcmp(s + a - b, suffix) == 0;
}

static int cmp_entries(const void *pa, const void *pb)
{
    const struct entry *a = pa, *b = pb;
    if (strcmp(a->name, "..") == 0 || strcmp(b->name, "..") == 0)
        return strcmp(a->name, "..") == 0 ? -1 : 1;
    if (a->dir != b->dir)
        return b->dir - a->dir;
    int c = strcasecmp(a->name, b->name);
    return c ? c : strcmp(a->name, b->name);
}

static void load_dir(void)
{
    char here[PATH_MAX];
    nents = 0;
    DIR *d = opendir(".");
    if (!d) {
        set_status(c_red(), "can't read this folder: %s", strerror(errno));
        return;
    }
    int root = getcwd(here, sizeof here) && strcmp(here, "/") == 0;
    struct dirent *e;
    for (int first = 1;; first = 0) {
        const char *name;
        if (first) {
            if (root)
                continue;
            name = "..";
        } else {
            if (!(e = readdir(d)))
                break;
            name = e->d_name;
            if (!strcmp(name, ".") || !strcmp(name, "..") || (name[0] == '.' && !show_hidden))
                continue;
        }
        if (nents == cap_ents) {
            int cap = cap_ents ? cap_ents * 2 : 256;
            struct entry *p = realloc(ents, (size_t)cap * sizeof *p);
            if (!p)
                break;
            ents = p;
            cap_ents = cap;
        }
        struct entry *en = &ents[nents];
        memset(en, 0, sizeof *en);
        snprintf(en->name, sizeof en->name, "%s", name);
        struct stat st;
        if (stat(name, &st) == 0) {
            en->dir = S_ISDIR(st.st_mode);
            en->size = st.st_size;
            if (S_ISREG(st.st_mode) && (ends_with(name, ".pnp") || strstr(name, ".key")))
                peek(name, &en->h);
        }
        nents++;
    }
    closedir(d);
    qsort(ents, (size_t)nents, sizeof *ents, cmp_entries);
    if (cur >= nents)
        cur = nents ? nents - 1 : 0;
}

static void refresh_all(void)
{
    scan_dests();
    scan_keys();
    load_dir();
}

/* an ordinary file pnp can encrypt: regular, and not already a ciphertext or a key */
static int is_plain(const struct entry *e)
{
    struct stat st;
    return !e->dir && e->h.kind == H_NONE && stat(e->name, &st) == 0 && S_ISREG(st.st_mode);
}

static void human(off_t n, char *b, size_t len)
{
    static const char *const unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)n;
    int u = 0;
    while (v >= 1000 && u < 4)
        v /= 1000, u++;
    if (u == 0)
        snprintf(b, len, "%lld B", (long long)n);
    else
        snprintf(b, len, "%.1f %s", v, unit[u]);
}

/* the decrypted file's name: FILE.pnp -> FILE, anything else -> NAME.decrypted */
static void out_name(const char *ct, char *buf, size_t len)
{
    if (ends_with(ct, ".pnp") && strlen(ct) > 4)
        snprintf(buf, len, "%.*s", (int)(strlen(ct) - 4), ct);
    else
        snprintf(buf, len, "%s.decrypted", ct);
}

/* ---------------------------------------------------------------- the screens */

static void header(const char *title)
{
    if (rows >= 28) {
        for (int i = 0; i < BANNER_LINES; i++) {
            cell(c_cyan(), BANNER[i], 22);
            if (i == BANNER_LINES - 1)
                cellf(S_DIM, -1, "   %s   pnp %s", TAGLINE, PNP_VERSION);
            endl();
        }
    } else {
        cell(S_BOLD, "pnp", 4);
        cellf(S_DIM, -1, "%s   %s", PNP_VERSION, TAGLINE);
        endl();
    }
    if (title) {
        cell(S_BOLD, title, -1);
        endl();
    }
}

static void cylinder_line(void)
{
    cell(NULL, "Code cylinder: ", 15);
    if (cyl)
        cellp(c_green(), dest[cyl].path, -1);
    else if (ndest > 1)
        cell(c_yellow(), "none chosen: keys go beside the files (press c to choose a drive)", -1);
    else
        cell(c_yellow(), "no drive found: plug in your key drive, or press c to choose a folder", -1);
    endl();
}

/* what the highlighted file is, and what Enter will do with it */
static void detail(const struct entry *e)
{
    if (!e) {
        endl(), endl();
        return;
    }
    if (e->dir) {
        cell(S_DIM, "Enter: open this folder.", -1);
        endl(), endl();
    } else if (e->h.kind == H_CT) {
        struct match m;
        char out[300];
        find_key(e->h.id, &m);
        out_name(e->name, out, sizeof out);
        cellf(NULL, -1, "Encrypted. Enter: decrypt to %s", out);
        endl();
        if (m.whole >= 0) {
            cellf(c_green(), -1, "Key: %s%s", keys[m.whole].path, m.prot ? "  (locked: passphrase needed)" : "");
        } else if (m.count && m.found == m.count) {
            cellf(c_green(), -1, "Key: all %d shares found%s", m.count, m.prot ? "  (locked: passphrase needed)" : "");
        } else if (m.count) {
            cellf(c_red(), -1, "Key: only %d of %d shares found: plug in the drive with the rest, then r", m.found,
                  m.count);
        } else {
            cell(c_red(), "Key: not found here or on any drive: plug in your code cylinder, then r", -1);
        }
        endl();
    } else if (e->h.kind == H_KEY || e->h.kind == H_SHARE) {
        cell(c_yellow(), "A pnp key. It belongs on your code cylinder, apart from its .pnp file.", -1);
        endl(), endl();
    } else if (is_plain(e)) {
        cellf(NULL, -1, "Enter: encrypt. Writes %s.pnp here", e->name);
        endl();
        if (cyl) {
            char k[PATH_MAX + 300];
            snprintf(k, sizeof k, "%s/%s.pnp.key", dest[cyl].path, e->name);
            cell(c_green(), "and its key to ", 15);
            cellp(c_green(), k, -1);
        }
        else
            cellf(c_yellow(), -1, "and its key beside it (%s.pnp.key): choose a code cylinder with c", e->name);
        endl();
    } else {
        cell(S_DIM, "Not a regular file: pnp can't encrypt it.", -1);
        endl(), endl();
    }
}

static void draw_browser(void)
{
    char here[PATH_MAX];
    begin_screen();
    header(NULL);
    cell(NULL, "Folder:        ", 15);
    cellp(S_BOLD, getcwd(here, sizeof here) ? here : "?", -1);
    endl();
    cylinder_line();
    rule();
    int footer = 6; /* rule, 2 detail lines, rule, status, help */
    int list = rows - row - footer;
    if (list < 1)
        list = 1;
    if (cur < top)
        top = cur;
    if (cur >= top + list)
        top = cur - list + 1;
    int nsel = 0;
    for (int i = 0; i < nents; i++)
        nsel += ents[i].sel;
    int namew = cols - 4 - 34;
    if (namew < 12)
        namew = 12;
    for (int i = top; i < top + list; i++) {
        if (i >= nents) {
            endl();
            continue;
        }
        const struct entry *e = &ents[i];
        const char *rev = i == cur ? S_REV : NULL;
        char name[300], info[160], size[32];
        snprintf(name, sizeof name, "%s%s", e->name, e->dir ? "/" : "");
        cell(rev, e->sel ? "[x] " : e->dir ? "    " : "[ ] ", 4);
        cell(rev ? S_REV S_BOLD : e->dir ? S_BOLD : NULL, name, namew);
        const char *style = S_DIM;
        human(e->size, size, sizeof size);
        if (e->dir) {
            snprintf(info, sizeof info, "folder");
        } else if (e->h.kind == H_CT) {
            struct match m;
            find_key(e->h.id, &m);
            style = match_ok(&m) ? c_green() : c_red();
            snprintf(info, sizeof info, "encrypted, %s", match_ok(&m) ? (m.prot ? "key found, locked" : "key found")
                                                         : m.count ? "shares missing" : "no key found");
        } else if (e->h.kind == H_KEY) {
            style = c_yellow();
            snprintf(info, sizeof info, "%s", e->h.prot ? "key (locked)" : "key");
        } else if (e->h.kind == H_SHARE) {
            style = c_yellow();
            snprintf(info, sizeof info, "key share %d of %d", e->h.num, e->h.count);
        } else {
            snprintf(info, sizeof info, "%s", size);
        }
        cell(rev ? S_REV : NULL, " ", 1);
        if (rev)
            cell(S_REV, info, -1);
        else
            cell(style, info, -1);
        endl();
    }
    rule();
    detail(nents ? &ents[cur] : NULL);
    rule();
    if (status[0])
        cell(status_style, status, -1);
    else if (nsel)
        cellf(S_BOLD, -1, "%d selected: Enter to continue, Esc to clear", nsel);
    endl();
    cell(S_DIM, "Space select  Enter go  Bksp up  c code cylinder  r rescan  . hidden  q quit", -1);
    end_screen();
}

/* ---- typing a folder name */

static int input_line(const char *prompt, char *buf, size_t len)
{
    size_t n = strlen(buf);
    for (;;) {
        begin_screen();
        header("Choose a folder for keys");
        endl();
        cell(NULL, prompt, -1);
        endl();
        cellf(S_BOLD, -1, "> %s_", buf);
        endl();
        endl();
        cell(S_DIM, "Type a path (~ for your home folder), Enter to use it, Esc to cancel.", -1);
        end_screen();
        int k = read_key();
        if (pnp_stop || k == K_QUIT || k == K_ESC)
            return 0;
        if (k == K_ENTER)
            return n > 0;
        if (k == K_BKSP && n > 0)
            buf[--n] = 0;
        else if (k >= 32 && k < 127 && n + 1 < len)
            buf[n++] = (char)k, buf[n] = 0;
    }
}

static void add_folder(void)
{
    char in[PATH_MAX] = "", path[PATH_MAX], *real;
    if (!input_line("Folder to keep keys in (your key drive, or a folder on it):", in, sizeof in))
        return;
    if (in[0] == '~' && getenv("HOME"))
        snprintf(path, sizeof path, "%s%s", getenv("HOME"), in + 1);
    else
        snprintf(path, sizeof path, "%s", in);
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode) || !(real = realpath(path, NULL))) {
        set_status(c_red(), "%s isn't a folder", path);
        return;
    }
    const char *base = strrchr(real, '/');
    add_dest(real, base && base[1] ? base + 1 : real, 1);
    for (int i = 1; i < ndest; i++)
        if (strcmp(dest[i].path, real) == 0)
            cyl = i;
    snprintf(cyl_path, sizeof cyl_path, "%s", real);
    free(real);
    scan_keys();
    set_status(c_green(), "Keys will go to %s", dest[cyl].name);
}

/* ---- choosing the code cylinder */

static void choose_cylinder(void)
{
    int sel = cyl;
    for (;;) {
        begin_screen();
        header("Code cylinder: where keys are written, and looked for");
        rule();
        for (int i = 0; i <= ndest; i++) {
            const char *rev = i == sel ? S_REV : NULL;
            char b[PATH_MAX + 64];
            if (i == ndest) {
                cell(rev, "  Another folder...", -1);
            } else {
                int nk = 0;
                for (int k = 0; i && k < nkeys; k++)
                    nk += strncmp(keys[k].path, dest[i].path, strlen(dest[i].path)) == 0;
                const char *ro = i && access(dest[i].path, W_OK) ? "  [read-only]" : "";
                cell(rev, i == cyl ? "* " : "  ", 2);
                if (i)
                    cellp(rev, dest[i].path, cols - 2 - (int)strlen(ro));
                else
                    cell(rev, dest_label(0, b, sizeof b), -1);
                cell(rev, ro, -1);
                if (i) {
                    endl();
                    cellf(S_DIM, -1, "    %d pnp key file%s here", nk, nk == 1 ? "" : "s");
                }
            }
            endl();
        }
        rule();
        if (ndest == 1)
            cell(c_yellow(), "No drive found in /media or /run/media. Plug in your key drive, then press r.", -1);
        endl();
        cell(S_DIM, "Up/Down move  Enter choose  r rescan  Esc back", -1);
        end_screen();
        int k = read_key();
        if (pnp_stop || k == K_QUIT || k == K_ESC || k == 'q')
            return;
        if (k == K_UP || k == 'k')
            sel = sel > 0 ? sel - 1 : 0;
        else if (k == K_DOWN || k == 'j')
            sel = sel < ndest ? sel + 1 : ndest;
        else if (k == 'r')
            scan_dests(), scan_keys();
        else if (k == K_ENTER) {
            if (sel == ndest) {
                add_folder();
            } else {
                cyl = sel;
                snprintf(cyl_path, sizeof cyl_path, "%s", sel ? dest[sel].path : "");
                set_status(sel ? c_green() : c_yellow(), "Keys will go %s%s", sel ? "to " : "beside the files",
                           sel ? dest[sel].name : "");
            }
            return;
        }
    }
}

/* ---------------------------------------------------------------- running */

/* shows prompt (on the normal screen, where pnp's own messages and passphrase prompts go) and waits for Enter */
static int wait_enter(const char *prompt)
{
    char c;
    printf("%s", prompt);
    fflush(stdout);
    for (;;) {
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r < 0 && errno == EINTR && !pnp_stop)
            continue;
        if (r <= 0 || pnp_stop)
            return -1;
        if (c == '\n')
            return 0;
    }
}

static int is_selected(const struct entry *e, int nsel, int i) { return nsel ? e->sel : i == cur; }

/* ---------------------------------------------------------------- encrypting */

static const uint32_t MEMS[] = {256, 1024, 4096, 16384, 51200};
#define NMEMS 5

static struct {
    int key_dest; /* -1: the code cylinder */
    int shares;   /* 0: one key file */
    int share_dest[MAX_SHARES];
    int lock, gen, mem, force;
} ep = {-1, 0, {0}, 0, 1, 1, 0};

enum { R_KEYDEST, R_SHARES, R_SHAREDEST, R_LOCK, R_PASS, R_MEM, R_FORCE, R_GO, R_BACK };

static int run_encrypt(int nsel);

static void encrypt_screen(int nsel)
{
    int kd = ep.key_dest < 0 || ep.key_dest >= ndest ? cyl : ep.key_dest, sel = 0, keep = -1;
    for (int i = 0; i < MAX_SHARES; i++)
        if (ep.share_dest[i] >= ndest)
            ep.share_dest[i] = 0;
    for (;;) {
        int nfiles = 0, conflicts = 0;
        for (int i = 0; i < nents; i++) {
            if (!is_selected(&ents[i], nsel, i))
                continue;
            nfiles++;
            char p[PATH_MAX];
            snprintf(p, sizeof p, "%s.pnp", ents[i].name);
            conflicts += access(p, F_OK) == 0;
        }
        /* the rows: what can be changed, then the buttons */
        int rt[8 + MAX_SHARES], ri[8 + MAX_SHARES], nr = 0;
        if (!ep.shares)
            rt[nr] = R_KEYDEST, ri[nr++] = 0;
        rt[nr] = R_SHARES, ri[nr++] = 0;
        for (int s = 0; s < ep.shares; s++)
            rt[nr] = R_SHAREDEST, ri[nr++] = s;
        rt[nr] = R_LOCK, ri[nr++] = 0;
        if (ep.lock) {
            rt[nr] = R_PASS, ri[nr++] = 0;
            rt[nr] = R_MEM, ri[nr++] = 0;
        }
        if (conflicts || ep.force)
            rt[nr] = R_FORCE, ri[nr++] = 0;
        rt[nr] = R_GO, ri[nr++] = 0;
        rt[nr] = R_BACK, ri[nr++] = 0;
        for (int r = 0; keep >= 0 && r < nr; r++) /* rows came or went: stay on the one just changed */
            if (rt[r] == keep)
                sel = r;
        keep = -1;
        if (sel >= nr)
            sel = nr - 2;

        long avail = pnp_mem_available_mib();
        char title[64], b[PATH_MAX + 64];
        snprintf(title, sizeof title, "Encrypt %d file%s", nfiles, nfiles == 1 ? "" : "s");
        begin_screen();
        header(title);
        rule();
        for (int r = 0; r < nr; r++) {
            const char *rev = r == sel ? S_REV : NULL;
            switch (rt[r]) {
            case R_KEYDEST:
                cell(NULL, "  Key goes to         ", 22);
                cell(rev, "< ", 2);
                cellp(rev, dest_label(kd, b, sizeof b), cols - col - 2);
                cell(rev, " >", 2);
                break;
            case R_SHARES:
                cell(NULL, "  Split the key       ", 22);
                if (ep.shares)
                    cellf(rev, -1, "< into %d shares, all needed to decrypt >", ep.shares);
                else
                    cell(rev, "< no: one key file >", -1);
                break;
            case R_SHAREDEST:
                cellf(NULL, 22, "    Share %d goes to", ri[r] + 1);
                cell(rev, "< ", 2);
                cellp(rev, dest_label(ep.share_dest[ri[r]], b, sizeof b), cols - col - 2);
                cell(rev, " >", 2);
                break;
            case R_LOCK:
                cell(NULL, "  Passphrase lock     ", 22);
                cell(rev, ep.lock ? "< on: the key also needs a passphrase >" : "< off >", -1);
                break;
            case R_PASS:
                cell(NULL, "    Passphrase        ", 22);
                cell(rev, ep.gen ? "< generate one for me (7 words) >" : "< I'll type my own >", -1);
                break;
            case R_MEM:
                cell(NULL, "    Memory per guess  ", 22);
                if (avail >= 0 && (long)MEMS[ep.mem] + 16 > avail)
                    cellf(rev ? rev : c_red(), -1, "< %u MiB: more than the %ld MiB free now >", MEMS[ep.mem], avail);
                else
                    cellf(rev, -1, "< %u MiB >", MEMS[ep.mem]);
                break;
            case R_FORCE:
                cell(NULL, "  Replace existing    ", 22);
                cell(rev ? rev : c_yellow(), ep.force ? "< yes: replace files that are there >" : "< no >", -1);
                break;
            case R_GO:
                endl();
                cell(rev ? S_REV S_BOLD : S_BOLD, "  [ Encrypt ]  ", 15);
                break;
            case R_BACK:
                cell(rev, "  [ Back ]  ", 12);
                break;
            }
            endl();
        }
        rule();
        /* what will be written, file by file, as far as there's room */
        cell(S_BOLD, "Will write:", -1);
        endl();
        int same = 0;
        for (int s = 1; s < ep.shares; s++)
            same += ep.share_dest[s] == ep.share_dest[0];
        for (int i = 0; i < nents && row < rows - 4; i++) {
            if (!is_selected(&ents[i], nsel, i))
                continue;
            char p[PATH_MAX];
            snprintf(p, sizeof p, "%s.pnp", ents[i].name);
            int ex = access(p, F_OK) == 0 && !ep.force;
            cellf(ex ? c_red() : NULL, -1, "  %s%s", p, ex ? "   (exists: won't be replaced)" : "   (here)");
            endl();
            for (int s = 0; s < (ep.shares ? ep.shares : 1) && row < rows - 4; s++) {
                int d = ep.shares ? ep.share_dest[s] : kd;
                char num[16] = "";
                if (ep.shares)
                    snprintf(num, sizeof num, ".%d", s + 1);
                if (d)
                    snprintf(b, sizeof b, "%s/%s.key%s", dest[d].path, p, num);
                else
                    snprintf(b, sizeof b, "%s.key%s", p, num);
                ex = access(b, F_OK) == 0 && !ep.force;
                const char *note = ex ? "   (exists: won't be replaced)" : d ? "" : "   (beside the .pnp file)";
                const char *st = ex ? c_red() : d ? c_green() : c_yellow();
                cell(NULL, "    ", 4);
                cellp(st, b, cols - 4 - (int)strlen(note));
                cell(st, note, -1);
                endl();
            }
        }
        while (row < rows - 2)
            endl();
        if ((!ep.shares && kd == 0) || (ep.shares && same == ep.shares - 1 && ep.share_dest[0] == 0))
            cell(c_yellow(), "The key stays beside the .pnp file: move it to your code cylinder afterwards.", -1);
        else if (ep.shares && same == ep.shares - 1)
            cell(c_yellow(), "Every share goes to the same place: put each on a different drive to gain anything.", -1);
        endl();
        cell(S_DIM, "Up/Down choose  Left/Right change  Enter confirm  Esc back", -1);
        end_screen();

        int k = read_key(), dir = 0;
        if (pnp_stop || k == K_QUIT || k == K_ESC || k == 'q')
            return;
        if (k == K_UP || k == 'k')
            sel = sel > 0 ? sel - 1 : 0;
        else if (k == K_DOWN || k == 'j' || k == '\t')
            sel = sel < nr - 1 ? sel + 1 : nr - 1;
        else if (k == K_LEFT || k == 'h')
            dir = -1;
        else if (k == K_RIGHT || k == 'l' || k == ' ')
            dir = 1;
        else if (k == K_ENTER) {
            if (rt[sel] == R_BACK)
                return;
            if (rt[sel] == R_GO) {
                ep.key_dest = kd;
                if (run_encrypt(nsel) < 0)
                    return;
                return;
            }
            dir = 1;
        }
        if (dir) {
            keep = rt[sel];
            switch (rt[sel]) {
            case R_KEYDEST: kd = (kd + dir + ndest) % ndest, ep.key_dest = kd; break;
            case R_SHARES:
                ep.shares = ep.shares + dir == 1 ? (dir > 0 ? 2 : 0) : ep.shares + dir;
                if (ep.shares < 0)
                    ep.shares = MAX_SHARES;
                if (ep.shares > MAX_SHARES)
                    ep.shares = 0;
                /* new shares: spread over the drives, starting with the cylinder */
                for (int s = 0; s < ep.shares; s++)
                    if (!ep.share_dest[s] && ndest > 1)
                        ep.share_dest[s] = 1 + (cyl ? cyl - 1 + s : s) % (ndest - 1);
                break;
            case R_SHAREDEST: {
                int *d = &ep.share_dest[ri[sel]];
                *d = (*d + dir + ndest) % ndest;
                break;
            }
            case R_LOCK: ep.lock = !ep.lock; break;
            case R_PASS: ep.gen = !ep.gen; break;
            case R_MEM: ep.mem = (ep.mem + dir + NMEMS) % NMEMS; break;
            case R_FORCE: ep.force = !ep.force; break;
            }
        }
    }
}

/* -1 if the terminal went away or a signal came */
static int run_encrypt(int nsel)
{
    char passbuf[PNP_PASS_MAX], err[512];
    int ok = 0, failed = 0, ret = 0;
    term_leave();
    printf("pnp: encrypting\n\n");
    if (ep.lock) {
        if (ep.gen) {
            if (pnp_make_passphrase(7, passbuf, sizeof passbuf, 0) < 0)
                goto done;
            printf("\nYour passphrase (7 words from the EFF list, about 90 bits):\n\n    %s\n\n"
                   "Write it down now and keep it apart from the key: without it the files can't be decrypted.\n",
                   passbuf);
            if (wait_enter("Press Enter once it's written down.") < 0) {
                ret = -1;
                goto done;
            }
            printf("\033[2J\033[H"); /* off the screen once written down */
        } else {
            long n = pnp_read_passphrase(NULL, 1, passbuf, sizeof passbuf, err, sizeof err);
            if (n < 0) {
                printf("pnp: %s\n", err);
                goto done;
            }
        }
        pnp_preset_passphrase(passbuf, strlen(passbuf));
        explicit_bzero(passbuf, sizeof passbuf);
    }
    struct protect_opts po = {ep.lock, MEMS[ep.mem], NULL};
    for (int i = 0; i < nents && !pnp_stop; i++) {
        if (!is_selected(&ents[i], nsel, i))
            continue;
        char *outs[MAX_SHARES];
        int nouts = 0;
        if (ep.shares) {
            for (int s = 0; s < ep.shares; s++)
                outs[nouts++] = dest[ep.share_dest[s]].path;
        } else if (ep.key_dest > 0) {
            outs[nouts++] = dest[ep.key_dest].path;
        }
        char shown[256];
        snprintf(shown, sizeof shown, "%s", ents[i].name);
        pnp_clean(shown);
        printf("--- %s\n", shown);
        fflush(stdout);
        if (pnp_encrypt(ents[i].name, NULL, outs, nouts, ep.shares, ep.force, 0, &po) == 0)
            ok++;
        else
            failed++;
    }
    printf("\n%d encrypted%s", ok, failed ? "" : ".");
    if (failed)
        printf(", %d failed (see above).", failed);
    printf("\n");
    set_status(failed ? c_red() : c_green(), "%d file%s encrypted%s", ok, ok == 1 ? "" : "s",
               failed ? ", some failed" : "");
done:
    explicit_bzero(passbuf, sizeof passbuf);
    pnp_clear_passphrase();
    if (!ret && !pnp_stop && wait_enter("\nPress Enter to go back to the files.") < 0)
        ret = -1;
    if (pnp_stop)
        ret = -1;
    term_enter();
    return ret;
}

/* ---------------------------------------------------------------- decrypting */

static int run_decrypt(int nsel, int force, int any_prot);

static void decrypt_screen(int nsel)
{
    int sel = 0, force = 0;
    for (;;) {
        int nfiles = 0, ready = 0, conflicts = 0, any_prot = 0;
        begin_screen();
        char title[64];
        for (int i = 0; i < nents; i++)
            nfiles += is_selected(&ents[i], nsel, i);
        snprintf(title, sizeof title, "Decrypt %d file%s", nfiles, nfiles == 1 ? "" : "s");
        header(title);
        rule();
        int list_end = rows - 7;
        for (int i = 0; i < nents; i++) {
            if (!is_selected(&ents[i], nsel, i))
                continue;
            struct match m;
            char out[300], *kp[MAX_SHARES];
            find_key(ents[i].h.id, &m);
            out_name(ents[i].name, out, sizeof out);
            int ex = access(out, F_OK) == 0;
            conflicts += ex;
            if (match_ok(&m)) {
                ready++;
                any_prot |= m.prot;
            }
            if (row >= list_end)
                continue;
            cellf(S_BOLD, -1, "  %s  ->  %s%s", ents[i].name, out, ex && !force ? "   (exists: won't be replaced)" : "");
            endl();
            if (match_ok(&m)) {
                int n = match_paths(&m, kp);
                for (int k = 0; k < n && row < list_end; k++) {
                    const char *note = m.prot && k == 0 ? "   (locked: passphrase needed)" : "";
                    cell(c_green(), n == 1 ? "      key:   " : "      share: ", 13);
                    cellp(c_green(), kp[k], cols - 13 - (int)strlen(note));
                    cell(c_green(), note, -1);
                    endl();
                }
            } else if (m.count) {
                char miss[64] = "";
                for (int s = 1; s <= m.count; s++)
                    if (m.share[s] < 0)
                        snprintf(miss + strlen(miss), sizeof miss - strlen(miss), "%s%d", miss[0] ? ", " : "", s);
                cellf(c_red(), -1, "      only %d of %d shares found (missing %s): skipped", m.found, m.count, miss);
                endl();
            } else {
                cell(c_red(), "      no key found here or on any drive: skipped", -1);
                endl();
            }
        }
        rule();
        int rt[3], nr = 0;
        if (conflicts)
            rt[nr++] = R_FORCE;
        rt[nr++] = R_GO;
        rt[nr++] = R_BACK;
        if (sel >= nr)
            sel = nr - 2;
        for (int r = 0; r < nr; r++) {
            const char *rev = r == sel ? S_REV : NULL;
            if (rt[r] == R_FORCE) {
                cell(NULL, "  Replace existing    ", 22);
                cell(rev ? rev : c_yellow(), force ? "< yes: replace files that are there >" : "< no >", -1);
            } else if (rt[r] == R_GO) {
                if (ready)
                    cellf(rev ? S_REV S_BOLD : S_BOLD, 18, "  [ Decrypt %d ]  ", ready);
                else
                    cell(rev ? rev : S_DIM, "  [ nothing to decrypt: keys missing ]  ", -1);
            } else {
                cell(rev, "  [ Back ]  ", 12);
            }
            endl();
        }
        while (row < rows - 1)
            endl();
        cell(S_DIM, "Up/Down choose  Left/Right change  Enter confirm  r rescan  Esc back", -1);
        end_screen();

        int k = read_key();
        if (pnp_stop || k == K_QUIT || k == K_ESC || k == 'q')
            return;
        if (k == K_UP || k == 'k')
            sel = sel > 0 ? sel - 1 : 0;
        else if (k == K_DOWN || k == 'j' || k == '\t')
            sel = sel < nr - 1 ? sel + 1 : nr - 1;
        else if (k == 'r')
            scan_dests(), scan_keys();
        else if ((k == K_LEFT || k == K_RIGHT || k == ' ' || k == K_ENTER) && rt[sel] == R_FORCE)
            force = !force;
        else if (k == K_ENTER && rt[sel] == R_BACK)
            return;
        else if (k == K_ENTER && rt[sel] == R_GO && ready) {
            run_decrypt(nsel, force, any_prot);
            return;
        }
    }
}

static int run_decrypt(int nsel, int force, int any_prot)
{
    char passbuf[PNP_PASS_MAX], err[512];
    int ok = 0, failed = 0, ret = 0;
    term_leave();
    printf("pnp: decrypting\n\n");
    if (any_prot) {
        long n = pnp_read_passphrase(NULL, 0, passbuf, sizeof passbuf, err, sizeof err);
        if (n < 0) {
            printf("pnp: %s\n", err);
            goto done;
        }
        pnp_preset_passphrase(passbuf, (size_t)n);
        explicit_bzero(passbuf, sizeof passbuf);
    }
    for (int i = 0; i < nents && !pnp_stop; i++) {
        if (!is_selected(&ents[i], nsel, i))
            continue;
        struct match m;
        char out[300], *kp[MAX_SHARES];
        find_key(ents[i].h.id, &m);
        if (!match_ok(&m))
            continue;
        out_name(ents[i].name, out, sizeof out);
        char shown[256];
        snprintf(shown, sizeof shown, "%s", ents[i].name);
        pnp_clean(shown);
        printf("--- %s\n", shown);
        fflush(stdout);
        if (pnp_decrypt(ents[i].name, kp, match_paths(&m, kp), out, force, NULL) == 0)
            ok++;
        else
            failed++;
    }
    printf("\n%d decrypted%s", ok, failed ? "" : ".");
    if (failed)
        printf(", %d failed (see above).", failed);
    printf("\n");
    set_status(failed ? c_red() : c_green(), "%d file%s decrypted%s", ok, ok == 1 ? "" : "s",
               failed ? ", some failed" : "");
done:
    explicit_bzero(passbuf, sizeof passbuf);
    pnp_clear_passphrase();
    if (!pnp_stop && wait_enter("\nPress Enter to go back to the files.") < 0)
        ret = -1;
    if (pnp_stop)
        ret = -1;
    term_enter();
    return ret;
}

/* ---------------------------------------------------------------- the main loop */

/* Enter in the file list: open a folder, or encrypt or decrypt the selection (or the highlighted file) */
static void go(void)
{
    int nsel = 0, plain = 0, ct = 0, other = 0;
    for (int i = 0; i < nents; i++)
        nsel += ents[i].sel;
    if (!nsel && nents && ents[cur].dir) {
        if (chdir(ents[cur].name) < 0) {
            set_status(c_red(), "can't open %s: %s", ents[cur].name, strerror(errno));
            return;
        }
        cur = top = 0;
        scan_keys();
        load_dir();
        return;
    }
    for (int i = 0; i < nents; i++) {
        if (!is_selected(&ents[i], nsel, i))
            continue;
        if (ents[i].h.kind == H_CT)
            ct++;
        else if (is_plain(&ents[i]))
            plain++;
        else
            other++;
    }
    if (other && !plain && !ct)
        set_status(c_yellow(), "That's %s: choose a file to encrypt, or a .pnp file to decrypt",
                   nents && (ents[cur].h.kind == H_KEY || ents[cur].h.kind == H_SHARE) ? "a key" : "not a regular file");
    else if (plain && ct)
        set_status(c_yellow(), "Select only files to encrypt, or only .pnp files to decrypt, not both");
    else if (other)
        set_status(c_yellow(), "The selection has keys or folders in it: select only files to encrypt or decrypt");
    else if (plain)
        encrypt_screen(nsel);
    else if (ct)
        decrypt_screen(nsel);
    if (plain || ct) {
        for (int i = 0; i < nents; i++)
            ents[i].sel = 0;
        refresh_all();
    }
}

static void up_folder(void)
{
    char here[PATH_MAX], *base;
    if (!getcwd(here, sizeof here) || strcmp(here, "/") == 0 || chdir("..") < 0)
        return;
    base = strrchr(here, '/');
    scan_keys();
    load_dir();
    cur = top = 0;
    for (int i = 0; base && i < nents; i++) /* land on the folder just left */
        if (strcmp(ents[i].name, base + 1) == 0)
            cur = i;
}

int pnp_tui(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_winch; /* no SA_RESTART: the read returns and the screen is redrawn */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGWINCH, &sa, NULL);
    color = getenv("NO_COLOR") == NULL || !getenv("NO_COLOR")[0];
    refresh_all();
    term_enter();
    for (int quit = 0; !quit && !pnp_stop;) {
        draw_browser();
        int k = read_key();
        if (k != K_NONE)
            status[0] = 0;
        switch (k) {
        case K_QUIT: case 'q': quit = 1; break;
        case K_UP: case 'k': cur = cur > 0 ? cur - 1 : 0; break;
        case K_DOWN: case 'j': cur = cur < nents - 1 ? cur + 1 : cur; break;
        case K_PGUP: cur = cur > 10 ? cur - 10 : 0; break;
        case K_PGDN: cur = cur + 10 < nents ? cur + 10 : (nents ? nents - 1 : 0); break;
        case K_HOME: case 'g': cur = 0; break;
        case K_END: case 'G': cur = nents ? nents - 1 : 0; break;
        case ' ':
            if (nents && !ents[cur].dir && (is_plain(&ents[cur]) || ents[cur].h.kind == H_CT))
                ents[cur].sel = !ents[cur].sel;
            cur = cur < nents - 1 ? cur + 1 : cur;
            break;
        case K_ESC:
            for (int i = 0; i < nents; i++)
                ents[i].sel = 0;
            break;
        case K_ENTER: case K_RIGHT: go(); break;
        case K_BKSP: case K_LEFT: up_folder(); break;
        case 'c': choose_cylinder(); break;
        case 'r': refresh_all(); set_status(NULL, "Looked again for drives and keys"); break;
        case '.': show_hidden = !show_hidden; load_dir(); break;
        }
    }
    term_leave();
#ifdef PNP_TEST
    if (getenv("PNP_TEST_FDS")) { /* test hook: what this process still has open, to catch leaked descriptors */
        FILE *f = fopen(getenv("PNP_TEST_FDS"), "we");
        DIR *d = opendir("/proc/self/fd");
        struct dirent *e;
        while (f && d && (e = readdir(d))) {
            char p[300], target[PATH_MAX];
            ssize_t n;
            snprintf(p, sizeof p, "/proc/self/fd/%s", e->d_name);
            if (e->d_name[0] != '.' && (n = readlink(p, target, sizeof target - 1)) > 0)
                fprintf(f, "%.*s\n", (int)n, target);
        }
        if (d)
            closedir(d);
        if (f)
            fclose(f);
    }
#endif
    free(ents);
    free(keys);
    free(scr);
    ents = NULL, keys = NULL, scr = NULL;
    return 0;
}
