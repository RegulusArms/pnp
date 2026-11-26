/* Writing outputs failure-atomically.
 *
 * A failure, a cancel (Ctrl-C) or a crash must never leave a half-written file under a real name, and never
 * replace an existing file unless asked (-f). So each output is written under a hidden part name in the same
 * folder (".NAME.XXXXXX.pnp-part", created with O_EXCL), fsynced, and renamed into place:
 *   - without replacing: renameat2(RENAME_NOREPLACE), which fails if the name was taken meanwhile. Filesystems
 *     without it get link() + unlink() (also refuses a taken name); ones without hard links either (FAT, some
 *     network filesystems) get a check-then-rename, which can race with another program creating the same name in
 *     between. That's the best those filesystems allow.
 *   - replacing (-f): rename(), atomic: the old file stays whole until the new one takes its name. With several
 *     outputs (encrypting), the old files are first moved aside instead (pnp_out_aside, below).
 * On failure only the part is removed. */
#define _GNU_SOURCE
#include "fileio.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef PNP_TEST
/* Test builds only: PNP_TEST_CRASH_AT=N kills pnp (SIGKILL: no cleanup, like a crash) at the Nth of these points,
 * which sit between every step that changes files: each write, each fsync, each rename, link and unlink. Tests
 * walk N up from 1 until a run gets through, and check after each crash that nothing is lost (tests/run.sh,
 * "crash"). With PNP_TEST_CRASH_SAY set, the point's name is printed first. */
void pnp_crash_point(const char *what)
{
    static long n;
    const char *at = getenv("PNP_TEST_CRASH_AT");
    if (at && ++n == atol(at)) {
        if (getenv("PNP_TEST_CRASH_SAY"))
            fprintf(stderr, "crash: %s\n", what);
        raise(SIGKILL);
    }
}
#endif

int pnp_write_all(int fd, const void *buf, size_t n)
{
    pnp_crash_point("write");
    const unsigned char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* dir part of path ("." for a bare name), malloc'd */
char *pnp_dir_of(const char *path)
{
    char *copy = strdup(path);
    if (!copy)
        return NULL;
    char *d = strdup(dirname(copy));
    free(copy);
    return d;
}

char *pnp_base_of(const char *path)
{
    char *copy = strdup(path);
    if (!copy)
        return NULL;
    char *b = strdup(basename(copy));
    free(copy);
    return b;
}

/* a random 6-letter suffix for hidden names; -1 if getrandom fails */
static int suffix6(char out[7])
{
    static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char r[6];
    if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r)
        return -1;
    for (int i = 0; i < 6; i++)
        out[i] = letters[r[i] % (sizeof letters - 1)];
    out[6] = 0;
    return 0;
}

int pnp_out_open(struct pnp_out *o, const char *path, mode_t mode, char *err, size_t errlen)
{
    memset(o, 0, sizeof *o);
    o->fd = -1;
    o->path = strdup(path);
    char *dir = pnp_dir_of(path), *base = pnp_base_of(path);
    if (!o->path || !dir || !base) {
        snprintf(err, errlen, "out of memory");
        goto fail;
    }
    for (int attempt = 0; attempt < 100; attempt++) {
        char suffix[7];
        if (suffix6(suffix) < 0) {
            snprintf(err, errlen, "getrandom: %s", strerror(errno));
            goto fail;
        }
        free(o->part);
        if (asprintf(&o->part, "%s/.%s.%s.pnp-part", dir, base, suffix) < 0) {
            o->part = NULL;
            snprintf(err, errlen, "out of memory");
            goto fail;
        }
        o->fd = open(o->part, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
        if (o->fd >= 0 || errno != EEXIST)
            break;
    }
    if (o->fd < 0) {
        snprintf(err, errlen, "can't create a file in %s: %s", dir, strerror(errno));
        goto fail;
    }
    pnp_crash_point("part created");
    free(dir);
    free(base);
    return 0;
fail:
    free(dir);
    free(base);
    pnp_out_discard(o);
    return -1;
}

int pnp_out_commit(struct pnp_out *o, int replace, char *err, size_t errlen)
{
    pnp_crash_point("before fsync");
    int synced = fsync(o->fd), e = errno;
    int closed = close(o->fd); /* always closed, even when fsync failed */
    o->fd = -1;
    if (synced < 0 || closed < 0) {
        snprintf(err, errlen, "can't write %s: %s", o->path, strerror(synced < 0 ? e : errno));
        return -1;
    }
    pnp_crash_point("before rename into place");
    int r;
    if (replace) {
        r = rename(o->part, o->path);
    } else {
        r = renameat2(AT_FDCWD, o->part, AT_FDCWD, o->path, RENAME_NOREPLACE);
        if (r < 0 && (errno == EINVAL || errno == ENOSYS)) {
            r = link(o->part, o->path);
            if (r == 0) {
                pnp_crash_point("linked, before unlinking the part");
                unlink(o->part);
            } else if (errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP) {
                /* no hard links here either: check, then rename (see the top of this file) */
                struct stat st;
                if (lstat(o->path, &st) == 0) {
                    errno = EEXIST;
                    r = -1;
                } else {
                    r = rename(o->part, o->path);
                }
            }
        }
    }
    if (r < 0) {
        snprintf(err, errlen, errno == EEXIST ? "%s appeared while pnp was writing it (left untouched)"
                                              : "can't save %s: %s",
                 o->path, strerror(errno));
        return -1;
    }
    o->placed = 1;
    pnp_crash_point("renamed into place");
    return 0;
}

/* Replacing (-f) with several outputs (a key or shares, then the ciphertext) can't be one atomic rename, and a
 * key replaced and then lost because a later output failed could mean a file lost for good. So each old file is
 * first renamed aside to a hidden ".NAME.XXXXXX.pnp-old" beside it, the new files take the free names, and the
 * old ones are deleted only once every new one is in place. If anything fails, discarding puts them back. A crash
 * in between leaves the old files under those names, never deleted. */
int pnp_out_aside(struct pnp_out *o, char *err, size_t errlen)
{
    struct stat st;
    if (lstat(o->path, &st) < 0)
        return errno == ENOENT ? 0 : (snprintf(err, errlen, "can't check %s: %s", o->path, strerror(errno)), -1);
    char *dir = pnp_dir_of(o->path), *base = pnp_base_of(o->path), suffix[7];
    int r = -1;
    pnp_crash_point("before moving the old file aside");
    if (!dir || !base || suffix6(suffix) < 0 || asprintf(&o->aside, "%s/.%s.%s.pnp-old", dir, base, suffix) < 0) {
        o->aside = NULL;
        snprintf(err, errlen, "out of memory");
    } else if ((r = renameat2(AT_FDCWD, o->path, AT_FDCWD, o->aside, RENAME_NOREPLACE)) < 0 &&
               (errno == EINVAL || errno == ENOSYS)) {
        r = rename(o->path, o->aside); /* no RENAME_NOREPLACE here; the random name won't be taken */
    }
    if (r < 0 && o->aside) {
        snprintf(err, errlen, "can't move the old %s aside to replace it: %s", o->path, strerror(errno));
        free(o->aside);
        o->aside = NULL;
    }
    free(dir);
    free(base);
    if (r == 0)
        pnp_crash_point("old file moved aside");
    return r < 0 ? -1 : 0;
}

void pnp_out_drop_old(struct pnp_out *o)
{
    if (o->aside) {
        pnp_crash_point("before deleting the old file");
        unlink(o->aside);
        free(o->aside);
        o->aside = NULL;
    }
}

void pnp_out_unplace(struct pnp_out *o)
{
    if (o->placed && o->path) {
        unlink(o->path);
        o->placed = 0;
    }
}

void pnp_out_discard(struct pnp_out *o)
{
    if (o->fd >= 0)
        close(o->fd);
    if (o->part && !o->placed)
        unlink(o->part);
    if (o->aside && o->path) { /* a failure after moving the old file aside: put it back */
        if (o->placed) {
            pnp_crash_point("putting back: before removing the new file");
            unlink(o->path);
        }
        pnp_crash_point("putting back: before renaming the old file back");
        rename(o->aside, o->path);
        free(o->aside);
    }
    free(o->part);
    free(o->path);
    memset(o, 0, sizeof *o);
    o->fd = -1;
}

void pnp_sync_dir(const char *path)
{
    char *dir = pnp_dir_of(path);
    if (!dir)
        return;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    pnp_crash_point("before fsyncing the folder");
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
    free(dir);
}

/* Leftovers of a run that was killed or lost power partway (see the top of this file and docs/recovery.md): a part
 * is ".NAME.XXXXXX.pnp-part", an old file moved aside ".NAME.XXXXXX.pnp-old". Only names in exactly that shape
 * count, so a user's own file is never reported. */
int pnp_leftover_name(const char *entry, char *name, size_t len, int *old)
{
    static const char part[] = ".pnp-part", aside[] = ".pnp-old";
    size_t n = strlen(entry), sfx;
    if (n > sizeof part - 1 && strcmp(entry + n - (sizeof part - 1), part) == 0)
        sfx = sizeof part - 1, *old = 0;
    else if (n > sizeof aside - 1 && strcmp(entry + n - (sizeof aside - 1), aside) == 0)
        sfx = sizeof aside - 1, *old = 1;
    else
        return -1;
    /* "." + NAME (at least 1) + "." + 6 letters + suffix */
    if (entry[0] != '.' || n < 1 + 1 + 7 + sfx || entry[n - sfx - 7] != '.')
        return -1;
    size_t name_len = n - sfx - 7 - 1;
    if (name_len + 1 > len)
        return -1;
    memcpy(name, entry + 1, name_len);
    name[name_len] = 0;
    return 0;
}

int pnp_find_leftovers(const char *dir, void (*found)(const char *dir, const char *entry, const char *name, int old,
                                                      void *ctx),
                       void *ctx)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        char name[256];
        int old;
        if (pnp_leftover_name(e->d_name, name, sizeof name, &old) == 0) {
            found(dir, e->d_name, name, old, ctx);
            count++;
        }
    }
    closedir(d);
    return count;
}
