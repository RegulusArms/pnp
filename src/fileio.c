/* Writing outputs failure-atomically.
 *
 * A failure, a cancel (Ctrl-C) or a crash must never leave a half-written file under a real name, and never
 * replace an existing file unless asked (-f). So each output is written under a hidden part name in the same
 * folder (".NAME.XXXXXX.pnp-part", created with O_EXCL), fsynced, and renamed into place:
 *   - without replacing: renameat2(RENAME_NOREPLACE), which fails if the name was taken meanwhile. Filesystems
 *     without it get link() + unlink() (also refuses a taken name); ones without hard links either (FAT, some
 *     network filesystems) get a check-then-rename, which can race with another program creating the same name in
 *     between. That's the best those filesystems allow.
 *   - replacing (-f): rename(), atomic: the old file stays whole until the new one takes its name.
 * On failure only the part is removed. */
#define _GNU_SOURCE
#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

int pnp_write_all(int fd, const void *buf, size_t n)
{
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
static char *dir_of(const char *path)
{
    char *copy = strdup(path);
    if (!copy)
        return NULL;
    char *d = strdup(dirname(copy));
    free(copy);
    return d;
}

static char *base_of(const char *path)
{
    char *copy = strdup(path);
    if (!copy)
        return NULL;
    char *b = strdup(basename(copy));
    free(copy);
    return b;
}

int pnp_out_open(struct pnp_out *o, const char *path, mode_t mode, char *err, size_t errlen)
{
    memset(o, 0, sizeof *o);
    o->fd = -1;
    o->path = strdup(path);
    char *dir = dir_of(path), *base = base_of(path);
    if (!o->path || !dir || !base) {
        snprintf(err, errlen, "out of memory");
        goto fail;
    }
    static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int attempt = 0; attempt < 100; attempt++) {
        unsigned char r[6];
        char suffix[7];
        if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r) {
            snprintf(err, errlen, "getrandom: %s", strerror(errno));
            goto fail;
        }
        for (int i = 0; i < 6; i++)
            suffix[i] = letters[r[i] % (sizeof letters - 1)];
        suffix[6] = 0;
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
    if (fsync(o->fd) < 0 || close(o->fd) < 0) {
        o->fd = -1;
        snprintf(err, errlen, "can't write %s: %s", o->path, strerror(errno));
        return -1;
    }
    o->fd = -1;
    int r;
    if (replace) {
        r = rename(o->part, o->path);
    } else {
        r = renameat2(AT_FDCWD, o->part, AT_FDCWD, o->path, RENAME_NOREPLACE);
        if (r < 0 && (errno == EINVAL || errno == ENOSYS)) {
            r = link(o->part, o->path);
            if (r == 0) {
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
    return 0;
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
    free(o->part);
    free(o->path);
    memset(o, 0, sizeof *o);
    o->fd = -1;
}

void pnp_sync_dir(const char *path)
{
    char *dir = dir_of(path);
    if (!dir)
        return;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
    free(dir);
}
