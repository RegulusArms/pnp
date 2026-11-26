/* Writing outputs failure-atomically: each is built under a hidden part name beside it and renamed into place only
 * when it's complete. See fileio.c. */
#ifndef PNP_FILEIO_H
#define PNP_FILEIO_H

#include <stddef.h>
#include <sys/types.h>

/* test builds: a place pnp can be made to crash at (PNP_TEST_CRASH_AT, fileio.c); nothing otherwise */
#ifdef PNP_TEST
void pnp_crash_point(const char *what);
#else
#define pnp_crash_point(what) ((void)0)
#endif

struct pnp_out {
    char *path;   /* the real name */
    char *part;   /* the hidden part it's written under */
    int fd;
    int placed;   /* renamed into place */
    char *aside;  /* the old file, moved aside to be replaced (pnp_out_aside), until dropped or put back */
};

/* Creates the part for path with mode (less the umask: a key made 0600 is never readable by others). */
int pnp_out_open(struct pnp_out *o, const char *path, mode_t mode, char *err, size_t errlen);
/* Writes all n bytes; -1 on failure (errno set). */
int pnp_write_all(int fd, const void *buf, size_t n);
/* fsyncs the part and moves it to its real name: without replacing anything, or replacing when replace is set. */
int pnp_out_commit(struct pnp_out *o, int replace, char *err, size_t errlen);
/* Moves an existing file at o's real name aside (to a hidden name beside it), so it can be put back if a later
 * step fails. 0 if there was nothing there or it was moved; -1 with the reason in err. */
int pnp_out_aside(struct pnp_out *o, char *err, size_t errlen);
/* Deletes the old file moved aside, once every new output is in place. */
void pnp_out_drop_old(struct pnp_out *o);
/* Removes the part (if not yet placed), puts back an old file moved aside (removing the new one if placed), and
 * frees o. Safe to call twice. */
void pnp_out_discard(struct pnp_out *o);
/* Removes the placed file again (undoing a commit whose partner output failed). */
void pnp_out_unplace(struct pnp_out *o);
/* The folder part of path ("." for a bare name) and its last part, malloc'd (NULL when out of memory). */
char *pnp_dir_of(const char *path);
char *pnp_base_of(const char *path);
/* fsyncs the folder holding path, so the renames survive a crash. */
void pnp_sync_dir(const char *path);
/* For a hidden part or moved-aside name (".NAME.XXXXXX.pnp-part" / ".pnp-old"): 0 with NAME in name and *old set,
 * or -1 if entry isn't one. */
int pnp_leftover_name(const char *entry, char *name, size_t len, int *old);
/* Calls found() for each part or moved-aside file left in dir by an interrupted run; returns how many. */
int pnp_find_leftovers(const char *dir, void (*found)(const char *dir, const char *entry, const char *name, int old,
                                                      void *ctx),
                       void *ctx);

#endif
