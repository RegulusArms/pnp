/* Writing outputs failure-atomically: each is built under a hidden part name beside it and renamed into place only
 * when it's complete. See fileio.c. */
#ifndef PNP_FILEIO_H
#define PNP_FILEIO_H

#include <stddef.h>
#include <sys/types.h>

struct pnp_out {
    char *path;   /* the real name */
    char *part;   /* the hidden part it's written under */
    int fd;
    int placed;   /* renamed into place */
};

/* Creates the part for path with mode (less the umask: a key made 0600 is never readable by others). */
int pnp_out_open(struct pnp_out *o, const char *path, mode_t mode, char *err, size_t errlen);
/* Writes all n bytes; -1 on failure (errno set). */
int pnp_write_all(int fd, const void *buf, size_t n);
/* fsyncs the part and moves it to its real name: without replacing anything, or replacing when replace is set. */
int pnp_out_commit(struct pnp_out *o, int replace, char *err, size_t errlen);
/* Removes the part (if not yet placed) and frees o. Safe to call twice. */
void pnp_out_discard(struct pnp_out *o);
/* Removes the placed file again (undoing a commit whose partner output failed). */
void pnp_out_unplace(struct pnp_out *o);
/* The folder part of path ("." for a bare name) and its last part, malloc'd (NULL when out of memory). */
char *pnp_dir_of(const char *path);
char *pnp_base_of(const char *path);
/* fsyncs the folder holding path, so the renames survive a crash. */
void pnp_sync_dir(const char *path);

#endif
