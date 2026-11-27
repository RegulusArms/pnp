/* Courier sticks, self sticks and kill cards: raw stores of checksummed records (courier.c). At a meeting every
 * transfer goes through them; the test setup (PNP_TEST_SETUP) uses plain files with the same format. */
#ifndef PNP_COURIER_H
#define PNP_COURIER_H

#include "group.h"

#include <stdint.h>

#define CS_HDR_LEN 64
#define CS_REC_HDR 16
#define CS_SUM_LEN 32 /* BLAKE2b-256 of a record's header and data: catches damage, not attacks (see courier.c) */

enum cs_role { CS_COURIER = 0, CS_SELF = 1, CS_KILLCARD = 2 };
enum cs_type {
    R_ROSTER = 1,      /* the group file as agreed at the meeting (me = the writer) */
    R_POOL = 2,        /* a member's random contribution to the two pools of a pair, for one key set */
    R_SIGN_FULL = 3,   /* a signer's own signing functions, for one key set */
    R_SIGN_BLOCK = 4,  /* the block of a signer's functions for one recipient */
    R_SPLIT = 5,       /* a recipient's share of a signer's block for another recipient: (position, function)s */
    R_TEST_SIG = 6,    /* a test signature (slot 0) */
    R_TEST_SEAL = 7,   /* a test seal on the pool from -> to (its first item) */
};

struct cstore {
    int fd;
    char *path;
    int role, owner, visiting, round;
    int done; /* the member it's visiting has finished writing: it can go back to its owner */
    uint8_t group[GRP_ID_LEN];
    uint32_t gen;
    uint64_t end;      /* where the records end */
    uint64_t capacity; /* the store's size */
};

struct crec {
    int type, from, to, signer, set;
    uint64_t len;
    uint64_t data; /* where the data starts in the store */
};

/* Makes path a fresh, empty store (a file is created or sized to capacity, or keeps its size if capacity is 0;
 * a device keeps its size). */
int cs_create(struct cstore *c, const char *path, int role, int owner, const uint8_t group[GRP_ID_LEN],
              uint32_t gen, uint64_t capacity, char *err, size_t errlen);
int cs_open(struct cstore *c, const char *path, char *err, size_t errlen);
void cs_close(struct cstore *c);
/* Sets who the courier is visiting next (not done yet) and saves the header. */
int cs_address(struct cstore *c, int visiting, int round, char *err, size_t errlen);
/* The visited member has finished: the courier can go back to its owner. */
int cs_done(struct cstore *c, char *err, size_t errlen);
/* Sets the group a store belongs to (the roster step) and saves the header. */
int cs_set_group(struct cstore *c, const uint8_t group[GRP_ID_LEN], uint32_t gen, char *err, size_t errlen);

/* pnp's partition type (pnp-courier-setup, data/61-pnp-courier.rules) */
#define CS_PART_TYPE "ec8e96c1-785d-4e11-b871-78e0064ee05e"
/* The pnp sticks plugged in (partitions of pnp's type), or, with dir, the files in that folder (tests). */
int cs_find_devices(const char *dir, char **paths, int max);
/* Writes the whole stick with a keystream and reads it all back: a stick that holds less than it claims, or
 * ignores writes, is caught. Leaves it blank. */
int cs_capacity_check(const char *path, char *err, size_t errlen);

/* Appending a record: begin, write its data in any number of pieces (exactly len bytes in all), end. */
struct cwriter {
    struct cstore *c;
    uint64_t start, len, done;
    uint8_t hdr[CS_REC_HDR];
    void *hash; /* struct pnp_blake2b */
};
int cs_begin(struct cstore *c, struct cwriter *w, const struct crec *r, char *err, size_t errlen);
int cs_write(struct cwriter *w, const void *buf, size_t n);
int cs_end(struct cwriter *w, char *err, size_t errlen);

/* Reads the records: i = 0, 1, ... until it returns 1 (no more); -1 on a damaged record (checksum or bounds). */
int cs_record(struct cstore *c, uint64_t *pos, struct crec *r);
int cs_read(struct cstore *c, const struct crec *r, uint64_t off, void *buf, size_t n);
/* Checks every record's checksum. 0, or -1 with the reason in err. */
int cs_verify(struct cstore *c, char *err, size_t errlen);
/* Finds a record by type/from/to/signer/set (-1 = any). 0 or -1. */
int cs_find(struct cstore *c, int type, int from, int to, int signer, int set, struct crec *r);
/* Copies every record of src addressed to (or written for) dst's owner into dst (moving a courier's contents onto
 * the self stick). */
int cs_copy_all(struct cstore *src, struct cstore *dst, char *err, size_t errlen);
/* Overwrites everything up to the records' end (and the header) with fresh random bytes, then reads it all back
 * to check the overwrite happened (a stick that ignores writes or fakes its size is caught). */
int cs_overwrite(struct cstore *c, char *err, size_t errlen);

#endif
