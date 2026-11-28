/* Pairs and groups: key material shared at an in-person meeting, for seals (pairs), signatures (groups of 3+),
 * messages and kill notices. Storage, the group file, pools and their locators, the clock and the timestamps live
 * in group.c; see it for the layout. docs/format.md has the file formats. */
#ifndef PNP_GROUP_H
#define PNP_GROUP_H

#include <stddef.h>
#include <stdint.h>

#define GRP_ID_LEN 16
#define GRP_MAX_MEMBERS 255
#define GRP_NAME_LEN 64   /* group name, NUL-terminated */
#define GRP_MEMBER_LEN 32 /* member name, NUL-terminated */
#define GRP_MAX_SETS 1024
#define GRP_LOC_LEN 16    /* a locator */
#define GRP_LOC_ENTRY 24  /* a locator and its 8-byte offset mask */
#define GRP_KEY_LEN 32    /* a one-time MAC key (k, s) */
#define GRP_INDEFINITE_START INT32_MIN
#define GRP_INDEFINITE_END INT32_MAX
#define GRP_ANON_TIME 946684800 /* 2000-01-01: every timestamp of an anonymous group */

enum grp_kind { GRP_SET_NORMAL = 0, GRP_SET_EMERGENCY = 1 };
enum grp_state { GRP_ACTIVE = 0, GRP_REPLACED = 1, GRP_KILLED = 2, GRP_CLOSED = 3 };
enum grp_reason { GRP_R_NONE = 0, GRP_R_COMPROMISED = 1, GRP_R_ENDED = 2 };

struct grp_set {
    uint8_t id[GRP_ID_LEN];
    uint8_t kind, state, reason;
    int32_t start_day, end_day; /* days since 1970-01-01 in the group's time zone, end inclusive */
    uint32_t slots;             /* signatures per member (groups of 3+; 0 for pairs) */
    uint32_t k;                 /* the signature scheme's security parameter (0 for pairs) */
    uint32_t nloc;              /* seals + messages per pool direction */
    uint64_t pool_bytes;        /* pad bytes per pool direction */
    int32_t suspect_day;        /* a kill's "suspect since" (0: none) */
    uint8_t suspect_member;
    uint32_t suspect_slot;
};

struct grp {
    uint8_t id[GRP_ID_LEN];
    uint32_t gen;
    int n, me;                 /* members, and which one this cylinder belongs to (0-based) */
    int omega, lmax;           /* cheaters tolerated and guaranteed hand-ons (groups of 3+) */
    int threshold;             /* kill threshold (1 for pairs) */
    int grace;                 /* days after a window closes that messages are still received */
    int anon, signed_default;
    int tz_min;                /* the group's time zone: minutes east of UTC */
    uint32_t dispute_days;     /* 0: verify keys kept indefinitely */
    int32_t guard_day;         /* the clock guard: the latest day pnp has seen */
    int32_t created_day;
    char name[GRP_NAME_LEN];
    char member[GRP_MAX_MEMBERS][GRP_MEMBER_LEN];
    uint8_t left[32], expelled[32]; /* bitmaps by member index */
    int nsets;
    struct grp_set *sets;
    char *dir; /* the group's folder */
};

/* ---- the group file ---- */
#define GRP_HDR_LEN 128
#define GRP_SET_LEN 64
size_t grp_file_len(int n, int nsets);
/* Parses a whole group file. 0, or -1 if it isn't one or anything in it is out of range. */
int grp_parse(const uint8_t *b, size_t len, struct grp *g);
/* Serialises g into buf (grp_file_len bytes). */
void grp_serialise(const struct grp *g, uint8_t *buf);
void grp_free(struct grp *g);

/* Loads the group in dir ("…/pnp-group-<hex>"). 0, or -1 with the reason in err. */
int grp_load(const char *dir, struct grp *g, char *err, size_t errlen);
/* Saves the group file atomically, then resets the timestamps. */
int grp_save(struct grp *g, char *err, size_t errlen);

/* ---- names and paths ---- */
void grp_hex(const uint8_t id[GRP_ID_LEN], char out[2 * GRP_ID_LEN + 1]);
int grp_unhex(const char *s, uint8_t id[GRP_ID_LEN]);
/* "<dir>/set-<hex>/<file>", malloc'd */
char *grp_set_path(const struct grp *g, const struct grp_set *s, const char *file);
const char *grp_member_name(const struct grp *g, int i, char *buf, size_t len);
/* a member by name or 1-based number; -1 if none */
int grp_find_member(const struct grp *g, const char *s);
int grp_bit(const uint8_t *map, int i);
void grp_set_bit(uint8_t *map, int i);
struct grp_set *grp_find_set(struct grp *g, const uint8_t id[GRP_ID_LEN]);

/* ---- the clock (days in the group's time zone) ---- */
int32_t grp_today(int tz_min);
/* The clock guard: -1 if the clock is earlier than the latest day seen (and not confirmed), else 0; moves the
 * guard forward. */
int grp_clock_guard(struct grp *g, int confirmed, char *err, size_t errlen);
/* the key set the group sends with today (the active normal set whose window holds today), or NULL */
struct grp_set *grp_current_set(struct grp *g, int32_t today);
int grp_can_send(const struct grp_set *s, int32_t today);
int grp_can_receive(const struct grp *g, const struct grp_set *s, int32_t today);
void grp_day_str(int32_t day, char out[16]);
/* "YYYY-MM-DD" to a day number; 0 or -1 */
int grp_parse_day(const char *s, int32_t *day);

/* ---- timestamps: no activity log ---- */
/* Sets path's mtime and atime to the group's fixed time (its creation day, or 2000-01-01 when anonymous). */
void grp_touch(const struct grp *g, const char *path);
/* open() for reading that leaves no access time (O_NOATIME where allowed) */
int grp_open_read(const char *path);
/* opendir() that leaves no access time on the folder */
struct __dirstream;
struct __dirstream *grp_opendir(const char *path);

/* ---- pools: one per direction and key set, for seals and messages ---- */
#define POOL_HDR_LEN 64
struct pool {
    int fd;
    char *path;
    uint8_t set_id[GRP_ID_LEN];
    int from, to;
    uint32_t nloc, next_loc;
    uint64_t bytes, next_off;
};
/* Opens the pool from -> to in key set s. 0, or -1 with the reason in err. */
int pool_open(const struct grp *g, const struct grp_set *s, int from, int to, struct pool *p, char *err, size_t errlen);
void pool_close(struct pool *p);
/* Sending: reserves the next locator and len bytes of pad (fsynced before anything is read or released, so a crash
 * can never let them be used twice). Gives the locator entry (locator + offset mask) and the pad offset. 0, or -1
 * with the reason ("meet again") in err. */
int pool_reserve(struct pool *p, uint64_t len, uint32_t *loc_i, uint8_t entry[GRP_LOC_ENTRY], uint64_t *off,
                 char *err, size_t errlen);
/* reads len pad bytes at off */
int pool_read(struct pool *p, uint64_t off, uint8_t *buf, size_t len);
/* overwrites len bytes at off with zeros (pad used), and locator entry i */
int pool_wipe(struct pool *p, uint64_t off, uint64_t len);
int pool_wipe_loc(struct pool *p, uint32_t i);
int pool_sync(struct pool *p);
/* a pool file's 64-byte header */
void pool_header(uint8_t h[POOL_HDR_LEN], const uint8_t set_id[GRP_ID_LEN], int from, int to, uint32_t nloc,
                 uint32_t next_loc, uint64_t bytes, uint64_t next_off);

/* Receiving: what has arrived on an incoming pool (its locators and pad ranges), in recv.<from>. */
struct recv_state {
    uint32_t nloc;
    uint8_t *seen;  /* bitmap of locators received */
    uint32_t nranges;
    uint64_t (*ranges)[2]; /* pad ranges used: offset, length */
};
int recv_load(const struct grp *g, const struct grp_set *s, int from, struct recv_state *r, uint32_t nloc);
int recv_save(const struct grp *g, const struct grp_set *s, int from, const struct recv_state *r, char *err,
              size_t errlen);
void recv_free(struct recv_state *r);
/* The lowest locator index not yet received. */
uint32_t recv_next(const struct recv_state *r);
/* whether [off, off+len) overlaps a range already used */
int recv_overlaps(const struct recv_state *r, uint64_t off, uint64_t len);
int recv_add(struct recv_state *r, uint32_t loc, uint64_t off, uint64_t len);

/* Finds which incoming pool and locator a 16-byte header belongs to: tries the next `lookahead` unreceived
 * locators of every incoming pool of every usable key set. 0 with *set, *from and *loc set, or -1. */
int grp_lookup(struct grp *g, const uint8_t loc[GRP_LOC_LEN], int lookahead, struct grp_set **set, int *from,
               uint32_t *loc_i, uint64_t *off);

/* ---- finding groups ---- */
/* The group folders under root (or, with root NULL, the mounted drives and $PNP_GROUPS), up to max. */
int grp_find_all(const char *root, char **dirs, int max);

/* the creation of a group's files from a roster (meeting.c and the test setup) */
int grp_mkdirs(const struct grp *g, char *err, size_t errlen);

#endif
