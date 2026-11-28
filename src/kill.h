/* Kill and leave notices (kill.c; docs/group.md "Kill notices", "Leaving a group"). */
#ifndef PNP_KILL_H
#define PNP_KILL_H

#include "group.h"

enum kill_scope {
    KS_SETS = 1,   /* the key sets listed */
    KS_MEMBER = 2, /* everything of one member (a stolen cylinder, or expelling someone) */
    KS_GROUP = 3,  /* every key set of the group */
    KS_LEAVE = 4,  /* the signer leaving: their own keys and pools only (threshold 1) */
};

#define KILL_MAX_SETS 64
struct kill_sig {
    int signer;
    int kind; /* 1: a group signature from the emergency set; 2: a seal from the emergency pool (pairs) */
    uint8_t *data;
    size_t len;
};
struct kill_notice {
    uint8_t group[GRP_ID_LEN], id[GRP_ID_LEN];
    int scope, member, reason, nsets;
    uint8_t sets[KILL_MAX_SETS][GRP_ID_LEN];
    int32_t suspect_day;
    int suspect_member;
    uint32_t suspect_slot;
    int nsig;
    struct kill_sig *sig; /* nsig of them (malloc'd; kill_free frees them) */
    size_t frame_len; /* bytes before the signatures: what each signature covers */
};

int kill_parse(const uint8_t *b, size_t len, struct kill_notice *k);
void kill_free(struct kill_notice *k);

/* Makes a notice signed by me (an emergency slot) and writes it to out. 0, or -1 with the reason in err. */
int kill_make(struct grp *g, int scope, int member, const uint8_t (*sets)[GRP_ID_LEN], int nsets, int reason,
              int32_t suspect_day, int suspect_member, uint32_t suspect_slot, const char *out, char *err,
              size_t errlen);
/* Adds my signature to the notice at path (rewritten in place). */
int kill_cosign(struct grp *g, const char *path, char *err, size_t errlen);

/* Reads every notice in the group's kills/ folder and in extra_dir (NULL: none), checks its signatures, stores new
 * ones in kills/ and applies those that reach the threshold. Warnings (below the threshold) and what was applied
 * are printed with say. Returns how many notices are pending (below the threshold). */
int kill_process(struct grp *g, const char *extra_dir, void (*say)(const char *fmt, ...));
/* whether a key set has a compromise report waiting for more signatures */
int kill_pending_for(struct grp *g, const struct grp_set *s);
/* the notices this cylinder knows, packed for a message: [u32 length, notice]... (malloc'd, may be empty) */
int kill_bundle(struct grp *g, uint8_t **out, size_t *len);
/* takes the notices that arrived inside a message */
void kill_absorb(struct grp *g, const uint8_t *b, size_t len, void (*say)(const char *fmt, ...));
/* the tolerance left for cheaters after leaves and expulsions */
int kill_tolerance_left(const struct grp *g);

#endif
