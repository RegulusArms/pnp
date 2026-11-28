/* Seals and messages on a pairwise pool (gmsg.c). */
#ifndef PNP_GMSG_H
#define PNP_GMSG_H

#include "group.h"

#define SEAL_LEN (GRP_LOC_LEN + 8 + 16) /* locator, masked offset, tag */
#define MSG_OVERHEAD (GRP_LOC_LEN + 8 + 16)

/* Seals the file at path for member `to` with the next item of my pool to them. 0 with the 40-byte seal, or -1
 * with the reason in err. */
int seal_make(struct grp *g, struct grp_set *s, int to, const char *path, uint8_t seal[SEAL_LEN], char *err,
              size_t errlen);

/* the same, over bytes in memory (kill notices) */
int seal_make_mem(struct grp *g, struct grp_set *s, int to, const uint8_t *buf, size_t len, uint8_t seal[SEAL_LEN],
                  char *err, size_t errlen);

struct seal_result {
    int from;
    struct grp_set *set;
};
/* Checks a seal on the file at path. 1 if it checks (the item is then recorded and its key wiped), 0 if it
 * doesn't, -1 if it can't be checked here (not for this cylinder's groups...), with the reason in err. */
int seal_check(struct grp *g, const char *path, const uint8_t seal[SEAL_LEN], int lookahead, struct seal_result *res,
               char *err, size_t errlen);

int seal_check_mem(struct grp *g, const uint8_t *buf, size_t len, const uint8_t seal[SEAL_LEN], int lookahead,
                   struct seal_result *res, char *err, size_t errlen);

/* Sends the file at in_path to member `to` as a message written to out_path (signed if sign). Kill notices known to
 * this cylinder travel inside it. 0, or -1 with the reason in err. */
int msg_send(struct grp *g, struct grp_set *s, int to, const char *in_path, const char *out_path, int sign, int force,
             char *err, size_t errlen);

struct msg_result {
    int from;
    int is_signed;
    int sig_level, sig_exact, sig_reused; /* when signed */
    int pending_warning;                  /* received while a compromise report about its key set was pending */
    int suspect;                          /* received from a key set killed with "suspect since" covering it */
    char name[256];                       /* the file name the sender gave */
    int nto, to[GRP_MAX_MEMBERS];         /* who it was sent to */
    struct grp_set *set;
};
/* Receives the message at in_path into out_path (NULL: the sender's file name beside it). With evidence, a signed
 * message's frame and signature are also kept as OUT.pnp-signed, so it can be shown to the group later. 1 if
 * received, 0 if it's not for this group or doesn't check (nothing written), -1 on an error, with the reason in
 * err. */
int msg_receive(struct grp *g, const char *in_path, const char *out_path, int force, int lookahead,
                struct msg_result *res, char *err, size_t errlen);

/* Checks the signature inside a kept .pnp-signed file; the frame's content is what was signed. */
int msg_verify_evidence(struct grp *g, const char *path, struct msg_result *res, char *err, size_t errlen);

#endif
