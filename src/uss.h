/* Group signatures that stay secure if P = NP (uss.c): Amiri, Abidin, Wallden and Andersson, "Efficient
 * unconditionally secure signatures using universal hashing" (ACNS 2018), with pnp's hash family. docs/research.md
 * and docs/group.md have the details. */
#ifndef PNP_USS_H
#define PNP_USS_H

#include "group.h"

#include <stddef.h>
#include <stdint.h>

#define USS_FN_LEN 49     /* one hash function: K (16, < p), A (2 x 16), c (1, two bits used) */
#define USS_SPLIT_LEN 53  /* a function as a verifier holds it: its position (4) and the function */
#define USS_SIG_HDR 36
#define USS_SIGN_HDR 48
#define USS_VERIFY_HDR 40

/* ---- parameters ---- */
/* whether ω cheaters and l_max hand-ons are allowed with N recipients (honest majority, (l_max+1)·d_R < 1/2) */
int uss_valid(int N, int omega, int lmax);
/* the smallest k (in steps of 50) for which every failure probability is at most 2^-64; 0 if invalid */
uint32_t uss_k(int N, int omega, int lmax);
/* the defaults: the most cheaters tolerated, then the most hand-ons that leaves room for (at most 1) */
void uss_defaults(int n, int *omega, int *lmax);
/* a set passes at level l (-1..lmax) with this many mismatches out of k */
int uss_set_passes(uint32_t mismatches, uint32_t k, int l, int lmax);
/* a signature is accepted at level l with this many sets passed out of N */
int uss_accepts(int passed, int N, int l, int omega);

/* ---- the hash family ---- */
/* Makes 49 random bytes a valid function (K below p). 0, or -1 if K came out as p itself: draw again. */
int uss_fn_fix(uint8_t fn[USS_FN_LEN]);
/* the 2-bit tag of a function on a value x = h_K(M) (16 bytes, little-endian) */
int uss_tag_of(const uint8_t fn[USS_FN_LEN], const uint8_t x[16]);
/* the second stage alone at a reduced width (tests): parity(a0 & x), parity(a1 & x), xor c */
int uss_stage2(uint64_t a0, uint64_t a1, int c, uint64_t x);

/* Tags of nf functions on one message, computed together (threads when there are many): begin with the message's
 * framing prefix fed, feed the message, then finish. */
struct uss_eval;
struct uss_eval *uss_eval_new(const uint8_t *fns, size_t stride, size_t nf);
void uss_eval_feed(struct uss_eval *e, const uint8_t *buf, size_t n);
/* writes nf tags (0..3), one per byte, and frees e */
void uss_eval_finish(struct uss_eval *e, uint8_t *tags);

/* the framing every signed message is hashed under: "PNPUS001" || key set ID || signer || slot || u64 length */
#define USS_FRAME_LEN (8 + GRP_ID_LEN + 1 + 4 + 8)
void uss_frame(uint8_t out[USS_FRAME_LEN], const uint8_t set_id[GRP_ID_LEN], int signer, uint32_t slot,
               uint64_t len);

/* ---- signing and verifying ---- */
/* a source of the message to sign or check: read(ctx, buf, n) returns bytes read (0 at the end) or -1 */
typedef long (*uss_read_fn)(void *ctx, uint8_t *buf, size_t n);

/* Signs len bytes from rd with the next slot of my signing file in key set s. The slot is burned (counter fsynced,
 * functions wiped) before the signature exists. Returns a malloc'd signature file of *siglen bytes, or NULL with
 * the reason in err. */
uint8_t *uss_sign(struct grp *g, struct grp_set *s, uint64_t len, uss_read_fn rd, void *ctx, size_t *siglen,
                  uint32_t *slot_out, char *err, size_t errlen);

struct uss_result {
    int signer;
    uint32_t slot;
    int level;      /* the highest level accepted at, or -2 if rejected */
    int exact;      /* no mismatches in any set */
    int reused;     /* this slot was seen with a different message */
    int passed;     /* sets passed at the level reported */
    uint8_t set_id[GRP_ID_LEN];
};
/* Parses a signature file's header (36 bytes + tags); 0 or -1. */
int uss_sig_parse(const uint8_t *sig, size_t siglen, uint8_t set_id[GRP_ID_LEN], int *signer, int *N, uint32_t *slot,
                  uint32_t *k);
/* Checks a signature on len bytes from rd. 0 with the result filled in (res->level -2 = rejected), or -1 with the
 * reason in err (no verify keys for it, damaged files...). record: remember the slot's message (sused). */
int uss_verify(struct grp *g, const uint8_t *sig, size_t siglen, uint64_t len, uss_read_fn rd, void *ctx,
               int record, struct uss_result *res, char *err, size_t errlen);

/* sizes of the files, for the meeting */
uint64_t uss_sign_len(int N, uint32_t k, uint32_t slots);
uint64_t uss_verify_len(int N, uint32_t k, uint32_t slots);
size_t uss_sig_len(int N, uint32_t k);
/* writes the empty sused file for signer j */
int uss_sused_create(const struct grp *g, const struct grp_set *s, int j, char *err, size_t errlen);
/* wipes the unused slots of my signing file (a window closed or the set was killed) */
int uss_wipe_unused(const struct grp *g, const struct grp_set *s);

#endif
