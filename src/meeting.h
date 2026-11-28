/* The meeting protocol (meeting.c): what each member's laptop writes onto its self stick and onto other members'
 * couriers, and the import at home that turns a self stick into a group folder. The wizard (gcli.c) and the test
 * setup (PNP_TEST_SETUP) both run exactly these steps. */
#ifndef PNP_MEETING_H
#define PNP_MEETING_H

#include "courier.h"
#include "group.h"
#include "rng.h"

/* the size of each kind of record, for sizing sticks */
uint64_t meet_pool_record_len(const struct grp_set *s);

/* Writes this member's own material onto the self stick: the roster, its signing functions and its random
 * contribution to every pool it shares. */
int meet_self_generate(const struct grp *roster, struct cstore *self, struct pnp_rng *rng, char *err, size_t errlen);
/* Round 1, run on member roster->me's laptop with owner's courier: its pool contributions and signer blocks for
 * the courier's owner. */
int meet_round1(const struct grp *roster, struct cstore *self, struct cstore *courier, char *err, size_t errlen);
/* After rounds 1, this member's random splits of every block it received (its own hardware RNG). */
int meet_make_splits(const struct grp *roster, struct cstore *self, struct pnp_rng *rng, char *err, size_t errlen);
/* Round 2: the splits for the courier's owner, a test signature and a test seal. */
int meet_round2(const struct grp *roster, struct cstore *self, struct cstore *courier, char *err, size_t errlen);
/* The owner, with their courier back: checks it, moves its records onto the self stick, overwrites it and reads
 * it back. */
int meet_collect(struct cstore *courier, struct cstore *self, char *err, size_t errlen);
/* At home: makes the group folder under root from the self stick, then checks every test signature and seal.
 * Prints nothing; on success *dir is the new folder (malloc'd). */
int meet_import(struct cstore *self, const char *root, char **dir, char *err, size_t errlen);

/* a fresh roster (group ID and key set IDs from rng) */
int meet_new_ids(struct grp *g, struct pnp_rng *rng, char *err, size_t errlen);

#endif
