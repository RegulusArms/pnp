/* pnp's file headers (docs/format.md): shared by main.c, which reads and writes them, and tui.c, which only peeks at
 * them to tell ciphertexts, keys and shares apart and match them up. */
#ifndef PNP_FORMAT_H
#define PNP_FORMAT_H

#define MAGIC_LEN 8
#define ID_LEN 16
#define HEADER_LEN (MAGIC_LEN + ID_LEN)       /* ciphertext and whole key */
#define SHARE_HEADER_LEN (HEADER_LEN + 2)     /* a key share: then its number (1..count) and the count */
/* "PNP" + the kind + the format version. Version 002 adds the integrity check: the key's (or each share's) body
 * starts with the MAC key (PNP_MAC_KEY_LEN), and the ciphertext ends with the tag (PNP_MAC_TAG_LEN). Version 001
 * (pnp 0.1.0-alpha.2 and older; no shares) is still decrypted, without a check, and never written. */
static const char MAGIC_CT[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '2'};
static const char MAGIC_KEY[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '2'};
static const char MAGIC_SHARE[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'H', '0', '0', '2'};
/* a key or share protected with a passphrase (--protect): the protection block (PNP_PROTECT_LEN) follows the header */
static const char MAGIC_KEY_P[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'P', '0', '0', '2'};
static const char MAGIC_SHARE_P[MAGIC_LEN] = {'P', 'N', 'P', 'S', 'P', '0', '0', '2'};
static const char MAGIC_CT_V1[MAGIC_LEN] = {'P', 'N', 'P', 'C', 'T', '0', '0', '1'};
static const char MAGIC_KEY_V1[MAGIC_LEN] = {'P', 'N', 'P', 'K', 'Y', '0', '0', '1'};

#endif
