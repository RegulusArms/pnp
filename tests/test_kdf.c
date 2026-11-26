/* Unit tests of --protect's building blocks: BLAKE2b, Argon2id, Balloon, ChaCha20 and protect.c's derivation.
 * The expected values come from the RFCs and from implementations independent of pnp's C code (hashlib,
 * argon2-cffi, cryptography: tests/kdf_vectors.py, which reproduces them). Prints PASS/FAIL lines; exits with the
 * number of failures. */
#define _GNU_SOURCE
#include "blake2b.h"
#include "chacha20.h"
#include "kdf.h"
#include "protect.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

volatile sig_atomic_t pnp_stop; /* protect.c's, normally in rng.c */

static int fails;

static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

static int same_hex(const uint8_t *b, size_t n, const char *hex)
{
    if (strlen(hex) != 2 * n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || v != b[i])
            return 0;
    }
    return 1;
}

static void msg(uint8_t *m, size_t n)
{
    for (size_t i = 0; i < n; i++)
        m[i] = (uint8_t)(i * 7 + 3);
}

static const struct {
    size_t n, outlen;
    const char *hex;
} B2[] = {
    {0, 64, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b14"
            "48b755d56f701afe9be2ce"},
    {3, 64, "76ce7e90c577d436a65b691e51f0a1ad536130d70a18df3bf5368551327258b6f706f4a47c45f2d0d8147cfbb5623077e798247972"
            "e4f9338603a13abc05a4db"},
    {127, 32, "c9ae3859964b35f04c54b36d33cf299d7290ee621005d28e51598a943560aaaa"},
    {128, 64, "2d9e329f42afa3601d646692b81c13e87fcaff5bf15972e9813d7373cb6d181f9599f4d513d4af4fd6ebd37497aceb29aba5ee23ed"
              "764d8510b552bd088814fb"},
    {129, 1, "16"},
    {1000, 48, "3910b84a1fe7f38f69f3cf3b0a217a0ac1a8865dd72e74a315d615e475039f6a7b7299bbfe070081f141f544620926b8"},
};

static const struct {
    uint32_t m, t, lanes;
    size_t outlen;
    const char *hex;
} A2[] = {
    {8, 1, 1, 4, "6b7a947d"},
    {64, 2, 2, 64, "07f4fffda0aed64bd50549438340ef1346f45c95891c212db834702b8c37dc18bf5a600612c76121855ec5974a6ddd78e4281"
                   "64a7d370d71d3babc97c7493185"},
    {100, 3, 4, 65, "d9c4b633f2a2d93f760ecdcf620660b6dbcaf7c105b997a60832adea51e8a60609f63e785b2ea92f7f7eeaa42ce6f40479eae"
                    "9826d227974ca6100265e759f0cdb"},
    {4096, 2, 3, 128, "ee3a2ac34ed2a58ed7a26373536cadca694084096223d073f0bce787b1e9fbad866c09625c68217355916b044c5926a0f035"
                      "23ce662c693d4a652cd2c2f6e3492e2f0b731c307804794bc45d58ea24e7b76be33dc02d63b8bf7d55a49b2b730e8a28a7f0"
                      "cca46048041c3a28564fc3470071a702f06a1db687aa2e66f34db24e"},
};

static const struct {
    uint64_t s;
    uint32_t t;
    const char *hex;
} BL[] = {
    {2, 1, "d3e9785916b5e09c2dbf79e16d8bc7d194a8ee715f16a8c9933648f85b87a7228ca1aefdabe867e5add0718b53895059fdc25ba37fd7"
           "7139c19ed7a44a8ed546"},
    {16, 3, "4b5a0c26d63bff18f299a6031c5a7a000da445fb09985b5f11752249d7f930184bfc87d6febcd11c67fafeb22aa1717076e70996ab1e"
            "dea35a0753ebcdece873"},
    {1000, 2, "b437c2056ff2ba5668d93b2a3ea164f54d2fddd99648d206e4191b610611595895a4294f0322599880fc063492d5dad9cf74d51e9a1"
              "61f23ac87010dae3859a0"},
};

static const char CHACHA[] =
    "af051e40bba0354981329a806a140eafd258a22a6dcb4bb9f6569cb3efe2deaf837bd87ca20b5ba12081a306af0eb35c41a239d20dfc74c8"
    "1771560d9c9c1e4b224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b93347"
    "94cba40c63e34cdea212c4cf07d41b769a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c1"
    "67eacd901d7e2bf363740373201aa188fbbce83991c4edc8ed064c6e939d40";

int main(void)
{
    uint8_t m[1000], out[1024];
    char what[160];

    /* BLAKE2b */
    pnp_blake2b(out, 64, "abc", 3);
    check(same_hex(out, 64, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533"
                            "cc9518d38aa8dbf1925ab92386edd4009923"),
          "BLAKE2b-512(\"abc\") is RFC 7693's Appendix A value");
    for (size_t i = 0; i < sizeof B2 / sizeof *B2; i++) {
        msg(m, B2[i].n);
        pnp_blake2b(out, B2[i].outlen, m, B2[i].n);
        snprintf(what, sizeof what, "BLAKE2b, %zu-byte message, %zu-byte digest, matches hashlib", B2[i].n,
                 B2[i].outlen);
        check(same_hex(out, B2[i].outlen, B2[i].hex), what);
    }
    struct pnp_blake2b s;
    msg(m, 1000);
    pnp_blake2b_init(&s, 48);
    for (size_t i = 0; i < 1000; i += 37)
        pnp_blake2b_update(&s, m + i, i + 37 <= 1000 ? 37 : 1000 - i);
    pnp_blake2b_final(&s, out);
    check(same_hex(out, 48, B2[5].hex), "BLAKE2b gives the same digest fed in pieces");

    /* Argon2id */
    uint8_t P[32], S[16], K[8], X[12];
    memset(P, 1, sizeof P);
    memset(S, 2, sizeof S);
    memset(K, 3, sizeof K);
    memset(X, 4, sizeof X);
    check(pnp_argon2id(out, 32, P, 32, S, 16, K, 8, X, 12, 32, 3, 4) == 0 &&
              same_hex(out, 32, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
          "Argon2id gives RFC 9106's test vector (section 5.3)");
    for (size_t i = 0; i < sizeof A2 / sizeof *A2; i++) {
        int r = pnp_argon2id(out, A2[i].outlen, (const uint8_t *)"password", 8, (const uint8_t *)"somesalt", 8, NULL,
                             0, NULL, 0, A2[i].m, A2[i].t, A2[i].lanes);
        snprintf(what, sizeof what, "Argon2id, %u KiB, %u passes, %u lanes, %zu bytes, matches argon2-cffi", A2[i].m,
                 A2[i].t, A2[i].lanes, A2[i].outlen);
        check(r == 0 && same_hex(out, A2[i].outlen, A2[i].hex), what);
    }
    check(pnp_argon2id(out, 32, P, 32, S, 16, NULL, 0, NULL, 0, 7, 1, 1) < 0 &&
              pnp_argon2id(out, 32, P, 32, S, 16, NULL, 0, NULL, 0, 64, 0, 1) < 0,
          "Argon2id refuses too little memory and zero passes");

    /* Balloon */
    uint8_t salt[16];
    for (int i = 0; i < 16; i++)
        salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof BL / sizeof *BL; i++) {
        int r = pnp_balloon(out, (const uint8_t *)"hunter2", 7, salt, 16, BL[i].s, BL[i].t);
        snprintf(what, sizeof what, "Balloon, %llu blocks, %u rounds, matches the Python version of the paper's",
                 (unsigned long long)BL[i].s, BL[i].t);
        check(r == 0 && same_hex(out, 64, BL[i].hex), what);
    }
    check(pnp_balloon(out, (const uint8_t *)"x", 1, salt, 16, 1, 1) < 0 &&
              pnp_balloon(out, (const uint8_t *)"x", 1, salt, 16, 16, 0) < 0,
          "Balloon refuses fewer than 2 blocks and zero rounds");

    /* ChaCha20, in pieces that cross block boundaries */
    uint8_t key[32], nonce[12] = {0};
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    nonce[7] = 0x4a;
    struct pnp_chacha20 c;
    memset(out, 0, 200);
    pnp_chacha20_init(&c, key, nonce);
    pnp_chacha20_xor(&c, out, 1);
    pnp_chacha20_xor(&c, out + 1, 70);
    pnp_chacha20_xor(&c, out + 71, 129);
    check(same_hex(out, 200, CHACHA), "ChaCha20's keystream matches the cryptography package's");

    /* protect.c: the whole derivation, the share's nonce, the check value, and the settings' bounds */
    struct pnp_protect p, q;
    uint8_t wkey[32], enc[PNP_PROTECT_LEN];
    memset(&p, 0, sizeof p);
    p.balloon_blocks = 8 * 256;
    p.balloon_rounds = 2;
    p.argon_kib = 8 * 1024;
    p.argon_passes = 2;
    for (int i = 0; i < 16; i++)
        p.salt[i] = (uint8_t)(16 + i);
    check(pnp_protect_lock(&p, "correct horse", 13, wkey) == 0 &&
              same_hex(wkey, 32, "f58c47fd00a53555f3d1a434bf29c5bafc7f98437900e2b65ce16a2df9920b37") &&
              same_hex(p.check, 16, "1726befff269fd0b8d8a728468075f91"),
          "--protect's key and check value are Argon2id(Balloon(passphrase)), as computed independently");
    memset(out, 0, 64);
    pnp_protect_stream(&c, wkey, 3);
    pnp_chacha20_xor(&c, out, 64);
    check(same_hex(out, 64, "a6bbb177102827ab3b7cdf5d8248a540eb7611a96990c5b5cff7201f5659af48dbc77447b84f3d7233a87f72"
                            "79fe4a862216697cd1f27a1ffdf79e7ae47a9eb2"),
          "share 3's keystream uses nonce LE32(3) || zeros");
    pnp_protect_encode(&p, enc);
    check(pnp_protect_decode(&q, enc) == 0 && memcmp(&p, &q, sizeof p) == 0, "the protection block decodes as encoded");
    check(pnp_protect_unlock(&q, "correct horse", 13, wkey) == 0, "the right passphrase unlocks");
    check(pnp_protect_unlock(&q, "correct horsf", 13, wkey) == -2, "a wrong passphrase is told apart by the check");
    enc[16] ^= 1; /* the salt */
    check(pnp_protect_decode(&q, enc) == 0 && pnp_protect_unlock(&q, "correct horse", 13, wkey) == -2,
          "a changed salt fails the check");
    enc[16] ^= 1;
    enc[8] = 8, enc[9] = 0, enc[10] = 0, enc[11] = 0; /* Argon2id memory 8 KiB: below pnp's 8 MiB */
    check(pnp_protect_decode(&q, enc) < 0, "settings below pnp's minimum are refused");
    enc[8] = 0, enc[9] = 0, enc[10] = 0, enc[11] = 0x10; /* 256 GiB: above the maximum */
    check(pnp_protect_decode(&q, enc) < 0, "settings above pnp's maximum are refused");
    return fails;
}
