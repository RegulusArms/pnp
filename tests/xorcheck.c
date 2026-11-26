/* An independent check of the file format (docs/format.md, version 002), written separately from pnp's own code:
 *   xorcheck PLAIN CIPHERTEXT KEY
 *   xorcheck PLAIN CIPHERTEXT SHARE1 SHARE2 ...
 * exits 0 when:
 *   - the ciphertext has its 24-byte header (PNPCT002 + ID); the key has PNPKY002 + the same ID, or each share a
 *     26-byte header (PNPSH002, the same ID, its number, the count) with the numbers 1..count once each and
 *     count = the number given;
 *   - the key material (the key's body, or all the share bodies XORed) is MAC key (32 bytes) + pad;
 *   - ciphertext body XOR pad == plaintext, byte for byte;
 *   - the ciphertext's last 16 bytes are the MAC tag of ID || plaintext.
 * The MAC is recomputed here by plain double-and-add mod 2^127 - 1, not pnp's 64-bit-limb multiplication. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXK 16

__extension__ typedef unsigned __int128 u128;
static const u128 P = ((u128)1 << 127) - 1;

static u128 addm(u128 a, u128 b) /* a, b < P */
{
    u128 r = a + b;
    return r >= P ? r - P : r;
}

static u128 mulm(u128 a, u128 b) /* a * b mod P, one bit of b at a time */
{
    u128 r = 0;
    for (int i = 126; i >= 0; i--) {
        r = addm(r, r);
        if ((b >> i) & 1)
            r = addm(r, a);
    }
    return r;
}

static u128 le(const unsigned char *b, int n)
{
    u128 v = 0;
    for (int i = 0; i < n; i++)
        v |= (u128)b[i] << (8 * i);
    return v;
}

/* the MAC state: Horner over 8-byte little-endian blocks, then the length */
static u128 acc, mk;
static unsigned char blk[8];
static int nblk;
static unsigned long long total;
static void mac_byte(int c)
{
    blk[nblk++] = (unsigned char)c;
    total++;
    if (nblk == 8) {
        acc = mulm(addm(acc, le(blk, 8)), mk);
        nblk = 0;
    }
}

static long size_of(FILE *f)
{
    long here = ftell(f), n;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, here, SEEK_SET);
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc - 3 > MAXK) {
        fprintf(stderr, "usage: xorcheck PLAIN CIPHERTEXT KEY | SHARE...\n");
        return 2;
    }
    int nk = argc - 3, shares = nk > 1;
    FILE *p = fopen(argv[1], "rb"), *c = fopen(argv[2], "rb"), *k[MAXK];
    if (!p || !c) {
        fprintf(stderr, "xorcheck: can't open a file\n");
        exit(2);
    }
    unsigned char hc[24], hk[26], key[32] = {0}, t[32];
    int seen[MAXK + 1] = {0};
    if (fread(hc, 1, 24, c) != 24 || memcmp(hc, "PNPCT002", 8) != 0) {
        fprintf(stderr, "xorcheck: bad ciphertext header\n");
        exit(1);
    }
    long body = size_of(c) - 24 - 16;
    for (int i = 0; i < nk; i++) {
        if (!(k[i] = fopen(argv[3 + i], "rb"))) {
            fprintf(stderr, "xorcheck: can't open %s\n", argv[3 + i]);
            exit(2);
        }
        size_t hl = shares ? 26 : 24;
        if (fread(hk, 1, hl, k[i]) != hl || memcmp(hk, shares ? "PNPSH002" : "PNPKY002", 8) != 0) {
            fprintf(stderr, "xorcheck: bad header in %s\n", argv[3 + i]);
            exit(1);
        }
        if (memcmp(hc + 8, hk + 8, 16) != 0) {
            fprintf(stderr, "xorcheck: IDs differ\n");
            exit(1);
        }
        if (shares && (hk[25] != nk || hk[24] < 1 || hk[24] > nk || seen[hk[24]]++)) {
            fprintf(stderr, "xorcheck: bad share number or count in %s\n", argv[3 + i]);
            exit(1);
        }
        if (size_of(k[i]) - (long)hl - 32 != body || fread(t, 1, 32, k[i]) != 32) {
            fprintf(stderr, "xorcheck: %s has the wrong size\n", argv[3 + i]);
            exit(1);
        }
        for (int j = 0; j < 32; j++)
            key[j] ^= t[j];
    }
    mk = le(key, 16);
    u128 s = le(key + 16, 16);
    if (mk >= P || s >= P) {
        fprintf(stderr, "xorcheck: MAC key out of range\n");
        exit(1);
    }
    for (int i = 0; i < 16; i++) /* the ID */
        mac_byte(hc[8 + i]);
    for (long n = 0; n < body; n++) {
        int a = fgetc(p), b = fgetc(c);
        for (int i = 0; i < nk; i++)
            b ^= fgetc(k[i]);
        if (a == EOF) {
            fprintf(stderr, "xorcheck: plaintext shorter than the ciphertext\n");
            exit(1);
        }
        if (b != a) {
            fprintf(stderr, "xorcheck: ciphertext XOR key != plaintext at byte %ld\n", n);
            exit(1);
        }
        mac_byte(a);
    }
    if (fgetc(p) != EOF) {
        fprintf(stderr, "xorcheck: plaintext longer than the ciphertext\n");
        exit(1);
    }
    if (nblk) {
        memset(blk + nblk, 0, (size_t)(8 - nblk));
        acc = mulm(addm(acc, le(blk, 8)), mk);
    }
    acc = mulm(addm(acc, (u128)total), mk); /* the length of ID || plaintext */
    unsigned char tag[16];
    if (fread(tag, 1, 16, c) != 16) {
        fprintf(stderr, "xorcheck: no tag\n");
        exit(1);
    }
    if (le(tag, 16) != addm(acc, s)) {
        fprintf(stderr, "xorcheck: wrong MAC tag\n");
        exit(1);
    }
    return 0;
}
