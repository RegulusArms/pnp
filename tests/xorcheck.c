/* An independent check of the file format (docs/format.md), written separately from pnp's own code:
 *   xorcheck PLAIN CIPHERTEXT KEY
 *   xorcheck PLAIN CIPHERTEXT SHARE1 SHARE2 ...
 * exits 0 when the ciphertext and key have their 24-byte headers with the right magics and the same ID, and
 * ciphertext body XOR key body == plaintext, byte for byte. With shares: each has a 26-byte header (PNPSH001, the
 * same ID, its number, the count), the numbers are 1..count once each, count = the number given, and ciphertext XOR
 * every share == plaintext. */
#include <stdio.h>
#include <string.h>

#define MAXK 16

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
        return 2;
    }
    unsigned char hc[24], hk[26];
    int seen[MAXK + 1] = {0};
    if (fread(hc, 1, 24, c) != 24 || memcmp(hc, "PNPCT001", 8) != 0) {
        fprintf(stderr, "xorcheck: bad ciphertext header\n");
        return 1;
    }
    for (int i = 0; i < nk; i++) {
        if (!(k[i] = fopen(argv[3 + i], "rb"))) {
            fprintf(stderr, "xorcheck: can't open %s\n", argv[3 + i]);
            return 2;
        }
        size_t hl = shares ? 26 : 24;
        if (fread(hk, 1, hl, k[i]) != hl || memcmp(hk, shares ? "PNPSH001" : "PNPKY001", 8) != 0) {
            fprintf(stderr, "xorcheck: bad header in %s\n", argv[3 + i]);
            return 1;
        }
        if (memcmp(hc + 8, hk + 8, 16) != 0) {
            fprintf(stderr, "xorcheck: IDs differ\n");
            return 1;
        }
        if (shares && (hk[25] != nk || hk[24] < 1 || hk[24] > nk || seen[hk[24]]++)) {
            fprintf(stderr, "xorcheck: bad share number or count in %s\n", argv[3 + i]);
            return 1;
        }
    }
    long n = 0;
    for (;;) {
        int a = fgetc(p), b = fgetc(c), eofs = (a == EOF) + (b == EOF);
        for (int i = 0; i < nk; i++) {
            int d = fgetc(k[i]);
            eofs += d == EOF;
            b ^= d;
        }
        if (eofs == nk + 2)
            break;
        if (eofs) {
            fprintf(stderr, "xorcheck: lengths differ at byte %ld\n", n);
            return 1;
        }
        if (b != a) {
            fprintf(stderr, "xorcheck: ciphertext XOR key != plaintext at byte %ld\n", n);
            return 1;
        }
        n++;
    }
    return 0;
}
