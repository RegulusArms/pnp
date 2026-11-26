/* An independent check of the file format (docs/format.md), written separately from pnp's own code:
 *   xorcheck PLAIN CIPHERTEXT KEY
 * exits 0 when both have their 24-byte headers with the right magics and the same ID, and
 * ciphertext body XOR key body == plaintext, byte for byte. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: xorcheck PLAIN CIPHERTEXT KEY\n");
        return 2;
    }
    FILE *p = fopen(argv[1], "rb"), *c = fopen(argv[2], "rb"), *k = fopen(argv[3], "rb");
    if (!p || !c || !k) {
        fprintf(stderr, "xorcheck: can't open a file\n");
        return 2;
    }
    unsigned char hc[24], hk[24];
    if (fread(hc, 1, 24, c) != 24 || fread(hk, 1, 24, k) != 24) {
        fprintf(stderr, "xorcheck: short header\n");
        return 1;
    }
    if (memcmp(hc, "PNPCT001", 8) != 0 || memcmp(hk, "PNPKY001", 8) != 0) {
        fprintf(stderr, "xorcheck: wrong magic\n");
        return 1;
    }
    if (memcmp(hc + 8, hk + 8, 16) != 0) {
        fprintf(stderr, "xorcheck: IDs differ\n");
        return 1;
    }
    long n = 0;
    for (;;) {
        int a = fgetc(p), b = fgetc(c), d = fgetc(k);
        if (a == EOF && b == EOF && d == EOF)
            break;
        if (a == EOF || b == EOF || d == EOF) {
            fprintf(stderr, "xorcheck: lengths differ at byte %ld\n", n);
            return 1;
        }
        if ((b ^ d) != a) {
            fprintf(stderr, "xorcheck: ciphertext XOR key != plaintext at byte %ld\n", n);
            return 1;
        }
        n++;
    }
    return 0;
}
