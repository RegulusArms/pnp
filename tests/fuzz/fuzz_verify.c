/* Fuzzing a whole pnp --verify (src/main.c's pnp_decrypt with nothing written): a ciphertext and one to three
 * key files, all made of fuzzed bytes, through header parsing, the key checks (IDs, sizes, share sets), the MAC
 * key and the integrity check. Input: [u16 length, bytes] for the ciphertext, then for each key file. Protected
 * keys stop at the passphrase (a file that doesn't exist), so no hashing runs. */
#define _GNU_SOURCE
#include "pnp.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void pnp_fuzz_init(void); /* main.c, with PNP_FUZZ */

static int file_of(const uint8_t **p, size_t *left, char *path, size_t pathlen)
{
    if (*left < 2)
        return -1;
    size_t n = (size_t)((*p)[0] | (*p)[1] << 8);
    *p += 2, *left -= 2;
    if (n > *left)
        n = *left;
    int fd = memfd_create("f", MFD_CLOEXEC);
    if (fd < 0 || write(fd, *p, n) != (ssize_t)n)
        abort();
    *p += n, *left -= n;
    snprintf(path, pathlen, "/proc/self/fd/%d", fd);
    return fd;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int ready;
    if (!ready) {
        pnp_fuzz_init(); /* pnp's messages are left out in this build (say(), PNP_FUZZ) */
        ready = 1;
    }
    char ct[64], keys[3][64];
    char *kp[3] = {keys[0], keys[1], keys[2]};
    int fds[4], nk = 0;
    if ((fds[0] = file_of(&data, &size, ct, sizeof ct)) < 0)
        return 0;
    while (nk < 3 && (fds[nk + 1] = file_of(&data, &size, keys[nk], sizeof keys[nk])) >= 0)
        nk++;
    if (nk)
        pnp_decrypt(ct, kp, nk, NULL, 0, "/nonexistent/pnp-fuzz-passphrase", 1);
    for (int i = 0; i <= nk; i++)
        close(fds[i]);
    return 0;
}
