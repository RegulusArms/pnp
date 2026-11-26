/* Fuzzing pnp_read_passphrase with a file (src/protect.c, --passphrase-file): the first line, without its "\n"
 * or "\r\n", must fit and be terminated, whatever the file holds. */
#define _GNU_SOURCE
#include "protect.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

volatile sig_atomic_t pnp_stop;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("pass", MFD_CLOEXEC);
    if (fd < 0 || write(fd, data, size) != (ssize_t)size)
        abort();
    char path[64], buf[PNP_PASS_MAX + 1], err[512];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    buf[PNP_PASS_MAX] = 0x5a; /* a canary just past the buffer pnp is given */
    long n = pnp_read_passphrase(path, 0, buf, PNP_PASS_MAX, err, sizeof err);
    if (n >= 0 && (n >= PNP_PASS_MAX || buf[n] != 0 || memchr(buf, '\n', (size_t)n) || n == 0))
        abort();
    if (buf[PNP_PASS_MAX] != 0x5a)
        abort();
    close(fd);
    return 0;
}
