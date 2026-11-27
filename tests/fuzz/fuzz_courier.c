/* Fuzzing the courier store parser (src/courier.c): a courier comes back from someone else's laptop, which could
 * have written anything on it. The input is the whole store. */
#define _GNU_SOURCE
#include "courier.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("courier", MFD_CLOEXEC);
    if (fd < 0 || write(fd, data, size) != (ssize_t)size) {
        if (fd >= 0)
            close(fd);
        return 0;
    }
    char path[64], err[512];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    struct cstore c;
    if (cs_open(&c, path, err, sizeof err) == 0) {
        if (c.end > c.capacity || c.capacity > size)
            abort();
        uint64_t pos = 0;
        struct crec r;
        uint8_t buf[64];
        while (cs_record(&c, &pos, &r) == 0) {
            if (r.data + r.len > c.end)
                abort();
            cs_read(&c, &r, 0, buf, r.len < sizeof buf ? (size_t)r.len : sizeof buf);
        }
        cs_verify(&c, err, sizeof err);
        cs_close(&c);
    }
    close(fd);
    return 0;
}
