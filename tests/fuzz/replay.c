/* Runs a fuzz harness on files given on the command line, without libFuzzer: so `make test` can run every harness
 * on its seeds with gcc (they then build and pass everywhere), and a crash found by fuzzing can be replayed. */
#undef main /* the build renames main.c's main with -Dmain=pnp_cli_main; this one stays */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            perror(argv[i]);
            return 1;
        }
        static uint8_t buf[1 << 20];
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("%d inputs ran\n", argc - 1);
    return 0;
}
