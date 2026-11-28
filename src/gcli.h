/* The command line for pairs and groups (gcli.c): pnp --seal, --check-seal, --sign, --verify-sig, --send,
 * --receive, --kill, --kill-sign, --leave, --info, --meet, --import, --move. */
#ifndef PNP_GCLI_H
#define PNP_GCLI_H

/* whether argv[1] starts a pairs-and-groups command */
int pnp_is_group_command(const char *arg);
/* runs it; the exit status */
int pnp_group_cli(int argc, char **argv);

#endif
