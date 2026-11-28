/* The sandbox (sandbox.c): no network or new programs at all, and once the files are open, only the system calls
 * and folders the rest of the work needs. */
#ifndef PNP_SANDBOX_H
#define PNP_SANDBOX_H

enum { PNP_SB_EARLY, PNP_SB_WORK };

struct pnp_sandbox_state {
    int seccomp;      /* the work filter is on */
    int landlock_abi; /* Landlock's version, or -1 when the kernel hasn't got it */
};

/* At start, every mode: no_new_privs, and a filter that kills network, exec, ptrace and the like. 0 if the filter
 * is on, -1 if this kernel or build can't (pnp then runs without it). */
int pnp_sandbox_early(void);
/* Once a command-line encrypt, decrypt or --verify has its files open: file access only to the folders given
 * (where outputs are saved), and only the system calls the rest of the work makes. Irreversible. */
void pnp_sandbox_work(char *const *dirs, int ndirs, struct pnp_sandbox_state *st);

/* Pairs and groups (gcli.c): file access only beneath the folders given (the group's, the input's, the output's,
 * the current one), on top of the early filter. They open their files as they go, so the work filter (which
 * allows read-only opens) doesn't fit them. The Landlock ABI version, or -1. Irreversible. */
int pnp_sandbox_dirs(char *const *dirs, int ndirs);

#endif
