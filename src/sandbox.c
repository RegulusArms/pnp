/* The sandbox: what pnp can still do once its files are open.
 *
 * pnp never needs the network, never runs another program, and once its inputs and outputs are open it needs
 * only a few folders. If a bug in pnp (or in what it reads) were ever exploited, the sandbox limits what the
 * exploit could do: no sending the pad anywhere, no reading other files, no starting a shell. Three parts, all
 * plain kernel interfaces (libc only, no libseccomp):
 *
 *   - no_new_privs (prctl): nothing pnp does can gain privileges (setuid programs, file capabilities). Needed
 *     for the other two without root.
 *   - seccomp: a BPF filter run on every system call. Two of them, which stack (the kernel applies both):
 *       PNP_SB_EARLY, at start for every mode: every network call fails (EPERM), and running programs,
 *       tracing other processes, io_uring (which would bypass the filter) and a few other dangerous calls kill
 *       the process. Network calls fail rather than kill because glibc itself may try a socket when looking up
 *       a group (systemd-userdb, sssd), and must just get "no" there. Everything else passes: the interactive
 *       mode and the passphrase hashes' threads need much of it.
 *       PNP_SB_WORK, once a command-line encrypt, decrypt or --verify has its files open: only the calls the
 *       rest of the work makes are allowed (reading, writing, renaming and removing in the output folders,
 *       getrandom, memory, signals). Opening a file is allowed read-only (the folder fsync needs it; Landlock
 *       limits where), creating one isn't. Any other call fails with EPERM, so a missed one gives an error
 *       message, not a crash halfway through saving.
 *   - Landlock (Linux 5.13+): file access limited to the output folders, and there only to what saving needs
 *     (create a file, remove one, rename within the folder, list it). Every input is already open, so nothing
 *     else is reachable: not your home folder, not /etc, not the key drive unless a key goes there. On kernels
 *     with ABI 4+ TCP is refused as well, and with ABI 6+ signals and abstract sockets outside pnp are.
 * Each part is used when the kernel has it and skipped quietly when it doesn't (-v says which ran). The
 * interactive mode keeps the early filter only: it opens files all along, so it can't be fenced in this way.
 * Builds with AddressSanitizer (make sanitize, never shipped) skip seccomp and Landlock: its leak checker traces
 * the process and reads /proc/self/task when pnp exits. */
#define _GNU_SOURCE
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#if defined(__x86_64__)
#define PNP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PNP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

#if defined(__SANITIZE_ADDRESS__)
#define PNP_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define PNP_SANITIZED 1
#endif
#endif

/* ---------------------------------------------------------------- seccomp */

#if defined(PNP_AUDIT_ARCH) && !defined(PNP_SANITIZED)

/* no network, in every mode: these always fail with EPERM (even on a socket pnp was started with) */
static const int net_calls[] = {
    __NR_socket, __NR_socketpair, __NR_connect, __NR_bind, __NR_listen, __NR_accept, __NR_accept4, __NR_sendto,
    __NR_sendmsg, __NR_sendmmsg, __NR_recvfrom, __NR_recvmsg, __NR_recvmmsg,
};

/* killed outright in every mode: no running programs, no reaching into other processes, nothing that could get
 * around the filter (io_uring's operations aren't seen by seccomp; bpf, perf and kernel modules are kernel attack
 * surface pnp has no use for) */
static const int kill_calls[] = {
    __NR_execve, __NR_execveat,
    __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev, __NR_io_uring_setup, __NR_io_uring_enter,
    __NR_io_uring_register, __NR_bpf, __NR_perf_event_open, __NR_init_module, __NR_finit_module,
    __NR_kexec_load, __NR_mount, __NR_umount2, __NR_pivot_root, __NR_chroot, __NR_unshare, __NR_setns,
    __NR_keyctl, __NR_add_key, __NR_request_key, __NR_userfaultfd, __NR_open_by_handle_at, __NR_name_to_handle_at,
    __NR_personality,
};

/* what the work allows once files are open (PNP_SB_WORK); openat and ioctl are handled separately, with their
 * arguments checked */
static const int work_calls[] = {
    /* the files already open: data, the hardware source, the progress line */
    __NR_read, __NR_write, __NR_readv, __NR_writev, __NR_pread64, __NR_lseek, __NR_close, __NR_fstat,
    __NR_newfstatat, __NR_statx, __NR_fcntl, __NR_fsync, __NR_fdatasync,
    /* saving: the part files take their real names (fileio.c), old ones go aside and come back on failure */
    __NR_renameat2, __NR_linkat, __NR_unlinkat,
#ifdef __NR_renameat /* not on aarch64 */
    __NR_renameat,
#endif
    /* the pad mixes in getrandom; memory; time for the progress line */
    __NR_getrandom, __NR_brk, __NR_mmap, __NR_munmap, __NR_mremap, __NR_mprotect, __NR_madvise, __NR_mlock,
    __NR_munlock, __NR_clock_gettime, __NR_clock_nanosleep, __NR_nanosleep, __NR_sched_yield, __NR_futex,
    /* signals: Ctrl-C stops the run, and pnp then dies of the same signal (raise) so the shell sees it */
    __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_restart_syscall, __NR_getpid, __NR_gettid,
    __NR_tgkill, __NR_exit, __NR_exit_group,
#ifdef __NR_stat /* the old calls glibc uses on x86-64; aarch64 never had them */
    __NR_stat, __NR_lstat, __NR_rename, __NR_link, __NR_unlink,
#endif
};

#define ARG_LO(i) (offsetof(struct seccomp_data, args) + 8 * (i)) /* the low 32 bits (little-endian) */
#define STMT(c, k) ((struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, f) ((struct sock_filter)BPF_JUMP((c), (k), (t), (f)))
#define RET(v) STMT(BPF_RET | BPF_K, (v))
#define LOAD(off) STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define IF_EQ(k, t, f) JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f))
#define PNP_TCGETS2 0x802c542aU /* _IOR('T', 0x2A, struct termios2), from <asm/ioctls.h> */
#define DENY (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static int load_filter(int mode)
{
    struct sock_filter f[512]; /* the work filter takes about 190 instructions (2 per listed call): room to spare */
    unsigned n = 0;
    f[n++] = LOAD(offsetof(struct seccomp_data, arch));
    f[n++] = IF_EQ(PNP_AUDIT_ARCH, 1, 0); /* calls from another ABI (32-bit x86) are refused */
    f[n++] = RET(SECCOMP_RET_KILL_PROCESS);
    f[n++] = LOAD(offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    f[n++] = JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1); /* x32 calls */
    f[n++] = RET(SECCOMP_RET_KILL_PROCESS);
#endif
    for (size_t i = 0; i < sizeof net_calls / sizeof *net_calls; i++) {
        f[n++] = IF_EQ((unsigned)net_calls[i], 0, 1);
        f[n++] = RET(DENY);
    }
    for (size_t i = 0; i < sizeof kill_calls / sizeof *kill_calls; i++) {
        f[n++] = IF_EQ((unsigned)kill_calls[i], 0, 1);
        f[n++] = RET(SECCOMP_RET_KILL_PROCESS);
    }
    if (mode == PNP_SB_EARLY) {
        f[n++] = RET(SECCOMP_RET_ALLOW);
    } else {
        /* openat: read-only only (no write access, no creating, no truncating). O_TMPFILE includes O_DIRECTORY's
         * bit, so only its own bit is tested: opening a folder to fsync it must pass. */
        f[n++] = IF_EQ(__NR_openat, 0, 5);
        f[n++] = LOAD(ARG_LO(2));
        f[n++] = STMT(BPF_ALU | BPF_AND | BPF_K,
                      O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | (O_TMPFILE & ~O_DIRECTORY));
        f[n++] = IF_EQ(0, 0, 1);
        f[n++] = RET(SECCOMP_RET_ALLOW);
        f[n++] = RET(DENY);
        /* ioctl: only asking whether stderr is a terminal and how wide (the progress line). glibc 2.42 and newer
         * ask with TCGETS2 (termios2, 44 bytes: the same number on x86-64 and aarch64), older ones with TCGETS */
        f[n++] = IF_EQ(__NR_ioctl, 0, 6);
        f[n++] = LOAD(ARG_LO(1));
        f[n++] = IF_EQ(TCGETS, 3, 0);
        f[n++] = IF_EQ(PNP_TCGETS2, 2, 0);
        f[n++] = IF_EQ(TIOCGWINSZ, 1, 0);
        f[n++] = RET(DENY);
        f[n++] = RET(SECCOMP_RET_ALLOW);
        for (size_t i = 0; i < sizeof work_calls / sizeof *work_calls; i++) {
            f[n++] = IF_EQ((unsigned)work_calls[i], 0, 1);
            f[n++] = RET(SECCOMP_RET_ALLOW);
        }
        f[n++] = RET(DENY);
    }
    struct sock_fprog prog = {(unsigned short)n, f};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}
#endif

/* ---------------------------------------------------------------- Landlock */

/* The kernel's stable Landlock ABI (include/uapi/linux/landlock.h), spelled out here so pnp builds against older
 * kernel headers (Ubuntu 22.04's know only ABI 1) and still uses what a newer running kernel offers. */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#define LL_CREATE_RULESET_VERSION (1U << 0)
#define LL_RULE_PATH_BENEATH 1
#define LL_FS_EXECUTE (1ULL << 0)
#define LL_FS_WRITE_FILE (1ULL << 1)
#define LL_FS_READ_FILE (1ULL << 2)
#define LL_FS_READ_DIR (1ULL << 3)
#define LL_FS_REMOVE_DIR (1ULL << 4)
#define LL_FS_REMOVE_FILE (1ULL << 5)
#define LL_FS_MAKE_CHAR (1ULL << 6)
#define LL_FS_MAKE_DIR (1ULL << 7)
#define LL_FS_MAKE_REG (1ULL << 8)
#define LL_FS_MAKE_SOCK (1ULL << 9)
#define LL_FS_MAKE_FIFO (1ULL << 10)
#define LL_FS_MAKE_BLOCK (1ULL << 11)
#define LL_FS_MAKE_SYM (1ULL << 12)
#define LL_FS_REFER (1ULL << 13)    /* ABI 2 */
#define LL_FS_TRUNCATE (1ULL << 14) /* ABI 3 */
#define LL_FS_IOCTL_DEV (1ULL << 15) /* ABI 5 */
#define LL_NET_BIND_TCP (1ULL << 0) /* ABI 4 */
#define LL_NET_CONNECT_TCP (1ULL << 1)
#define LL_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0) /* ABI 6 */
#define LL_SCOPE_SIGNAL (1ULL << 1)

struct ll_ruleset_attr {
    uint64_t handled_access_fs, handled_access_net, scoped;
};
struct ll_path_beneath {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

#ifndef PNP_SANITIZED
/* -1 if Landlock isn't there (or is turned off); otherwise its ABI version */
static int landlock(char *const *dirs, int ndirs, uint64_t allowed)
{
    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LL_CREATE_RULESET_VERSION);
    if (abi < 1)
        return -1;
    struct ll_ruleset_attr attr = {0, 0, 0};
    size_t attr_len = sizeof attr.handled_access_fs;
    /* every kind of access this kernel can restrict is restricted, unless a rule below allows it */
    attr.handled_access_fs = (LL_FS_MAKE_SYM << 1) - 1;
    if (abi >= 2)
        attr.handled_access_fs |= LL_FS_REFER;
    if (abi >= 3)
        attr.handled_access_fs |= LL_FS_TRUNCATE;
    if (abi >= 5)
        attr.handled_access_fs |= LL_FS_IOCTL_DEV;
    if (abi >= 4) {
        attr.handled_access_net = LL_NET_BIND_TCP | LL_NET_CONNECT_TCP; /* no rules: no TCP at all */
        attr_len = offsetof(struct ll_ruleset_attr, scoped);
    }
    if (abi >= 6) {
        attr.scoped = LL_SCOPE_ABSTRACT_UNIX_SOCKET | LL_SCOPE_SIGNAL;
        attr_len = sizeof attr;
    }
    int rs = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_len, 0);
    if (rs < 0)
        return -1;
    /* in each output folder: create the part files' real names, remove (parts, old files put aside), rename within
     * the folder (needs no LL_FS_REFER: that's only for moving between folders), and open it to fsync it */
    struct ll_path_beneath pb = {allowed & attr.handled_access_fs, -1};
    int ok = 1;
    for (int i = 0; i < ndirs && ok; i++) {
        pb.parent_fd = open(dirs[i], O_PATH | O_DIRECTORY | O_CLOEXEC);
        ok = pb.parent_fd >= 0 && syscall(__NR_landlock_add_rule, rs, LL_RULE_PATH_BENEATH, &pb, 0) == 0;
        if (pb.parent_fd >= 0)
            close(pb.parent_fd);
    }
    ok = ok && syscall(__NR_landlock_restrict_self, rs, 0) == 0;
    close(rs);
    return ok ? (int)abi : -1;
}
#endif

/* ---------------------------------------------------------------- the two steps */

int pnp_sandbox_early(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
#if defined(PNP_AUDIT_ARCH) && !defined(PNP_SANITIZED)
    return load_filter(PNP_SB_EARLY);
#else
    return -1;
#endif
}

void pnp_sandbox_work(char *const *dirs, int ndirs, struct pnp_sandbox_state *st)
{
    memset(st, 0, sizeof *st);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return;
#ifdef PNP_SANITIZED
    (void)dirs;
    (void)ndirs;
    st->landlock_abi = -1;
#else
    st->landlock_abi = landlock(dirs, ndirs, LL_FS_MAKE_REG | LL_FS_REMOVE_FILE | LL_FS_READ_DIR);
#ifdef PNP_AUDIT_ARCH
    st->seccomp = load_filter(PNP_SB_WORK) == 0;
#endif
#endif
}

int pnp_sandbox_dirs(char *const *dirs, int ndirs)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
#ifdef PNP_SANITIZED
    (void)dirs;
    (void)ndirs;
    return -1;
#else
    /* everything a group command does in its folders: read and write files, make and remove files and folders,
     * list them, cut files short. Nothing outside them, and never running anything. */
    return landlock(dirs, ndirs,
                    LL_FS_READ_FILE | LL_FS_WRITE_FILE | LL_FS_READ_DIR | LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR |
                        LL_FS_MAKE_REG | LL_FS_MAKE_DIR | LL_FS_TRUNCATE);
#endif
}
