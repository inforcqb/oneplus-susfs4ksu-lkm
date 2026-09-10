// test_sc.c - SUSFS supercall ABI smoke test (no libc, raw syscalls).
// Compiled for arm64 with: clang --target=aarch64-linux-gnu -static -nostdlib
typedef unsigned long size_t;

#define __NR_write 64
#define __NR_exit  93
#define __NR_reboot 142

static long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
static long sc_reboot(int m1, int m2, unsigned int cmd, void *arg)
{ return raw_syscall6(__NR_reboot, m1, m2, cmd, (long)arg, 0, 0); }
static long sc_write(int fd, const void *b, size_t n)
{ return raw_syscall6(__NR_write, fd, (long)b, n, 0, 0, 0); }

static void putstr(const char *s) { size_t n = 0; while (s[n]) n++; sc_write(1, s, n); }
static void puthex(unsigned int v)
{
    char b[16]; int i;
    for (i = 0; i < 8; i++) { unsigned int n = (v >> ((7 - i) * 4)) & 0xf; b[i] = n < 10 ? '0' + n : 'a' + n - 10; }
    sc_write(1, b, 8);
}
static void putdec(int v)
{
    char b[12]; int i = 0;
    unsigned int u = v < 0 ? (unsigned int)(-v) : (unsigned int)v;
    if (v < 0) { char m = '-'; sc_write(1, &m, 1); }
    if (u == 0) { char z = '0'; sc_write(1, &z, 1); return; }
    while (u && i < 12) { b[i++] = '0' + (u % 10); u /= 10; }
    while (i--) sc_write(1, &b[i], 1);
}
void *memset(void *s, int c, unsigned long n)
{ volatile unsigned char *p = s; while (n--) *p++ = (unsigned char)c; return s; }
static void setstr(char *dst, const char *src, int max)
{ int i; for (i = 0; src[i] && i < max - 1; i++) dst[i] = src[i]; dst[i] = 0; }

#define KSU_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA
#define CMD_ADD_SUS_PATH        0x55550
#define CMD_ADD_SUS_KSTAT       0x55570
#define CMD_UPDATE_SUS_KSTAT    0x55571
#define CMD_ADD_OPEN_REDIRECT   0x555c0
#define CMD_SET_UNAME           0x55590
#define CMD_ENABLE_LOG          0x555a0
#define CMD_SHOW_VERSION        0x555e1

struct susfs_version { char v[16]; int err; };
struct susfs_path { char target_pathname[256]; int err; };
struct susfs_uname { char release[65]; char version[65]; int err; };
struct susfs_log { int enabled; int err; };
struct susfs_open_redirect { char target_pathname[256]; char redirected_pathname[256]; int uid_scheme; int err; };

/* must match susfs_abi.h / upstream st_susfs_sus_kstat exactly (376 bytes) */
struct susfs_kstat {
    int is_statically;                    /*   0 */
    unsigned long target_ino;             /*   8 */
    char target_pathname[256];            /*  16 */
    unsigned long spoofed_ino;            /* 272 */
    unsigned long spoofed_dev;            /* 280 */
    unsigned int spoofed_nlink;           /* 288 */
    long long spoofed_size;               /* 296 */
    long spoofed_atime_tv_sec;            /* 304 */
    unsigned long spoofed_atime_tv_nsec;  /* 312 */
    long spoofed_mtime_tv_sec;            /* 320 */
    unsigned long spoofed_mtime_tv_nsec;  /* 328 */
    long spoofed_ctime_tv_sec;            /* 336 */
    unsigned long spoofed_ctime_tv_nsec;  /* 344 */
    long long spoofed_blocks;             /* 352 */
    long spoofed_blksize;                 /* 360 */
    int flags;                            /* 368 */
    int err;                              /* 372 */
};

static struct susfs_kstat ks;

void _start(void)
{
    struct susfs_version ver; struct susfs_path sp; struct susfs_open_redirect orr;
    struct susfs_uname un; struct susfs_log lg;

    putstr("sizeof(susfs_kstat)="); putdec((int)sizeof(struct susfs_kstat));
    putstr(" err_off="); putdec((int)((char *)&ks.err - (char *)&ks));
    putstr("\n");

    memset(&ver, 0, sizeof(ver)); ver.err = 126;
    putstr("show_version: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_SHOW_VERSION, &ver);
    putstr(ver.v); putstr(" err="); puthex((unsigned int)ver.err); putstr("\n");

    memset(&sp, 0, sizeof(sp)); sp.err = 126;
    setstr(sp.target_pathname, "/data/local/tmp/abi_t", 256);
    putstr("add_sus_path: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_ADD_SUS_PATH, &sp);
    putstr("err="); puthex((unsigned int)sp.err); putstr("\n");

    memset(&ks, 0, sizeof(ks)); ks.err = 126;
    setstr(ks.target_pathname, "/data/local/tmp/abi_t", 256);
    putstr("add_sus_kstat: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_ADD_SUS_KSTAT, &ks);
    putstr("err="); puthex((unsigned int)ks.err); putstr("\n");

    memset(&orr, 0, sizeof(orr)); orr.err = 126;
    setstr(orr.target_pathname, "/data/local/tmp/abi_t", 256);
    setstr(orr.redirected_pathname, "/data/local/tmp/abi_r", 256);
    orr.uid_scheme = 0;
    putstr("add_open_redirect: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_ADD_OPEN_REDIRECT, &orr);
    putstr("err="); puthex((unsigned int)orr.err); putstr("\n");

    memset(&un, 0, sizeof(un)); un.err = 126;
    setstr(un.release, "5.15.180-abitest", 65);
    setstr(un.version, "#1 ABI", 65);
    putstr("set_uname: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_SET_UNAME, &un);
    putstr("err="); puthex((unsigned int)un.err); putstr("\n");

    memset(&lg, 0, sizeof(lg)); lg.enabled = 1; lg.err = 126;
    putstr("enable_log: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_ENABLE_LOG, &lg);
    putstr("err="); puthex((unsigned int)lg.err); putstr("\n");

    raw_syscall6(__NR_exit, 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
