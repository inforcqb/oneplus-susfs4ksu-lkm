// test_sc.c - SUSFS supercall ABI smoke test (no libc, raw syscalls).
// Compiled for arm64 with: clang --target=aarch64-linux-gnu -static -nostdlib
// Issues reboot(0xDEADBEEF, 0xFAFAFAFA, cmd, &payload) and prints results.
typedef unsigned long size_t;
typedef long ssize_t;

#define __NR_write 64
#define __NR_exit  93
#define __NR_reboot 142

static long raw_syscall6(long nr, long a0, long a1, long a2, long a3,
                         long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}

static long sc_reboot(int magic1, int magic2, unsigned int cmd, void *arg)
{
    return raw_syscall6(__NR_reboot, magic1, magic2, cmd, (long)arg, 0, 0);
}

static ssize_t sc_write(int fd, const void *buf, size_t len)
{
    return raw_syscall6(__NR_write, fd, (long)buf, len, 0, 0, 0);
}

static void putstr(const char *s)
{
    size_t len = 0;
    while (s[len]) len++;
    sc_write(1, s, len);
}

static void puthex(unsigned int v)
{
    char b[16];
    int i;
    for (i = 0; i < 8; i++) {
        unsigned int n = (v >> ((7 - i) * 4)) & 0xf;
        b[i] = n < 10 ? '0' + n : 'a' + n - 10;
    }
    sc_write(1, b, 8);
}

static int strequal(const char *a, const char *b)
{
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

#define KSU_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA
#define CMD_SET_UNAME 0x55590
#define CMD_ENABLE_LOG 0x555a0
#define CMD_SHOW_VERSION 0x555e1

struct susfs_version { char v[16]; int err; };
struct susfs_uname { char release[65]; char version[65]; int err; };
struct susfs_log { int enabled; int err; };

void _start(void)
{
    struct susfs_version ver = {{0}, 126};
    struct susfs_uname uname = {{0}, {0}, 126};
    struct susfs_log log = {0, 126};

    putstr("show_version: ");
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_SHOW_VERSION, &ver);
    putstr(ver.v);
    putstr(" err=");
    puthex((unsigned int)ver.err);
    putstr("\n");

    putstr("set_uname: ");
    // copy strings into uname
    { const char *r = "5.15.180-test"; const char *vv = "#1 test";
      int i; for (i = 0; r[i]; i++) uname.release[i] = r[i];
      for (i = 0; vv[i]; i++) uname.version[i] = vv[i]; }
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_SET_UNAME, &uname);
    putstr(" err=");
    puthex((unsigned int)uname.err);
    putstr("\n");

    putstr("enable_log: ");
    log.enabled = 1;
    sc_reboot(KSU_MAGIC1, SUSFS_MAGIC, CMD_ENABLE_LOG, &log);
    putstr(" err=");
    puthex((unsigned int)log.err);
    putstr("\n");

    raw_syscall6(__NR_exit, 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
