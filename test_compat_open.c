// test_compat_open.c - 32-bit ARM raw-syscall probe for sus_path's compat coverage.
// Compiled with: clang --target=armv7-linux-gnueabi -march=armv7-a -static -nostdlib -fuse-ld=lld
//
// Prints the raw return of openat(AT_FDCWD, argv-less hardcoded path, O_RDONLY):
//   -2  => ENOENT   (sus_path answered, compat path is covered)
//  -13  => EACCES   (DAC rejected before we got a say)
//   >=0 => opened
typedef unsigned long u32;

#define __NR_exit   1
#define __NR_write  4
#define __NR_openat 322
#define AT_FDCWD    (-100)
#define O_RDONLY    0

static const char target[] = "/data/local/tmp/dac_probe/f600";

static long sc3(long nr, long a0, long a1, long a2)
{
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;

    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2)
                     : "memory", "cc");
    return r0;
}

static void putstr(const char *s)
{
    long n = 0;

    while (s[n])
        n++;
    sc3(__NR_write, 1, (long)s, n);
}

static void putdec(long v)
{
    char b[12];
    int i = 0;
    u32 u = v < 0 ? (u32)(-v) : (u32)v;

    if (v < 0)
        sc3(__NR_write, 1, (long)"-", 1);
    if (!u) {
        sc3(__NR_write, 1, (long)"0", 1);
        return;
    }
    while (u && i < 12) {
        b[i++] = '0' + (u % 10);
        u /= 10;
    }
    while (i--)
        sc3(__NR_write, 1, (long)&b[i], 1);
}

void _start(void)
{
    long ret = sc3(__NR_openat, AT_FDCWD, (long)target, O_RDONLY);

    putstr("32-bit openat -> ");
    putdec(ret);
    putstr(ret == -2 ? "  (ENOENT: hidden by sus_path)\n"
                     : ret == -13 ? "  (EACCES: DAC rejected first)\n"
                                  : "  (opened or other)\n");

    sc3(__NR_exit, 0, 0, 0);
    for (;;)
        ;
}
