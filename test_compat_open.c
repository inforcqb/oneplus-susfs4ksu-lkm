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

void _start(void)
{
    long ret = sc3(__NR_openat, AT_FDCWD, (long)target, O_RDONLY);

    /* Deliberately no number formatting: 32-bit division would pull in
     * __aeabi_uidiv, which -nostdlib does not provide.  The three cases are all
     * this probe needs to tell apart. */
    putstr("32-bit openat -> ");
    if (ret == -2)
        putstr("ENOENT  (hidden by sus_path)\n");
    else if (ret == -13)
        putstr("EACCES  (DAC rejected before sus_path got a say)\n");
    else if (ret < 0)
        putstr("other negative (not ENOENT/EACCES)\n");
    else
        putstr("opened\n");

    sc3(__NR_exit, 0, 0, 0);
    for (;;)
        ;
}
