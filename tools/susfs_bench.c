// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_bench - micro-benchmark for the syscall interception layers, no libc.
 *
 * The point is to measure what the hook costs per call, which is far below what a
 * shell loop can resolve: the fp layer adds a wrapper call, one strncpy_from_user
 * and one rule match to every hooked syscall, all of it in the hundred-nanosecond
 * range.  So this is a tight loop around four syscalls with only
 * clock_gettime(CLOCK_MONOTONIC) around it - no libc, no printf, no allocation.
 *
 * Run it four times and compare:
 *
 *   no module                       -> baseline
 *   module, no rule                 -> the layers are not armed at all
 *   module, rule that does NOT hit  -> the wrapper's full path, then the original
 *   module, rule that DOES hit      -> the wrapper answers ENOENT before the original
 *
 * Android refuses non-PIE executables and the DDK container has no bionic sysroot,
 * so this is freestanding: -nostdlib -static-pie with our own _start.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_bench tools/susfs_bench.c
 *
 * Usage:
 *
 *     susfs_bench <path> [iterations]      # default 200000 iterations
 */

typedef unsigned long u64;
typedef long s64;

#define SYS_faccessat   48
#define SYS_openat      56
#define SYS_close       57
#define SYS_write       64
#define SYS_newfstatat  79
#define SYS_exit        93
#define SYS_clock_gettime 113
#define SYS_statx       291

#define AT_FDCWD      (-100)
#define CLOCK_MONOTONIC 1
#define O_RDONLY       0

#define STATX_BASIC_STATS 0x7ff

static char out[512];
static char statbuf[512] __attribute__((aligned(16)));

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory", "cc");
	return x0;
}

static u64 slen(const char *s)
{
	u64 n = 0;

	while (s[n])
		n++;
	return n;
}

static u64 put(char *dst, u64 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u64 putnum(char *dst, u64 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

/* Both of these are system calls here: the ABI passes nanoseconds in the second
 * word, which is all this needs. */
static u64 now_ns(void)
{
	long ts[2];

	sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long)ts, 0, 0, 0, 0);
	return (u64)ts[0] * 1000000000ull + (u64)ts[1];
}

static void report(const char *what, u64 iters, u64 took)
{
	u64 per = iters ? took / iters : 0;
	u64 pos = 0;

	pos = put(out, pos, what);
	pos = put(out, pos, ": iters=");
	pos = putnum(out, pos, iters);
	pos = put(out, pos, " total=");
	pos = putnum(out, pos, took);
	pos = put(out, pos, "ns per=");
	pos = putnum(out, pos, per);
	pos = put(out, pos, "ns\n");
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static u64 parse_num(const char *s)
{
	u64 v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (u64)(*s++ - '0');
	return v;
}

/* Same entry stub susfs_sc uses: sp points at argc, then argv[0..]. */
__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	bench_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void bench_main(long argc, char **argv);

void bench_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	u64 iters = 100000;
	u64 i, r, t0, t1, took, best;
	long rc = 0;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		iters = parse_num(argv[2]);

	/* Warm up: the first pass over a cold path resolver is not what we measure,
	 * and the rule table/matches are per-call anyway. */
	for (i = 0; i < 1000; i++)
		sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)statbuf, 0, 0, 0);

	/* The interesting difference is a few hundred nanoseconds on a phone that is
	 * also running Android, so a single pass is mostly noise.  Take the best of
	 * several: the minimum is the run that was least disturbed, which is the
	 * number the layer itself is responsible for. */
#define ROUNDS 5
	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("faccessat", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)statbuf, 0, 0, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("newfstatat", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_BASIC_STATS,
				   (long)statbuf, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("statx", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++) {
			long fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);

			if (fd >= 0)
				sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		}
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("openat+close", iters, best);

	/* Keep the compiler honest: rc is used so the loops cannot be optimised
	 * away, and its value is not interesting. */
	if (rc == 0x7fffffff)
		sys6(SYS_write, 1, (long)"unexpected\n", 11, 0, 0, 0);
}
