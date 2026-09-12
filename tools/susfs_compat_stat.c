// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_compat_stat - a 32-bit (AArch32) caller, to test the compat stat path.
 *
 * The kernel-side ABI audit found that the module was spoofing the WRONG compat
 * structure: __NR_fstatat64 (327) and __NR_fstat64 (197) are mapped to
 * sys_fstatat64/sys_fstat64, which fill `struct stat64` (arch/arm64/include/asm/
 * stat.h:19-48) - not `struct compat_stat`, which belongs to __NR_stat/lstat/fstat
 * (106/107/108).  Nothing in the repository could have caught that, because no
 * 32-bit client existed: a 64-bit process cannot make a 32-bit syscall here.
 *
 * This is that client.  It calls fstatat64 (and fstat64) and prints what came
 * back, so a rule's spoofed ino/dev/size/nlink can be compared against the same
 * rule observed from a 64-bit caller.
 *
 * The struct below is `packed` on purpose: the AArch32 struct stat64 uses
 * compat_u64/compat_s64, which arm64 defines as `__attribute__((aligned(4)))`
 * (include/linux/compat.h:37-38), while the compiler's default alignment for
 * unsigned long long on armv7 is 8.  Without the attribute the client's own
 * view of the struct would disagree with the kernel's and the test would be
 * measuring its own bug.
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *     clang --target=armv7a-linux-androideabi -march=armv7-a -O2 -nostdlib \
 *           -static-pie -fno-stack-protector -fno-builtin -fuse-ld=lld \
 *           -Wl,-e,_start -o susfs_compat_stat tools/susfs_compat_stat.c
 *
 * Usage: susfs_compat_stat <path>
 */

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define __NR_fstatat64 327
#define __NR_fstat64 197
#define AT_FDCWD (-100)

struct stat64_compat {
	u64 st_dev;			/* 0  */
	unsigned char __pad0[4];	/* 8  */
	u32 __st_ino;			/* 12 */
	u32 st_mode;			/* 16 */
	u32 st_nlink;			/* 20 */
	u32 st_uid;			/* 24 */
	u32 st_gid;			/* 28 */
	u64 st_rdev;			/* 32 */
	unsigned char __pad3[4];	/* 40 */
	s64 st_size;			/* 44 */
	u32 st_blksize;			/* 52 */
	u64 st_blocks;			/* 56 */
	u32 st_atime;			/* 64 */
	u32 st_atime_nsec;		/* 68 */
	u32 st_mtime;			/* 72 */
	u32 st_mtime_nsec;		/* 76 */
	u32 st_ctime;			/* 80 */
	u32 st_ctime_nsec;		/* 84 */
	u64 st_ino;			/* 88 */
} __attribute__((packed));

static struct stat64_compat st;
static char out[512];

static long sys4(long n, long a, long b, long c, long d)
{
	register long r7 __asm__("r7") = n;
	register long r0 __asm__("r0") = a;
	register long r1 __asm__("r1") = b;
	register long r2 __asm__("r2") = c;
	register long r3 __asm__("r3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(r0)
			 : "r"(r7), "r"(r1), "r"(r2), "r"(r3)
			 : "memory", "cc");
	return r0;
}

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

/* armv7 has no 64-bit division instruction, and a freestanding binary has no
 * libgcc, so `v / 10` would pull in __aeabi_uldivmod and fail to link (it did).
 * Shift-subtract long division instead: 64 iterations, no library call. */
static u64 u64_div10(u64 v, u64 *rem)
{
	u64 q = 0, r = 0;
	int i;

	for (i = 63; i >= 0; i--) {
		r = (r << 1) | ((v >> i) & 1);
		if (r >= 10) {
			r -= 10;
			q |= (1ull << i);
		}
	}
	*rem = r;
	return q;
}

static u32 putnum(char *dst, u32 pos, u64 v, int neg)
{
	char tmp[24];
	int n = 0;

	if (neg)
		dst[pos++] = '-';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		u64 rem;

		v = u64_div10(v, &rem);
		tmp[n++] = (char)('0' + (u32)rem);
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static u32 puthex(char *dst, u32 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

	dst[pos++] = '0';
	dst[pos++] = 'x';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = d[v & 0xf];
		v >>= 4;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static void show(const char *what, long rc)
{
	u32 pos = 0;

	pos = put(out, pos, what);
	if (rc < 0) {
		pos = put(out, pos, " rc=");
		pos = putnum(out, pos, (u64)(-rc), 0);
		pos = put(out, pos, " (failed)\n");
		sys4(SYS_write, 1, (long)out, pos, 0);
		return;
	}
	pos = put(out, pos, " ino=");
	pos = putnum(out, pos, st.st_ino, 0);
	pos = put(out, pos, " broken_ino=");
	pos = putnum(out, pos, st.__st_ino, 0);
	pos = put(out, pos, " dev=");
	pos = puthex(out, pos, st.st_dev);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, st.st_nlink, 0);
	pos = put(out, pos, " size=");
	pos = putnum(out, pos, (u64)st.st_size, 0);
	pos = put(out, pos, " mtime=");
	pos = putnum(out, pos, (u64)st.st_mtime, 0);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	fp, #0\n"
"	ldr	r0, [sp]\n"
"	add	r1, sp, #4\n"
"	bl	compat_main\n"
"	mov	r7, #1\n"
"	svc	#0\n"
);

void compat_main(long argc, char **argv);

void compat_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	long fd, rc;
	u32 pos = 0;

	if (argc > 1)
		path = argv[1];

	pos = put(out, pos, "struct stat64 size=");
	pos = putnum(out, pos, (u64)sizeof(st), 0);
	pos = put(out, pos, " (expect 96; a mismatch means this client's layout is wrong)\n");
	sys4(SYS_write, 1, (long)out, pos, 0);

	rc = sys4(__NR_fstatat64, AT_FDCWD, (long)path, (long)&st, 0);
	show("fstatat64", rc);

	fd = sys4(SYS_open, (long)path, 0, 0, 0);
	if (fd >= 0) {
		rc = sys4(__NR_fstat64, fd, (long)&st, 0, 0);
		show("fstat64  ", rc);
	}
}
