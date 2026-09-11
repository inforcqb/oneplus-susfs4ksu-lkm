// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_sc - minimal SUSFS supercall client, no libc.
 *
 * The module's supercall entry point is the KernelSU reboot ABI:
 *
 *     reboot(KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, payload)
 *
 * (see kernel/susfs_supercall.c: reboot_pre() checks regs[0] against
 * KSU_INSTALL_MAGIC1 and regs[1] against SUSFS_MAGIC -- the second magic is the
 * SUSFS one, not KernelSU's MAGIC2.)
 *
 * The prebuilt ksu_susfs tool covers most commands, but not
 * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS and not CMD_SUSFS_ADD_SUS_PATH_LOOP,
 * so those have to be sent by hand.  This is the hand: it writes the command
 * number and a caller-supplied payload (as hex) straight to the syscall.
 *
 * Android refuses non-PIE executables, and we have no bionic sysroot in the
 * build container, so this is freestanding: -nostdlib -static-pie with our own
 * _start and raw svc instructions.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_sc tools/susfs_sc.c
 *
 * Usage:
 *
 *     susfs_sc <cmd-hex> [payload-hex]
 *     susfs_sc 0x55561 0100000000000000      # hide_sus_mnts_for_non_su_procs 1
 *
 * Exit status: 0 on a successful syscall, the syscall's (negated) error
 * otherwise, 2 for a usage error.
 */

typedef unsigned long u64;
typedef long s64;

#define SYS_write 64
#define SYS_exit 93
#define SYS_reboot 142

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA

#define PAYLOAD_MAX 4096

static char payload[PAYLOAD_MAX] __attribute__((aligned(16)));
static char out[256];

static long sys4(long n, long a, long b, long c, long d)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
			 : "memory", "cc");
	return x0;
}

static unsigned long slen(const char *s)
{
	unsigned long n = 0;

	while (s[n])
		n++;
	return n;
}

static void puts_len(const char *s, unsigned long n)
{
	sys4(SYS_write, 1, (long)s, (long)n, 0);
}

static void say(const char *s)
{
	puts_len(s, slen(s));
}

static void say_hex(unsigned long v)
{
	static const char d[] = "0123456789abcdef";
	char *p = out;
	int i;

	p[0] = '0';
	p[1] = 'x';
	p += 2;
	for (i = 60; i >= 0; i -= 4)
		*p++ = d[(v >> i) & 0xf];
	*p++ = '\n';
	puts_len(out, p - out);
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Parses a hex string (optionally 0x-prefixed) into payload[]. */
static long parse_hex(const char *s, char *dst, long cap)
{
	long n = 0;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	while (s[0] && s[1] && n < cap) {
		int hi = hexval(s[0]);
		int lo = hexval(s[1]);

		if (hi < 0 || lo < 0)
			return -1;
		dst[n++] = (char)((hi << 4) | lo);
		s += 2;
	}
	if (s[0] == ' ' || s[0] == '\n')
		return n;
	if (s[0])
		return -1;
	return n;
}

static long parse_cmd(const char *s)
{
	long v = 0;
	int i;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	for (i = 0; s[i]; i++) {
		int d = hexval(s[i]);

		if (d < 0)
			return -1;
		v = (v << 4) | d;
	}
	return v;
}

int sc_main(long argc, char **argv)
{
	long cmd, len;
	long rc;

	if (argc < 2) {
		say("usage: susfs_sc <cmd-hex> [payload-hex]\n");
		return 2;
	}
	cmd = parse_cmd(argv[1]);
	if (cmd < 0) {
		say("susfs_sc: bad command number\n");
		return 2;
	}

	len = 0;
	if (argc > 2) {
		len = parse_hex(argv[2], payload, PAYLOAD_MAX);
		if (len < 0) {
			say("susfs_sc: bad payload hex\n");
			return 2;
		}
	}

	say("susfs_sc: cmd ");
	say_hex((unsigned long)cmd);
	rc = sys4(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd,
		  (long)payload);
	say("susfs_sc: reboot() returned ");
	say_hex((unsigned long)rc);
	if (rc == 0 && len >= 8) {
		/* Most SUSFS reply structs end with an int err; echo it so the
		 * caller can tell success from a handled failure. */
		say("susfs_sc: payload tail: ");
		say_hex(*(unsigned long *)(payload + ((len - 8) & ~7L)));
	}
	return rc == 0 ? 0 : 1;
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	sc_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);
