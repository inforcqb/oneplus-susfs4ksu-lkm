// SPDX-License-Identifier: GPL-2.0
/*
 * ih_hook_main.c - inline-hook test module.
 *
 * Two modes, so that a bug never has to be found on a system hot path again:
 *
 *   selftest=1 (default) points the machinery at ih_test_target(), a function in
 *   this module, and checks the three outcomes that matter: unchanged result
 *   through the trampoline, the hooked answer, and restore.  A failure here
 *   crashes this module's own call, not every openat in the system.
 *
 *   hook_syscall=1 additionally patches __arm64_sys_openat for real.
 *
 * Mechanics (all measured with ih_probe_test first):
 *   - entries start with paciasp, which doubles as the BTI landing pad, so the
 *     patch supplies its own 'bti c';
 *   - no PC-relative instruction in the window, so the two clobbered
 *     instructions replay verbatim;
 *   - 79-89MB to module text, inside B's reach, checked at runtime;
 *   - the trampoline lives in a module_alloc() page because ksu_patch_text
 *     converts addresses with __pa(), which is meaningless for vmalloc memory.
 *
 * The one bug the first version had is worth recording: the stub called a C
 * function without saving x0-x18, so the allow path handed the trampoline a
 * clobbered argument register.  See ih_hook_stub.S.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include "patch_memory.h"
#include "symbol_resolver.h"

#define IH_TARGET	"__arm64_sys_openat"
#define IH_HIDDEN	"/data/local/tmp/dac_probe/f600"
#define IH_TRAMP_SIZE	64

extern u64 ih_openat_tramp;
extern u64 ih_selftest_tramp;
extern void ih_openat_stub(void);
extern void ih_selftest_stub(void);

static void *(*pfn_module_alloc)(unsigned long size);
static int (*pfn_set_memory_ro)(unsigned long addr, int numpages);
static int (*pfn_set_memory_rw)(unsigned long addr, int numpages);
static int (*pfn_set_memory_x)(unsigned long addr, int numpages);

static bool ih_openat_installed;
static unsigned long ih_openat_entry;
static u32 ih_openat_orig[2];
static void *ih_openat_tramp_mem;

static int selftest = 1;
module_param(selftest, int, 0444);
static int hook_syscall;
module_param(hook_syscall, int, 0444);

/* ------------------------------------------------------------------ */
/* self-test target: a real function in this module, so the whole path can be
 * exercised without touching anything the system depends on. */

static noinline long ih_test_target(long x)
{
	return x * 3 + 7;
}

static long (*volatile ih_test_call)(long) = ih_test_target;

static long ih_selftest_arg;
static int ih_selftest_hide;

/* Called from ih_selftest_stub with the target's arguments still in place. */
int ih_selftest_decide(long x)
{
	ih_selftest_arg = x;
	return ih_selftest_hide;
}

/* ------------------------------------------------------------------ */
/* the real decision: only apps, only one path */

int ih_openat_decide(const struct pt_regs *uregs)
{
	const char __user *uname;
	char buf[256];
	long n;

	if (!uregs)
		return 0;
	if (current_uid().val < 10000)
		return 0;
	uname = (const char __user *)uregs->regs[1];
	if (!uname)
		return 0;
	n = strncpy_from_user(buf, uname, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	if (strcmp(buf, IH_HIDDEN))
		return 0;

	pr_info_ratelimited("ih_hook: inline hook answered ENOENT for '%s'\n", buf);
	return 1;
}

static void ih_flush_icache(void *addr, unsigned long len)
{
#if KSU_NEW_DCACHE_FLUSH
	caches_clean_inval_pou((unsigned long)addr, (unsigned long)addr + len);
#else
	__flush_icache_range((unsigned long)addr, (unsigned long)addr + len);
#endif
}

/* Patch either core text (ksu_patch_text, which knows how to get at read-only
 * kernel text) or this module's own read-only text (unlock, write, re-lock). */
static int ih_write_text(void *dst, const void *src, size_t len, bool core_text)
{
	unsigned long page = (unsigned long)dst & PAGE_MASK;

	if (core_text)
		return ksu_patch_text(dst, (void *)src, len,
				      KSU_PATCH_TEXT_FLUSH_ICACHE |
				      KSU_PATCH_TEXT_FLUSH_DCACHE);

	if (pfn_set_memory_rw(page, 1))
		return -EPERM;
	memcpy(dst, src, len);
	ih_flush_icache(dst, len);
	if (pfn_set_memory_ro(page, 1))
		return -EPERM;
	return 0;
}

static bool ih_sane_prologue(const u32 *insn)
{
	int i;

	for (i = 0; i < 2; i++) {
		if ((insn[i] & 0x1f000000u) == 0x10000000u)	/* adr/adrp  */
			return false;
		if ((insn[i] & 0x3b000000u) == 0x18000000u)	/* ldr lit   */
			return false;
		if ((insn[i] & 0x7c000000u) == 0x14000000u)	/* b/bl      */
			return false;
		if ((insn[i] & 0xff000010u) == 0x54000000u)	/* b.cond    */
			return false;
		if ((insn[i] & 0x7f000000u) == 0x34000000u)	/* cbz/cbnz  */
			return false;
		if ((insn[i] & 0x7f000000u) == 0x36000000u)	/* tbz/tbnz  */
			return false;
	}
	return true;
}

/* Build the trampoline for `entry`: replay the two instructions we overwrite,
 * then ldr x16, #8 / ret x16 into entry+8.  Returns the page or NULL. */
static void *ih_build_tramp(unsigned long entry, const u32 *orig)
{
	u32 *tr = pfn_module_alloc(IH_TRAMP_SIZE);

	if (!tr)
		return NULL;

	tr[0] = orig[0];
	tr[1] = orig[1];
	tr[2] = 0x58000050u;			/* ldr x16, #8         */
	tr[3] = 0xd65f0200u;			/* ret x16 (BTI-exempt) */
	*(u64 *)(tr + 4) = entry + 8;

	ih_flush_icache(tr, IH_TRAMP_SIZE);

	if (pfn_set_memory_ro((unsigned long)tr, 1) ||
	    pfn_set_memory_x((unsigned long)tr, 1)) {
		pr_err("ih_hook: cannot seal trampoline %px executable\n", tr);
		vfree(tr);
		return NULL;
	}
	return tr;
}

static int ih_patch(unsigned long entry, void *stub, bool core_text,
		    u32 *saved, void **tramp_slot, u64 *tramp_var)
{
	u32 patch[2];
	long delta;
	void *tr;

	if (!ih_sane_prologue((const u32 *)entry)) {
		pr_err("ih_hook: %px prologue not understood, refusing\n",
		       (void *)entry);
		return -EPERM;
	}

	delta = (long)(unsigned long)stub - (long)(entry + 4);
	if (delta < -(124L << 20) || delta > (124L << 20)) {
		pr_err("ih_hook: stub %ldMB away, outside B's reach\n", delta >> 20);
		return -ERANGE;
	}

	saved[0] = ((u32 *)entry)[0];
	saved[1] = ((u32 *)entry)[1];

	tr = ih_build_tramp(entry, saved);
	if (!tr)
		return -ENOMEM;
	*tramp_slot = tr;
	*tramp_var = (u64)(unsigned long)tr;

	patch[0] = 0xd503245fu;					/* bti c */
	patch[1] = 0x14000000u | (((u32)(delta >> 2)) & 0x03ffffffu);

	if (ih_write_text((void *)entry, patch, sizeof(patch), core_text)) {
		pr_err("ih_hook: could not patch %px\n", (void *)entry);
		*tramp_var = 0;
		return -EIO;
	}
	return 0;
}

static void ih_unpatch(unsigned long entry, const u32 *saved, bool core_text,
		       u64 *tramp_var)
{
	if (ih_write_text((void *)entry, saved, sizeof(u32) * 2, core_text))
		pr_err("ih_hook: could not restore %px\n", (void *)entry);
	*tramp_var = 0;
}

/* ------------------------------------------------------------------ */
static void ih_run_selftest(void)
{
	unsigned long entry = (unsigned long)ih_test_target;
	u32 saved[2];
	void *tr = NULL;
	long got;
	int rc;

	pr_info("ih_selftest: target %s @ %px\n", "ih_test_target", (void *)entry);

	got = ih_test_call(5);
	pr_info("ih_selftest: step 1 baseline target(5) = %ld (expect 22)\n", got);

	rc = ih_patch(entry, ih_selftest_stub, false, saved, &tr,
		      &ih_selftest_tramp);
	pr_info("ih_selftest: step 2 patch rc=%d tramp=%px saved=%08x %08x\n",
		rc, tr, saved[0], saved[1]);
	if (rc)
		return;

	ih_selftest_hide = 0;
	got = ih_test_call(5);
	pr_info("ih_selftest: step 3 allow -> target(5) = %ld (expect 22, via trampoline)\n",
		got);

	ih_selftest_hide = 1;
	got = ih_test_call(5);
	pr_info("ih_selftest: step 4 hide  -> target(5) = %ld (expect -2), decide saw %ld\n",
		got, ih_selftest_arg);

	ih_selftest_hide = 0;
	ih_unpatch(entry, saved, false, &ih_selftest_tramp);
	got = ih_test_call(5);
	pr_info("ih_selftest: step 5 restored target(5) = %ld (expect 22)\n", got);
}

static int ih_hook_openat(void)
{
	int rc;

	ih_openat_entry = find_kernel_symbol_exact(IH_TARGET);
	if (!ih_openat_entry) {
		pr_err("ih_hook: %s not found\n", IH_TARGET);
		return -ENOENT;
	}

	rc = ih_patch(ih_openat_entry, ih_openat_stub, true, ih_openat_orig,
		      &ih_openat_tramp_mem, &ih_openat_tramp);
	if (rc)
		return rc;

	ih_openat_installed = true;
	pr_info("ih_hook: %s hooked (entry %px, tramp %px)\n", IH_TARGET,
		(void *)ih_openat_entry, ih_openat_tramp_mem);
	return 0;
}

static int __init ih_hook_init(void)
{
	pr_info("ih_hook: inline-hook test (selftest=%d hook_syscall=%d)\n",
		selftest, hook_syscall);
	ksu_init_symbol_resolver();

	pfn_module_alloc = (void *)find_kernel_symbol_exact("module_alloc");
	pfn_set_memory_ro = (void *)find_kernel_symbol_exact("set_memory_ro");
	pfn_set_memory_rw = (void *)find_kernel_symbol_exact("set_memory_rw");
	pfn_set_memory_x = (void *)find_kernel_symbol_exact("set_memory_x");
	if (!pfn_module_alloc || !pfn_set_memory_ro || !pfn_set_memory_rw ||
	    !pfn_set_memory_x) {
		pr_err("ih_hook: helpers missing (alloc=%d ro=%d rw=%d x=%d)\n",
		       !!pfn_module_alloc, !!pfn_set_memory_ro,
		       !!pfn_set_memory_rw, !!pfn_set_memory_x);
		return -ENOENT;
	}

	if (selftest)
		ih_run_selftest();

	if (hook_syscall)
		ih_hook_openat();

	return 0;
}

static void __exit ih_hook_exit(void)
{
	if (ih_openat_installed) {
		ih_unpatch(ih_openat_entry, ih_openat_orig, true, &ih_openat_tramp);
		ih_openat_installed = false;
		pr_info("ih_hook: %s restored\n", IH_TARGET);
	}
	/* Trampoline pages are retired, not freed: a CPU may still be running
	 * one, and this is a test module. */
	pr_info("ih_hook: unloaded\n");
}

module_init(ih_hook_init);
module_exit(ih_hook_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("inline hook test module (self-test + optional syscall hook)");
