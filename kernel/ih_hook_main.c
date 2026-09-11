// SPDX-License-Identifier: GPL-2.0
/*
 * ih_hook_main.c - stage 1 of the inline-hook plan, as a throwaway test module.
 *
 * Hooks exactly one entry point, __arm64_sys_openat, and answers -ENOENT for one
 * hard-coded path when the caller is an app.  Everything else must keep working,
 * which is the real test: it exercises the trampoline.
 *
 * Why this shape (all of it measured with ih_probe_test first):
 *   - every candidate entry starts with paciasp, which doubles as the BTI
 *     landing pad, so a patch that overwrites it must supply its own: this one
 *     writes `bti c` first;
 *   - no instruction in the first 20 bytes is PC-relative, so the two we clobber
 *     can be replayed verbatim from a trampoline;
 *   - the module sits 79-89MB from core text, inside B's +/-128MB, so an 8-byte
 *     patch (bti c ; b stub) is enough - and the distance is checked at runtime,
 *     not assumed;
 *   - the trampoline lives in a page from module_alloc(), because the kernel's
 *     text-patch helper converts addresses with __pa() and that is meaningless
 *     for vmalloc memory: this page is written while still writable, then
 *     sealed read-only and executable.
 *
 * Unloading restores the entry but deliberately leaks the trampoline page rather
 * than vfree()ing memory a CPU might still be executing (the same reasoning as
 * the open_redirect retirement).
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

/* Defined in ih_hook_stub.S. */
extern u64 ih_openat_tramp;
extern void ih_openat_stub(void);

static void *(*pfn_module_alloc)(unsigned long size);
static int (*pfn_set_memory_ro)(unsigned long addr, int numpages);
static int (*pfn_set_memory_x)(unsigned long addr, int numpages);

static unsigned long ih_entry;
static u32 ih_orig[2];
static void *ih_tramp_mem;
static bool ih_installed;

/* Called from the stub with the wrapper's argument untouched in x0.  Returns 1
 * to hide the path, 0 to let the call run normally. */
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

static int ih_install(void)
{
	u32 *entry, patch[2];
	long delta;
	u32 *tr;
	int rc;

	ih_entry = find_kernel_symbol_exact(IH_TARGET);
	if (!ih_entry) {
		pr_err("ih_hook: %s not found\n", IH_TARGET);
		return -ENOENT;
	}

	entry = (u32 *)ih_entry;
	ih_orig[0] = entry[0];
	ih_orig[1] = entry[1];

	pr_info("ih_hook: entry %px: %08x %08x\n", (void *)ih_entry, ih_orig[0],
		ih_orig[1]);

	/* Refuse anything we cannot reason about. */
	if ((ih_orig[0] & 0x1f000000u) == 0x10000000u ||
	    (ih_orig[1] & 0x1f000000u) == 0x10000000u ||
	    (ih_orig[0] & 0x7c000000u) == 0x14000000u ||
	    (ih_orig[1] & 0x7c000000u) == 0x14000000u) {
		pr_err("ih_hook: entry is not a recognised prologue, refusing\n");
		return -EPERM;
	}

	delta = (long)(unsigned long)ih_openat_stub - (long)(ih_entry + 4);
	if (delta < -(124L << 20) || delta > (124L << 20)) {
		pr_err("ih_hook: stub is %ldMB away, outside B's reach\n",
		       delta >> 20);
		return -ERANGE;
	}

	tr = pfn_module_alloc(IH_TRAMP_SIZE);
	if (!tr) {
		pr_err("ih_hook: module_alloc failed\n");
		return -ENOMEM;
	}
	ih_tramp_mem = tr;

	tr[0] = ih_orig[0];			/* paciasp            */
	tr[1] = ih_orig[1];			/* sub sp, sp, #imm   */
	tr[2] = 0x58000050u;			/* ldr x16, #8        */
	tr[3] = 0xd65f0200u;			/* ret x16 (BTI-exempt) */
	*(u64 *)(tr + 4) = ih_entry + 8;	/* -> entry + 8       */

	ih_flush_icache(tr, IH_TRAMP_SIZE);

	if (pfn_set_memory_ro((unsigned long)tr, 1) ||
	    pfn_set_memory_x((unsigned long)tr, 1)) {
		pr_err("ih_hook: could not seal the trampoline executable\n");
		vfree(tr);
		ih_tramp_mem = NULL;
		return -EPERM;
	}

	ih_openat_tramp = (u64)(unsigned long)tr;

	patch[0] = 0xd503245fu;					/* bti c */
	patch[1] = 0x14000000u | (((u32)(delta >> 2)) & 0x03ffffffu);

	rc = ksu_patch_text((void *)ih_entry, patch, sizeof(patch),
			    KSU_PATCH_TEXT_FLUSH_ICACHE | KSU_PATCH_TEXT_FLUSH_DCACHE);
	if (rc) {
		pr_err("ih_hook: patch_text failed %d\n", rc);
		ih_openat_tramp = 0;
		vfree(tr);
		ih_tramp_mem = NULL;
		return rc;
	}

	ih_installed = true;
	pr_info("ih_hook: %s hooked: tramp=%px patch=%08x %08x\n", IH_TARGET,
		tr, patch[0], patch[1]);
	return 0;
}

static void ih_remove(void)
{
	if (!ih_installed)
		return;

	if (ksu_patch_text((void *)ih_entry, ih_orig, sizeof(ih_orig),
			   KSU_PATCH_TEXT_FLUSH_ICACHE | KSU_PATCH_TEXT_FLUSH_DCACHE))
		pr_err("ih_hook: failed to restore the entry\n");
	else
		pr_info("ih_hook: entry restored\n");

	ih_installed = false;
	ih_openat_tramp = 0;

	/* Deliberately not freed: a CPU may still be inside it.  This is a test
	 * module, one page, and the retirement trick is the safe answer. */
	pr_info("ih_hook: trampoline page %px retired (not freed)\n", ih_tramp_mem);
	ih_tramp_mem = NULL;
}

static int __init ih_hook_init(void)
{
	int rc;

	pr_info("ih_hook: stage-1 inline hook test\n");
	ksu_init_symbol_resolver();

	pfn_module_alloc = (void *)find_kernel_symbol_exact("module_alloc");
	pfn_set_memory_ro = (void *)find_kernel_symbol_exact("set_memory_ro");
	pfn_set_memory_x = (void *)find_kernel_symbol_exact("set_memory_x");
	if (!pfn_module_alloc || !pfn_set_memory_ro || !pfn_set_memory_x) {
		pr_err("ih_hook: helpers missing (module_alloc=%d ro=%d x=%d)\n",
		       !!pfn_module_alloc, !!pfn_set_memory_ro, !!pfn_set_memory_x);
		return -ENOENT;
	}

	rc = ih_install();
	if (rc) {
		pr_err("ih_hook: install failed %d\n", rc);
		return rc;
	}

	pr_info("ih_hook: armed; hidden path for apps: %s\n", IH_HIDDEN);
	return 0;
}

static void __exit ih_hook_exit(void)
{
	ih_remove();
	pr_info("ih_hook: unloaded\n");
}

module_init(ih_hook_init);
module_exit(ih_hook_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("stage-1 inline hook test (__arm64_sys_openat)");
