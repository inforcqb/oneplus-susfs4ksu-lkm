// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_inline_hook.c - patch an entry point so it jumps into our stub.
 *
 * Ported from the stage-1 test module (kernel/ih_hook_main.c), where every step
 * below was measured on the target kernel; see INLINE_HOOK.md for the reasoning
 * and for the four faults that were hit on the way.
 *
 * Shape of a hook:
 *
 *   entry:  bti c                 landing pad kept - the syscall table and
 *           b <stub>              .cfi_jt reach these entries indirectly
 *   stub:   save x0-x18, x30 -> bl decide -> restore
 *           hit:   x0 = -ENOENT ; ret
 *           allow: ret x16 -> trampoline
 *   tramp:  bti c ; <orig[0]> ; <orig[1]> ; ldr x16,#8 ; ret x16 ; entry+8
 *
 * The two exits use `ret`, which is exempt from the BTI check, and the
 * trampoline carries its own `bti c` as well, because the instruction it replays
 * is a landing pad only by accident (paciasp is, stp is not).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <asm/cacheflush.h>
#include "patch_memory.h"
#include "symbol_resolver.h"
#include "susfs_log.h"
#include "susfs_inline_hook.h"

#define IH_TRAMP_SIZE	64

static void *(*pfn_module_alloc)(unsigned long size);
static int (*pfn_set_memory_ro)(unsigned long addr, int numpages);
static int (*pfn_set_memory_rw)(unsigned long addr, int numpages);
static int (*pfn_set_memory_x)(unsigned long addr, int numpages);
static int (*pfn_smp_call_function)(void (*func)(void *), void *info, int wait);
static void (*pfn_sync_rcu_tasks)(void);

/* The cross-CPU flush is part of the contract, not a bonus: without it only the
 * patching CPU would drop its stale I-cache lines and the other cores would keep
 * running the old - or a half-updated - instruction stream.  A missing helper
 * must fail the install instead of silently degrading.
 *
 * Note the symbol: on_each_cpu() is a static inline wrapper in 5.15's smp.h, so
 * it is NOT in kallsyms - resolving it always failed, which is exactly how this
 * flush spent a release doing nothing.  smp_call_function() is a real exported
 * function and runs the callback on every other CPU; this CPU is handled
 * directly by the caller. */
bool susfs_ih_ready(void)
{
	return pfn_module_alloc && pfn_set_memory_ro && pfn_set_memory_rw &&
	       pfn_set_memory_x && pfn_smp_call_function;
}

/* __nocfi on every function that reaches a resolved kernel symbol through a
 * function pointer: kCFI checks the type hash at such a call site and panics
 * with "CFI failure" otherwise. */
static __nocfi int susfs_ih_init_impl(void)
{
	pfn_module_alloc = (void *)find_kernel_symbol_exact("module_alloc");
	pfn_set_memory_ro = (void *)find_kernel_symbol_exact("set_memory_ro");
	pfn_set_memory_rw = (void *)find_kernel_symbol_exact("set_memory_rw");
	pfn_set_memory_x = (void *)find_kernel_symbol_exact("set_memory_x");
	pfn_smp_call_function = (void *)find_kernel_symbol_exact("smp_call_function");
	pfn_sync_rcu_tasks = (void *)find_kernel_symbol_exact("synchronize_rcu_tasks");

	if (!susfs_ih_ready()) {
		pr_warn("susfs_ih: helpers missing (alloc=%d ro=%d rw=%d x=%d call_fn=%d)\n",
			!!pfn_module_alloc, !!pfn_set_memory_ro,
			!!pfn_set_memory_rw, !!pfn_set_memory_x,
			!!pfn_smp_call_function);
		return -ENOENT;
	}
	return 0;
}

int susfs_ih_init(void)
{
	return susfs_ih_init_impl();
}

/* The range travels in the info pointer rather than in globals: two installs can
 * be in flight at once (one per entry) and globals would let them overwrite each
 * other's range. */
struct ih_flush_range {
	unsigned long lo, hi;
};

/* ksu_patch_text only flushes the CPU that ran it, which is fine for the data it
 * was written for (hook-table pointers) but not for code: another core can keep
 * executing the old or a half-updated instruction stream.  Every core now flushes
 * for itself after the write. */
static void susfs_ih_remote_flush(void *info)
{
	const struct ih_flush_range *r = info;

	caches_clean_inval_pou(r->lo, r->hi);
	isb();
}

/* __nocfi for the same reason as susfs_ih_init_impl(): this calls a resolved
 * kernel symbol through a function pointer, and kCFI validates the type hash at
 * that call site - without it the very first flush panics with
 * "CFI failure (target: smp_call_function)". */
static __nocfi void susfs_ih_flush_range_remote(unsigned long lo, unsigned long hi)
{
	struct ih_flush_range r = { lo, hi };

	if (!pfn_smp_call_function)
		return;
	pfn_smp_call_function(susfs_ih_remote_flush, &r, 1);
	susfs_ih_remote_flush(&r);	/* smp_call_function skips this CPU */
}

static void susfs_ih_flush_icache(void *addr, unsigned long len)
{
#if KSU_NEW_DCACHE_FLUSH
	caches_clean_inval_pou((unsigned long)addr, (unsigned long)addr + len);
#else
	__flush_icache_range((unsigned long)addr, (unsigned long)addr + len);
#endif
}

/* Overwriting two instructions must not swallow a PC-relative one: those cannot
 * be replayed verbatim from the trampoline.  A BRK means somebody else already
 * owns this entry (a kprobe, a livepatch): patching it would be overwritten by
 * their restore and vice versa. */
static bool susfs_ih_sane_prologue(const u32 *insn)
{
	int i;

	for (i = 0; i < 2; i++) {
		if ((insn[i] & 0xffe0001fu) == 0xd4200000u)	/* brk #imm */
			return false;
		if ((insn[i] & 0x1f000000u) == 0x10000000u)	/* adr/adrp */
			return false;
		if ((insn[i] & 0x3b000000u) == 0x18000000u)	/* ldr lit  */
			return false;
		if ((insn[i] & 0x7c000000u) == 0x14000000u)	/* b/bl     */
			return false;
		if ((insn[i] & 0xff000010u) == 0x54000000u)	/* b.cond   */
			return false;
		if ((insn[i] & 0x7f000000u) == 0x34000000u)	/* cbz/cbnz */
			return false;
		if ((insn[i] & 0x7f000000u) == 0x36000000u)	/* tbz/tbnz */
			return false;
	}
	return true;
}

static __nocfi void *susfs_ih_build_tramp(unsigned long entry, const u32 *orig)
{
	u32 *tr = pfn_module_alloc(IH_TRAMP_SIZE);

	if (!tr)
		return NULL;

	tr[0] = 0xd503245fu;			/* bti c                */
	tr[1] = orig[0];
	tr[2] = orig[1];
	tr[3] = 0x58000050u;			/* ldr x16, #8          */
	tr[4] = 0xd65f0200u;			/* ret x16 (BTI-exempt) */
	*(u64 *)(tr + 5) = entry + 8;		/* -> entry + 8         */

	susfs_ih_flush_icache(tr, IH_TRAMP_SIZE);
	/* module_alloc() can hand back an address some other core still has stale
	 * I-cache lines for, so this page has to be flushed everywhere too. */
	susfs_ih_flush_range_remote((unsigned long)tr,
				    (unsigned long)tr + IH_TRAMP_SIZE);

	if (pfn_set_memory_ro((unsigned long)tr, 1) ||
	    pfn_set_memory_x((unsigned long)tr, 1)) {
		pr_err("susfs_ih: cannot seal trampoline %px executable\n", tr);
		vfree(tr);
		return NULL;
	}
	return tr;
}

static __nocfi int susfs_ih_write(unsigned long entry, const void *src,
				  size_t len, bool core_text)
{
	if (core_text) {
		int rc = ksu_patch_text((void *)entry, (void *)src, len,
					KSU_PATCH_TEXT_FLUSH_ICACHE |
					KSU_PATCH_TEXT_FLUSH_DCACHE);

		if (!rc) {
			/* smp_call_function() runs the callback on the other CPUs
			 * in IRQ context, where the range has to come from the
			 * info pointer. */
			susfs_ih_flush_range_remote(entry, entry + len);
		}
		return rc;
	}

	/* Our own module text: read-only, so unlock, write, re-lock. */
	if (pfn_set_memory_rw(entry & PAGE_MASK, 1))
		return -EPERM;
	memcpy((void *)entry, src, len);
	susfs_ih_flush_icache((void *)entry, len);
	if (pfn_set_memory_ro(entry & PAGE_MASK, 1))
		return -EPERM;
	return 0;
}

static __nocfi int susfs_ih_install_impl(struct susfs_ih_hook *h,
					 const char *sym, void *stub,
					 u64 *tramp_var)
{
	u32 patch[2];
	long delta;

	if (!susfs_ih_ready())
		return -ENODEV;

	h->entry = find_kernel_symbol_exact(sym);
	if (!h->entry) {
		pr_warn("susfs_ih: %s not found\n", sym);
		return -ENOENT;
	}

	/* ksu_patch_text goes through a single fixmap page, so an 8-byte write that
	 * straddles a page boundary would land half in the next slot and fail with
	 * the first four bytes (the `bti c`) already committed - the entry would
	 * lose its prologue and never be restored.  Refuse such an entry. */
	if (((h->entry & (PAGE_SIZE - 1)) + sizeof(u32[2])) > PAGE_SIZE) {
		pr_err("susfs_ih: %s entry straddles a page boundary\n", sym);
		return -ERANGE;
	}

	memcpy(h->orig, (void *)h->entry, sizeof(h->orig));

	if (!susfs_ih_sane_prologue(h->orig)) {
		pr_err("susfs_ih: %s prologue not replayable: %08x %08x\n", sym,
		       h->orig[0], h->orig[1]);
		return -EPERM;
	}

	delta = (long)(unsigned long)stub - (long)(h->entry + 4);
	if (delta < -(124L << 20) || delta > (124L << 20)) {
		pr_err("susfs_ih: %s stub is %ldMB away, outside B's reach\n",
		       sym, delta >> 20);
		return -ERANGE;
	}

	h->tramp = susfs_ih_build_tramp(h->entry, h->orig);
	if (!h->tramp)
		return -ENOMEM;
	h->tramp_var = tramp_var;
	if (tramp_var)
		*tramp_var = (u64)(unsigned long)h->tramp;

	patch[0] = 0xd503245fu;					/* bti c */
	patch[1] = 0x14000000u | (((u32)(delta >> 2)) & 0x03ffffffu);

	if (susfs_ih_write(h->entry, patch, sizeof(patch), true)) {
		pr_err("susfs_ih: could not patch %s\n", sym);
		/* A partially committed write may have left the entry inconsistent
		 * (the first word is written separately from the second), so put the
		 * original instructions back.  Do NOT clear *tramp_var and do NOT
		 * free the trampoline: if even one byte of the branch landed, some
		 * core may already be inside the stub and needs both. */
		susfs_ih_write(h->entry, h->orig, sizeof(h->orig), true);
		return -EIO;
	}

	h->installed = true;
	pr_info("susfs_ih: hooked %s (entry %px tramp %px)\n", sym,
		(void *)h->entry, h->tramp);
	return 0;
}

int susfs_ih_install(struct susfs_ih_hook *h, const char *sym, void *stub,
		     u64 *tramp_var)
{
	return susfs_ih_install_impl(h, sym, stub, tramp_var);
}

static __nocfi void susfs_ih_uninstall_impl(struct susfs_ih_hook *h)
{
	if (!h->installed)
		return;

	if (susfs_ih_write(h->entry, h->orig, sizeof(h->orig), true))
		pr_err("susfs_ih: could not restore %px\n", (void *)h->entry);
	else
		pr_info("susfs_ih: restored %px\n", (void *)h->entry);

	h->installed = false;

	/*
	 * Restoring the entry only stops NEW calls from reaching the stub; a core
	 * that is already inside it is still there, and it will read its
	 * trampoline pointer after the decision function returns - so:
	 *
	 *  - *tramp_var must stay valid (the trampoline is retired, never freed),
	 *    otherwise an in-flight stub loads 0 and branches to it;
	 *  - the stub itself lives in this module's text, which is about to be
	 *    unmapped, so wait for in-flight executions to drain first.
	 */
	if (pfn_sync_rcu_tasks)
		pfn_sync_rcu_tasks();
	else
		msleep(50);

	h->tramp = NULL;	/* retired, not freed */
}

void susfs_ih_uninstall(struct susfs_ih_hook *h)
{
	susfs_ih_uninstall_impl(h);
}
