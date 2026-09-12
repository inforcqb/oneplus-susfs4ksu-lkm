/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * susfs_fp_hook.c - intercept syscalls by replacing a sys_call_table entry.
 *
 * Why this and not an inline hook
 * -------------------------------
 * sys_call_table[nr] holds a pointer to the kernel's CFI jump-table stub
 * (__arm64_sys_xxx.cfi_jt), and KernelSU reads that very array when it wants the
 * original behaviour (ksu_syscall_table[orig_nr](regs), see ksu_hook_faccessat).
 * Rewriting the instructions of such a wrapper therefore interferes with every
 * other caller of it - measured on this device as an unrecoverable
 *
 *     Internal error: Oops - FPAC: 0000000072000000
 *     pc : __arm64_sys_faccessat+0x2c4/0x848
 *     lr : ksu_hook_faccessat+0x44/0x58 [kernelsu]
 *
 * Replacing the table entry touches data only, so the whole chain stays as the
 * kernel built it:
 *
 *     invoke_syscall()          -> sys_call_table[nr]        (ours)
 *     sys_enter + dispatcher    -> ksu_syscall_table[nr]     (the same array)
 *     ksu_hook_faccessat()      -> our wrapper
 *     our wrapper (not hidden)  -> saved entry -> .cfi_jt stub -> real wrapper
 *
 * Nothing on that path has a rewritten instruction, so BTI, PAC, the CFI jump
 * table and LTO all remain untouched.
 *
 * The write itself reuses the fixmap primitive that the inline hook layer
 * already brought over from KernelSU/SukiSU (phys_from_virt + FIX_TEXT_POKE0 +
 * copy_to_kernel_nofault + stop_machine + d-cache flush): the table is data in
 * .rodata, so only the d-cache needs maintenance - never the i-cache.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <asm/unistd.h>

#include "patch_memory.h"
#include "symbol_resolver.h"
#include "susfs_log.h"
#include "susfs_fp_hook.h"

/* The BTI landing pad of an indirect call target: 'bti c' (an unallocated HINT
 * on cores without BTI, so checking for it is correct either way). */
#define SUSFS_ARM64_BTI_C	0xd503245fu

static susfs_syscall_fn_t *sys_call_table_ptr;

int susfs_fp_init(void)
{
	if (sys_call_table_ptr)
		return 0;

	sys_call_table_ptr = (susfs_syscall_fn_t *)find_kernel_symbol_exact("sys_call_table");
	if (!sys_call_table_ptr) {
		pr_warn("susfs_fp: sys_call_table not found\n");
		return -ENOENT;
	}

	pr_info("susfs_fp: sys_call_table at %px (first entry %px)\n",
		sys_call_table_ptr, (void *)READ_ONCE(sys_call_table_ptr[0]));
	return 0;
}

unsigned long susfs_fp_syscall_table(void)
{
	return (unsigned long)sys_call_table_ptr;
}

void susfs_fp_dump_entry(int nr, const char *sym)
{
	char cfi_name[128];
	unsigned long plain, cfi, resolved;

	if (!sys_call_table_ptr || nr < 0 || nr >= __NR_syscalls) {
		pr_warn("susfs_fp: dump: table %d or nr %d unusable\n", !!sys_call_table_ptr, nr);
		return;
	}

	plain = find_kernel_symbol_exact(sym);
	snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", sym);
	cfi = find_kernel_symbol_exact(cfi_name);
	resolved = (unsigned long)ksu_resolve_symbol_for_functable_hook(sym);

	pr_info("susfs_fp: nr %d table=%px plain=%px cfi_jt=%px resolved=%px -> %s\n",
		nr, (void *)READ_ONCE(sys_call_table_ptr[nr]),
		(void *)plain, (void *)cfi, (void *)resolved,
		(READ_ONCE(sys_call_table_ptr[nr]) == (susfs_syscall_fn_t)cfi) ? "cfi_jt match" :
		((READ_ONCE(sys_call_table_ptr[nr]) == (susfs_syscall_fn_t)plain) ? "plain match" : "neither"));
}

/* An indirect call into us is checked against the target's BTI landing pad, so a
 * wrapper that does not start with 'bti c' would give "Oops - BTI" instead of
 * hiding anything.  The kernel itself is built with
 * -mbranch-protection=pac-ret+leaf+bti; the module's flags are ours to verify,
 * so verify them and refuse to install rather than find out the hard way. */
static bool fp_has_landing_pad(const void *fn)
{
	return READ_ONCE(*(const u32 *)fn) == SUSFS_ARM64_BTI_C;
}

int susfs_fp_install(struct susfs_fp_hook *h)
{
	susfs_syscall_fn_t old;
	int err;

	if (h->installed)
		return 0;
	if (!sys_call_table_ptr) {
		err = susfs_fp_init();
		if (err)
			return err;
	}
	if (h->nr < 0 || h->nr >= __NR_syscalls) {
		pr_warn("susfs_fp: %s: bogus nr %d\n", h->name, h->nr);
		return -EINVAL;
	}
	if (!h->wrapper || !fp_has_landing_pad((const void *)h->wrapper)) {
		pr_warn("susfs_fp: %s does not start with 'bti c' (0x%08x) - not installed\n",
			h->name, h->wrapper ? READ_ONCE(*(const u32 *)h->wrapper) : 0);
		return -EINVAL;
	}

	old = READ_ONCE(sys_call_table_ptr[h->nr]);
	if (!old) {
		pr_warn("susfs_fp: %s: table entry is NULL\n", h->name);
		return -ENOENT;
	}

	err = ksu_patch_text(&sys_call_table_ptr[h->nr], &h->wrapper,
			     sizeof(h->wrapper), KSU_PATCH_TEXT_FLUSH_DCACHE);
	if (err) {
		pr_warn("susfs_fp: %s: write failed %d\n", h->name, err);
		return err;
	}
	if (READ_ONCE(sys_call_table_ptr[h->nr]) != h->wrapper) {
		/* A half-written pointer is worse than none: put the old one back. */
		ksu_patch_text(&sys_call_table_ptr[h->nr], &old,
			       sizeof(old), KSU_PATCH_TEXT_FLUSH_DCACHE);
		pr_warn("susfs_fp: %s: write did not stick, rolled back\n", h->name);
		return -EIO;
	}

	/* Published only after the table is live, and with a barrier so the wrapper
	 * cannot read a stale slot. */
	h->orig = old;
	if (h->orig_slot)
		WRITE_ONCE(*h->orig_slot, old);
	h->installed = true;

	pr_info("susfs_fp: nr %d (%s) armed: table=%px -> %px, original %px\n",
		h->nr, h->name, (void *)&sys_call_table_ptr[h->nr],
		(void *)h->wrapper, (void *)old);
	return 0;
}

void susfs_fp_remove(struct susfs_fp_hook *h)
{
	int err;

	if (!h->installed || !sys_call_table_ptr)
		return;

	if (READ_ONCE(sys_call_table_ptr[h->nr]) != h->wrapper) {
		pr_warn("susfs_fp: nr %d is not ours any more, leaving it alone\n", h->nr);
		h->installed = false;
		return;
	}

	if (h->orig_slot)
		WRITE_ONCE(*h->orig_slot, NULL);

	err = ksu_patch_text(&sys_call_table_ptr[h->nr], &h->orig,
			     sizeof(h->orig), KSU_PATCH_TEXT_FLUSH_DCACHE);
	if (err)
		pr_warn("susfs_fp: nr %d restore failed %d\n", h->nr, err);
	else
		pr_info("susfs_fp: nr %d (%s) disarmed, entry %px restored\n",
			h->nr, h->name, (void *)h->orig);

	h->installed = false;
}
