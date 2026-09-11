// SPDX-License-Identifier: GPL-2.0
/*
 * ih_probe_test.c - stage 0 of the inline-hook plan: report whether a given
 * kernel entry point can be patched at all.
 *
 * It patches NOTHING.  For each candidate it reads the first instructions,
 * classifies them by hand (the kernel's aarch64_insn_is_* helpers are not
 * exported) and prints:
 *
 *   - the first 6 instruction words, so the prologue can be recognised;
 *   - whether instruction 0 is a BTI landing pad and/or PAC prologue: a patched
 *     entry that is reached by an indirect branch (the syscall table, .cfi_jt)
 *     must keep its landing pad;
 *   - whether any instruction inside the window we would overwrite is
 *     PC-relative (ADR/ADRP/LDR-literal/B/B.cond/CBZ/TBZ).  Those cannot be
 *     copied into a trampoline verbatim, which is what makes an entry
 *     unpatchable at a fixed window size;
 *   - whether the entry already holds a BRK, i.e. a kprobe or livepatch has
 *     claimed it;
 *   - the distance to this module's own text, because a direct B only reaches
 *     +/-128MB and anything further has to go through `ret`.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include "symbol_resolver.h"

/* ---- instruction classification (masks from arch/arm64/kernel/insn.c) ---- */
#define IH_MASK_ADR_ADRP	0x1f000000u
#define IH_VAL_ADR_ADRP		0x10000000u
#define IH_MASK_LDR_LIT		0x3b000000u
#define IH_VAL_LDR_LIT		0x18000000u
#define IH_MASK_B_BL		0x7c000000u
#define IH_VAL_B_BL		0x14000000u
#define IH_MASK_B_COND		0xff000010u
#define IH_VAL_B_COND		0x54000000u
#define IH_MASK_CBZ_CBNZ	0x7f000000u
#define IH_VAL_CBZ_CBNZ		0x34000000u
#define IH_MASK_TBZ_TBNZ	0x7f000000u
#define IH_VAL_TBZ_TBNZ		0x36000000u
#define IH_MASK_BRK		0xffe0001fu
#define IH_VAL_BRK		0xd4200000u

static bool is_pc_relative(u32 insn)
{
	return ((insn & IH_MASK_ADR_ADRP) == IH_VAL_ADR_ADRP) ||
	       ((insn & IH_MASK_LDR_LIT) == IH_VAL_LDR_LIT) ||
	       ((insn & IH_MASK_B_BL) == IH_VAL_B_BL) ||
	       ((insn & IH_MASK_B_COND) == IH_VAL_B_COND) ||
	       ((insn & IH_MASK_CBZ_CBNZ) == IH_VAL_CBZ_CBNZ) ||
	       ((insn & IH_MASK_TBZ_TBNZ) == IH_VAL_TBZ_TBNZ);
}

static const char *landing_pad_name(u32 insn)
{
	if (insn == 0xd503245fu)
		return "bti c";
	if (insn == 0xd503233fu)
		return "paciasp";
	if (insn == 0xd503237fu)
		return "pacibsp";
	if ((insn & 0xfffff01fu) == 0xd503201fu)
		return "bti/hint";
	return NULL;
}

#define IH_WINDOW 20

static void inspect(const char *name)
{
	unsigned long addr = find_kernel_symbol_exact(name);
	u32 insn[6];
	long delta;
	const char *pad;
	int i, pc_rel_at = -1;

	if (!addr) {
		pr_info("ih_probe: %-26s NOT FOUND\n", name);
		return;
	}

	memcpy(insn, (void *)addr, sizeof(insn));
	pad = landing_pad_name(insn[0]);

	for (i = 0; i < IH_WINDOW / 4; i++) {
		if (is_pc_relative(insn[i])) {
			pc_rel_at = i * 4;
			break;
		}
	}

	delta = (long)addr - (long)(unsigned long)inspect;

	pr_info("ih_probe: %-26s @ %px  %08x %08x %08x %08x %08x %08x\n",
		name, (void *)addr, insn[0], insn[1], insn[2], insn[3], insn[4],
		insn[5]);
	pr_info("ih_probe:   pad=%-6s delta_from_module=%ldMB pc_rel=%d brk=%d -> %s\n",
		pad ? pad : "none", delta / (1024 * 1024), pc_rel_at,
		(insn[0] & IH_MASK_BRK) == IH_VAL_BRK,
		(insn[0] & IH_MASK_BRK) == IH_VAL_BRK ? "CLAIMED" :
		(pc_rel_at >= 0 ? "UNSAFE(pc-rel)" : "PATCHABLE"));
}

static const char *const targets[] = {
	"__arm64_sys_openat",
	"__arm64_sys_openat2",
	"__arm64_sys_newfstatat",
	"__arm64_sys_statx",
	"__arm64_sys_faccessat",
	"__arm64_sys_faccessat2",
	"__arm64_sys_readlinkat",
	"__arm64_sys_execve",
	"__arm64_sys_getdents64",
	"__arm64_compat_sys_openat",
	"__arm64_compat_sys_execve",
	"getname",
	"getname_flags",
	"filename_lookup",
	"do_filp_open",
	"user_path_at_empty",
	"vfs_getattr",
	"vfs_open",
	"show_map_vma",
	"generic_permission",
	"inode_permission",
};

static int __init ih_init(void)
{
	int i;

	pr_info("ih_probe: inline-hook feasibility check (patches nothing)\n");
	ksu_init_symbol_resolver();

	pr_info("ih_probe: helper set_memory_rw=%d set_memory_ro=%d set_memory_x=%d\n",
		find_kernel_symbol_exact("set_memory_rw") ? 1 : 0,
		find_kernel_symbol_exact("set_memory_ro") ? 1 : 0,
		find_kernel_symbol_exact("set_memory_x") ? 1 : 0);
	pr_info("ih_probe: helper module_alloc=%d text_poke=%d aarch64_insn_patch_text=%d\n",
		find_kernel_symbol_exact("module_alloc") ? 1 : 0,
		find_kernel_symbol_exact("text_poke") ? 1 : 0,
		find_kernel_symbol_exact("aarch64_insn_patch_text") ? 1 : 0);
	pr_info("ih_probe: module text at %px\n", (void *)ih_init);

	for (i = 0; i < ARRAY_SIZE(targets); i++)
		inspect(targets[i]);

	pr_info("ih_probe: done\n");
	return 0;
}

static void __exit ih_exit(void)
{
	pr_info("ih_probe: unloaded\n");
}

module_init(ih_init);
module_exit(ih_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("inline-hook feasibility probe (read-only)");
