// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_hide_syms.c - hide ksu/susfs symbols from /proc/kallsyms
 * (SUSFS HIDE_KSU_SUSFS_SYMBOLS feature), LKM port.
 *
 * Upstream SUSFS patches kernel/kallsyms.c s_show() to skip symbols whose name
 * starts with ksu_/__ksu_/susfs_/ksud/...  s_show is static but referenced by
 * the kallsyms_op.show seq_operations function pointer, so LTO keeps an
 * out-of-line copy and we can kprobe it.
 *
 * s_show(m, p): iter = m->private (struct kallsym_iter).  On a matching name
 * prefix we return early (regs->regs[0] = 0, regs->pc = x30) so the line is
 * never printed — this covers BOTH core-kernel and module symbols, because we
 * skip the whole function body before it branches on module_name.
 *
 * Unlike most features this is on-by-default like upstream (it is a build-time
 * CONFIG there, no runtime toggle).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include "susfs_log.h"
#include "symbol_resolver.h"	/* find_kernel_symbol_exact (kallsyms_op) */

/* local mirror of kernel/kallsyms.c struct kallsym_iter (layout is KMI-frozen);
 * only the name field matters here. */
struct kallsym_iter_local {
	loff_t pos;
	loff_t pos_arch_end;
	loff_t pos_mod_end;
	loff_t pos_ftrace_mod_end;
	loff_t pos_bpf_end;
	unsigned long value;
	unsigned int nameoff;
	char type;
	char name[KSYM_NAME_LEN];
	char module_name[MODULE_NAME_LEN];
	int exported;
	int show_value;
};

/* prefixes to hide (matches upstream's list) */
static const char *const hide_prefixes[] = {
	"ksu_", "__ksu_", "susfs_", "susfs_guard_lkm", "ksud",
	"is_ksu_", "is_manager_", "escape_to_", "setup_selinux",
	"track_throne", "on_post_fs_data", "try_umount", "kernelsu",
	"__initcall__kmod_kernelsu", "apply_kernelsu", "handle_sepolicy",
	"getenforce", "setenforce", "is_zygote",
};

static bool name_should_hide(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hide_prefixes); i++)
		if (!strncmp(name, hide_prefixes[i], strlen(hide_prefixes[i])))
			return true;
	return false;
}

static atomic_t hide_hit_count = ATOMIC_INIT(0);
static atomic_t hide_enter_count = ATOMIC_INIT(0);

/* s_show(m, p): m is arg #1 (regs->regs[0]) */
static int hide_syms_s_show_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct kallsym_iter_local *iter;

	atomic_inc(&hide_enter_count);
	if (!m || !m->private)
		return 0;
	iter = (struct kallsym_iter_local *)m->private;
	if (!iter->name[0])
		return 0;

	/* hide by name prefix OR by our module name (module symbols carry the
	 * real name like __kstrtab_susfs_xxx, with susfs_guard_lkm in module_name) */
	if (name_should_hide(iter->name) ||
	    !strcmp(iter->module_name, "susfs_guard_lkm")) {
		atomic_inc(&hide_hit_count);
		regs->regs[0] = 0;              /* s_show returns 0 */
		regs->pc = regs->regs[30];      /* skip the line */
		return 1;
	}
	return 0;
}

/* Registered by ADDRESS, not by name.
 *
 * This tree has CONFIG_KALLSYMS_ALL=y and FULL LTO, and there are three
 * different `s_show` functions: kernel/kallsyms.c:741 (the one we want),
 * kernel/trace/trace.c:4654 and mm/vmalloc.c:4052.  A kprobe registered with
 * .symbol_name gets whichever one kallsyms happens to list first, and the
 * handler above would then read a struct trace_iterator / vmap_area as if it
 * were struct kallsym_iter - reading inside someone else's allocation, and
 * silently failing to hide anything.
 *
 * kallsyms_op is the seq_operations table (a data symbol, again thanks to
 * KALLSYMS_ALL) whose .show is exactly the function kallsyms actually calls, so
 * take the address from the table itself. */
static struct kprobe kp_s_show = {
	.pre_handler = hide_syms_s_show_pre,
};

static unsigned long hide_syms_target(void)
{
	const struct seq_operations *op;
	unsigned long addr = find_kernel_symbol_exact("kallsyms_op");

	if (!addr)
		return 0;
	op = (const struct seq_operations *)addr;
	return (unsigned long)op->show;
}

static bool hide_registered;

int susfs_hide_syms_init(void)
{
	int rc;
	unsigned long fn = hide_syms_target();

	if (!fn) {
		pr_warn("susfs_hide_syms: kallsyms_op.show not found, not armed\n");
		return -ENOENT;
	}

	kp_s_show.addr = (kprobe_opcode_t *)fn;
	rc = register_kprobe(&kp_s_show);
	if (rc) {
		pr_warn("susfs_hide_syms: register_kprobe(%px) failed %d\n",
			(void *)fn, rc);
		return rc;
	}
	hide_registered = true;
	pr_info("susfs_hide_syms: armed (kallsyms_op.show=%px)\n", (void *)fn);
	return 0;
}

bool susfs_hide_syms_active(void)
{
	return hide_registered;
}

void susfs_hide_syms_exit(void)
{
	if (hide_registered) {
		unregister_kprobe(&kp_s_show);
		hide_registered = false;
	}
	pr_info("susfs_hide_syms: exit enter=%d hit=%d\n",
		atomic_read(&hide_enter_count), atomic_read(&hide_hit_count));
}
