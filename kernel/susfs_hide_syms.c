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
#include <linux/proc_fs.h>	/* the runtime control node */
#include <linux/cred.h>		/* current_uid() */
#include "susfs_log.h"
#include "susfs.h"		/* sus_path_add_self_hidden / sus_path_del_path */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact (kallsyms_op) */

/* ---- hide_modules: filter other kernel modules out of /proc/modules ----
 *
 * /proc/modules is world-readable (0444) and lists every loaded module by name, so a
 * checker that greps it sees the whole set - including whichever module is doing the
 * hiding.  This feature keeps a list of module NAMES and removes them from:
 *
 *   1. /proc/modules - the m_show() line, for EVERY reader, root included.  A checker
 *      may well run as root, and this listing is what it compares against; the counter
 *      in the node below shows the filter is running.
 *   2. /sys/module/<name> - registered in sus_path with self_protect, so stat/open/
 *      readdir of that path answer ENOENT for every non-root caller.  Root keeps
 *      access (that is where a module's parameters live), which is the one asymmetry
 *      to know about: a root checker can still list /sys/module.
 *   3. /proc/kallsyms lines whose module_name matches (also for every reader).
 *
 * Control surface, two frontends over one list:
 *
 *   /proc/susfs_hide_modules       (write, root only, ENOENT for everyone else)
 *       add <name> | del <name> | clear | <name> [<name> ...]
 *   .../parameters/hide_modules    (same commands; settable at insmod time)
 *
 * The node follows the house pattern of this module's other control nodes: 0777 so
 * that DAC passes and sus_path's hidden set is the only thing that answers - ENOENT,
 * which is indistinguishable from "no such file" - plus a uid check in open() AND
 * write() so a passed-on fd is not a way in.
 *
 * The default list holds just this module: a built-in SUSFS has no module entry, so
 * leaving one behind would be a trace upstream does not have.  `clear` is the
 * debugging mode (`lsmod` lists us again).
 *
 * Not a new CMD_SUSFS_* command: the command space is shared with KernelSU's own copy
 * of SUSFS and a new id there is a compatibility risk that buys nothing here. */
#define HIDE_MODULES_MAX 16
#define HIDE_MODULES_CMDLINE (HIDE_MODULES_MAX * (MODULE_NAME_LEN + 1) + 96)

static char hide_modules[HIDE_MODULES_MAX][MODULE_NAME_LEN];
static char hide_modules_applied[HIDE_MODULES_MAX][MODULE_NAME_LEN];	/* sysfs rules live */
static int n_hide_modules;
static int n_hide_modules_applied;
static DEFINE_SPINLOCK(hide_modules_lock);

static atomic_t n_modlines_skipped = ATOMIC_INIT(0);	/* /proc/modules lines removed */
static atomic_t n_kallsyms_mod_skipped = ATOMIC_INIT(0);	/* kallsyms lines of those modules */
static atomic_t n_sysfs_rules_added = ATOMIC_INIT(0);
static atomic_t n_sysfs_rules_failed = ATOMIC_INIT(0);

/* Interrupt/kprobe safe: no allocation, no sleeping - both callers are probe handlers
 * and the list is only ever swapped by the two process-context frontends below. */
static bool hide_module_name_match(const char *name)
{
	unsigned long flags;
	bool hit = false;
	int i;

	if (!name || !name[0])
		return false;

	spin_lock_irqsave(&hide_modules_lock, flags);
	for (i = 0; i < n_hide_modules; i++) {
		if (!strcmp(hide_modules[i], name)) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&hide_modules_lock, flags);
	return hit;
}

bool susfs_hide_modules_active(void)
{
	return n_hide_modules > 0;
}

/* Reconcile the /sys/module/<name> rules with the list: every name that gained an
 * entry gets one, every name that lost one loses it.  Process context (kern_path and
 * iput inside sus_path). */
static void hide_modules_sync_sysfs(void)
{
	char path[64];
	int i;

	/* Drop what is no longer listed.  sus_path_del_path() is a no-op for a name that
	 * was never registered, so this is safe even after a failed add. */
	for (i = 0; i < n_hide_modules_applied; i++) {
		snprintf(path, sizeof(path), "/sys/module/%s", hide_modules_applied[i]);
		sus_path_del_path(path);
	}
	n_hide_modules_applied = 0;

	for (i = 0; i < n_hide_modules; i++) {
		int rc;

		snprintf(path, sizeof(path), "/sys/module/%s", hide_modules[i]);
		rc = sus_path_add_self_hidden(path);
		if (rc) {
			/* Not fatal: the /proc/modules line is filtered by the probe whether or
			 * not the module has a sysfs directory, and a module that is not loaded
			 * yet has none (-ENOENT).  Counted, and named here, so "listed but
			 * /sys/module is not hidden" is visible instead of assumed. */
			atomic_inc(&n_sysfs_rules_failed);
			SUSFS_LOGI("hide_modules: %s: no sus_path rule (%d%s)\n", path, rc,
				rc == -ENOENT ? " - not loaded, so its sysfs directory does not exist yet" : "");
			continue;
		}
		strscpy(hide_modules_applied[n_hide_modules_applied++],
			hide_modules[i], MODULE_NAME_LEN);
		atomic_inc(&n_sysfs_rules_added);
	}
}

/* Parse @val into @dst and return the count, or a negative errno.  Separators are
 * spaces, commas and tabs, so both the insmod form (hide_modules=a,b) and the /proc
 * form (a b) work. */
static int hide_modules_parse(const char *val, char dst[][MODULE_NAME_LEN], int max)
{
	char buf[HIDE_MODULES_CMDLINE];
	const char *p;
	int n = 0;

	strscpy(buf, val, sizeof(buf));
	p = buf;
	while (*p) {
		char *tok = (char *)p;
		int len;

		while (*p == ' ' || *p == ',' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (!*p)
			break;
		tok = (char *)p;
		while (*p && *p != ' ' && *p != ',' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		len = (int)(p - tok);
		if (len <= 0)
			continue;
		if (len >= MODULE_NAME_LEN)
			return -ENAMETOOLONG;	/* longer than any module name */
		if (n >= max)
			return -ENOSPC;
		memcpy(dst[n], tok, len);
		dst[n][len] = '\0';
		n++;
	}
	return n;
}

static void hide_modules_commit(char dst[][MODULE_NAME_LEN], int n)
{
	unsigned long flags;

	spin_lock_irqsave(&hide_modules_lock, flags);
	memset(hide_modules, 0, sizeof(hide_modules));
	memcpy(hide_modules, dst, (size_t)n * MODULE_NAME_LEN);
	n_hide_modules = n;
	spin_unlock_irqrestore(&hide_modules_lock, flags);
}

/* One implementation for both frontends.
 *
 * Commands: `clear`, `add <name>`, `del <name>`, `set <name> [<name>...]`.
 *
 * @bare_list is the one difference between the frontends: insmod hands the parameter
 * a bare value (`hide_modules=a,b`), so its setter accepts a command-less list.  The
 * /proc node does NOT: a typo there would otherwise silently *replace* the list with
 * whatever was typed - measured during the first device test, where a deliberately
 * bogus command discarded the list and the next read showed a name nobody meant. */
static int hide_modules_command(const char *val, bool bare_list)
{
	char cmd[HIDE_MODULES_CMDLINE];
	char staged[HIDE_MODULES_MAX][MODULE_NAME_LEN];
	const char *arg;
	int i, n;

	strscpy(cmd, val, sizeof(cmd));
	for (i = (int)strlen(cmd) - 1; i >= 0 && (cmd[i] == '\n' || cmd[i] == '\r' || cmd[i] == ' '); i--)
		cmd[i] = '\0';

	if (!strcmp(cmd, "clear")) {
		hide_modules_commit(staged, 0);
		hide_modules_sync_sysfs();
		SUSFS_LOGI("hide_modules: list cleared (no module is filtered)\n");
		return 0;
	}

	if (!strncmp(cmd, "set ", 4)) {
		n = hide_modules_parse(cmd + 4, staged, HIDE_MODULES_MAX);
		if (n < 0)
			return n;
		hide_modules_commit(staged, n);
		hide_modules_sync_sysfs();
		SUSFS_LOGI("hide_modules: list set to %d name(s)\n", n);
		return 0;
	}

	if (!strncmp(cmd, "add ", 4) || !strncmp(cmd, "del ", 4)) {
		bool adding = (cmd[0] == 'a');

		arg = cmd + 4;
		while (*arg == ' ')
			arg++;
		if (!*arg || strlen(arg) >= MODULE_NAME_LEN)
			return -EINVAL;

		/* Rebuild from the current list: one entry added or dropped. */
		spin_lock(&hide_modules_lock);
		n = n_hide_modules;
		if (n > HIDE_MODULES_MAX)
			n = HIDE_MODULES_MAX;
		memcpy(staged, hide_modules, (size_t)n * MODULE_NAME_LEN);
		spin_unlock(&hide_modules_lock);

		/* `found` is kept separate from `i` on purpose: after a del the index and
		 * the new count coincide whenever the removed entry was the last one, and
		 * reusing `i` for both questions answered -ENOENT for a name that was
		 * right there (measured: `del <last entry>` always failed). */
		{
			bool found = false;

			for (i = 0; i < n; i++) {
				if (strcmp(staged[i], arg))
					continue;
				found = true;
				if (adding)
					return 0;		/* already listed */
				memmove(&staged[i], &staged[i + 1],
					(size_t)(n - i - 1) * MODULE_NAME_LEN);
				n--;
				break;
			}
			if (adding) {
				if (found)
					return 0;
				if (n >= HIDE_MODULES_MAX)
					return -ENOSPC;
				strscpy(staged[n], arg, MODULE_NAME_LEN);
				n++;
			} else if (!found) {
				return -ENOENT;			/* not listed */
			}
		}
		hide_modules_commit(staged, n);
		hide_modules_sync_sysfs();
		SUSFS_LOGI("hide_modules: %s %s -> %d name(s) filtered\n",
			adding ? "add" : "del", arg, n);
		return 0;
	}

	if (!bare_list)
		return -EINVAL;

	n = hide_modules_parse(cmd, staged, HIDE_MODULES_MAX);
	if (n < 0)
		return n;
	hide_modules_commit(staged, n);
	hide_modules_sync_sysfs();
	SUSFS_LOGI("hide_modules: list set to %d name(s)\n", n);
	return 0;
}

static int hide_modules_format(char *buf, size_t size)
{
	int n = 0;
	int i;

	n += scnprintf(buf + n, size - n,
		"hide_modules: %d/%d name(s), /sys/module rules=%d (failed=%d), "
		"/proc/modules lines removed=%d, kallsyms lines removed=%d\n",
		n_hide_modules, HIDE_MODULES_MAX, n_hide_modules_applied,
		atomic_read(&n_sysfs_rules_failed),
		atomic_read(&n_modlines_skipped), atomic_read(&n_kallsyms_mod_skipped));
	n += scnprintf(buf + n, size - n, "names:");
	for (i = 0; i < n_hide_modules && n < (int)size - 64; i++)
		n += scnprintf(buf + n, size - n, " %s", hide_modules[i]);
	n += scnprintf(buf + n, size - n, "\n");
	return n;
}

/* ---- the two frontends ---- */

static int hide_modules_param_set(const char *val, const struct kernel_param *kp)
{
	/* insmod passes a bare value, so the parameter accepts a command-less list. */
	return hide_modules_command(val, true);
}

static int hide_modules_param_get(char *buf, const struct kernel_param *kp)
{
	return hide_modules_format(buf, PAGE_SIZE);
}

static const struct kernel_param_ops hide_modules_ops = {
	.get = hide_modules_param_get,
	.set = hide_modules_param_set,
};
/* 0600: root reads and writes it, and the whole directory is inside the one the
 * hide_modules feature hides from everyone else. */
module_param_cb(hide_modules, &hide_modules_ops, NULL, 0600);

static int hide_modules_proc_show(struct seq_file *m, void *v)
{
	char buf[512];

	hide_modules_format(buf, sizeof(buf));
	seq_puts(m, buf);
	return 0;
}

static int hide_modules_proc_open(struct inode *inode, struct file *file)
{
	/* 0777 node + this check, exactly like the other control nodes: a restrictive
	 * mode would answer EACCES (which advertises that the node exists) before
	 * sus_path could answer ENOENT. */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, hide_modules_proc_show, NULL);
}

static ssize_t hide_modules_proc_write(struct file *file, const char __user *buf,
				       size_t len, loff_t *off)
{
	char cmd[HIDE_MODULES_CMDLINE];
	int rc;

	/* Same reason as the open check: an fd opened before the process dropped
	 * privileges must not become a way in. */
	if (current_uid().val != 0)
		return -ENOENT;
	if (len == 0)
		return 0;
	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';

	/* The node takes commands only: a typo must not silently replace the list. */
	rc = hide_modules_command(cmd, false);
	if (rc)
		return rc;
	return len;
}

static const struct proc_ops hide_modules_proc_ops = {
	.proc_open = hide_modules_proc_open,
	.proc_read = seq_read,
	.proc_write = hide_modules_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *hide_modules_entry;

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

	/* Substring form for the names whose prefix differs from the list above.
	 * Measured: with the prefix rules alone a 257 -> 7 sweep left exactly
	 * anon_ksu_fops, anon_ksu_ioctl(.cfi_jt), anon_ksu_release(.cfi_jt),
	 * setup_ksu_cred and is_task_ksu_domain visible - each one a plain
	 * "KernelSU is loaded here" tell in /proc/kallsyms. */
	if (strstr(name, "ksu") || strstr(name, "susfs"))
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

	/* Two different features, counted apart:
	 *   - the prefix list is upstream's HIDE_KSU_SUSFS_SYMBOLS (KernelSU's names);
	 *   - the module_name test is hide_modules, which filters the lines of whichever
	 *     modules the operator listed (module symbols carry their own spelling, e.g.
	 *     __kstrtab_foo, with the module's name in module_name). */
	if (name_should_hide(iter->name)) {
		atomic_inc(&hide_hit_count);
		regs->regs[0] = 0;              /* s_show returns 0 */
		regs->pc = regs->regs[30];      /* skip the line */
		return 1;
	}
	if (iter->module_name[0] && hide_module_name_match(iter->module_name)) {
		atomic_inc(&n_kallsyms_mod_skipped);
		regs->regs[0] = 0;
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

/* Registered by name, which is what was measured to work: with this in place
 * `grep -cE 'susfs_|ksu_' /proc/kallsyms` goes 257 -> 0.
 *
 * An audit pointed out that this tree has three different `s_show` functions
 * (kernel/kallsyms.c, kernel/trace/trace.c, mm/vmalloc.c) and that a name-based
 * registration gets whichever kallsyms lists first - a real hazard, since the
 * handler reads m->private as struct kallsym_iter *.  Taking the address out of
 * the kallsyms_op table instead and registering with .addr CRASHED the device on
 * the first read of /proc/kallsyms, so the table's .show is not the address a
 * kprobe can be hung on there (most likely the arm64 CFI jump-table thunk, which
 * is what a function pointer in a table actually holds under this config).
 *
 * So: keep the working registration, and log both addresses so a mismatch is
 * visible instead of silent. */
static struct kprobe kp_s_show = {
	.symbol_name = "s_show",
	.pre_handler = hide_syms_s_show_pre,
};

/* /proc/modules is 0444 - any app can read it - and nothing in a built-in SUSFS
 * is listed there.  Our own line is printed by m_show(m, p), where p is
 * &module->list; answering success without emitting anything leaves the listing
 * exactly as it would be without the module.  struct module's layout is what this
 * module was built against (RANDSTRUCT is off on this kernel), so recovering the
 * module from the iterator is safe. */
static int hide_syms_m_show_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct module *mod;
	void *p = (void *)regs_get_kernel_argument(regs, 1);

	if (!p)
		return 0;

	/* Same recovery the kernel's own m_show() does with list_entry(): the iterator
	 * hands over &module->list, so the module (and its name) is one offset away. */
	mod = (struct module *)((char *)p - offsetof(struct module, list));
	if (!hide_module_name_match(mod->name))
		return 0;

	atomic_inc(&n_modlines_skipped);
	regs_set_return_value(regs, 0);		/* no output for this entry */
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe kp_m_show = {
	.symbol_name = "m_show",
	.pre_handler = hide_syms_m_show_pre,
};

static bool m_show_registered;

/* Read-only comparison target: the function kallsyms itself calls. */
static unsigned long hide_syms_table_show(void)
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
	unsigned long table_show;

	rc = register_kprobe(&kp_s_show);
	if (rc) {
		pr_warn("susfs_hide_syms: register_kprobe(s_show) failed %d\n", rc);
		return rc;
	}
	hide_registered = true;

	table_show = hide_syms_table_show();
	/* The two addresses differ by design and that is not a fault: a function
	 * pointer inside a table holds the CFI jump-table thunk (bti c ; b func),
	 * while the kprobe lands on the function itself.  The check that matters is
	 * the one on device - /proc/kallsyms going from 257 ksu_/susfs_ matches to
	 * none - and that is what the line is for. */
	SUSFS_LOGI("susfs_hide_syms: armed at %px (kallsyms_op.show=%px%s)\n",
		(void *)kp_s_show.addr, (void *)table_show,
		(table_show && (unsigned long)kp_s_show.addr == table_show) ?
		" - same address" : " - different address (expected: table holds the CFI thunk)");

	/* Separate probe, separate failure: hiding the symbol names and hiding module
	 * entries are independent, and neither should stop the other. */
	rc = register_kprobe(&kp_m_show);
	if (rc)
		pr_warn("susfs_hide_syms: register_kprobe(m_show) failed %d - /proc/modules keeps listing the modules in hide_modules\n",
			rc);
	else
		m_show_registered = true;

	/* hide_modules starts with just this module in its list: a built-in SUSFS has no
	 * module entry, so leaving ours visible would be a trace upstream does not have.
	 * The sysfs rule can only be registered now, because sus_path is up (this layer is
	 * last in the init table) - hence the default list is seeded here and not from the
	 * parameter's initial value. */
	{
		char staged[HIDE_MODULES_MAX][MODULE_NAME_LEN] = { { 0 } };

		strscpy(staged[0], SUSFS_LKM_MODULE_NAME, MODULE_NAME_LEN);
		hide_modules_commit(staged, 1);
	}
	hide_modules_sync_sysfs();

	/* The runtime control node, same shape as the other control nodes: only when the
	 * LSM layer that hides it is installed, so an unprotected world-writable node
	 * cannot exist (see susfs_control_node_allowed()). */
	if (susfs_control_node_allowed()) {
		hide_modules_entry = proc_create("susfs_hide_modules", 0777, NULL,
						 &hide_modules_proc_ops);
		if (!hide_modules_entry)
			pr_warn("susfs_hide_syms: proc_create(susfs_hide_modules) failed - runtime control unavailable, use the hide_modules parameter\n");
	} else {
		SUSFS_LOGI("susfs_hide_syms: /proc/susfs_hide_modules not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	return 0;
}

bool susfs_hide_syms_active(void)
{
	return hide_registered;
}

bool susfs_hide_modules_node_ready(void)
{
	return hide_modules_entry != NULL;
}

void susfs_hide_syms_exit(void)
{
	if (hide_modules_entry) {
		proc_remove(hide_modules_entry);
		hide_modules_entry = NULL;
	}
	if (m_show_registered) {
		unregister_kprobe(&kp_m_show);
		m_show_registered = false;
	}
	if (hide_registered) {
		unregister_kprobe(&kp_s_show);
		hide_registered = false;
	}
	/* The /sys/module rules are ours; drop them here rather than leaving it to
	 * sus_path's table teardown, so this layer cleans up exactly what it registered. */
	hide_modules_commit(hide_modules_applied, 0);
	hide_modules_sync_sysfs();
	SUSFS_LOGI("susfs_hide_syms: exit enter=%d hit=%d (module lines=%d listed modules' syms=%d)\n",
		atomic_read(&hide_enter_count), atomic_read(&hide_hit_count),
		atomic_read(&n_modlines_skipped), atomic_read(&n_kallsyms_mod_skipped));
}
