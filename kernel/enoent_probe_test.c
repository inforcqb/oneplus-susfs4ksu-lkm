// SPDX-License-Identifier: GPL-2.0
/*
 * enoent_probe_test.c - can a kprobe pre_handler make stat/open return -ENOENT?
 *
 * Why this exists: inode_permission() survives LTO but is useless for hiding a
 * file from stat - Linux only checks execute permission on the directories along
 * the path, never on the final target.  Measured on this kernel: 178
 * __arm64_sys_newfstatat hits vs only 34 inode_permission hits, and those 34 are
 * directory checks.  The syscall wrapper, by contrast, fires once per call and
 * is never inlined (it is referenced by the syscall table).
 *
 * So the only reliable place to reject a path is the wrapper itself.  This
 * module tests the short-circuit trick, the same one that already makes
 * reboot(2) return 0 in susfs_supercall.c:
 *
 *     regs->pc = regs->regs[30];      // return to the caller immediately
 *     regs->regs[0] = -ENOENT;        // our forced return value
 *     return 1;                       // tell kprobes not to single-step
 *
 * Because the syscall body never runs, there is no side effect at all - unlike
 * rewriting the return value on the way out, which would leak an fd for open().
 *
 * The target path is a module parameter.  Empty means "do nothing"; only
 * absolute paths are considered.  No real hiding list is wired up here.
 *
 *   echo /path/to/hide > /sys/module/enoent_probe_test/parameters/target_path
 *   cat /proc/susfs_enoent_probe      # per-symbol hit counts
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>

#define NPATH_ARGS 4

struct enoent_probe {
	const char *name;
	int argn;		/* register index holding the filename */
	struct kprobe kp;
	bool armed;
	atomic_t hits;
	atomic_t shorted;
};

static struct enoent_probe probes[NPATH_ARGS] = {
	{ .name = "__arm64_sys_newfstatat", .argn = 1 },
	{ .name = "__arm64_sys_statx",      .argn = 1 },
	{ .name = "__arm64_sys_openat",     .argn = 1 },
	{ .name = "__arm64_sys_faccessat",  .argn = 1 },
};

#define TARGET_LEN 256
static char target_path[TARGET_LEN];
module_param_string(target_path, target_path, sizeof(target_path), 0644);

static int short_error = -ENOENT;
module_param(short_error, int, 0644);

static int enoent_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct enoent_probe *ep = container_of(kp, struct enoent_probe, kp);
	struct pt_regs *real_regs;
	const char __user *fname;
	char buf[TARGET_LEN];

	atomic_inc(&ep->hits);

	if (!target_path[0])
		return 0;

	/* The arm64 syscall wrapper receives struct pt_regs * in x0; the real
	 * arguments live in that structure (same convention as the reboot
	 * supercall hook). */
	real_regs = (struct pt_regs *)regs->regs[0];
	fname = (const char __user *)real_regs->regs[ep->argn];
	if (!fname)
		return 0;

	/* pre_handler runs with preemption disabled, so only a nofault copy is
	 * allowed here; give up quietly if the page is not resident. */
	if (strncpy_from_user_nofault(buf, fname, sizeof(buf)) <= 0)
		return 0;
	if (buf[0] != '/')
		return 0;
	if (strcmp(buf, target_path))
		return 0;

	atomic_inc(&ep->shorted);
	pr_info("enoent_probe: short-circuit %s('%s') -> %d\n",
		ep->name, buf, short_error);

	regs->pc = regs->regs[30];
	regs->regs[0] = (unsigned long)short_error;
	return 1;
}

static int probe_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "target_path = '%s'\n", target_path);
	seq_printf(m, "short_error = %d\n\n", short_error);
	for (i = 0; i < NPATH_ARGS; i++)
		seq_printf(m, "%-28s %-8s hits=%-6d shorted=%d\n",
			   probes[i].name,
			   probes[i].armed ? "armed" : "FAILED",
			   atomic_read(&probes[i].hits),
			   atomic_read(&probes[i].shorted));
	return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
	return single_open(file, probe_show, NULL);
}

static ssize_t probe_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *off)
{
	char cmd[16];
	int i;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;
	if (!strcmp(cmd, "reset")) {
		for (i = 0; i < NPATH_ARGS; i++) {
			atomic_set(&probes[i].hits, 0);
			atomic_set(&probes[i].shorted, 0);
		}
	}
	return len;
}

static const struct proc_ops probe_ops = {
	.proc_open = probe_open,
	.proc_read = seq_read,
	.proc_write = probe_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static int __init enoent_probe_init(void)
{
	int i, rc;

	for (i = 0; i < NPATH_ARGS; i++) {
		probes[i].kp.symbol_name = probes[i].name;
		probes[i].kp.pre_handler = enoent_pre;
		atomic_set(&probes[i].hits, 0);
		atomic_set(&probes[i].shorted, 0);
		rc = register_kprobe(&probes[i].kp);
		if (rc)
			pr_warn("enoent_probe: register_kprobe(%s) failed %d\n",
				probes[i].name, rc);
		else {
			probes[i].armed = true;
			pr_info("enoent_probe armed: %s\n", probes[i].name);
		}
	}

	proc_entry = proc_create("susfs_enoent_probe", 0666, NULL, &probe_ops);
	if (!proc_entry)
		pr_warn("enoent_probe: proc_create failed\n");
	return 0;
}

static void __exit enoent_probe_exit(void)
{
	int i;

	if (proc_entry)
		proc_remove(proc_entry);
	for (i = 0; i < NPATH_ARGS; i++)
		if (probes[i].armed)
			unregister_kprobe(&probes[i].kp);
	pr_info("enoent_probe bye\n");
}

module_init(enoent_probe_init);
module_exit(enoent_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kprobe pre_handler -ENOENT short-circuit test");
