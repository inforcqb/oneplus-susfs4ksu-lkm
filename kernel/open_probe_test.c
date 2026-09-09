// SPDX-License-Identifier: GPL-2.0
/*
 * open_probe_test.c - locate which open-path symbols survive LTO inlining.
 *
 * do_sys_openat2 is static and inlined into the syscall entry, so
 * do_filp_open's kallsyms symbol is the out-of-line copy used by exec.c /
 * file_open_name, NOT the user-open path.  This module counts hits on every
 * candidate symbol so we know the real hook point.  Read /proc/susfs_open_probe,
 * write "reset" to zero counters.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "susfs_log.h"

#define NPROBES 8

struct probe_stat {
	const char *name;
	struct kprobe kp;
	atomic_t hits;
};

static struct probe_stat probes[NPROBES] = {
	{ .name = "__arm64_sys_openat" },
	{ .name = "__arm64_sys_openat2" },
	{ .name = "do_sys_open" },
	{ .name = "getname" },
	{ .name = "getname_flags" },
	{ .name = "do_filp_open" },
	{ .name = "vfs_open" },
	{ .name = "do_dentry_open" },
};

static int probe_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct probe_stat *ps = container_of(kp, struct probe_stat, kp);

	atomic_inc(&ps->hits);
	return 0;
}

static int probe_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < NPROBES; i++)
		seq_printf(m, "%s: %d\n", probes[i].name, atomic_read(&probes[i].hits));
	return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
	return single_open(file, probe_show, NULL);
}

static ssize_t probe_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *off)
{
	int i;
	char cmd[16];

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;
	if (strcmp(cmd, "reset") == 0) {
		for (i = 0; i < NPROBES; i++)
			atomic_set(&probes[i].hits, 0);
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
static bool armed[NPROBES];

static int __init open_probe_init(void)
{
	int i, rc;

	for (i = 0; i < NPROBES; i++) {
		probes[i].kp.symbol_name = probes[i].name;
		probes[i].kp.pre_handler = probe_pre;
		atomic_set(&probes[i].hits, 0);
		rc = register_kprobe(&probes[i].kp);
		if (rc)
			pr_warn("register_kprobe(%s) failed %d\n", probes[i].name, rc);
		else {
			armed[i] = true;
			pr_info("probe armed: %s\n", probes[i].name);
		}
	}

	proc_entry = proc_create("susfs_open_probe", 0666, NULL, &probe_ops);
	if (!proc_entry)
		pr_warn("proc_create(susfs_open_probe) failed\n");
	else
		pr_info("read /proc/susfs_open_probe for counters\n");
	return 0;
}

static void __exit open_probe_exit(void)
{
	int i;

	if (proc_entry)
		proc_remove(proc_entry);
	for (i = 0; i < NPROBES; i++)
		if (armed[i])
			unregister_kprobe(&probes[i].kp);
	pr_info("open_probe bye\n");
}

module_init(open_probe_init);
module_exit(open_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("open-path symbol hit test");
