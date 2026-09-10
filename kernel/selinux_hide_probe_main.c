// SPDX-License-Identifier: GPL-2.0
/*
 * selinux_hide_probe.c - make stat() report ENOENT for one inode, via LSM.
 *
 * Why this hook and not a kprobe:
 *
 *   - inode_permission() survives LTO but cannot hide a file from stat - Linux
 *     checks execute permission only on the directories along a path, never on
 *     the final target (measured: 178 newfstatat vs 34 inode_permission hits).
 *   - kprobes on the hot SELinux paths work but are far too expensive:
 *     selinux_inode_permission/avc_has_perm run hundreds of thousands of times
 *     per second, and a 7-probe version of this test froze the device.
 *   - The project already links lsm_hook.c (KernelSU's runtime security_hook
 *     replacement).  Patching the hook slot costs nothing per call and hands us
 *     the struct inode directly.
 *
 * vfs_getattr() calls security_inode_getattr() before it ever looks at the
 * inode, so this is on the path of every stat/fstatat/statx - with SELinux
 * enforcing it is unavoidable for a caller, regardless of DAC.
 *
 * Matching on the inode pointer covers '..', duplicate slashes, symlinks, hard
 * links, bind mounts and /proc/self/fd/N: none of them can dodge inode identity.
 *
 * Only inode_getattr is hooked here on purpose: it does not take part in any
 * permission decision, so a mistake can only affect stat - unlike
 * inode_permission, where a wrong hook would disable SELinux enforcement.
 *
 *   echo 'arm /path/to/hide' > /proc/susfs_hide_probe
 *   cat  /proc/susfs_hide_probe
 *   echo 'disarm' > /proc/susfs_hide_probe
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/atomic.h>

#include "lsm_hook.h"

static int susfs_test_inode_getattr(const struct path *path);

static struct ksu_lsm_hook getattr_hook = KSU_LSM_HOOK_INIT(
	inode_getattr, "selinux_inode_getattr",
	(void *)susfs_test_inode_getattr, 0);

static struct inode *target_inode;	/* ihold'ed while armed */
static bool armed;
static int gate_apps_only;		/* off for the experiment */
module_param(gate_apps_only, int, 0644);

static atomic_t n_calls = ATOMIC_INIT(0);
static atomic_t n_hidden = ATOMIC_INIT(0);
static atomic_t n_orig = ATOMIC_INIT(0);
static atomic_t n_no_orig = ATOMIC_INIT(0);

static int susfs_test_inode_getattr(const struct path *path)
{
	int (*orig)(const struct path *path) = (void *)getattr_hook.original;
	struct inode *inode;

	atomic_inc(&n_calls);

	if (armed && !(gate_apps_only && current_uid().val < 10000)) {
		inode = path && path->dentry ? d_inode(path->dentry) : NULL;
		if (inode && inode == target_inode) {
			atomic_inc(&n_hidden);
			return -ENOENT;
		}
	}

	if (!orig) {
		atomic_inc(&n_no_orig);
		return 0;
	}
	atomic_inc(&n_orig);
	return orig(path);
}

static void hide_arm(const char *path)
{
	struct path p;
	struct inode *inode;

	if (kern_path(path, LOOKUP_FOLLOW, &p)) {
		pr_warn("selinux_hide_probe: kern_path(%s) failed\n", path);
		return;
	}
	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		pr_warn("selinux_hide_probe: %s has no inode\n", path);
		return;
	}
	if (target_inode)
		iput(target_inode);
	target_inode = inode;
	ihold(target_inode);
	path_put(&p);
	armed = true;
	pr_info("selinux_hide_probe: ARMED for %s (ino=%lu)\n", path, target_inode->i_ino);
}

static void hide_disarm(void)
{
	armed = false;
	if (target_inode) {
		iput(target_inode);
		target_inode = NULL;
	}
	pr_info("selinux_hide_probe: disarmed\n");
}

static int probe_show(struct seq_file *m, void *v)
{
	seq_printf(m, "hook: %s -> %s  entry=%s original=%ps\n",
		   getattr_hook.head_name ?: "?", getattr_hook.target_name ?: "?",
		   getattr_hook.entry ? "patched" : "NOT-PATCHED",
		   getattr_hook.original);
	seq_printf(m, "calls=%d hidden=%d orig_called=%d orig_missing=%d\n",
		   atomic_read(&n_calls), atomic_read(&n_hidden),
		   atomic_read(&n_orig), atomic_read(&n_no_orig));
	seq_printf(m, "armed=%s gate_apps_only=%d target=%s\n",
		   armed ? "yes" : "no", gate_apps_only,
		   target_inode ? "set" : "none");
	return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
	return single_open(file, probe_show, NULL);
}

static ssize_t probe_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *off)
{
	char cmd[300];

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;
	while (len && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' ||
		       cmd[len - 1] == ' '))
		cmd[--len] = 0;

	if (!strcmp(cmd, "reset")) {
		atomic_set(&n_calls, 0);
		atomic_set(&n_hidden, 0);
		atomic_set(&n_orig, 0);
		atomic_set(&n_no_orig, 0);
	} else if (!strcmp(cmd, "disarm")) {
		hide_disarm();
	} else if (!strncmp(cmd, "arm ", 4)) {
		hide_arm(cmd + 4);
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

static int __init selinux_hide_probe_init(void)
{
	int rc;

	ksu_lsm_hook_init();

	rc = ksu_register_lsm_hook(&getattr_hook);
	if (rc) {
		pr_warn("selinux_hide_probe: ksu_register_lsm_hook failed %d\n", rc);
		return rc;
	}
	pr_info("selinux_hide_probe: hook installed, original=%ps\n",
		getattr_hook.original);

	proc_entry = proc_create("susfs_hide_probe", 0666, NULL, &probe_ops);
	if (!proc_entry)
		pr_warn("selinux_hide_probe: proc_create failed\n");
	return 0;
}

static void __exit selinux_hide_probe_exit(void)
{
	hide_disarm();
	if (proc_entry)
		proc_remove(proc_entry);
	if (getattr_hook.entry)
		ksu_unregister_lsm_hook(&getattr_hook);
	ksu_lsm_hook_exit();
	pr_info("selinux_hide_probe bye\n");
}

module_init(selinux_hide_probe_init);
module_exit(selinux_hide_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LSM inode_getattr ENOENT test");
