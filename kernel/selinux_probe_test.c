// SPDX-License-Identifier: GPL-2.0
/*
 * selinux_probe_test.c - hide a path from ALL path-based access via SELinux.
 *
 * Measured facts on this kernel that drove this design:
 *
 *   - inode_permission() survives LTO (34 hits) but CANNOT hide a file from
 *     stat: Linux only checks execute permission on the directories along a
 *     path, never on the final target.
 *   - The SELinux implementations are static functions but are referenced by
 *     the LSM hook structures, so their addresses escape and LTO cannot inline
 *     them (confirmed present in kallsyms as 't' symbols).
 *   - Every path-based operation reaches SELinux regardless of DAC:
 *       stat/fstatat/statx  -> vfs_getattr()     -> security_inode_getattr()
 *       open/exec/unlink/... -> inode_permission()-> security_inode_permission()
 *     with SELinux enforcing that is one hook pair covering everything, instead
 *     of enumerating a dozen syscalls whose signatures and register layouts we
 *     would have to get right one by one.
 *
 * The match key is the inode pointer itself, so '..', duplicate slashes,
 * symlinks, hard links, bind mounts and /proc/self/fd/N are all covered - none
 * of them can dodge an inode identity check.
 *
 * Mechanism: kprobe pre_handler short-circuit, the same trick already proven
 * on the reboot syscall wrapper and on __arm64_sys_newfstatat:
 *
 *     regs->pc = regs->regs[30];   // never run the function body
 *     regs->regs[0] = -ENOENT;
 *     return 1;
 *
 * The module is INERT until armed at runtime:
 *
 *   echo '/path/to/hide' > /proc/... no such path - use the write interface:
 *   echo 'arm /data/local/tmp/susfs.ko' > /proc/susfs_selinux_probe
 *   cat /proc/susfs_selinux_probe          # counts + which register matched
 *   echo 'disarm' > /proc/susfs_selinux_probe
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/cred.h>

#define NCOUNT 5

struct count_probe {
	const char *name;
	struct kprobe kp;
	bool armed;
	atomic_t hits;
};

static struct count_probe counters[NCOUNT] = {
	{ .name = "selinux_inode_getattr" },
	{ .name = "selinux_inode_permission" },
	{ .name = "selinux_file_permission" },
	{ .name = "selinux_inode_follow_link" },
	{ .name = "avc_has_perm" },
};

static int count_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct count_probe *cp = container_of(kp, struct count_probe, kp);

	atomic_inc(&cp->hits);
	return 0;
}

/* ---- the two short-circuit hooks ---- */

static struct kprobe kp_getattr, kp_perm;
static bool kp_getattr_armed, kp_perm_armed;

static struct inode *target_inode;	/* ihold'ed while armed */
static bool enoent_armed;
static int gate_apps_only;		/* off during the experiment */

module_param(gate_apps_only, int, 0644);

static atomic_t ga_hits = ATOMIC_INIT(0);
static atomic_t ga_shorted = ATOMIC_INIT(0);
static atomic_t pm_hits = ATOMIC_INIT(0);
static atomic_t pm_shorted = ATOMIC_INIT(0);
static atomic_t pm_reg0 = ATOMIC_INIT(0);	/* matched in x0 */
static atomic_t pm_reg1 = ATOMIC_INIT(0);	/* matched in x1 */
static atomic_t pm_regN = ATOMIC_INIT(0);	/* matched, unknown register */
static atomic_t ga_inode_null = ATOMIC_INIT(0);

/* Read a path and dig out its inode without ever touching a bad pointer. */
static struct inode *safe_path_to_inode(unsigned long pathp)
{
	struct path p;
	struct inode *i;

	if (!pathp)
		return NULL;
	if (copy_from_kernel_nofault(&p, (void *)pathp, sizeof(p)))
		return NULL;
	if (!p.dentry)
		return NULL;
	if (copy_from_kernel_nofault(&i,
			(void *)((unsigned long)p.dentry + offsetof(struct dentry, d_inode)),
			sizeof(i)))
		return NULL;
	return i;
}

static inline bool gate_blocks(void)
{
	if (!gate_apps_only)
		return false;
	/* upstream: TIF_PROC_UMOUNTED && uid >= 10000; the thread flag is a
	 * SUSFS-specific addition we do not have, so uid is the proxy here */
	return current_uid().val < 10000;
}

static int getattr_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct inode *inode;

	atomic_inc(&ga_hits);
	if (!enoent_armed || gate_blocks())
		return 0;

	inode = safe_path_to_inode(regs->regs[0]);
	if (!inode) {
		atomic_inc(&ga_inode_null);
		return 0;
	}
	if (inode != target_inode)
		return 0;

	atomic_inc(&ga_shorted);
	regs->pc = regs->regs[30];
	regs->regs[0] = (unsigned long)(-ENOENT);
	return 1;
}

static int perm_pre(struct kprobe *kp, struct pt_regs *regs)
{
	int i;

	atomic_inc(&pm_hits);
	if (!enoent_armed || gate_blocks())
		return 0;

	/* selinux_inode_permission(mnt_userns, inode, mask) on 5.12+, but probe
	 * the first three registers so a different signature still matches
	 * instead of crashing: comparing pointers cannot fault. */
	for (i = 0; i < 3; i++) {
		if ((void *)regs->regs[i] != target_inode)
			continue;
		if (i == 0)
			atomic_inc(&pm_reg0);
		else if (i == 1)
			atomic_inc(&pm_reg1);
		else
			atomic_inc(&pm_regN);
		atomic_inc(&pm_shorted);
		regs->pc = regs->regs[30];
		regs->regs[0] = (unsigned long)(-ENOENT);
		return 1;
	}
	return 0;
}

static void selinux_hide_arm(const char *path)
{
	struct path p;
	struct inode *inode;

	if (kern_path(path, LOOKUP_FOLLOW, &p)) {
		pr_warn("selinux_probe: kern_path(%s) failed\n", path);
		return;
	}
	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		pr_warn("selinux_probe: %s has no inode\n", path);
		return;
	}
	if (target_inode)
		iput(target_inode);
	target_inode = inode;
	ihold(target_inode);
	path_put(&p);

	enoent_armed = true;
	atomic_set(&ga_hits, 0);
	atomic_set(&ga_shorted, 0);
	atomic_set(&ga_inode_null, 0);
	atomic_set(&pm_hits, 0);
	atomic_set(&pm_shorted, 0);
	atomic_set(&pm_reg0, 0);
	atomic_set(&pm_reg1, 0);
	atomic_set(&pm_regN, 0);

	pr_info("selinux_probe: ARMED -ENOENT for %s (ino=%lu)\n", path, target_inode->i_ino);
}

static void selinux_hide_disarm(void)
{
	enoent_armed = false;
	if (target_inode) {
		iput(target_inode);
		target_inode = NULL;
	}
	pr_info("selinux_probe: disarmed\n");
}

static int probe_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < NCOUNT; i++)
		seq_printf(m, "%-30s %-8s hits=%d\n", counters[i].name,
			   counters[i].armed ? "armed" : "FAILED",
			   atomic_read(&counters[i].hits));

	seq_printf(m, "\nshort-circuit hooks:\n");
	seq_printf(m, "  getattr kprobe  %s  hits=%d shorted=%d inode_null=%d\n",
		   kp_getattr_armed ? "armed" : "FAILED",
		   atomic_read(&ga_hits), atomic_read(&ga_shorted),
		   atomic_read(&ga_inode_null));
	seq_printf(m, "  perm   kprobe  %s  hits=%d shorted=%d (x0=%d x1=%d xN=%d)\n",
		   kp_perm_armed ? "armed" : "FAILED",
		   atomic_read(&pm_hits), atomic_read(&pm_shorted),
		   atomic_read(&pm_reg0), atomic_read(&pm_reg1),
		   atomic_read(&pm_regN));
	seq_printf(m, "\nstate: armed=%s gate_apps_only=%d target=%s\n",
		   enoent_armed ? "yes" : "no", gate_apps_only,
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
	int i;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;
	while (len && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' ||
		       cmd[len - 1] == ' '))
		cmd[--len] = 0;

	if (!strcmp(cmd, "reset")) {
		for (i = 0; i < NCOUNT; i++)
			atomic_set(&counters[i].hits, 0);
	} else if (!strcmp(cmd, "disarm")) {
		selinux_hide_disarm();
	} else if (!strncmp(cmd, "arm ", 4)) {
		selinux_hide_arm(cmd + 4);
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

static int __init selinux_probe_init(void)
{
	int i, rc;

	for (i = 0; i < NCOUNT; i++) {
		counters[i].kp.symbol_name = counters[i].name;
		counters[i].kp.pre_handler = count_pre;
		atomic_set(&counters[i].hits, 0);
		rc = register_kprobe(&counters[i].kp);
		if (rc)
			pr_warn("selinux_probe: register_kprobe(%s) failed %d\n",
				counters[i].name, rc);
		else
			counters[i].armed = true;
	}

	kp_getattr.symbol_name = "selinux_inode_getattr";
	kp_getattr.pre_handler = getattr_pre;
	if (register_kprobe(&kp_getattr))
		pr_warn("selinux_probe: register_kprobe(selinux_inode_getattr) failed\n");
	else
		kp_getattr_armed = true;

	kp_perm.symbol_name = "selinux_inode_permission";
	kp_perm.pre_handler = perm_pre;
	if (register_kprobe(&kp_perm))
		pr_warn("selinux_probe: register_kprobe(selinux_inode_permission) failed\n");
	else
		kp_perm_armed = true;

	proc_entry = proc_create("susfs_selinux_probe", 0666, NULL, &probe_ops);
	if (!proc_entry)
		pr_warn("selinux_probe: proc_create failed\n");
	pr_info("selinux_probe: loaded (inert until 'arm <path>')\n");
	return 0;
}

static void __exit selinux_probe_exit(void)
{
	int i;

	selinux_hide_disarm();
	if (proc_entry)
		proc_remove(proc_entry);
	if (kp_getattr_armed)
		unregister_kprobe(&kp_getattr);
	if (kp_perm_armed)
		unregister_kprobe(&kp_perm);
	for (i = 0; i < NCOUNT; i++)
		if (counters[i].armed)
			unregister_kprobe(&counters[i].kp);
	pr_info("selinux_probe bye\n");
}

module_init(selinux_probe_init);
module_exit(selinux_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SELinux-hook -ENOENT hide test");
