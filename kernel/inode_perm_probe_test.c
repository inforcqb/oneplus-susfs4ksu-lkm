// SPDX-License-Identifier: GPL-2.0
/*
 * inode_perm_probe_test.c - locate a VFS-layer hook that survives LTO.
 *
 * The upstream SUSFS sus_path hides a file from path-based access by patching
 * fs/namei.c (link_path_walk returns -ENOENT, __lookup_slow/lookup_open redo the
 * lookup with the fake qstr "..5.u.S").  A loadable module cannot patch namei.c,
 * so the equivalent has to be an out-of-line hook.  inode_permission() is the
 * ideal candidate: every path-based operation (open/stat/exec/access/unlink/...)
 * passes through it and it receives the struct inode directly, which matches the
 * (dev, ino) keys this project already keeps for sus_path.
 *
 * This module first just COUNTS hits on every candidate symbol (no behaviour
 * change at all), because LTO can inline a symbol away: do_filp_open has a
 * kallsyms entry on this kernel yet never fires for user opens.  Only if
 * inode_permission actually fires is the second, behaviour-changing experiment
 * meaningful - and that one is opt-in at runtime.
 *
 *   /proc/susfs_perm_probe        read   : per-symbol registration + hit counts
 *                                 write  : "reset"
 *                                          "arm <path>"  (kretprobe -ENOENT experiment)
 *                                          "disarm"
 *
 * The kretprobe experiment is DISARMED by default and only ever alters the
 * return value for the single inode named by "arm <path>", plus it never fires
 * for uid 0.  Nothing else in the system is affected.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/cred.h>

#define NPROBES 13

struct probe_stat {
	const char *name;
	struct kprobe kp;
	bool armed;
	atomic_t hits;
};

static struct probe_stat probes[NPROBES] = {
	{ .name = "__arm64_sys_newfstatat" },	/* control: definitely not inlined */
	{ .name = "__arm64_sys_openat" },
	{ .name = "__arm64_sys_faccessat" },
	{ .name = "__arm64_sys_execve" },
	{ .name = "vfs_statx" },
	{ .name = "vfs_getattr" },
	{ .name = "filename_lookup" },
	{ .name = "may_lookup" },
	{ .name = "link_path_walk" },
	{ .name = "walk_component" },
	{ .name = "may_open" },
	{ .name = "inode_permission" },		/* <== the one we actually want */
	{ .name = "security_inode_permission" },
};

static int probe_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct probe_stat *ps = container_of(kp, struct probe_stat, kp);

	atomic_inc(&ps->hits);
	return 0;
}

/* ---- opt-in kretprobe: force -ENOENT for one inode, uid 0 exempt ---- */

static struct kretprobe ip_krp;
static struct inode *target_inode;
static atomic_t enoent_hits = ATOMIC_INIT(0);
static bool enoent_armed;
static bool ip_krp_armed;

static int ip_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs->regs[1];

	if (!enoent_armed || !inode || inode != target_inode)
		return 0;
	if (current_uid().val == 0)
		return 0;
	return 1;
}

static int ip_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	regs->regs[0] = (unsigned long)(-ENOENT);
	atomic_inc(&enoent_hits);
	return 0;
}

static void enoent_arm(const char *path)
{
	struct path p;
	struct inode *inode;

	if (kern_path(path, LOOKUP_FOLLOW, &p)) {
		pr_warn("perm_probe: kern_path(%s) failed\n", path);
		return;
	}
	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		pr_warn("perm_probe: %s has no inode\n", path);
		return;
	}

	if (target_inode)
		iput(target_inode);
	target_inode = inode;
	ihold(target_inode);
	path_put(&p);

	if (!ip_krp_armed) {
		ip_krp.kp.symbol_name = "inode_permission";
		ip_krp.entry_handler = ip_entry;
		ip_krp.handler = ip_ret;
		ip_krp.maxactive = 32;
		if (register_kretprobe(&ip_krp)) {
			pr_warn("perm_probe: register_kretprobe(inode_permission) failed\n");
			iput(target_inode);
			target_inode = NULL;
			return;
		}
		ip_krp_armed = true;
	}

	enoent_armed = true;
	atomic_set(&enoent_hits, 0);
	pr_info("perm_probe: ARMED -ENOENT for %s (dev=%u ino=%lu), uid 0 exempt\n",
		path, target_inode->i_sb->s_dev, target_inode->i_ino);
}

static void enoent_disarm(void)
{
	enoent_armed = false;
	if (target_inode) {
		iput(target_inode);
		target_inode = NULL;
	}
	pr_info("perm_probe: disarmed\n");
}

static int probe_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < NPROBES; i++)
		seq_printf(m, "%-28s %-8s %d\n", probes[i].name,
			   probes[i].armed ? "armed" : "FAILED",
			   atomic_read(&probes[i].hits));
	seq_printf(m, "\nenoent experiment: krp=%s armed=%s hits=%d target=%s\n",
		   ip_krp_armed ? "registered" : "not-registered",
		   enoent_armed ? "yes" : "no",
		   atomic_read(&enoent_hits),
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
		for (i = 0; i < NPROBES; i++)
			atomic_set(&probes[i].hits, 0);
		atomic_set(&enoent_hits, 0);
	} else if (!strcmp(cmd, "disarm")) {
		enoent_disarm();
	} else if (!strncmp(cmd, "arm ", 4)) {
		enoent_arm(cmd + 4);
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

static int __init perm_probe_init(void)
{
	int i, rc;

	for (i = 0; i < NPROBES; i++) {
		probes[i].kp.symbol_name = probes[i].name;
		probes[i].kp.pre_handler = probe_pre;
		atomic_set(&probes[i].hits, 0);
		rc = register_kprobe(&probes[i].kp);
		if (rc)
			pr_warn("perm_probe: register_kprobe(%s) failed %d\n",
				probes[i].name, rc);
		else {
			probes[i].armed = true;
			pr_info("perm_probe armed: %s\n", probes[i].name);
		}
	}

	proc_entry = proc_create("susfs_perm_probe", 0666, NULL, &probe_ops);
	if (!proc_entry)
		pr_warn("perm_probe: proc_create failed\n");
	return 0;
}

static void __exit perm_probe_exit(void)
{
	int i;

	enoent_armed = false;
	if (ip_krp_armed) {
		unregister_kretprobe(&ip_krp);
		ip_krp_armed = false;
	}
	if (target_inode) {
		iput(target_inode);
		target_inode = NULL;
	}
	if (proc_entry)
		proc_remove(proc_entry);
	for (i = 0; i < NPROBES; i++)
		if (probes[i].armed)
			unregister_kprobe(&probes[i].kp);
	pr_info("perm_probe bye\n");
}

module_init(perm_probe_init);
module_exit(perm_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VFS permission-layer symbol hit test");
