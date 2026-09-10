// SPDX-License-Identifier: GPL-2.0
/*
 * selinux_hide_probe_main.c - make ALL path-based access report ENOENT, via LSM.
 *
 * Background (all measured on this device):
 *
 *   - inode_permission() survives LTO but cannot hide a file from stat: Linux
 *     only checks execute permission on the directories along a path, never on
 *     the final target (178 __arm64_sys_newfstatat hits vs 34 inode_permission
 *     hits, and those 34 are directory checks).
 *   - kprobes on the SELinux paths work but are too expensive: a 7-probe build
 *     froze the device, because selinux_inode_permission/avc_has_perm run
 *     hundreds of thousands of times per second.
 *   - The project already links lsm_hook.c (KernelSU runtime security_hook
 *     replacement): one slot patch, zero per-call cost.
 *
 * Two hooks cover everything, without enumerating a single syscall:
 *
 *   inode_getattr      <- vfs_getattr() calls security_inode_getattr() before it
 *                         looks at the inode: stat/fstatat/statx
 *   inode_permission   <- every path-based operation: open/exec/unlink/chmod/
 *                         truncate/chdir/readdir/...
 *
 * Matching is on the inode pointer, so '..', '//', './', relative paths,
 * symlinks (followed), hard links, bind mounts and /proc/self/root/... are all
 * covered.
 *
 * CFI: both hooks MUST be __nocfi, and the permission hook forwards its
 * arguments generically.  Details on the declarations below.
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

/* Type signature MUST match the LSM hook type exactly, and must NOT be __nocfi.
 *
 * Measured on this device: this kernel uses kCFI with cross-module checks.  The
 * kernel's call site compares the callee's CFI type hash, so
 *   - a mismatched signature  -> "CFI failure (target: ...cfi_jt)";
 *   - a __nocfi function      -> no type hash at all -> __cfi_check_fail as well.
 * (KernelSU's __nocfi advice assumes a non-kCFI or same-module setup.)
 *
 * The permission hook therefore uses the 5.15 LSM type int(inode, mask) - the
 * mnt_userns parameter only reached the LSM hook in 6.3.  The build prints the
 * authoritative declaration from the DDK headers so this can be verified rather
 * than guessed. */
static int susfs_test_inode_getattr(const struct path *path);
static int susfs_test_inode_permission(struct inode *inode, int mask);

/* Compile-time proof that both signatures match what the kernel actually calls
 * through the hook.  kCFI compares type hashes, so a mismatch is a hard panic at
 * runtime; this turns that into a build failure instead of another reboot.  The
 * types are taken from the kernel's own union security_list_options, so they are
 * authoritative for whichever kernel we build against - no guessing.
 *
 * NOTE: the hook field is a function POINTER type, so take the function's address
 * (typeof(f) alone yields the function type and never compares equal). */
#define LSM_HOOK_FN_TYPE(member) typeof(((union security_list_options *)0)->member)

static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_getattr),
					   typeof(&susfs_test_inode_getattr)),
	      "inode_getattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_permission),
					   typeof(&susfs_test_inode_permission)),
	      "inode_permission hook signature mismatch");

static struct ksu_lsm_hook getattr_hook = KSU_LSM_HOOK_INIT(
	inode_getattr, "selinux_inode_getattr",
	(void *)susfs_test_inode_getattr, 0);

static struct ksu_lsm_hook perm_hook = KSU_LSM_HOOK_INIT(
	inode_permission, "selinux_inode_permission",
	(void *)susfs_test_inode_permission, 0);

static struct inode *target_inode;	/* ihold'ed while armed */
static bool armed;
static int gate_apps_only;		/* off by default for the experiment */
module_param(gate_apps_only, int, 0644);

/* Counters are only touched on a hit: inode_permission runs hundreds of
 * thousands of times per second and an atomic_inc there costs real time. */
static atomic_t n_hidden_getattr = ATOMIC_INIT(0);
static atomic_t n_hidden_perm = ATOMIC_INIT(0);
static atomic_t n_orig_missing = ATOMIC_INIT(0);

static inline bool gated(void)
{
	return gate_apps_only && current_uid().val < 10000;
}

static int susfs_test_inode_getattr(const struct path *path)
{
	int (*orig)(const struct path *path) = (void *)getattr_hook.original;
	struct inode *inode;

	if (READ_ONCE(armed)) {
		inode = (path && path->dentry) ? d_inode(path->dentry) : NULL;
		if (inode && inode == READ_ONCE(target_inode) && !gated()) {
			atomic_inc(&n_hidden_getattr);
			return -ENOENT;
		}
	}
	if (!orig) {
		atomic_inc(&n_orig_missing);
		return 0;
	}
	return orig(path);
}

static int susfs_test_inode_permission(struct inode *inode, int mask)
{
	int (*orig)(struct inode *, int) = (void *)perm_hook.original;

	if (READ_ONCE(armed) && inode == READ_ONCE(target_inode) && !gated()) {
		atomic_inc(&n_hidden_perm);
		return -ENOENT;
	}
	if (!orig) {
		atomic_inc(&n_orig_missing);
		return 0;
	}
	return orig(inode, mask);
}

static int probe_show(struct seq_file *m, void *v)
{
	seq_printf(m, "getattr hook: %s -> %s entry=%s orig=%ps\n",
		   getattr_hook.head_name ?: "?", getattr_hook.target_name ?: "?",
		   getattr_hook.entry ? "patched" : "NOT-PATCHED",
		   getattr_hook.original);
	seq_printf(m, "perm    hook: %s -> %s entry=%s orig=%ps\n",
		   perm_hook.head_name ?: "?", perm_hook.target_name ?: "?",
		   perm_hook.entry ? "patched" : "NOT-PATCHED",
		   perm_hook.original);
	seq_printf(m, "hidden: getattr=%d perm=%d  orig_missing=%d\n",
		   atomic_read(&n_hidden_getattr), atomic_read(&n_hidden_perm),
		   atomic_read(&n_orig_missing));
	seq_printf(m, "armed=%s gate_apps_only=%d target=%s\n",
		   armed ? "yes" : "no", gate_apps_only,
		   target_inode ? "set" : "none");
	return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
	return single_open(file, probe_show, NULL);
}

static void hide_disarm(void);

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

	atomic_set(&n_hidden_getattr, 0);
	atomic_set(&n_hidden_perm, 0);
	WRITE_ONCE(armed, true);
	pr_info("selinux_hide_probe: ARMED %s (ino=%lu) getattr=%s perm=%s\n",
		path, target_inode->i_ino,
		getattr_hook.entry ? "on" : "off",
		perm_hook.entry ? "on" : "off");
}

static void hide_disarm(void)
{
	WRITE_ONCE(armed, false);
	if (target_inode) {
		iput(target_inode);
		target_inode = NULL;
	}
	pr_info("selinux_hide_probe: disarmed\n");
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

	if (!strcmp(cmd, "disarm")) {
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
	if (rc)
		pr_warn("selinux_hide_probe: getattr hook failed %d\n", rc);
	else
		pr_info("selinux_hide_probe: getattr hook on, orig=%ps\n",
			getattr_hook.original);

	rc = ksu_register_lsm_hook(&perm_hook);
	if (rc)
		pr_warn("selinux_hide_probe: perm hook failed %d\n", rc);
	else
		pr_info("selinux_hide_probe: perm hook on, orig=%ps\n",
			perm_hook.original);

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
	if (perm_hook.entry)
		ksu_unregister_lsm_hook(&perm_hook);
	if (getattr_hook.entry)
		ksu_unregister_lsm_hook(&getattr_hook);
	ksu_lsm_hook_exit();
	pr_info("selinux_hide_probe bye\n");
}

module_init(selinux_hide_probe_init);
module_exit(selinux_hide_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LSM getattr+permission ENOENT hide test");
