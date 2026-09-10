// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_open_redirect.c - redirect open of a target path to another path
 * (SUSFS OPEN_REDIRECT feature), LKM port.
 *
 * Upstream SUSFS hooks path_openat() and swaps the filename once the target
 * inode is resolved.  path_openat / do_sys_openat2 / do_filp_open are all
 * LTO-inlined into the syscall entry, so none of them can be kprobed.
 * A layer-by-layer probe showed the only out-of-line symbol on the user-open
 * path is vfs_open(path, file) (123/123 hits for `cat`), so we hook that.
 *
 * vfs_open is the inode layer: path->dentry->d_inode is already resolved, so
 * we match rules by (target_ino, target_dev) exactly like upstream.
 *
 * The kprobe pre_handler runs in interrupt context (preempt disabled), so it
 * must not sleep.  We therefore resolve the redirected path at RULE-ADD time
 * (proc write, process context) with kern_path() and cache its `struct path`
 * in the entry.  The pre_handler only does: match (ino,dev), then point
 * regs->regs[0] at the cached path.  vfs_open copies *path into file->f_path
 * and do_dentry_open does path_get(&f->f_path), so the file takes its own
 * reference; the entry keeps the base reference until del/clear path_put()s it.
 *
 * No kretprobe needed.  The base reference is held for the entry's lifetime,
 * so the redirected file stays pinned (like upstream's re-walk, which also
 * pins the inode during the open).
 *
 * Interface mirrors upstream: /proc/susfs_open_redirect
 *   add_open_redirect <target> <redirected> <uid_scheme>
 *   del <target>
 *   clear
 *
 * uid_scheme: 0 = non-app proc (uid % 100000 < 10000).  Schemes 1..4 depend
 * on KernelSU-internal su-domain/umount state that an LKM cannot see; they
 * are rejected with -EOPNOTSUPP for now.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc */

#define SUS_OR_MAX 64
#define OR_PATH_MAX 128

/* UID_SCHEME (uid_scheme values) now lives in susfs_abi.h, mirroring upstream
 * susfs.h where the enum sits next to the ABI structs. */

struct sus_or_entry {
	char target_pathname[OR_PATH_MAX];
	char redirected_pathname[OR_PATH_MAX];
	unsigned long target_ino;
	dev_t target_dev;
	/* cached redirected path, resolved at add time (base ref) */
	struct path redirected_path;
	int uid_scheme;
	/* Set while the slot is being rewritten or has been deleted.  The reader
	 * checks this with READ_ONCE and the writer clears it LAST, so a false
	 * value means the rest of the entry is complete. */
	bool dead;
};

static struct sus_or_entry or_entries[SUS_OR_MAX];
static int nor;
static DEFINE_MUTEX(or_lock);

/* Cached paths that have been replaced or deleted.
 *
 * or_vfs_open_pre() runs in interrupt context with no lock and hands
 * &e->redirected_path straight to vfs_open, which path_get()s it.  Freeing the
 * old path on replace/delete therefore raced a concurrent open into a
 * use-after-free.  (Upstream avoids this with SRCU plus a re-walk, so it never
 * holds a cached path at all.)  Retiring keeps the reference alive until
 * unload; the price is one pinned dentry/mount per rule update, and updates are
 * rare, configuration-time operations. */
struct or_retired_path {
	struct list_head list;
	struct path path;
};

static LIST_HEAD(or_retired_paths);

static void or_retire_path(struct path *p)
{
	struct or_retired_path *r;

	if (!p->dentry)
		return;
	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r) {
		/* Cannot record it: leaking the reference is strictly safer than
		 * dropping it while an open may still be using it. */
		pr_warn("open_redirect: cannot retire path, leaking reference\n");
		return;
	}
	r->path = *p;
	list_add_tail(&r->list, &or_retired_paths);
}

static bool or_uid_matches(int scheme)
{
	switch (scheme) {
	case UID_NON_APP_PROC:
		return current_uid().val % 100000 < 10000;
	default:
		/* 1..4 need su-domain / umount state unavailable to an LKM */
		return false;
	}
}

static struct sus_or_entry *or_find_by_path(const char *target)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		if (!strcmp(or_entries[i].target_pathname, target))
			return &or_entries[i];
	}
	return NULL;
}

static struct sus_or_entry *or_find_by_inode(unsigned long ino, dev_t dev)
{
	int i;

	for (i = 0; i < nor; i++) {
		/* dead is cleared LAST by the writer, so skipping dead entries also
		 * skips any entry whose fields are still being written. */
		if (READ_ONCE(or_entries[i].dead))
			continue;
		smp_rmb();
		if (or_entries[i].target_ino == ino &&
		    or_entries[i].target_dev == dev)
			return &or_entries[i];
	}
	return NULL;
}

/* ---- vfs_open kprobe: swap path on match ----
 * Runs in interrupt context: no sleeping, no kern_path here. */
static int or_vfs_open_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	if (!path || !path->dentry)
		return 0;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return 0;

	e = or_find_by_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;
	if (!or_uid_matches(e->uid_scheme))
		return 0;

	/* vfs_open does file->f_path = *path; do_dentry_open path_get()s it. */
	regs->regs[0] = (unsigned long)&e->redirected_path;
	return 0;
}

static struct kprobe kp_or = {
	.symbol_name = "vfs_open",
	.pre_handler = or_vfs_open_pre,
};

static bool or_registered;

static int or_register(void)
{
	int rc;

	if (or_registered)
		return 0;
	rc = register_kprobe(&kp_or);
	if (rc)
		return rc;
	or_registered = true;
	pr_info("susfs_open_redirect: hook installed (vfs_open)\n");
	return 0;
}

static void or_unregister(void)
{
	if (!or_registered)
		return;
	unregister_kprobe(&kp_or);
	or_registered = false;
	pr_info("susfs_open_redirect: hook removed\n");
}

/* ---- /proc/susfs_open_redirect ---- */
static int or_proc_show(struct seq_file *m, void *v);
static int or_proc_open(struct inode *inode, struct file *file);
static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off);

static const struct proc_ops or_proc_ops = {
	.proc_open = or_proc_open,
	.proc_read = seq_read,
	.proc_write = or_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *or_proc_entry;

int susfs_open_redirect_init(void)
{
	/* Not created unless asked for: see susfs_expose_proc. */
	if (!susfs_expose_proc) {
		pr_info("susfs_open_redirect: /proc node disabled (expose_proc=0)\n");
		return 0;
	}

	/* 0777 so DAC passes and sus_path's LSM layer gets to answer ENOENT;
	 * see the long note in susfs_kstat.c.  Without that layer the node would
	 * be world-writable, so do not create it at all. */
	if (!sus_path_lsm_active()) {
		pr_err("susfs_open_redirect: sus_path LSM layer inactive - NOT creating a 0777 node\n");
		return 0;
	}

	or_proc_entry = proc_create("susfs_open_redirect", 0777, NULL, &or_proc_ops);
	if (!or_proc_entry)
		pr_warn("proc_create(susfs_open_redirect) failed\n");

	pr_info("susfs_open_redirect: %d rules (proc: /proc/susfs_open_redirect)\n", nor);
	return 0;
}

void susfs_open_redirect_exit(void)
{
	struct or_retired_path *r, *tmp;
	int i;

	or_unregister();
	if (or_proc_entry) {
		proc_remove(or_proc_entry);
		or_proc_entry = NULL;
	}

	/* Nothing can reach these any more: the kprobe is already gone.
	 * path_put() tolerates the NULLs left by or_del(). */
	for (i = 0; i < nor; i++) {
		path_put(&or_entries[i].redirected_path);
		or_entries[i].redirected_path.dentry = NULL;
		or_entries[i].redirected_path.mnt = NULL;
		or_entries[i].dead = true;
	}
	nor = 0;

	/* And only now the retired ones. */
	list_for_each_entry_safe(r, tmp, &or_retired_paths, list) {
		list_del(&r->list);
		path_put(&r->path);
		kfree(r);
	}
}

static int or_proc_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&or_lock);
	if (nor == 0) {
		seq_puts(m, "(empty)\n");
	} else {
		for (i = 0; i < nor; i++) {
			if (READ_ONCE(or_entries[i].dead))
				continue;
			seq_printf(m, "%s -> %s uid=%d (ino=%lu dev=%lu)\n",
				   or_entries[i].target_pathname,
				   or_entries[i].redirected_pathname,
				   or_entries[i].uid_scheme,
				   or_entries[i].target_ino,
				   (unsigned long)or_entries[i].target_dev);
		}
	}
	mutex_unlock(&or_lock);
	return 0;
}

static int or_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, or_proc_show, NULL);
}

static int split_ws(char *buf, char **argv, int max)
{
	int argc = 0;
	char *p = buf;

	while (argc < max) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p)
			*p++ = '\0';
	}
	return argc;
}

static int or_add(const char *target, const char *redirected, int scheme)
{
	struct sus_or_entry *e;
	struct path tp, rp;
	struct inode *ti;
	int rc;

	if (scheme < UID_NON_APP_PROC || scheme > UID_UMOUNTED_PROC)
		return -EINVAL;
	if (scheme != UID_NON_APP_PROC)
		return -EOPNOTSUPP;

	/* resolve target for ino/dev (released immediately) */
	rc = kern_path(target, LOOKUP_FOLLOW, &tp);
	if (rc)
		return rc;
	ti = d_backing_inode(tp.dentry);
	if (!ti) {
		path_put(&tp);
		return -ENOENT;
	}

	/* resolve redirected and CACHE it (base ref kept for entry lifetime) */
	rc = kern_path(redirected, LOOKUP_FOLLOW, &rp);
	if (rc) {
		path_put(&tp);
		return rc;
	}

	/* Register the hook BEFORE touching any entry: a rule that is listed but
	 * cannot fire (because the hook is missing) silently does nothing while
	 * looking configured - worse than no rule at all. */
	rc = or_register();
	if (rc) {
		path_put(&rp);
		path_put(&tp);
		pr_warn("open_redirect: hook registration failed %d\n", rc);
		return rc;
	}

	e = or_find_by_path(target);
	if (e) {
		/* Rewriting a live entry: mark it dead and retire its old path.
		 * Freeing it here would race a concurrent vfs_open holding it. */
		WRITE_ONCE(e->dead, true);
		smp_wmb();
		or_retire_path(&e->redirected_path);
	} else {
		int i;

		/* Reuse a retired slot before growing the array. */
		for (i = 0; i < nor; i++) {
			if (READ_ONCE(or_entries[i].dead)) {
				e = &or_entries[i];
				break;
			}
		}
		if (!e) {
			if (nor >= SUS_OR_MAX) {
				path_put(&rp);
				path_put(&tp);
				return -ENOSPC;
			}
			e = &or_entries[nor];
			nor++;
		}
		strscpy(e->target_pathname, target, OR_PATH_MAX);
	}

	strscpy(e->redirected_pathname, redirected, OR_PATH_MAX);
	e->target_ino = ti->i_ino;
	e->target_dev = ti->i_sb->s_dev;
	e->redirected_path = rp;   /* transfer the cached reference */
	e->uid_scheme = scheme;
	smp_wmb();
	WRITE_ONCE(e->dead, false);	/* publish last: readers key off this */

	path_put(&tp);
	return 0;
}

static void or_del(const char *target)
{
	struct sus_or_entry *e;

	e = or_find_by_path(target);
	if (!e)
		return;

	/* Retire, never free: an in-flight vfs_open may still hold this path.
	 * The slot stays in the array (marked dead) and is reused by or_add. */
	WRITE_ONCE(e->dead, true);
	smp_wmb();
	or_retire_path(&e->redirected_path);
	e->redirected_path.dentry = NULL;
	e->redirected_path.mnt = NULL;
	e->target_ino = 0;
	e->target_dev = 0;
	e->target_pathname[0] = '\0';
	e->redirected_pathname[0] = '\0';
}

/* Slots are never compacted (that array move was itself part of the race).
 * The kprobe stays registered for the module's whole lifetime: repeatedly
 * unregistering and re-registering it was observed to leave the hook silently
 * gone after a burst of add/del cycles, while an empty rule table already makes
 * or_find_by_inode() miss - so staying registered costs nothing. */

static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off)
{
	char cmd[640];
	char *argv[8];
	int argc, err;
	long scheme;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;

	argc = split_ws(cmd, argv, 8);
	if (argc == 0)
		return len;

	mutex_lock(&or_lock);
	err = -EINVAL;

	if (!strcmp(argv[0], "add_open_redirect") && argc == 4) {
		if (kstrtol(argv[3], 10, &scheme))
			err = -EINVAL;
		else
			err = or_add(argv[1], argv[2], (int)scheme);
	} else if (!strcmp(argv[0], "del") && argc == 2) {
		or_del(argv[1]);
		err = 0;
	} else if (!strcmp(argv[0], "clear")) {
		int i;

		for (i = 0; i < nor; i++) {
			if (READ_ONCE(or_entries[i].dead))
				continue;
			or_del(or_entries[i].target_pathname);
		}
		err = 0;
	}

	mutex_unlock(&or_lock);

	if (err)
		pr_warn("open_redirect proc write '%s' -> err %d\n", argv[0], err);
	return len;
}

/* supercall: CMD_SUSFS_ADD_OPEN_REDIRECT */
void susfs_open_redirect_supercall(void __user **arg)
{
	struct st_susfs_open_redirect info = {0};
	int err;

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	mutex_lock(&or_lock);
	err = or_add(info.target_pathname, info.redirected_pathname,
		     info.uid_scheme);
	mutex_unlock(&or_lock);
	info.err = err;
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_open_redirect __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("open_redirect supercall copy_to_user failed\n");
}
