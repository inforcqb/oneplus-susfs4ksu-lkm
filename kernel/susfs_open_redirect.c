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
 * Every handler runs in interrupt context (preempt disabled), so it must not
 * sleep.  We therefore resolve the paths at RULE-ADD time (proc write or
 * supercall, process context) with kern_path() and cache both `struct path`s
 * in the entry: the redirected one for the forward direction, the target one
 * for the reverse direction (below).  A handler only does: match (ino, dev),
 * then swap the path pointer the caller is working on.
 *
 * No kretprobe needed.  The base references are held for the entry's lifetime,
 * so the files stay pinned (like upstream's re-walk, which also pins the inode
 * during the open).
 *
 * uid_scheme - enum UID_SCHEME (upstream susfs.h:28-34), all five values, with
 * upstream's predicates (susfs.c:941-964).  Two of the five need state an LKM
 * cannot read here; see or_uid_matches() and or_in_su_domain().
 *
 * Reverse disguise.  Upstream registers TWO hash entries per rule
 * (susfs.c:844-863): the second one carries reversed_lookup_only = true and has
 * target_pathname / redirected_pathname swapped, and every "where did this file
 * come from" reporter answers from it:
 *
 *   vfs_readlink()          patch:510-548    readlink() of a flagged inode
 *   do_proc_readlink()      patch:1062-1083  /proc/<pid>/fd/N, exe, cwd, root
 *   fdinfo seq_show()       patch:1145-1217  /proc/<pid>/fdinfo/N mnt_id + ino
 *   show_map_vma()          patch:1257-1288  /proc/<pid>/maps dev:ino + name
 *   vfs_statfs()            patch:2038-2056  statfs() / fstatfs()
 *
 * Upstream gates all of them on the same hardcoded SUSFS_IS_INODE_OPEN_REDIRECT
 * (susfs_def.h:148-151) = the inode flag *and* susfs_is_current_proc_umounted_app()
 * - the rule's uid_scheme is deliberately NOT consulted on this side, so even a
 * scheme-0 rule is disguised for app processes.  or_reverse_visible() keeps that
 * gate with the substitute this LKM uses everywhere (uid >= 10000).
 *
 * None of those five functions is reachable from an LKM on this kernel: the
 * first two and seq_show() are static and the maps/fdinfo numbers are printed
 * from locals a kprobe cannot see.  What IS reachable are helpers they share,
 * and there the substitute is the same one the forward direction already uses -
 * point the caller at the *target's* path:
 *
 *   d_path()                 <- do_proc_readlink() and seq_path() (the maps
 *                               name column) both d_path() the file's f_path
 *   show_vma_header_prefix() <- args 6/7 are exactly the maps dev:ino columns
 *   vfs_statfs()             <- fstatfs()/statfs()
 *
 * All three are best effort, and never silent: registration outcome and hit
 * counts are logged and shown by /proc/susfs_open_redirect, because registering
 * successfully only proves the symbol exists - the probes the audit found
 * "registered, zero hits" were LTO-inlined call sites.
 * /proc/<pid>/fdinfo/N (mnt_id/ino) stays uncovered, and why is noted at
 * or_proc_show().
 *
 * Interface mirrors upstream: /proc/susfs_open_redirect
 *   add_open_redirect <target> <redirected> <uid_scheme>
 *   del <target>
 *   clear
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
#include <linux/atomic.h>	/* reverse-disguise hit counters */
#include <linux/security.h>	/* security_secctx_to_secid */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"		/* susfs_expose_proc, sus_path_lsm_active */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact */

#define SUS_OR_MAX 64
/* The ABI fields are char[256]; matching them stops a legal long path from
 * being silently truncated into a rule for a different path. */
#define OR_PATH_MAX 256

/* UID_SCHEME (uid_scheme values) now lives in susfs_abi.h, mirroring upstream
 * susfs.h where the enum sits next to the ABI structs. */

/* FUSE is the one filesystem upstream refuses outright (susfs.c:824-829): the
 * daemon resolves the name itself, so a kernel-side swap either does nothing or
 * makes the request happen twice.  Upstream carries the constant in
 * susfs_def.h:49-51 for the same reason we do - neither <linux/magic.h> (absent
 * from this tree) nor <uapi/linux/magic.h> defines it; the fs defines it
 * privately in fs/fuse/fuse_i.h:39. */
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

/* Upstream's app threshold: susfs_is_current_proc_umounted_app() is
 * (TIF_PROC_UMOUNTED && current_uid().val >= 10000) (susfs_def.h:122-125), and
 * the uid half is the part this kernel can answer. */
#define OR_APP_UID_MIN 10000

/* SELinux context of the su/ksu domain, resolved to a sid at init.
 *
 * Upstream gets the sid from KernelSU itself (susfs_set_sid(KERNEL_SU_CONTEXT,
 * &susfs_ksu_sid), 10_enable_susfs_for_ksu.patch:2496); an LKM has to resolve
 * the string.  "u:r:ksu:s0" is the SukiSU variant this device runs
 * (SukiSU-Ultra kernel/selinux/selinux.h:8-11: KERNEL_SU_DOMAIN "ksu"); stock
 * KernelSU uses "u:r:su:s0" - override with susfs_guard_lkm.or_su_ctx.
 * Deliberately a separate parameter from sus_mount's su_ctx / avc_spoof's
 * avc_su_ctx: module parameters are per name, and defaulting to the wrong
 * domain must not silently change another feature's gating. */
static char or_su_ctx[128] = "u:r:ksu:s0";
module_param_string(or_su_ctx, or_su_ctx, sizeof(or_su_ctx), 0644);

static u32 or_su_sid;

/* security_cred_getsecid() is an EXPORT_SYMBOL, but GKI's module symbol list is
 * not guaranteed to carry it, so it is resolved in kallsyms like sus_mount.c
 * does (sus_mount.c:108-113, :338-340).  The wrapper needs __nocfi: kCFI
 * validates the type hash at a call through a function pointer. */
static void (*or_cred_getsecid)(const struct cred *cred, u32 *secid);

struct sus_or_entry {
	char target_pathname[OR_PATH_MAX];
	char redirected_pathname[OR_PATH_MAX];
	unsigned long target_ino;
	dev_t target_dev;
	/* Reverse direction: the redirected inode is the lookup key, and
	 * target_path is what the reporters above are made to show instead. */
	unsigned long redirected_ino;
	dev_t redirected_dev;
	/* Cached at add time, base references held for the entry's lifetime. */
	struct path target_path;
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

/* Reverse-disguise bookkeeping.  The counters are the only way to tell a hook
 * that never fires from one that fires and matches nothing: a kprobe registers
 * against a symbol's out-of-line copy, which GKI's full LTO may leave with no
 * live call sites (AUDIT_FINDINGS.md: five probes registered, zero hits). */
static atomic_t or_rev_dpath_hits = ATOMIC_INIT(0);
static atomic_t or_rev_statfs_hits = ATOMIC_INIT(0);
static atomic_t or_rev_vma_hits = ATOMIC_INIT(0);

/* Cached paths that have been replaced or deleted.
 *
 * The handlers run in interrupt context with no lock and hand
 * &e->redirected_path (or &e->target_path) straight to vfs_open()/d_path()/
 * vfs_statfs(), which read or path_get() it.  Freeing the old path on
 * replace/delete therefore raced a concurrent open into a use-after-free.
 * (Upstream avoids this with SRCU plus a re-walk on the open path, so it never
 * holds a cached path at all.)  Retiring keeps the reference alive until
 * unload; the price is one pinned dentry/mount per rule update and direction,
 * and updates are rare, configuration-time operations. */
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

static void or_resolve_su_sid(void)
{
	int err;

	if (or_su_sid)
		return;
	if (!or_su_ctx[0])
		return;
	err = security_secctx_to_secid(or_su_ctx, strlen(or_su_ctx), &or_su_sid);
	if (err) {
		pr_warn("open_redirect: secctx_to_secid(%s) failed %d\n",
			or_su_ctx, err);
		or_su_sid = 0;
		return;
	}
	pr_info("open_redirect: su ctx \"%s\" -> sid %u (stock KernelSU uses \"u:r:su:s0\", override with susfs_guard_lkm.or_su_ctx)\n",
		or_su_ctx, or_su_sid);
}

/* Upstream susfs_is_current_ksu_domain() = (current_sid() == susfs_ksu_sid)
 * (10_enable_susfs_for_ksu.patch:2484-2486); current_sid() itself lives in
 * SELinux's private objsec.h, so the LSM-agnostic security_cred_getsecid() is
 * used instead - same sid, public interface. */
static __nocfi bool or_in_su_domain(void)
{
	u32 sid = 0;

	/* Unresolved symbol or unresolvable context: "not su" would be a guess,
	 * and for schemes 1/2 that guess redirects the very process the rule
	 * exists to spare.  or_add() refuses those schemes instead. */
	if (!or_cred_getsecid || !or_su_sid)
		return false;
	/* interrupt context: reading current->cred and walking the (static) LSM
	 * hook list never sleeps. */
	or_cred_getsecid(current_cred(), &sid);
	return sid == or_su_sid;
}

/* Upstream's reverse-disguise gate, verbatim in shape: SUSFS_IS_INODE_OPEN_REDIRECT
 * (susfs_def.h:148-151) = flag bit AND susfs_is_current_proc_umounted_app().
 * TIF_PROC_UMOUNTED is never set on this kernel (no SUSFS integration in it, and
 * nothing calls ksu_handle_setresuid - see AUDIT_FINDINGS.md, "设备环境事实"), so
 * uid >= 10000 is the proxy, exactly as sus_path.c:245 and susfs_kstat.c:199. */
static bool or_reverse_visible(void)
{
	return current_uid().val >= OR_APP_UID_MIN;
}

/* uid_scheme decision, mirroring upstream's switch in
 * susfs_open_redirect_spoof_do_sys_openat() (susfs.c:941-964) case for case. */
static bool or_uid_matches(int scheme)
{
	switch (scheme) {
	case UID_NON_APP_PROC:			/* susfs.c:942-945 */
		return current_uid().val % 100000 < 10000;
	case UID_ROOT_PROC_EXCEPT_SU_PROC:	/* susfs.c:946-949 */
		return current_uid().val == 0 && !or_in_su_domain();
	case UID_NON_SU_PROC:			/* susfs.c:950-953 */
		return !or_in_su_domain();
	case UID_UMOUNTED_APP_PROC:		/* susfs.c:954-957 */
	case UID_UMOUNTED_PROC:			/* susfs.c:958-961 */
		/* Upstream: test_thread_flag(TIF_PROC_UMOUNTED) [&& uid >= 10000
		 * for the _APP variant] (susfs_def.h:98-125).  This kernel never
		 * sets that flag, so uid >= 10000 stands in for it - which makes
		 * schemes 3 and 4 degenerate into the same predicate here.  That
		 * is a strictly narrower gate than scheme 2, and it is the same
		 * substitute sus_path / sus_kstat already gate on. */
		return current_uid().val >= OR_APP_UID_MIN;
	default:				/* susfs.c:962-963 */
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

/* Reverse direction: keyed on the redirected (really opened) inode.  Same
 * publication protocol as or_find_by_inode(). */
static struct sus_or_entry *or_find_by_redirected_inode(unsigned long ino, dev_t dev)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		smp_rmb();
		if (or_entries[i].redirected_ino == ino &&
		    or_entries[i].redirected_dev == dev)
			return &or_entries[i];
	}
	return NULL;
}

/* Is `target` another rule's redirected path?  Upstream refuses to touch such a
 * name: "duplicated '%s' cannot be removed/added because it is used for reversed
 * lookup only" (susfs.c:867-881) - that name belongs to the reverse entry of an
 * existing rule and replacing it would silently break that rule's disguise. */
static bool or_is_redirected_path(const char *target)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		if (!strcmp(or_entries[i].redirected_pathname, target))
			return true;
	}
	return false;
}

/* ---- forward: vfs_open(path, file) - swap the path on match ----
 * Runs in interrupt context: no sleeping, no kern_path here.
 *
 * Note on the scheme check: upstream leaves the lookup loop entirely when the
 * inode matches but the scheme does not (goto out_srcu_read_unlock,
 * susfs.c:945/949/953/957/961), so a non-matching entry with the same inode
 * suppresses the remaining same-inode entries as well.  Here the first live
 * (ino, dev) match is the only candidate anyway, which is the same outcome for
 * distinct inodes; two rules sharing one inode (hard links) differ only in which
 * entry is picked (upstream: newest hash_add_rcu first, here: slot order). */
static int or_vfs_open_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	/* IS_ERR_OR_NULL on the same principle as the sus_path name handlers: a
	 * kprobe runs before the callee, so a caller that leaves argument checking
	 * to it hands us an error pointer. */
	if (IS_ERR_OR_NULL(path) || !path->dentry)
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

/* ---- reverse: d_path(path, buf, buflen) ----
 *
 * Covers the two surfaces whose name comes from a path walk:
 *   - readlink("/proc/<pid>/fd/N"): proc_pid_readlink() -> do_proc_readlink()
 *     -> d_path(&path, tmp, PAGE_SIZE) (fs/proc/base.c:1825-1848, upstream
 *     spoofs it at patch:1062-1083);
 *   - the /proc/<pid>/maps name column: show_map_vma() -> seq_file_path()
 *     -> seq_path() -> d_path(&file->f_path, ...) (fs/seq_file.c:486-500,
 *     upstream spoofs it inside show_map_vma, patch:1257-1288).
 *
 * Both hand d_path() a path that points at the redirected file, so replacing it
 * with the target's cached path makes d_path render the target name - the same
 * mechanism the forward direction uses.  Divergence to know about: upstream
 * returns the literal string it was given at add time, while d_path() renders the
 * canonical name of the cached target path in the *reader's* namespace, so a
 * rule registered through a symlink (or from another mount namespace) can read
 * back differently.  See the report; the literal string is in the entry
 * (target_pathname) if that ever needs to be exact. */
static int or_dpath_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	if (!READ_ONCE(nor) || IS_ERR_OR_NULL(path) || !path->dentry)
		return 0;
	if (!or_reverse_visible())
		return 0;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return 0;

	e = or_find_by_redirected_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;

	atomic_inc(&or_rev_dpath_hits);
	regs->regs[0] = (unsigned long)&e->target_path;
	return 0;
}

/* ---- reverse: vfs_statfs(path, buf) ----
 * Upstream answers statfs()/fstatfs() of the redirected file with the target's
 * kstatfs snapshot (susfs.c:1029-1046, taken with vfs_statfs() at add time,
 * susfs.c:851).  Swapping in the cached target path makes the kernel compute
 * exactly that value from the live target instead of from a snapshot. */
static int or_vfs_statfs_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	if (!READ_ONCE(nor) || IS_ERR_OR_NULL(path) || !path->dentry)
		return 0;
	if (!or_reverse_visible())
		return 0;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return 0;

	e = or_find_by_redirected_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;

	atomic_inc(&or_rev_statfs_hits);
	regs->regs[0] = (unsigned long)&e->target_path;
	return 0;
}

/* ---- reverse: show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino) ----
 * args 7 and 8 of that call are the "dev:ino" columns of /proc/<pid>/maps
 * (fs/proc/task_mmu.c:252-255, called from show_map_vma() at :293).  Upstream
 * rewrites the two locals that feed them (patch:1270-1288) to the *target's*
 * ino/dev; those locals are out of reach for a kprobe, but the values arrive in
 * x5/x6 (AAPCS64 argument order), which a pre_handler can rewrite - the same
 * technique sus_map's show_map_vma probe and the other register-level probes in
 * this LKM use.
 *
 * The lookup key is what the line is about to print: the redirected file's
 * (dev, ino).  A vma that has neither (the smaps_rollup trailer prints 0:0,
 * task_mmu.c:1096-1097) is skipped so no rule can ever match it. */
static int or_vma_hdr_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct sus_or_entry *e;

	if (!READ_ONCE(nor))
		return 0;
	if (!regs->regs[5] && !regs->regs[6])
		return 0;
	if (!or_reverse_visible())
		return 0;

	e = or_find_by_redirected_inode((unsigned long)regs->regs[6],
					(dev_t)regs->regs[5]);
	if (!e)
		return 0;

	atomic_inc(&or_rev_vma_hits);
	regs->regs[5] = (unsigned long)e->target_dev;
	regs->regs[6] = (unsigned long)e->target_ino;
	return 0;
}

static struct kprobe kp_or = {
	.symbol_name = "vfs_open",
	.pre_handler = or_vfs_open_pre,
};

static struct kprobe kp_or_dpath = {
	.symbol_name = "d_path",
	.pre_handler = or_dpath_pre,
};

static struct kprobe kp_or_vfs_statfs = {
	.symbol_name = "vfs_statfs",
	.pre_handler = or_vfs_statfs_pre,
};

static struct kprobe kp_or_vma_hdr = {
	.symbol_name = "show_vma_header_prefix",
	.pre_handler = or_vma_hdr_pre,
};

static bool or_registered;
static bool or_dpath_registered;
static bool or_statfs_registered;
static bool or_vma_hdr_registered;

/* The forward hook is the feature: a rule that cannot fire is worse than no
 * rule, so its registration failure is reported to the caller. */
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

/* Reverse-disguise hooks: best effort.  The forward redirect is already live and
 * each of these only closes one report path, so a failure must not reject the
 * rule - but it must never be silent either: registering successfully proves the
 * symbol exists, not that the kernel's call sites reach it (GKI's full LTO
 * inlines across translation units), which is why every hit is counted and the
 * counters are readable from /proc/susfs_open_redirect.  Called from the
 * rule-management paths (process context, may sleep). */
static void or_register_reverse(void)
{
	int rc;

	if (!or_dpath_registered) {
		rc = register_kprobe(&kp_or_dpath);
		if (rc)
			pr_warn("open_redirect: register_kprobe(d_path) failed %d - readlink/maps name not disguised (or already inlined)\n",
				rc);
		else {
			or_dpath_registered = true;
			pr_info("susfs_open_redirect: reverse hook installed (d_path)\n");
		}
	}
	if (!or_statfs_registered) {
		rc = register_kprobe(&kp_or_vfs_statfs);
		if (rc)
			pr_warn("open_redirect: register_kprobe(vfs_statfs) failed %d - statfs not disguised (or already inlined)\n",
				rc);
		else {
			or_statfs_registered = true;
			pr_info("susfs_open_redirect: reverse hook installed (vfs_statfs)\n");
		}
	}
	if (!or_vma_hdr_registered) {
		rc = register_kprobe(&kp_or_vma_hdr);
		if (rc)
			pr_warn("open_redirect: register_kprobe(show_vma_header_prefix) failed %d - maps dev:ino not disguised (or already inlined)\n",
				rc);
		else {
			or_vma_hdr_registered = true;
			pr_info("susfs_open_redirect: reverse hook installed (show_vma_header_prefix)\n");
		}
	}
}

static void or_unregister(void)
{
	if (or_vma_hdr_registered) {
		unregister_kprobe(&kp_or_vma_hdr);
		or_vma_hdr_registered = false;
	}
	if (or_statfs_registered) {
		unregister_kprobe(&kp_or_vfs_statfs);
		or_statfs_registered = false;
	}
	if (or_dpath_registered) {
		unregister_kprobe(&kp_or_dpath);
		or_dpath_registered = false;
	}
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
	or_cred_getsecid =
		(void *)find_kernel_symbol_exact("security_cred_getsecid");
	if (!or_cred_getsecid)
		pr_warn("open_redirect: security_cred_getsecid not found - schemes 1/2 will be refused\n");
	or_resolve_su_sid();

	/* Only the /proc node is optional.  The vfs_open hook is registered by
	 * or_add() - i.e. by the supercall as well - so this gate must never
	 * return early and skip other work.  See susfs_control_node_allowed():
	 * 0777 so DAC passes and sus_path's LSM layer gets to answer ENOENT, and
	 * without that layer the node would be world-writable, so it is not
	 * created at all. */
	if (susfs_control_node_allowed()) {
		or_proc_entry = proc_create("susfs_open_redirect", 0777, NULL,
					    &or_proc_ops);
		if (!or_proc_entry)
			pr_warn("proc_create(susfs_open_redirect) failed\n");
	} else {
		pr_info("susfs_open_redirect: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	pr_info("susfs_open_redirect: %d rules (hook %s, proc %d)\n", nor,
		or_registered ? "armed" : "lazy", or_proc_entry != NULL);
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

	/* Nothing can reach these any more: the kprobes are already gone.
	 * path_put() tolerates the NULLs left by or_del(). */
	for (i = 0; i < nor; i++) {
		path_put(&or_entries[i].redirected_path);
		or_entries[i].redirected_path.dentry = NULL;
		or_entries[i].redirected_path.mnt = NULL;
		path_put(&or_entries[i].target_path);
		or_entries[i].target_path.dentry = NULL;
		or_entries[i].target_path.mnt = NULL;
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
			seq_printf(m, "%s -> %s uid=%d (ino=%lu dev=%lu | rev: ino=%lu dev=%lu)\n",
				   or_entries[i].target_pathname,
				   or_entries[i].redirected_pathname,
				   or_entries[i].uid_scheme,
				   or_entries[i].target_ino,
				   (unsigned long)or_entries[i].target_dev,
				   or_entries[i].redirected_ino,
				   (unsigned long)or_entries[i].redirected_dev);
		}
	}
	/* Remember what the previous round learned the hard way: "registered" is
	 * not "reached".  A hook whose counter stays 0 across a real read means
	 * GKI inlined its call sites and that surface is NOT disguised.
	 *
	 * /proc/<pid>/fdinfo/N (upstream: patch:1145-1217, susfs.c:1048-1064) is
	 * the one surface with no reachable hook here: its mnt_id/ino are values
	 * passed straight to seq_printf() from fs/proc/fd.c's static seq_show(),
	 * so there is no path to swap and no function to intercept that would not
	 * also have to rewrite the already-printed line.  The data it needs
	 * (spoofed_mnt_id = target's mnt_id, and the target's ino) is what
	 * `rev: ino`/the target ino above carry, should that ever be attempted. */
	seq_printf(m, "hooks: open=%d dpath=%d statfs=%d vma_hdr=%d | rev hits: dpath=%d statfs=%d vma_hdr=%d | su_sid=%u\n",
		   or_registered, or_dpath_registered, or_statfs_registered,
		   or_vma_hdr_registered,
		   atomic_read(&or_rev_dpath_hits),
		   atomic_read(&or_rev_statfs_hits),
		   atomic_read(&or_rev_vma_hits),
		   or_su_sid);
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
	struct inode *ti, *ri;
	int rc, i;

	/* upstream susfs.c:792-796 */
	if (scheme < UID_NON_APP_PROC || scheme > UID_UMOUNTED_PROC)
		return -EINVAL;

	/* Both come from char[256] ABI fields (supercall) or a NUL-terminated
	 * command buffer (proc write); reject the unterminated case instead of
	 * letting strcmp()/kern_path() read past the struct or truncate a path
	 * into a rule for some other file. */
	if (!susfs_abi_path_ok(target, OR_PATH_MAX) ||
	    !susfs_abi_path_ok(redirected, OR_PATH_MAX))
		return -ENAMETOOLONG;

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
	ri = d_backing_inode(rp.dentry);
	if (!ri) {
		path_put(&rp);
		path_put(&tp);
		return -ENOENT;
	}

	/* upstream susfs.c:824-829 - FUSE is refused outright, on either side.
	 * Rejecting is the whole handling: no silent rewrite, no partial rule.
	 * (d_sb is the dentry's superblock, i.e. the same scene the upstream
	 * check reads through inode->i_sb.) */
	if (tp.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC ||
	    rp.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC) {
		pr_warn("open_redirect: FUSE fs is not supported for open_redirect feature\n");
		path_put(&rp);
		path_put(&tp);
		return -EINVAL;
	}

	/* Schemes 1 and 2 are decisions about the KernelSU su domain.  Upstream
	 * always has that sid (KernelSU hands it over at setuid-hook setup), an
	 * LKM resolves the context itself - and if it does not resolve, "not in
	 * su domain" is true for the su process too, i.e. the one process the
	 * rule exists to spare would be redirected.  Refuse loudly instead. */
	if (scheme == UID_ROOT_PROC_EXCEPT_SU_PROC ||
	    scheme == UID_NON_SU_PROC) {
		or_resolve_su_sid();
		if (!or_su_sid) {
			pr_warn("open_redirect: scheme %d needs a resolvable su domain - set or_su_ctx=u:r:su:s0 (currently \"%s\")\n",
				scheme, or_su_ctx);
			path_put(&rp);
			path_put(&tp);
			return -EOPNOTSUPP;
		}
	}

	/* Register the hooks BEFORE touching any entry: a rule that is listed but
	 * cannot fire (because the hook is missing) silently does nothing while
	 * looking configured - worse than no rule at all. */
	rc = or_register();
	if (rc) {
		path_put(&rp);
		path_put(&tp);
		pr_warn("open_redirect: hook registration failed %d\n", rc);
		return rc;
	}
	or_register_reverse();

	/* upstream susfs.c:867-881: a name that another rule already uses as its
	 * redirected path belongs to that rule's reverse entry and must not be
	 * taken over. */
	e = or_find_by_path(target);
	if (!e && or_is_redirected_path(target)) {
		pr_warn("open_redirect: '%s' cannot be added because it is used for reversed lookup only\n",
			target);
		path_put(&rp);
		path_put(&tp);
		return -EINVAL;
	}

	if (e) {
		/* Rewriting a live entry: mark it dead and retire its old paths.
		 * Freeing them here would race a concurrent reader holding one. */
		WRITE_ONCE(e->dead, true);
		smp_wmb();
		or_retire_path(&e->redirected_path);
		or_retire_path(&e->target_path);
	} else {
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
	e->redirected_ino = ri->i_ino;
	e->redirected_dev = ri->i_sb->s_dev;
	e->redirected_path = rp;   /* transfer the cached references */
	e->target_path = tp;
	e->uid_scheme = scheme;
	smp_wmb();
	WRITE_ONCE(e->dead, false);	/* publish last: readers key off this */

	return 0;			/* both path references now belong to e */
}

/* Only the rules whose target path matches are dropped; the reverse entry is not
 * a separate object here, so it goes with the rule by definition. */
static void or_del(const char *target)
{
	struct sus_or_entry *e;

	e = or_find_by_path(target);
	if (!e)
		return;

	/* Retire, never free: an in-flight reader may still hold these paths.
	 * The slot stays in the array (marked dead) and is reused by or_add. */
	WRITE_ONCE(e->dead, true);
	smp_wmb();
	or_retire_path(&e->redirected_path);
	or_retire_path(&e->target_path);
	e->redirected_path.dentry = NULL;
	e->redirected_path.mnt = NULL;
	e->target_path.dentry = NULL;
	e->target_path.mnt = NULL;
	e->target_ino = 0;
	e->target_dev = 0;
	e->redirected_ino = 0;
	e->redirected_dev = 0;
	e->target_pathname[0] = '\0';
	e->redirected_pathname[0] = '\0';
}

/* Slots are never compacted (that array move was itself part of the race).
 * The kprobes stay registered for the module's whole lifetime: repeatedly
 * unregistering and re-registering them was observed to leave the hook silently
 * gone after a burst of add/del cycles, while an empty rule table already makes
 * the lookups miss - so staying registered costs nothing. */

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
