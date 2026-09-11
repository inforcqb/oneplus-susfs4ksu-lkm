// SPDX-License-Identifier: GPL-2.0
/*
 * sus_path.c - SUSFS SUS_PATH for the LKM, in two independent layers.
 *
 * Upstream SUSFS sets AS_FLAGS_SUS_PATH on inode->i_mapping and then
 *   (a) skips the entry inside filldir64() (fs/readdir.c), and
 *   (b) hides it from path-based access by patching fs/namei.c
 *       (link_path_walk returns -ENOENT; __lookup_slow/lookup_open redo the
 *       lookup with the fake qstr "..5.u.S" so the filesystem itself reports it).
 *
 * This LKM cannot touch either: filldir64 is static and LTO-inlined, and namei.c
 * is compiled into the kernel.  It reproduces both effects instead:
 *
 *   Layer 1 - directory entries
 *     The (sb dev, inode number) of every registered path goes into a list, and
 *     the buffer returned by getdents64 is rewritten on sys_exit, dropping
 *     entries whose d_ino matches.
 *
 *   Layer 2 - path-based access (stat/open/exec/...)
 *     Two LSM hooks are replaced (see the block below): inode_getattr covers
 *     stat/fstatat/statx, inode_permission covers open/exec/chmod/truncate/...
 *     Registered inodes are answered with -ENOENT, so the file appears not to
 *     exist at all - the same outcome as upstream's namei patch.
 *
 * Matching semantics deliberately mirror upstream:
 *   - exact inode identity, not name substring matching;
 *   - an unbounded set of registered paths (upstream keeps one inode flag each);
 *   - a path registered anywhere hides that inode everywhere it is reached,
 *     including via '..', '//', relative paths, symlinks, hard links and
 *     /proc/self/root/...;
 *   - the gate is the upstream one: app processes only, and never a file owned
 *     by the caller (see sus_path_gate_ok; hide_from_apps=0 disables the gate
 *     for testing from a root shell).
 */
#include <linux/module.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "lsm_hook.h"

#define DIRENT_BUF_SIZE 65536  /* getdents usually returns <= 32-64KB */
#define SUS_PATH_MAX_ENTRIES 8192

/* arm64 compat (32-bit) getdents64.  Not reachable through asm/unistd.h in this
 * build, so spelled out per arch/arm64/include/asm/unistd32.h. */
#define __NR_compat_getdents64 217

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define D_NAME_OFF offsetof(struct linux_dirent64, d_name)

/*
 * One registered path.
 *
 * Kept for two independent mechanisms:
 *   - the getdents64 filter hides the directory entry (by dev+ino+name);
 *   - the LSM hooks reject path-based access outright (by the ihold'ed inode
 *     pointer, which is what upstream's AS_FLAGS_SUS_PATH inode flag achieves).
 *
 * dev is kept for diagnostics only: a sys_exit tracepoint cannot recover the
 * listing's fd or superblock (regs->regs[0] already holds the return value).
 */
struct sus_path_entry {
    struct list_head list;
    struct inode *inode;    /* ihold'ed; NULL only if kern_path failed */
    u64 dev;
    u64 ino;
    char name[NAME_MAX + 1];
};

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);
static unsigned int sus_path_count;

/* legacy/debug: hide a single exact filename everywhere (empty = disabled) */
static char hide_name[NAME_MAX + 1];
module_param_string(hide_name, hide_name, sizeof(hide_name), 0644);

static char *dirent_tmp;

/* Guards dirent_tmp.  It is a single global scratch buffer shared by every
 * getdents64 exit, and the tracepoint can fire concurrently on several CPUs:
 * without this, two listings compact into the same buffer and one process can
 * get another directory's entries.  sus_path_lock cannot be reused - it is taken
 * inside the traversal by sus_path_is_hidden(). */
static DEFINE_SPINLOCK(sus_path_buf_lock);

static bool sus_path_is_hidden(u64 ino, const char *name)
{
    struct sus_path_entry *e;
    bool hidden = false;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list) {
        if (e->ino == ino && !strcmp(e->name, name)) {
            hidden = true;
            break;
        }
    }
    spin_unlock(&sus_path_lock);

    if (!hidden && hide_name[0])
        hidden = !strcmp(name, hide_name);

    return hidden;
}

/* ---------------------------------------------------------------------------
 * LSM hooks - make path-based access report ENOENT.
 *
 * Upstream hides sus_path entries from path-based access by patching
 * fs/namei.c (link_path_walk returns -ENOENT; __lookup_slow/lookup_open redo the
 * lookup with the fake qstr "..5.u.S" so the filesystem itself reports it).  A
 * loadable module cannot patch namei.c, but it can replace the two LSM hooks
 * that every path-based operation has to pass:
 *
 *   inode_getattr     <- vfs_getattr() calls security_inode_getattr() before it
 *                        ever looks at the inode: stat/fstatat/statx
 *   inode_permission  <- open/exec/chmod/truncate/chdir/readdir/...
 *
 * Matching on the inode pointer means '//', './', relative paths, symlinks
 * (followed), hard links, bind mounts and /proc/self/root/... are all covered -
 * none of them can dodge inode identity.  (unlink/rename operate on the PARENT
 * directory's inode, so they are not blocked here.)
 * ------------------------------------------------------------------------- */

static int sus_path_inode_getattr(const struct path *path);
static int sus_path_inode_permission(struct inode *inode, int mask);

/* The signatures MUST match the LSM hook types exactly, and must NOT be __nocfi:
 * this kernel uses kCFI with cross-module checks, so the call site compares type
 * hashes.  A mismatched signature panics, and __nocfi panics just as hard because
 * the function then emits no hash at all.  These assertions turn any mistake into
 * a build failure instead of a reboot.  NOTE: the address-of is required -
 * typeof(fn) is the function type while the hook field is a function pointer. */
#define LSM_HOOK_FN_TYPE(member) typeof(((union security_list_options *)0)->member)

static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_getattr),
					   typeof(&sus_path_inode_getattr)),
	      "inode_getattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_permission),
					   typeof(&sus_path_inode_permission)),
	      "inode_permission hook signature mismatch");

static struct ksu_lsm_hook sus_path_getattr_hook = KSU_LSM_HOOK_INIT(
	inode_getattr, "selinux_inode_getattr",
	(void *)sus_path_inode_getattr, 0);

static struct ksu_lsm_hook sus_path_perm_hook = KSU_LSM_HOOK_INIT(
	inode_permission, "selinux_inode_permission",
	(void *)sus_path_inode_permission, 0);

/* Upstream gates on susfs_is_current_proc_umounted_app() &&
 * is_i_uid_not_allowed(inode i_uid): only app processes, and never a file owned
 * by the caller.  TIF_PROC_UMOUNTED is a SUSFS-specific thread flag this LKM does
 * not have, so uid >= 10000 is the proxy.  Set hide_from_apps=0 to apply to every
 * process including root - handy when testing from an adb shell. */
static int hide_from_apps = 1;
module_param(hide_from_apps, int, 0644);

static atomic_t n_enoent_getattr = ATOMIC_INIT(0);
static atomic_t n_enoent_perm = ATOMIC_INIT(0);

static bool sus_path_inode_hidden(struct inode *inode)
{
    struct sus_path_entry *e;
    bool hidden = false;

    if (!inode || !READ_ONCE(sus_path_count))
        return false;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list) {
        if (e->inode == inode) {
            hidden = true;
            break;
        }
    }
    spin_unlock(&sus_path_lock);

    return hidden;
}

/* UID half of the upstream gate.  Separate because the getdents64 tracepoint
 * only has an inode NUMBER, not an inode, so it cannot apply the ownership
 * check below. */
static inline bool sus_path_gate_uid_ok(void)
{
    if (!hide_from_apps)
        return true;
    return current_uid().val >= 10000;
}

/* Full upstream gate for the LSM layer: an app process, and the file is not
 * owned by the caller (upstream is_i_uid_not_allowed()).
 *
 * hide_from_apps=0 must bypass the WHOLE gate, ownership check included -
 * otherwise a root-owned file would still be skipped for root (0 != 0 is false)
 * and disabling the gate would silently do nothing for exactly the case it is
 * meant for. */
static inline bool sus_path_gate_ok(struct inode *inode)
{
    if (!hide_from_apps)
        return true;
    if (current_uid().val < 10000)
        return false;
    return current_uid().val != inode->i_uid.val;
}

static int sus_path_inode_getattr(const struct path *path)
{
    int (*orig)(const struct path *) = (void *)sus_path_getattr_hook.original;
    struct inode *inode;

    if (path && path->dentry) {
        inode = d_inode(path->dentry);
        if (sus_path_inode_hidden(inode) && sus_path_gate_ok(inode)) {
            atomic_inc(&n_enoent_getattr);
            return -ENOENT;
        }
    }
    if (!orig)
        return 0;
    return orig(path);
}

static int sus_path_inode_permission(struct inode *inode, int mask)
{
    int (*orig)(struct inode *, int) = (void *)sus_path_perm_hook.original;

    if (sus_path_inode_hidden(inode) && sus_path_gate_ok(inode)) {
        atomic_inc(&n_enoent_perm);
        return -ENOENT;
    }
    if (!orig)
        return 0;
    return orig(inode, mask);
}

/* ---- DAC layer ----
 *
 * Everything else in this file sits either after the DAC check (the LSM hooks)
 * or beside it (the getdents64 tracepoint).  inode_permission() is:
 *
 *     retval = sb_permission(...);
 *     retval = do_inode_permission(...);        DAC   <-- EACCES leaves HERE
 *     retval = devcgroup_inode_permission(...);
 *     return security_inode_permission(...);    our LSM hook
 *
 * So an inode the caller may not touch is answered EACCES before any hook of
 * ours runs - and "permission denied" also tells the caller the entry EXISTS,
 * which is precisely what sus_path must never say.  Reported from the device:
 * an app listing /data/adb/service.d got EACCES, while every earlier test had
 * passed because those used 0755 paths (/data/local/tmp) where DAC lets the
 * caller through and the LSM layer is reached.
 *
 * Upstream rewrites the answer inside fs/namei.c at the lookup level, i.e.
 * before the target inode is permission-checked at all.  An LKM cannot patch
 * namei: the helpers are inlined by this kernel's LTO (lookup_fast and
 * open_last_lookups have no symbol) and struct nameidata is defined inside
 * fs/namei.c rather than in a header.
 *
 * DAC, however, has exactly one entry point and it is exported: skip
 * inode_permission() itself for a hidden inode.  Being entered before a single
 * check runs, one kprobe covers every caller - including the path walk's own
 * MAY_EXEC check on a hidden directory, which is what makes
 * `ls /data/adb/service.d` answer ENOENT once /data/adb is registered.
 *
 * The limit no layer can remove: hiding a child of a directory that denies the
 * caller and is not itself registered still answers EACCES, because the walk
 * cannot reach the child's lookup at all.  Upstream behaves the same way -
 * register the directory. */
static atomic_t n_enoent_dac = ATOMIC_INIT(0);      /* inode_permission */
static atomic_t n_enoent_gper = ATOMIC_INIT(0);     /* generic_permission */

/* The other layers' decision, reused so every layer agrees. */
static bool sus_path_lookup_hit(struct inode *inode)
{
    if (!inode)
        return false;
    return sus_path_inode_hidden(inode) && sus_path_gate_ok(inode);
}

/* 5.15 signature: inode_permission(struct user_namespace *mnt_userns,
 * struct inode *inode, int mask) - the inode is argument 2, i.e. x1.  If that
 * ever changes the lookup simply misses and nothing else is affected. */
static int kp_dac_hit(struct pt_regs *regs, atomic_t *counter)
{
    struct inode *inode = (struct inode *)regs->regs[1];

    if (!sus_path_lookup_hit(inode))
        return 0;

    atomic_inc(counter);
    /* Says whether this probe is reached at all: on this kernel both DAC
     * symbols look inlined, and only a hit proves otherwise. */
    pr_info_ratelimited("sus_path: DAC hit on ino=%lu (uid=%u)\n",
                        inode->i_ino, current_uid().val);
    /* Answer "no such file" and skip the whole function: the DAC check inside
     * it is what would otherwise answer EACCES. */
    regs_set_return_value(regs, (unsigned long)-ENOENT);
    regs->pc = regs->regs[30];
    return 1;
}

static int kp_inode_permission_pre(struct kprobe *kp, struct pt_regs *regs)
{
    return kp_dac_hit(regs, &n_enoent_dac);
}

/* inode_permission() itself turns out to be a dead end on this kernel: the
 * 0600-file test (DAC denies the app, so the LSM layer can never be reached)
 * still answered EACCES, i.e. the kprobe never fired - GKI's LTO inlines the
 * function into its callers and the kallsyms entry is just the copy kept for
 * module references.  Patching its entry would be equally pointless.
 *
 * generic_permission() is where that DAC decision actually lands for any
 * filesystem without its own ->permission(), and it is NOT inlined (it has both
 * a symbol and a .cfi_jt entry).  Same handler, same answer. */
static int kp_generic_permission_pre(struct kprobe *kp, struct pt_regs *regs)
{
    return kp_dac_hit(regs, &n_enoent_gper);
}

static struct kprobe kp_inode_permission = {
    .symbol_name = "inode_permission",
    .pre_handler = kp_inode_permission_pre,
};

static struct kprobe kp_generic_permission = {
    .symbol_name = "generic_permission",
    .pre_handler = kp_generic_permission_pre,
};

static struct kprobe *dac_probes[] = {
    &kp_inode_permission,
    &kp_generic_permission,
};

#define N_DAC_PROBES ARRAY_SIZE(dac_probes)
static bool dac_registered[N_DAC_PROBES];

/* Off means an app gets EACCES instead of ENOENT whenever the DAC check would
 * have denied it - i.e. the layer this exists for. */
static int hide_by_dac = 1;
module_param_named(hide_by_dac, hide_by_dac, int, 0644);

static void sus_path_dac_register(void)
{
    int i;

    if (!hide_by_dac)
        return;

    for (i = 0; i < N_DAC_PROBES; i++) {
        int rc = register_kprobe(dac_probes[i]);

        if (rc) {
            pr_warn("sus_path: kprobe(%s) failed %d\n",
                    dac_probes[i]->symbol_name, rc);
            continue;
        }
        dac_registered[i] = true;
    }
    pr_info("sus_path: DAC layer armed (inode_permission=%d generic_permission=%d)\n",
            dac_registered[0], dac_registered[1]);
}

static void sus_path_dac_unregister(void)
{
    int i;

    for (i = 0; i < N_DAC_PROBES; i++) {
        if (!dac_registered[i])
            continue;
        unregister_kprobe(dac_probes[i]);
        dac_registered[i] = false;
    }
}

/* ---- lookup layer ----
 *
 * The DAC probes above turn out not to fire on this kernel: a registered 0600
 * root file still answers EACCES on read, which only happens if neither
 * inode_permission() nor generic_permission() is reached - GKI's LTO inlines
 * them into their callers, so the kallsyms entries are just the copies kept for
 * module references.  (That also answers "why not patch a jump instead of using
 * a kprobe": patching those entries would rewrite code nothing executes.)
 *
 * So the answer has to be produced where upstream produces it - at lookup time,
 * before the target inode is permission-checked at all.  Upstream patches
 * fs/namei.c; an LKM cannot, but it can watch the lookup helpers, and unlike the
 * DAC helpers these are big enough that LTO leaves them alone (each has a symbol
 * and a .cfi_jt entry, verified on the device).
 *
 * A hit is rewritten into -ENOENT:
 *   - walk_component()  every component of the path walk, i.e. also the
 *                       directory whose MAY_EXEC check would answer EACCES;
 *   - lookup_dcache()   open's last component;
 *   - __lookup_slow()   the cache-miss path.
 *
 * struct nameidata is defined inside fs/namei.c, not in a header, so it cannot
 * be declared here.  It is not needed either: the only field used is the first
 * one, and nameidata has always started with `struct path path`.  Reading that
 * prefix is what keeps this compilable. */
struct sus_path_nd_prefix {
    struct path path;
};

struct sus_path_walk_args {
    struct sus_path_nd_prefix *nd;
};

static int kr_walk_component_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_path_walk_args *a = (struct sus_path_walk_args *)ri->data;

    a->nd = (struct sus_path_nd_prefix *)regs->regs[0];
    return 0;
}

/* walk_component() returns 1 with nd->path already moved to the component it
 * resolved, so rewriting that into -ENOENT makes the walk stop here - before
 * the caller's inode_permission() on the parent can answer EACCES. */
static int kr_walk_component_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_path_walk_args *a = (struct sus_path_walk_args *)ri->data;
    struct dentry *d;

    if ((long)regs_return_value(regs) <= 0 || !a->nd)
        return 0;

    d = READ_ONCE(a->nd->path.dentry);
    if (d && sus_path_lookup_hit(READ_ONCE(d->d_inode)))
        regs_set_return_value(regs, (unsigned long)-ENOENT);
    return 0;
}

/* lookup_dcache() and __lookup_slow() return struct dentry *, so they take the
 * ERR_PTR form. */
static int kr_lookup_dcache_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dentry *d = (struct dentry *)regs_return_value(regs);

    if (IS_ERR_OR_NULL(d))
        return 0;
    if (sus_path_lookup_hit(READ_ONCE(d->d_inode)))
        regs_set_return_value(regs, (unsigned long)ERR_PTR(-ENOENT));
    return 0;
}

static struct kretprobe krp_walk_component = {
    .kp.symbol_name = "walk_component",
    .entry_handler = kr_walk_component_entry,
    .handler = kr_walk_component_ret,
    .data_size = sizeof(struct sus_path_walk_args),
    .maxactive = 64,
};

static struct kretprobe krp_lookup_dcache = {
    .kp.symbol_name = "lookup_dcache",
    .handler = kr_lookup_dcache_ret,
    .maxactive = 64,
};

static struct kretprobe krp_lookup_slow = {
    .kp.symbol_name = "__lookup_slow",
    .handler = kr_lookup_dcache_ret,     /* same return-value rewrite */
    .maxactive = 64,
};

static struct kretprobe *lookup_krps[] = {
    &krp_walk_component,
    &krp_lookup_dcache,
    &krp_lookup_slow,
};

#define N_LOOKUP_KRPS ARRAY_SIZE(lookup_krps)
static bool lookup_registered[N_LOOKUP_KRPS];

static void sus_path_lookup_register(void)
{
    int i;

    for (i = 0; i < N_LOOKUP_KRPS; i++) {
        int rc = register_kretprobe(lookup_krps[i]);

        if (rc) {
            pr_warn("sus_path: kretprobe(%s) failed %d\n",
                    lookup_krps[i]->kp.symbol_name, rc);
            continue;
        }
        lookup_registered[i] = true;
    }
    pr_info("sus_path: lookup layer armed (walk_component=%d lookup_dcache=%d __lookup_slow=%d)\n",
            lookup_registered[0], lookup_registered[1], lookup_registered[2]);
}

static void sus_path_lookup_unregister(void)
{
    int i;

    for (i = 0; i < N_LOOKUP_KRPS; i++) {
        if (!lookup_registered[i])
            continue;
        unregister_kretprobe(lookup_krps[i]);
        lookup_registered[i] = false;
    }
}

/* compact the dirent chain in-place; returns the new byte count */
static long sus_path_filter(unsigned long buf, long count)
{
    long offset = 0;
    long out = 0;
    char *tmp;
    bool complete = true;

    spin_lock(&sus_path_buf_lock);

    tmp = dirent_tmp;
    if (!tmp) {
        spin_unlock(&sus_path_buf_lock);
        return count;
    }

    while (offset < count) {
        struct linux_dirent64 d;
        unsigned short reclen;
        char name[NAME_MAX + 1];
        long nlen;
        bool hide;

        if (copy_from_user(&d, (void __user *)(buf + offset), sizeof(d))) {
            complete = false;
            break;
        }
        reclen = d.d_reclen;
        /* d_reclen is filesystem-supplied: bound it before it is used as a
         * copy length, as a step, and before out+reclen can leave the buffer. */
        if (reclen < D_NAME_OFF + 1 ||
            offset + reclen > count ||
            reclen > DIRENT_BUF_SIZE - out) {
            complete = false;
            break;
        }

        nlen = strnlen_user((void __user *)(buf + offset + D_NAME_OFF),
                            sizeof(name) - 1);
        if (nlen == 0) {            /* no readable NUL in the name field */
            complete = false;
            break;
        }
        if (nlen >= sizeof(name))   /* longer than NAME_MAX: cannot match */
            nlen = sizeof(name) - 1;
        if (nlen > reclen - D_NAME_OFF) {
            complete = false;
            break;
        }
        if (copy_from_user(name, (void __user *)(buf + offset + D_NAME_OFF), nlen)) {
            complete = false;
            break;
        }
        name[nlen] = 0;

        hide = sus_path_is_hidden((u64)d.d_ino, name);
        /* Same gate as the LSM layer, otherwise listing and open would disagree
         * (upstream's filldir64 also goes through susfs_is_inode_sus_path). */
        if (hide && !sus_path_gate_uid_ok())
            hide = false;

        if (!hide) {
            if (copy_from_user(tmp + out, (void __user *)(buf + offset), reclen)) {
                complete = false;
                break;
            }
            out += reclen;
        }
        offset += reclen;
    }

    /* A partial compaction would silently drop every record after the failure
     * point (the old code returned the partial count), so on any failure hand
     * the listing back exactly as the kernel wrote it and filter nothing. */
    if (!complete) {
        spin_unlock(&sus_path_buf_lock);
        return count;
    }

    if (out != count)   /* out == count means nothing was hidden */
        if (copy_to_user((void __user *)buf, tmp, out))
            out = count;   /* failed to write back: leave untouched */

    spin_unlock(&sus_path_buf_lock);
    return out;
}

static void sus_path_sys_exit(void *data, struct pt_regs *regs, long ret)
{
    unsigned long args[6];
    unsigned long dirent_buf;
    long new_count;
    int nr;

    /* 32-bit tasks reach getdents64 through the compat table with a different
     * syscall number, but the dirent64 buffer layout is identical (v5.15 has no
     * compat_filldir64).  The old code returned early for compat tasks, which
     * left 32-bit apps able to list hidden entries for no reason. */
    nr = syscall_get_nr(current, regs);
    if (is_compat_task()) {
        if (nr != __NR_compat_getdents64)
            return;
    } else if (nr != __NR_getdents64) {
        return;
    }

    if (ret <= 0)
        return;
    if (!READ_ONCE(sus_path_count) && !hide_name[0])
        return;

    /* NOTE: in a sys_exit probe regs->regs[0] already holds the return value,
     * so only args[1] (the buffer) and args[2] (the byte count) are usable. */
    syscall_get_arguments(current, regs, args);
    dirent_buf = args[1];
    if (!dirent_buf)
        return;

    new_count = sus_path_filter(dirent_buf, ret);

    if (new_count != ret)
        regs->regs[0] = new_count;   /* shrink the returned byte count */
}

/* read-only view of the registered paths, for verification */
static int sus_path_show_list(char *buf, const struct kernel_param *kp)
{
    struct sus_path_entry *e;
    int n = 0;

    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "hide_from_apps=%d  enoent: getattr=%d perm=%d dac=%d gper=%d\n",
                   hide_from_apps, atomic_read(&n_enoent_getattr),
                   atomic_read(&n_enoent_perm), atomic_read(&n_enoent_dac),
                   atomic_read(&n_enoent_gper));

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list)
        n += scnprintf(buf + n, PAGE_SIZE - n,
                       "dev=%llu ino=%llu name=%s\n",
                       e->dev, e->ino, e->name);
    spin_unlock(&sus_path_lock);

    if (!sus_path_count)
        n += scnprintf(buf + n, PAGE_SIZE - n, "(no paths registered)\n");
    return n;
}

static const struct kernel_param_ops sus_path_list_ops = {
    .get = sus_path_show_list,
};
/* 0400, not 0444: this listing names every hidden path.  It must not be
 * readable by an app - that would hand the detector the exact answer it is
 * looking for.  (A raw inode pointer used to be printed here too; removed.) */
module_param_cb(hide_list, &sus_path_list_ops, NULL, 0400);

static bool path_registered;

/* Add a path to the hidden set from kernel code, bypassing the supercall.
 * Used by susfs_init() to self-hide the /proc control nodes.
 *
 * Same entry shape and the same ihold discipline as sus_path_supercall(): the
 * inode pointer is what the LSM layer matches on, and it must outlive
 * path_put() below or the address could be recycled. */
int sus_path_add_hidden(const char *path)
{
	struct path p;
	struct inode *inode;
	struct sus_path_entry *e;
	int rc;

	rc = kern_path(path, LOOKUP_FOLLOW, &p);
	if (rc)
		return rc;

	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		path_put(&p);
		return -ENOMEM;
	}

	e->dev = (u64)inode->i_sb->s_dev;
	e->ino = (u64)inode->i_ino;
	e->inode = inode;
	ihold(inode);
	strscpy(e->name, p.dentry->d_name.name, sizeof(e->name));
	INIT_LIST_HEAD(&e->list);
	path_put(&p);

	spin_lock(&sus_path_lock);
	{
		struct sus_path_entry *cur;

		list_for_each_entry(cur, &sus_path_list, list) {
			if (cur->inode == inode) {
				spin_unlock(&sus_path_lock);
				iput(e->inode);
				kfree(e);
				return 0;	/* already hidden */
			}
		}
	}
	if (sus_path_count >= SUS_PATH_MAX_ENTRIES) {
		spin_unlock(&sus_path_lock);
		iput(e->inode);
		kfree(e);
		return -ENOSPC;
	}
	list_add_tail(&e->list, &sus_path_list);
	sus_path_count++;
	spin_unlock(&sus_path_lock);

	pr_info("sus_path: hidden (built-in) '%s'\n", path);
	return 0;
}

/* Whether the path-based layer actually installed.  Both hooks must be patched:
 * with only one, stat and open would disagree with each other. */
bool sus_path_lsm_active(void)
{
	return sus_path_getattr_hook.entry && sus_path_perm_hook.entry;
}

int sus_path_init(void)
{
    int rc;

    dirent_tmp = kmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
    if (!dirent_tmp) {
        pr_warn("sus_path: kmalloc failed\n");
        return -ENOMEM;
    }

    rc = register_trace_sys_exit(sus_path_sys_exit, NULL);
    if (rc)
        pr_warn("register_trace_sys_exit(getdents64) failed %d\n", rc);
    else {
        path_registered = true;
        pr_info("sus_path: getdents64 filter armed\n");
    }

    /* LSM hooks: reject path-based access to registered inodes outright. */
    rc = ksu_register_lsm_hook(&sus_path_getattr_hook);
    if (rc)
        pr_warn("sus_path: getattr hook failed %d\n", rc);
    else
        pr_info("sus_path: getattr hook armed, orig=%ps\n",
                sus_path_getattr_hook.original);

    rc = ksu_register_lsm_hook(&sus_path_perm_hook);
    if (rc)
        pr_warn("sus_path: perm hook failed %d\n", rc);
    else
        pr_info("sus_path: perm hook armed, orig=%ps\n",
                sus_path_perm_hook.original);

    /* And the DAC layer, without which a caller DAC denies gets EACCES instead
     * of ENOENT (see the note above it). */
    sus_path_dac_register();

    /* Plus the lookup layer: the DAC probes above do not fire on this kernel,
     * and this is the layer that actually answers ENOENT before the DAC check
     * on a hidden directory can answer EACCES. */
    sus_path_lookup_register();

    return 0;
}

void sus_path_exit(void)
{
    struct sus_path_entry *e, *tmp;
    LIST_HEAD(doomed);

    /* Unregister the hooks FIRST: after this nothing can match, so the entries
     * (and their inode references) can be torn down safely. */
    sus_path_lookup_unregister();
    sus_path_dac_unregister();
    if (sus_path_perm_hook.entry)
        ksu_unregister_lsm_hook(&sus_path_perm_hook);
    if (sus_path_getattr_hook.entry)
        ksu_unregister_lsm_hook(&sus_path_getattr_hook);

    if (path_registered) {
        unregister_trace_sys_exit(sus_path_sys_exit, NULL);
        tracepoint_synchronize_unregister();
        path_registered = false;
    }
    kfree(dirent_tmp);
    dirent_tmp = NULL;

    spin_lock(&sus_path_lock);
    list_splice_init(&sus_path_list, &doomed);
    sus_path_count = 0;
    spin_unlock(&sus_path_lock);

    /* iput outside the lock: it can sleep and evict the inode. */
    list_for_each_entry_safe(e, tmp, &doomed, list) {
        list_del(&e->list);
        if (e->inode)
            iput(e->inode);
        kfree(e);
    }
}

/* supercall: CMD_SUSFS_ADD_SUS_PATH / CMD_SUSFS_ADD_SUS_PATH_LOOP
 *
 * Upstream keeps every added path (one inode flag per path) and its _LOOP variant
 * only re-flags the same inode after a zygote-spawned app is marked umounted.
 * Since our list is permanent and the match is unconditional, both commands do
 * exactly the same thing here. */
void sus_path_supercall(void __user **arg)
{
    struct st_susfs_sus_path info = {0};
    struct sus_path_entry *e;
    struct path path;
    struct inode *inode;
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    if (!info.target_pathname[0]) {
        info.err = -EINVAL;
        goto out;
    }
    /* The field is char[256] and need not be NUL-terminated; kern_path() on an
     * unterminated one reads off the end of our stack copy of the struct. */
    if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {
        info.err = -ENAMETOOLONG;
        goto out;
    }

    rc = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
    if (rc) {
        pr_warn("sus_path: failed opening '%s' (%d)\n", info.target_pathname, rc);
        info.err = rc;
        goto out;
    }

    inode = d_inode(path.dentry);
    if (!inode) {
        path_put(&path);
        info.err = -ENOENT;
        goto out;
    }

    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        path_put(&path);
        info.err = -ENOMEM;
        goto out;
    }
    e->dev = (u64)inode->i_sb->s_dev;
    e->ino = (u64)inode->i_ino;
    e->inode = inode;
    /* Hold the inode: the LSM hooks match on this pointer, and the dentry is
     * about to be released by path_put(), which would otherwise be free to
     * evict it and let the address be reused. */
    ihold(inode);
    strscpy(e->name, path.dentry->d_name.name, sizeof(e->name));
    INIT_LIST_HEAD(&e->list);
    path_put(&path);

    if (!e->ino) {
        /* filesystem does not expose a usable inode number: fall back to name */
        pr_warn("sus_path: '%s' has ino 0, falling back to name matching\n",
                info.target_pathname);
    }

    spin_lock(&sus_path_lock);
    if (sus_path_count >= SUS_PATH_MAX_ENTRIES) {
        spin_unlock(&sus_path_lock);
        iput(e->inode);
        kfree(e);
        info.err = -ENOSPC;
        goto out;
    }
    {
        struct sus_path_entry *cur;
        list_for_each_entry(cur, &sus_path_list, list) {
            if (cur->inode == inode) {
                spin_unlock(&sus_path_lock);
                iput(e->inode);
                kfree(e);
                info.err = 0;   /* already registered, upstream is idempotent */
                goto out;
            }
        }
    }
    list_add_tail(&e->list, &sus_path_list);
    sus_path_count++;
    spin_unlock(&sus_path_lock);

    if (!dirent_tmp) {
        dirent_tmp = kmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
        if (!dirent_tmp) {
            info.err = -ENOMEM;
            goto out;
        }
    }
    if (!path_registered) {
        rc = register_trace_sys_exit(sus_path_sys_exit, NULL);
        if (rc) {
            info.err = rc;
            goto out;
        }
        path_registered = true;
    }

    info.err = 0;
    pr_info("sus_path: hide '%s' (dev=%llu ino=%llu)\n",
            info.target_pathname, e->dev, e->ino);
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_path __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_path supercall copy_to_user failed\n");
}
