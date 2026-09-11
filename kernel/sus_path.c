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
#include <linux/compat.h>	/* compat_ptr(), for 32-bit callers */
#include <linux/limits.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact, for optional compat probes */
#include "susfs_inline_hook.h"	/* entry patching, replaces the hot kprobes */
#include "lsm_hook.h"

#define DIRENT_BUF_SIZE 65536  /* getdents usually returns <= 32-64KB */
#define SUS_PATH_MAX_ENTRIES 8192
/* Longest registered path, for the string-level hooks.  256 matches the ABI's
 * target_pathname field. */
#define SUS_PATH_LEN 256

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
    /* The path as it was registered, for the string-level hooks below: the
     * lookup entry points hand us the caller's own path string, not an inode.
     * Stored without a trailing slash, path_len == strlen(path). */
    char path[SUS_PATH_LEN];
    unsigned int path_len;
};

static void sus_path_entry_set_path(struct sus_path_entry *e, const char *path);

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

/* Store the registered path for the string-level hooks, without a trailing
 * slash (so "path/" and "path" both match "path" and "path/child"). */
static void sus_path_entry_set_path(struct sus_path_entry *e, const char *path)
{
    size_t n = strnlen(path, SUS_PATH_LEN - 1);

    while (n > 1 && path[n - 1] == '/')
        n--;
    memcpy(e->path, path, n);
    e->path[n] = '\0';
    e->path_len = (unsigned int)n;
}

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

/* ---- path-string layer ----
 *
 * Measured on this device: inode_permission, generic_permission, walk_component,
 * lookup_dcache and __lookup_slow all register as kprobes and then never fire.
 * GKI's full LTO inlines them into their callers, so their kallsyms entries are
 * only the out-of-line copies kept for module references - which is also the
 * answer to "why not patch a jump in instead of a kprobe": patching those
 * entries would rewrite code nothing executes.
 *
 * Every hook of ours that does work on this kernel is one that LTO cannot
 * inline: vfs_open, vfs_getattr, show_map_vma (called through a function
 * pointer) and __arm64_sys_reboot - i.e. functions called across compilation
 * units.  The path-resolution entry points are the same kind of citizen, and
 * they are where the answer has to be produced: before any permission check on
 * the target, so a hidden directory answers ENOENT instead of EACCES.
 *
 * They hand us the caller's path STRING (struct filename::name), not an inode,
 * so matching is string-based: an absolute path that equals a registered path,
 * or has one as a '/'-terminated prefix.  Upstream matches by inode instead,
 * which also catches symlinked spellings and relative paths; a relative path is
 * skipped here because it cannot be compared without the cwd - and reaching one
 * under a hidden directory requires the directory's MAY_EXEC first, which the
 * lookup on it does cover.
 *
 *   filename_lookup     stat/access/chdir and friends (kernel-side string)
 *   do_filp_open        open/openat (kernel-side string)
 *   user_path_at_empty  the same, one level up, in case the above are inlined
 *                       into it - takes a __user pointer, read with
 *                       strncpy_from_user
 */
static atomic_t n_enoent_path = ATOMIC_INIT(0);

static bool sus_path_match_path(const char *path)
{
    struct sus_path_entry *e;
    bool hit = false;

    if (!path || path[0] != '/')    /* only absolute paths are comparable */
        return false;
    if (!sus_path_gate_uid_ok())
        return false;
    if (!READ_ONCE(sus_path_count))
        return false;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list) {
        unsigned int n = e->path_len;

        if (!n || strncmp(path, e->path, n))
            continue;
        if (path[n] == '\0' || path[n] == '/') {
            hit = true;
            break;
        }
    }
    spin_unlock(&sus_path_lock);
    return hit;
}

/* Shared tail: count, log (so that "registered" and "reached" can be told
 * apart, which is exactly what the DAC probes above failed to do), answer
 * -ENOENT and skip the function. */
static int kp_path_answer(struct pt_regs *regs, const char *name, bool errptr)
{
    if (!sus_path_match_path(name))
        return 0;

    atomic_inc(&n_enoent_path);
    pr_info_ratelimited("sus_path: path hit '%s' (uid=%u)\n",
                        name, current_uid().val);
    if (errptr)
        regs_set_return_value(regs, (unsigned long)ERR_PTR(-ENOENT));
    else
        regs_set_return_value(regs, (unsigned long)-ENOENT);
    regs->pc = regs->regs[30];
    return 1;
}

/* filename_lookup(dfd, struct filename *name, ...) and
 * do_filp_open(dfd, struct filename *pathname, ...): the name is argument 2 in
 * both, already a kernel string. */
static int kp_filename_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct filename *f = (struct filename *)regs->regs[1];

    if (!f || !f->name)
        return 0;
    return kp_path_answer(regs, f->name, false);
}

static int kp_filp_open_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct filename *f = (struct filename *)regs->regs[1];

    if (!f || !f->name)
        return 0;
    return kp_path_answer(regs, f->name, true);     /* returns struct file * */
}

/* user_path_at_empty(dfd, const char __user *name, ...) */
static int kp_user_path_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const char __user *uname = (const char __user *)regs->regs[1];
    char buf[SUS_PATH_LEN];
    long n;

    if (!uname)
        return 0;
    /* Bounded read of the caller's own path.  Fails harmlessly (-EFAULT) if the
     * page is not there; this is the same uaccess the getdents64 tracepoint
     * already does in a context that cannot sleep. */
    n = strncpy_from_user(buf, uname, sizeof(buf) - 1);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return kp_path_answer(regs, buf, false);
}

static struct kprobe kp_filename_lookup = {
    .symbol_name = "filename_lookup",
    .pre_handler = kp_filename_pre,
};

static struct kprobe kp_filp_open = {
    .symbol_name = "do_filp_open",
    .pre_handler = kp_filp_open_pre,
};

static struct kprobe kp_user_path = {
    .symbol_name = "user_path_at_empty",
    .pre_handler = kp_user_path_pre,
};

/* ---- syscall-entry layer ----
 *
 * The measured rule on this kernel: only ABI entry points and a handful of
 * cross-unit functions survive LTO as symbols that are actually executed.
 * filename_lookup earns its keep (its hit log fired for stat), but do_filp_open
 * is called from do_sys_openat2 in the same file and was inlined, so `cat` on a
 * hidden 0600 file still answered EACCES.
 *
 * Syscall wrappers cannot be inlined - they ARE the ABI - which is why the
 * supercall probe on __arm64_sys_reboot has never missed.  Same treatment: read
 * the caller's path and answer -ENOENT straight away, before any permission
 * check runs.
 *
 * These wrappers take the user's registers as their only argument, so
 * regs->regs[0] is the pt_regs to read from (verified for this kernel by the
 * uname and supercall probes, which rely on the same fact); argno is the
 * x-register holding the pathname in the 64-bit ABI. */
static int kp_sys_path_answer(struct pt_regs *regs, int argno)
{
    const struct pt_regs *uregs = (const struct pt_regs *)regs->regs[0];
    unsigned long reg;
    void __user *up;
    char buf[SUS_PATH_LEN];
    long n;

    if (!uregs)
        return 0;

    reg = uregs->regs[argno];
    /* A 32-bit task's registers are 32 bits wide: only the low half of the saved
     * slot is meaningful, so mask it exactly like compat_ptr() does - otherwise
     * whatever the upper half holds becomes part of a user pointer. */
    if (is_compat_task()) {
#ifdef CONFIG_COMPAT
        up = compat_ptr((u32)reg);
#else
        return 0;
#endif
    } else {
        up = (void __user *)reg;
    }

    n = strncpy_from_user(buf, (const char __user *)up, sizeof(buf) - 1);
    if (n <= 0 && is_compat_task())
        pr_info_ratelimited("sus_path: compat pathname unreadable (reg=%#lx) - the getname layer covers this\n",
                            reg);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return kp_path_answer(regs, buf, false);    /* syscalls return long */
}

#define SUSFS_SYS_PROBE(fn, argno)					\
	static int kp_##fn##_pre(struct kprobe *kp, struct pt_regs *regs) \
	{								\
		return kp_sys_path_answer(regs, argno);			\
	}								\
	static struct kprobe kp_##fn = {				\
		.symbol_name = #fn,					\
		.pre_handler = kp_##fn##_pre,				\
	}

SUSFS_SYS_PROBE(__arm64_sys_openat, 1);
SUSFS_SYS_PROBE(__arm64_sys_openat2, 1);
SUSFS_SYS_PROBE(__arm64_sys_newfstatat, 1);
SUSFS_SYS_PROBE(__arm64_sys_statx, 1);
SUSFS_SYS_PROBE(__arm64_sys_faccessat, 1);
SUSFS_SYS_PROBE(__arm64_sys_faccessat2, 1);
SUSFS_SYS_PROBE(__arm64_sys_readlinkat, 1);
SUSFS_SYS_PROBE(__arm64_sys_execve, 0);

static struct kprobe *sys_path_probes[] = {
    &kp___arm64_sys_openat,
    &kp___arm64_sys_openat2,
    &kp___arm64_sys_newfstatat,
    &kp___arm64_sys_statx,
    &kp___arm64_sys_faccessat,
    &kp___arm64_sys_faccessat2,
    &kp___arm64_sys_readlinkat,
    &kp___arm64_sys_execve,
};

/* 32-bit (AArch32) callers.
 *
 * Only the syscalls that need different semantics get their own wrapper: on
 * this kernel kallsyms has __arm64_compat_sys_openat, _execve and _execveat and
 * nothing else, which means the rest of the 32-bit table points at the very
 * __arm64_sys_* wrappers above and is already covered.  These entries are
 * registered only when the symbol exists, so a name that is absent on another
 * kernel is skipped silently instead of warning. */
SUSFS_SYS_PROBE(__arm64_compat_sys_openat, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_openat2, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_fstatat64, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_statx, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_faccessat, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_readlinkat, 1);
SUSFS_SYS_PROBE(__arm64_compat_sys_execve, 0);

static struct kprobe *compat_path_probes[] = {
    &kp___arm64_compat_sys_openat,
    &kp___arm64_compat_sys_openat2,
    &kp___arm64_compat_sys_fstatat64,
    &kp___arm64_compat_sys_statx,
    &kp___arm64_compat_sys_faccessat,
    &kp___arm64_compat_sys_readlinkat,
    &kp___arm64_compat_sys_execve,
};

#define N_SYS_PATH_PROBES ARRAY_SIZE(sys_path_probes)
#define N_COMPAT_PATH_PROBES ARRAY_SIZE(compat_path_probes)
static bool sys_path_probes_registered[N_SYS_PATH_PROBES];
static bool compat_path_probes_registered[N_COMPAT_PATH_PROBES];

static void sus_path_syscall_register(void)
{
    int i, n = 0, c = 0;

    for (i = 0; i < N_SYS_PATH_PROBES; i++) {
        int rc = register_kprobe(sys_path_probes[i]);

        if (rc) {
            pr_warn("sus_path: kprobe(%s) failed %d\n",
                    sys_path_probes[i]->symbol_name, rc);
            continue;
        }
        sys_path_probes_registered[i] = true;
        n++;
    }

    for (i = 0; i < N_COMPAT_PATH_PROBES; i++) {
        const char *sym = compat_path_probes[i]->symbol_name;

        /* Absent by design on kernels that share the native wrapper. */
        if (!find_kernel_symbol_exact(sym))
            continue;
        if (register_kprobe(compat_path_probes[i])) {
            pr_warn("sus_path: kprobe(%s) failed\n", sym);
            continue;
        }
        compat_path_probes_registered[i] = true;
        c++;
    }

    pr_info("sus_path: syscall layer armed (%d/%d native, %d/%d compat probes)\n",
            n, (int)N_SYS_PATH_PROBES, c, (int)N_COMPAT_PATH_PROBES);
}

static void sus_path_syscall_unregister(void)
{
    int i;

    for (i = 0; i < N_COMPAT_PATH_PROBES; i++) {
        if (!compat_path_probes_registered[i])
            continue;
        unregister_kprobe(compat_path_probes[i]);
        compat_path_probes_registered[i] = false;
    }
    for (i = 0; i < N_SYS_PATH_PROBES; i++) {
        if (!sys_path_probes_registered[i])
            continue;
        unregister_kprobe(sys_path_probes[i]);
        sys_path_probes_registered[i] = false;
    }
}

/* ---- getname layer ----
 *
 * The syscall-entry layer reads the caller's pathname itself.  That works for
 * 64-bit callers, but not for 32-bit ones: measured, in that probe context
 * copy_from_user, get_user and strncpy_from_user all answered -EFAULT for a
 * pointer the kernel read without any trouble a moment later (the argument
 * registers were right: r0=0xffffff9c AT_FDCWD, r1=0x100f4, r2=0).
 *
 * getname() is where the kernel has just copied that pathname into kernel
 * memory, and it returns it as struct filename.  Hooking its return touches no
 * user memory at all and covers both ABIs, so this is where the decision is
 * really made; the syscall layer stays as the earlier, cheaper answer for
 * 64-bit callers and for anything that never goes through getname.
 *
 * Rewriting the return to ERR_PTR(-ENOENT) is what callers already handle
 * (IS_ERR is checked at every call site), but the filename just allocated would
 * then leak, so the original is released with putname() first.  When getname()
 * merely forwards getname_flags()' result, the inner probe has already done
 * this and the outer one sees ERR_PTR and stops. */
static int kr_getname_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct filename *f = (struct filename *)regs_return_value(regs);

    if (IS_ERR_OR_NULL(f) || !f->name)
        return 0;
    if (!sus_path_match_path(f->name))
        return 0;

    atomic_inc(&n_enoent_path);
    pr_info_ratelimited("sus_path: getname hit '%s' (uid=%u)\n",
                        f->name, current_uid().val);
    putname(f);
    regs_set_return_value(regs, (unsigned long)ERR_PTR(-ENOENT));
    return 0;
}

static struct kretprobe krp_getname = {
    .kp.symbol_name = "getname",
    .handler = kr_getname_ret,
    .maxactive = 64,
};

static struct kretprobe krp_getname_flags = {
    .kp.symbol_name = "getname_flags",
    .handler = kr_getname_ret,
    .maxactive = 64,
};

static struct kretprobe *getname_krps[] = {
    &krp_getname,
    &krp_getname_flags,
};

#define N_GETNAME_KRPS ARRAY_SIZE(getname_krps)
static bool getname_registered[N_GETNAME_KRPS];

static void sus_path_getname_register(void)
{
    int i, n = 0;

    for (i = 0; i < N_GETNAME_KRPS; i++) {
        if (!find_kernel_symbol_exact(getname_krps[i]->kp.symbol_name))
            continue;       /* same sharing story as the compat wrappers */
        if (register_kretprobe(getname_krps[i])) {
            pr_warn("sus_path: kretprobe(%s) failed\n",
                    getname_krps[i]->kp.symbol_name);
            continue;
        }
        getname_registered[i] = true;
        n++;
    }
    pr_info("sus_path: getname layer armed (%d/%d probes)\n", n,
            (int)N_GETNAME_KRPS);
}

static void sus_path_getname_unregister(void)
{
    int i;

    for (i = 0; i < N_GETNAME_KRPS; i++) {
        if (!getname_registered[i])
            continue;
        unregister_kretprobe(getname_krps[i]);
        getname_registered[i] = false;
    }
}

static struct kprobe *path_probes[] = {
    &kp_filename_lookup,
    &kp_filp_open,
    &kp_user_path,
};

#define N_PATH_PROBES ARRAY_SIZE(path_probes)
static bool path_probes_registered[N_PATH_PROBES];

static void sus_path_path_register(void)
{
    int i;

    for (i = 0; i < N_PATH_PROBES; i++) {
        int rc = register_kprobe(path_probes[i]);

        if (rc) {
            pr_warn("sus_path: kprobe(%s) failed %d\n",
                    path_probes[i]->symbol_name, rc);
            continue;
        }
        path_probes_registered[i] = true;
    }
    pr_info("sus_path: path layer armed (filename_lookup=%d do_filp_open=%d user_path_at_empty=%d)\n",
            path_probes_registered[0], path_probes_registered[1],
            path_probes_registered[2]);
}

static void sus_path_path_unregister(void)
{
    int i;

    for (i = 0; i < N_PATH_PROBES; i++) {
        if (!path_probes_registered[i])
            continue;
        unregister_kprobe(path_probes[i]);
        path_probes_registered[i] = false;
    }
}

/* Every hook below the LSM layer is only worth its cost once something is
 * actually registered: kprobe/kretprobe entry costs a brk trap per hit, and the
 * getdents64 tracepoint sits on every syscall exit.  With no rules there is
 * nothing to answer, so they are armed on the first rule and torn down when the
 * module goes - the same "no rules, no cost" effect as nop'ing a patched call
 * site, but through the kernel's own register/unregister paths (unregistering a
 * kprobe restores the original instruction) instead of hand-written text
 * patching.
 *
 * The LSM hooks are exempt: they are pointer swaps, already cost-free. */
static bool path_registered;
static bool hooks_armed;

/* The tracepoint callback and the filter it drives are defined below. */
static void sus_path_sys_exit(void *data, struct pt_regs *regs, long ret);

static void sus_path_tracepoint_register(void)
{
    int rc = register_trace_sys_exit(sus_path_sys_exit, NULL);

    if (rc) {
        pr_warn("register_trace_sys_exit(getdents64) failed %d\n", rc);
        return;
    }
    path_registered = true;
    pr_info("sus_path: getdents64 filter armed\n");
}

static void sus_path_hooks_arm(void)
{
    if (hooks_armed || !READ_ONCE(sus_path_count))
        return;

    hooks_armed = true;
    sus_path_tracepoint_register();
    sus_path_getname_register();

    /* Entry-decision hooks: patch the entries if we can, otherwise probe them.
     * Never both - a kprobe owns the first instruction of its target. */
    if (sus_path_ih_register())
        pr_info("sus_path: syscall/path entries use inline hooks\n");
    else {
        sus_path_syscall_register();
        sus_path_path_register();
    }
    pr_info("sus_path: hooks armed (first rule registered)\n");
}

/* ---- inline hooks ----
 *
 * The entry points below are the ones where a decision can be made at the
 * ENTRY: read the caller's path, answer ENOENT, or let the call run.  They are
 * patched instead of kprobed, because arm64 kprobe is a brk trap on every hit
 * while this is a branch (see INLINE_HOOK.md).
 *
 * Entries that need to run the original function and inspect its RESULT
 * (getname's struct filename, vfs_getattr's kstat, the getdents64 tracepoint)
 * keep their probe: that is an onLeave hook, not an entry decision.
 *
 * A kprobe and an inline hook cannot share an entry - the kprobe replaces the
 * first instruction with brk - so if inline hooking fails for any entry, all of
 * them are rolled back and the kprobes are used instead.
 */
extern void susfs_ih_stub_openat(void);
extern void susfs_ih_stub_openat2(void);
extern void susfs_ih_stub_newfstatat(void);
extern void susfs_ih_stub_statx(void);
extern void susfs_ih_stub_faccessat(void);
extern void susfs_ih_stub_faccessat2(void);
extern void susfs_ih_stub_readlinkat(void);
extern void susfs_ih_stub_execve(void);
extern void susfs_ih_stub_filename_lookup(void);
extern void susfs_ih_stub_do_filp_open(void);
extern void susfs_ih_stub_user_path_at_empty(void);

extern u64 susfs_ih_tramp_openat;
extern u64 susfs_ih_tramp_openat2;
extern u64 susfs_ih_tramp_newfstatat;
extern u64 susfs_ih_tramp_statx;
extern u64 susfs_ih_tramp_faccessat;
extern u64 susfs_ih_tramp_faccessat2;
extern u64 susfs_ih_tramp_readlinkat;
extern u64 susfs_ih_tramp_execve;
extern u64 susfs_ih_tramp_filename_lookup;
extern u64 susfs_ih_tramp_do_filp_open;
extern u64 susfs_ih_tramp_user_path_at_empty;

/* Called from the syscall stubs: x0 is the wrapper's pt_regs, argno the register
 * holding the pathname. */
int susfs_ih_decide(u64 uregs_arg, int argno)
{
	const struct pt_regs *uregs = (const struct pt_regs *)uregs_arg;
	const char __user *up;
	char buf[SUS_PATH_LEN];
	long n;

	if (!uregs || argno < 0 || argno > 5)
		return 0;
	if (!sus_path_gate_uid_ok())
		return 0;

	up = (const char __user *)uregs->regs[argno];
	if (is_compat_task()) {
#ifdef CONFIG_COMPAT
		up = compat_ptr((u32)uregs->regs[argno]);
#else
		return 0;
#endif
	}
	if (!up)
		return 0;

	n = strncpy_from_user(buf, up, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	return sus_path_match_path(buf) ? 1 : 0;
}

/* Called from the name-taking stubs: mode 0 = struct filename (already copied
 * into kernel memory, so no uaccess at all), mode 1 = __user pointer. */
int susfs_ih_decide_name(u64 p, int mode)
{
	char buf[SUS_PATH_LEN];
	long n;

	if (!p || !sus_path_gate_uid_ok())
		return 0;

	if (mode == 0) {
		const struct filename *f = (const struct filename *)p;

		if (!f->name)
			return 0;
		return sus_path_match_path(f->name) ? 1 : 0;
	}

	n = strncpy_from_user(buf, (const char __user *)p, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	return sus_path_match_path(buf) ? 1 : 0;
}

static int ih_enabled = 1;
module_param(ih_enabled, int, 0644);

static struct {
	const char *sym;
	void *stub;
	u64 *tramp;
} ih_table[] = {
	{ "__arm64_sys_openat",        susfs_ih_stub_openat,        &susfs_ih_tramp_openat },
	{ "__arm64_sys_openat2",       susfs_ih_stub_openat2,       &susfs_ih_tramp_openat2 },
	{ "__arm64_sys_newfstatat",    susfs_ih_stub_newfstatat,    &susfs_ih_tramp_newfstatat },
	{ "__arm64_sys_statx",         susfs_ih_stub_statx,         &susfs_ih_tramp_statx },
	{ "__arm64_sys_faccessat",     susfs_ih_stub_faccessat,     &susfs_ih_tramp_faccessat },
	{ "__arm64_sys_faccessat2",    susfs_ih_stub_faccessat2,    &susfs_ih_tramp_faccessat2 },
	{ "__arm64_sys_readlinkat",    susfs_ih_stub_readlinkat,    &susfs_ih_tramp_readlinkat },
	{ "__arm64_sys_execve",        susfs_ih_stub_execve,        &susfs_ih_tramp_execve },
	{ "filename_lookup",           susfs_ih_stub_filename_lookup, &susfs_ih_tramp_filename_lookup },
	{ "do_filp_open",              susfs_ih_stub_do_filp_open,  &susfs_ih_tramp_do_filp_open },
	{ "user_path_at_empty",        susfs_ih_stub_user_path_at_empty, &susfs_ih_tramp_user_path_at_empty },
};

#define N_IH_HOOKS ARRAY_SIZE(ih_table)
static struct susfs_ih_hook ih_hooks[N_IH_HOOKS];

/* Returns the number installed, or 0 if inline hooking is unavailable/disabled. */
static int sus_path_ih_register(void)
{
	int i, n = 0;

	if (!ih_enabled)
		return 0;
	if (susfs_ih_init())
		return 0;

	for (i = 0; i < N_IH_HOOKS; i++) {
		if (susfs_ih_install(&ih_hooks[i], ih_table[i].sym, ih_table[i].stub,
				     ih_table[i].tramp))
			break;
		n++;
	}

	if (n != N_IH_HOOKS) {
		pr_warn("sus_path: inline hooks incomplete (%d/%d), rolling back to kprobes\n",
			n, (int)N_IH_HOOKS);
		while (n-- > 0)
			susfs_ih_uninstall(&ih_hooks[n]);
		return 0;
	}

	pr_info("sus_path: inline hooks armed (%d entries patched)\n", n);
	return n;
}

static void sus_path_ih_unregister(void)
{
	int i;

	for (i = 0; i < N_IH_HOOKS; i++)
		susfs_ih_uninstall(&ih_hooks[i]);
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
	sus_path_entry_set_path(e, path);
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
	sus_path_hooks_arm();
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

    /* The getdents64 tracepoint (it sits on every syscall exit), the syscall
     * probes and the getname hooks are armed by sus_path_hooks_arm() once a
     * rule exists: with nothing registered there is nothing to answer, so they
     * cost nothing until then. */
    pr_info("sus_path: hooks deferred until the first rule\n");

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
     * of ENOENT (see the note above it).  Registered eagerly because it is the
     * layer that would otherwise answer EACCES, and it has never been observed
     * to fire on this kernel anyway. */
    sus_path_dac_register();

    return 0;
}

void sus_path_exit(void)
{
    struct sus_path_entry *e, *tmp;
    LIST_HEAD(doomed);

    /* Unregister the hooks FIRST: after this nothing can match, so the entries
     * (and their inode references) can be torn down safely. */
    sus_path_getname_unregister();
    sus_path_ih_unregister();
    sus_path_syscall_unregister();
    sus_path_path_unregister();
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
    sus_path_entry_set_path(e, info.target_pathname);
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

    /* First rule: arm the tracepoint, the syscall probes and the getname
     * hooks.  Idempotent, and safe to call with a rule already in the list. */
    sus_path_hooks_arm();

    info.err = 0;
    pr_info("sus_path: hide '%s' (dev=%llu ino=%llu)\n",
            info.target_pathname, e->dev, e->ino);
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_path __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_path supercall copy_to_user failed\n");
}
