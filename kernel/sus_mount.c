// SPDX-License-Identifier: GPL-2.0
/*
 * sus_mount.c - hide KSU mounts from /proc/mounts and /proc/mountinfo.
 *
 * Upstream SUSFS skips a mount line when r->mnt_id >= DEFAULT_KSU_MNT_ID, and
 * (patch:1561-1585) it only installs those show functions for NON-ksu domains:
 * mounts_open()/mountinfo_open()/mountstats_open() pick susfs_show_vfsmnt()/
 * susfs_show_mountinfo()/susfs_show_vfsstat() only when
 * !susfs_is_current_ksu_domain(), so the su/ksu domain keeps seeing its own
 * mounts.  The stock show functions are static but live behind proc_ops
 * function pointers, so they are NOT LTO-inlined and remain kprobe-able
 * (verified in kallsyms).
 *
 * The LKM hooks all three show functions with a kprobe pre_handler and returns
 * early (regs->pc = x30) when the mount id is in the KSU range - but only for
 * non-su/ksu processes, mirroring upstream's domain gate: the su domain must
 * keep seeing its own mounts or su tooling (zygisk in post-fs-data, ksud)
 * breaks.  struct mount / real_mount() come from the private fs/mount.h (its
 * includes are all public headers, so -I$(srctree)/fs is enough).
 *
 * HOW THE ID RANGE IS PRODUCED (this is the part that used to be missing):
 * upstream gets KSU mounts into that range by ADDING an allocator
 * (susfs_alloc_non_unshare_ksu_vfsmnt(), which calls
 * ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID, GFP_KERNEL), patch:676-693) and
 * SWAPPING THE CALL SITES in vfs_create_mount()/clone_mnt() (patch:764, 800);
 * mnt_alloc_id() itself is never patched.  The LKM does not patch kernel text
 * at all, so its stock allocator (plain ida_alloc, smallest free id) keeps
 * handing out small ids - measured on device: 91..39693, so the old fixed 2e9
 * threshold could never match and the feature was 100% OFF.
 *
 * Instead, sus_mount_mark_ksu_mounts() retro-fits upstream's semantics: at
 * enable time (and at module load) it walks the current mount namespace and
 * rewrites the mnt_id of every mount that looks like one of KernelSU's.
 *
 * The new id is a REAL id taken from the kernel's own mnt_id_ida:
 *   ida_alloc_range(&mnt_id_ida, DEFAULT_KSU_MNT_ID, INT_MAX - 1, GFP_KERNEL)
 * NOT an invented number.  That is not a style choice.  mnt_free_id()
 * (fs/namespace.c:136-139) unconditionally calls ida_free(&mnt_id_ida,
 * mnt->mnt_id) when the mount finally goes away, so a hand-made id makes
 * lib/idr.c:523-525 fire WARN(1, "ida_free called for id=%d which is not
 * allocated.") on umount - and a WARN plus stack dump in dmesg is exactly the
 * kind of trace a root detector greps for, i.e. worse than the feature doing
 * nothing.  Upstream is under the same constraint and short-circuits the free
 * for its fake ids (patch:582-588); mnt_free_id() is static + LTO-inlined on
 * this kernel, so we cannot patch it - owning the id for real is the fix.
 *
 * Degradation: if mnt_id_ida / ida_alloc_range / ida_free cannot ALL be
 * resolved, nothing is marked at all.  min_mnt_id then stays false, the feature
 * does nothing, and every missing symbol is named in a pr_warn.  Falling back to
 * a self-made id is deliberately NOT an option (see the WARN above).
 *
 * A mount is recognised by either of:
 *   - mnt_devname contains "/data/adb/" (KSU/module bind mounts, whose source is
 *     the file under /data/adb/modules/...);
 *   - the mount POINT - d_path() of {mnt, mnt_root}, i.e. the same path
 *     show_mountinfo() prints - is under /data/adb/modules, /data/adb/ksu or
 *     /data/adb/magisk (catches meta-overlayfs, whose source is a loop device:
 *     "/dev/block/loop48 /data/adb/modules/meta-overlayfs/mnt ext4 rw,...").
 * Marked ids are never restored on disable, matching upstream, where an id is
 * assigned once at mount time and stays for the mount's lifetime.
 *
 * Known blind spots of the scan (see AUDIT_FINDINGS.md B10):
 *   - overlayfs mounts that KernelSU places on /system have d_path "/system"
 *     and mnt_devname "overlay", so they are NOT recognised; only intercepting
 *     vfs_create_mount()/clone_mnt() by su domain (upstream's group (1)) would
 *     catch those;
 *   - only the mount namespace of the process that enables the feature is
 *     scanned; a mount namespace cloned later (copy_mnt_ns()/unshare()) gets
 *     fresh small ids from the stock allocator (upstream handles that in
 *     clone_mnt() with CL_COPY_MNT_NS, patch:789-810).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>     /* struct statx (stx_mnt_id) */
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/idr.h>      /* struct ida + ida_alloc_range()/ida_free() prototypes */
#include <linux/err.h>
#include <linux/errno.h>    /* -ENOSYS/-ENOENT/-ENOMEM used by the scan result */
#include <linux/dcache.h>   /* d_path() - called through a resolved symbol */
#include <linux/limits.h>   /* PATH_MAX, INT_MAX (via vdso/limits.h) */
#include <linux/security.h> /* security_secctx_to_secid() */
#include "mount.h"      /* fs/mount.h: struct mount + struct mnt_namespace + real_mount() */
#include "symbol_resolver.h"
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* module-wide declarations */

#define DEFAULT_KSU_MNT_ID 2000000000ULL

/* P3: min_mnt_id is a raw ulong tunable and 0/1 would make EVERY mount line
 * match the threshold below, hiding the whole of /proc/mounts,
 * /proc/<pid>/mountinfo and /proc/<pid>/mountstats from every process (su
 * included).  Anything below this is clamped back to DEFAULT_KSU_MNT_ID. */
#define SUS_MOUNT_MIN_SANE_MNT_ID 1000

/* Hard bound on the mount-namespace walk.  A concurrent umount_tree() does
 * list_del_init() on the entry it removes, which makes that node point at
 * itself, so an unbounded list_for_each() can spin forever if it lands on it. */
#define SUS_MOUNT_MAX_SCAN 65536

/* Everything at/above this is "already a KSU-range id" (upstream's own test,
 * patch:807).  The marking side deliberately uses this constant instead of the
 * min_mnt_id tunable: if the tunable were raised above 2e9 a tunable-based test
 * would re-mark an already-marked mount and allocate a SECOND id from the ida,
 * leaking the first one for the mount's lifetime.  With the default tunable
 * (2e9) the two tests are identical. */
#define SUS_MOUNT_KSU_ID_MIN ((unsigned int)DEFAULT_KSU_MNT_ID)

static unsigned long param_min_mnt_id = DEFAULT_KSU_MNT_ID;
module_param_named(min_mnt_id, param_min_mnt_id, ulong, 0644);

/* P2-12: SELinux context of the su/ksu domain, resolved to a sid at init.
 * Keep in sync with susfs_avc_spoof.c's avc_su_ctx default ("u:r:ksu:s0", the
 * SukiSU variant; stock KernelSU uses "u:r:su:s0", override with
 * susfs_guard_lkm.su_ctx=u:r:su:s0). */
static char param_su_ctx[128] = "u:r:ksu:s0";
module_param_string(su_ctx, param_su_ctx, sizeof(param_su_ctx), 0644);

static u32 su_sid;

/* The kernel's own mount-id allocator, resolved at init:
 *   - mnt_id_ida: `static DEFINE_IDA(mnt_id_ida)` in fs/namespace.c:68 (data
 *     symbol; exactly one definition in the tree);
 *   - ida_alloc_range(): the out-of-line allocator (lib/idr.c:380;
 *     ida_alloc_min() is only a header inline over it, which is why ida_alloc_min
 *     has no kallsyms entry - do not try to resolve that one);
 *   - ida_free(): resolved as a corroborating check only.  We never call it: the
 *     paired free is done by the kernel itself in mnt_free_id()
 *     (fs/namespace.c:136-139) when a marked mount is finally freed, which is
 *     exactly what we want (and what keeps the umount path WARN-free).
 * All three must be present or we refuse to mark anything (fail closed). */
static struct ida *sus_mount_mnt_id_ida;
static int (*pfn_ida_alloc_range)(struct ida *ida, unsigned int min,
                                  unsigned int max, gfp_t gfp);
static void (*pfn_ida_free)(struct ida *ida, unsigned int id);

static bool sus_mount_ida_ready(void)
{
    return sus_mount_mnt_id_ida && pfn_ida_alloc_range && pfn_ida_free;
}

/* Resolved kernel symbols.  security_cred_getsecid() is an EXPORT_SYMBOL in
 * security/security.c:1742, but GKI's symbol list is not guaranteed to carry it
 * for modules, so it is looked up in kallsyms like the other optional symbols
 * this LKM uses. */
static void (*pfn_security_cred_getsecid)(const struct cred *cred, u32 *secid);
static char *(*pfn_d_path)(const struct path *path, char *buf, int buflen);

/* __nocfi on every function that reaches a resolved kernel symbol through a
 * function pointer: kCFI validates the type hash at such a call site and panics
 * with "CFI failure (target: ...)" otherwise.  We hit exactly that once (see
 * susfs_inline_hook.c:60-63 and :106-118, "CFI failure (target:
 * smp_call_function)"), so these wrappers must keep the attribute. */
static __nocfi bool sus_mount_is_su_domain(void)
{
    u32 sid = 0;

    /* Unresolved symbol or an unresolvable su context: we cannot tell su apart,
     * so nothing is exempted (hide from every process) - loud in the init log. */
    if (!pfn_security_cred_getsecid || !su_sid)
        return false;
    /* kprobe pre_handler runs on the probed task with preemption disabled:
     * reading current->cred and the LSM hook list never sleeps. */
    pfn_security_cred_getsecid(current_cred(), &sid);
    return sid == su_sid;
}

/* Allocate a genuine id in the KSU range out of the kernel's mnt_id_ida.
 * Process context (GFP_KERNEL, may sleep).  Returns the id, or a negative errno
 * (-ENOMEM / -ENOSPC) - never a bogus id. */
static __nocfi int sus_mount_ida_alloc(void)
{
    return pfn_ida_alloc_range(sus_mount_mnt_id_ida,
                               (unsigned int)DEFAULT_KSU_MNT_ID,
                               (unsigned int)(INT_MAX - 1), GFP_KERNEL);
}

static __nocfi char *sus_mount_d_path(const struct path *path, char *buf, int buflen)
{
    if (!pfn_d_path)
        return ERR_PTR(-ENOSYS);
    return pfn_d_path(path, buf, buflen);
}

/* Effective threshold: clamped on every read too, because the sysfs knob can be
 * written at any time (init/enable also write the clamped value back). */
static unsigned long sus_mount_min_mnt_id(void)
{
    if (param_min_mnt_id < SUS_MOUNT_MIN_SANE_MNT_ID)
        return DEFAULT_KSU_MNT_ID;
    return param_min_mnt_id;
}

/* Declared up here because the new hooks' stat node reports it (it is otherwise
 * set by sus_mount_register() further down). */
static bool mount_registered;

/* ---- the same id in the two other places upstream rewrites ----
 *
 * Skipping the mount line is not enough on its own: /proc/<pid>/fdinfo/N prints
 * "mnt_id:\t<i>" and statx(2) returns stx_mnt_id, both taken straight from the
 * mount the file lives on.  An app can therefore walk the fds it holds, collect
 * their mnt_ids and look for ones /proc/self/mountinfo never mentions - a
 * positive indicator that something is hidden, and one that needs no root.
 *
 * Upstream rewrites both to the id of the first mount up the chain that is not a
 * KSU mount (susfs_get_non_sus_mnt_id_from_mnt(), patch:849-858), so the number
 * the app sees is one that mountinfo does print for a line it keeps.  That value
 * is computed here once per marked mount - at marking time, when the mount
 * pointer is still in hand - and kept in a small id table, because at rewrite
 * time all we have is the id (kprobe context, no sleeping, no lookups). */
#define SUS_MOUNT_IDMAP_MAX 64

struct sus_mount_idmap_entry {
    int sus_id;
    int shown_id;
};

static struct sus_mount_idmap_entry mount_idmap[SUS_MOUNT_IDMAP_MAX];
static int n_idmap;
static DEFINE_SPINLOCK(idmap_lock);

static atomic_t n_fdinfo_hits = ATOMIC_INIT(0);
static atomic_t n_fdinfo_rewrites = ATOMIC_INIT(0);
static atomic_t n_statx_hits = ATOMIC_INIT(0);
static atomic_t n_statx_rewrites = ATOMIC_INIT(0);

static void sus_mount_idmap_add(int sus_id, int shown_id)
{
    unsigned long flags;
    int i;

    if (sus_id <= 0 || shown_id <= 0)
        return;
    spin_lock_irqsave(&idmap_lock, flags);
    /* The same mount is seen again on every enable (and by both ways in below),
     * so an entry that is already there must not be appended twice: the table is
     * fixed size and a re-enable loop would fill it with copies. */
    for (i = 0; i < n_idmap; i++) {
        if (mount_idmap[i].sus_id == sus_id) {
            mount_idmap[i].shown_id = shown_id;
            goto out;
        }
    }
    if (n_idmap < SUS_MOUNT_IDMAP_MAX) {
        mount_idmap[n_idmap].sus_id = sus_id;
        mount_idmap[n_idmap].shown_id = shown_id;
        n_idmap++;
    }
out:
    spin_unlock_irqrestore(&idmap_lock, flags);
}

/* 0 means "not one of ours" - mnt_id 0 is never handed out. */
static int sus_mount_shown_for(int sus_id)
{
    unsigned long flags;
    int i, shown = 0;

    if (sus_id <= 0)
        return 0;
    spin_lock_irqsave(&idmap_lock, flags);
    for (i = 0; i < n_idmap; i++) {
        if (mount_idmap[i].sus_id == sus_id) {
            shown = mount_idmap[i].shown_id;
            break;
        }
    }
    spin_unlock_irqrestore(&idmap_lock, flags);
    return shown;
}

/* Upstream's susfs_get_non_sus_mnt_id_from_mnt(): climb past every marked mount
 * and report the id of the first one that is not ours.  Must be called AFTER
 * r->mnt_id has been replaced - upstream relies on the same thing, i.e. on the
 * starting mount already carrying a KSU-range id, or the loop would stop at the
 * mount itself and report its own (hidden) number. */
static int sus_mount_shown_id(struct mount *mnt)
{
    while (mnt && mnt->mnt_parent && mnt != mnt->mnt_parent &&
           (unsigned int)mnt->mnt_id >= SUS_MOUNT_KSU_ID_MIN)
        mnt = mnt->mnt_parent;
    return mnt ? mnt->mnt_id : 0;
}

/* ---- /proc/<pid>/fdinfo/N ----
 *
 * fs/proc/fd.c:seq_show() formats pos/flags/mnt_id/ino into the seq_file buffer
 * and returns; the buffer is handed to userspace right after.  A kprobe cannot
 * see the mnt_id as a value (it is a local of that function), but it can read the
 * text that is already in m->buf at return time, which is the same information:
 * find the label, parse the decimal that follows it, replace it with the id the
 * app is supposed to see.  The replacement is never longer than the original
 * (a shown id is a normal, small one), so the buffer is only ever shortened.
 *
 * Works whether the kernel formats that line with one seq_printf (as AOSP 5.15
 * does) or with seq_put_decimal_ull() - both leave "mnt_id:\t<digits>" in the
 * buffer by the time the function returns. */
#define SUS_MOUNT_MNTID_LABEL		"mnt_id:\t"
#define SUS_MOUNT_MNTID_LABEL_LEN	8

/* Per-instance state for the four kretprobes below (fdinfo + the two statx
 * landing points).
 *
 * It lives in ri->data, NOT in per-CPU storage: seq_show() formats through
 * seq_printf(), whose seq_buf_alloc() is GFP_KERNEL and can sleep - with
 * CONFIG_PREEMPT=y the task may be preempted inside the probed function and
 * resume on another CPU, where a per-CPU slot would hold NULL or, worse, a
 * seq_file belonging to an unrelated /proc read that the return handler would
 * then memmove into.  A kretprobe instance is per-task, which is what makes the
 * entry/return pair safe; the getdents64 filter in sus_path.c does the same.
 *
 * The same struct serves all of them because the fields are disjoint. */
struct sus_mount_kretprobe_state {
    struct seq_file *m;		/* fdinfo: the seq_file being filled */
    unsigned long ubuf;		/* statx: the caller's struct statx __user * */
    char where;			/* statx: 's' = __arm64_sys_statx, 'd' = do_statx */
};

static atomic_t n_fdinfo_entry = ATOMIC_INIT(0);
static atomic_t n_fdinfo_nolabel = ATOMIC_INIT(0);

static int sus_mount_fdinfo_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_kretprobe_state *st = (struct sus_mount_kretprobe_state *)ri->data;

    atomic_inc(&n_fdinfo_entry);
    st->m = (struct seq_file *)regs->regs[0];
    return 0;
}

/* Replaces the decimal that follows the mnt_id label in the seq_file's already
 * formatted buffer, when the id has a disguise in sus_mount's table (KSU-range id
 * -> the host id).  Returns true when the buffer was rewritten.  The replacement
 * never grows, so the buffer is only ever shortened and m->count stays consistent.
 *
 * The other half of the same fdinfo line (the ino) belongs to open_redirect and is
 * rewritten by that feature's own kretprobe - it must fire whether or not this
 * feature's hide switch is on, and this probe is only registered while it is. */
static bool sus_mount_fdinfo_replace_mntid(struct seq_file *m)
{
    char *buf = m->buf, digits[12];
    size_t count = m->count, i, pos = 0, len = 0, n = 0;
    unsigned long old = 0;
    int shown;
    unsigned int v;

    for (i = 0; i + SUS_MOUNT_MNTID_LABEL_LEN < count; i++) {
        if (!memcmp(buf + i, SUS_MOUNT_MNTID_LABEL, SUS_MOUNT_MNTID_LABEL_LEN)) {
            pos = i + SUS_MOUNT_MNTID_LABEL_LEN;
            break;
        }
    }
    if (!pos)
        return false;

    while (pos + len < count && len < 10 &&
           buf[pos + len] >= '0' && buf[pos + len] <= '9') {
        old = old * 10 + (unsigned long)(buf[pos + len] - '0');
        len++;
    }
    if (!len)
        return false;

    shown = sus_mount_shown_for((int)old);
    if (shown <= 0)
        return false;

    v = (unsigned int)shown;
    while (v) {
        digits[n++] = (char)('0' + v % 10);
        v /= 10;
    }
    if (!n)
        return false;
    /* In practice a KSU-range id is replaced by a small host id, so this shrinks -
     * but the room check is here so a rule with an unexpectedly long host id
     * cannot overwrite past the seq_file buffer. */
    if (n > len && count + (n - len) >= m->size)
        return false;
    for (i = 0; i < n / 2; i++) {
        char t = digits[i];

        digits[i] = digits[n - 1 - i];
        digits[n - 1 - i] = t;
    }
    if (n != len)
        memmove(buf + pos + n, buf + pos + len, count - (pos + len));
    memcpy(buf + pos, digits, n);
    m->count = count - len + n;
    return true;
}

static int sus_mount_fdinfo_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_kretprobe_state *st = (struct sus_mount_kretprobe_state *)ri->data;
    struct seq_file *m = st->m;

    if (!m || (long)regs_return_value(regs) != 0)
        return 0;
    if (!m->buf || !m->count)
        return 0;
    /* The su/ksu domain keeps seeing its own mounts' real ids, exactly like the
     * mount-line skip above. */
    if (sus_mount_is_su_domain())
        return 0;

    atomic_inc(&n_fdinfo_hits);

    if (sus_mount_fdinfo_replace_mntid(m))
        atomic_inc(&n_fdinfo_rewrites);
    else
        atomic_inc(&n_fdinfo_nolabel);
    return 0;
}

static struct kretprobe kr_fdinfo = {
    .kp.symbol_name = "seq_show",		/* fs/proc/fd.c, unique in kallsyms */
    .entry_handler = sus_mount_fdinfo_entry,
    .handler = sus_mount_fdinfo_ret,
    .data_size = sizeof(struct sus_mount_kretprobe_state),
    .maxactive = 16,
};
static bool kr_fdinfo_ok;

/* ---- statx(2): stx_mnt_id ----
 *
 * vfs_statx() fills stat->mnt_id from the path's mount right after the getattr
 * callback, so the only place a kprobe can change it is the uapi struct the
 * syscall is about to copy out - hence entry (take the user pointer, argument 5)
 * plus return (rewrite the field if the call succeeded).
 *
 * Two landing points, because "the wrapper exists in kallsyms" says nothing
 * about who is really called: __arm64_sys_statx is the syscall entry, do_statx is
 * what it delegates to.  The rewrite is idempotent (the second one finds a
 * rewritten id that is not in the table), so arming both is safe - which of them
 * fires is reported separately.
 *
 * The two entry points do NOT read the same register:
 *   - __arm64_sys_statx is `asmlinkage long __arm64_sys_statx(const struct
 *     pt_regs *)` (arch/arm64/include/asm/syscall_wrapper.h), i.e. its only
 *     argument is the pt_regs pointer, so the user buffer is
 *     ((struct pt_regs *)regs->regs[0])->regs[4].  Reading regs->regs[4] directly
 *     happens to work only because the dispatcher leaves x1..x7 untouched - the
 *     same reason the reboot handler in susfs_supercall.c goes through
 *     PT_REAL_REGS.
 *   - do_statx(int dfd, const char __user *filename, unsigned flags, unsigned int
 *     mask, struct statx __user *buffer) is an ordinary function, so x4 IS the
 *     buffer. */
static atomic_t n_statx_entry = ATOMIC_INIT(0);
static atomic_t n_statx_ret = ATOMIC_INIT(0);
static atomic_t n_statx_nobuf = ATOMIC_INIT(0);
static atomic_t n_statx_err = ATOMIC_INIT(0);
static atomic_t n_statx_copyfail = ATOMIC_INIT(0);
static atomic_t n_statx_nomap = ATOMIC_INIT(0);

static int sus_mount_statx_entry_sys(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_kretprobe_state *st = (struct sus_mount_kretprobe_state *)ri->data;
    const struct pt_regs *uregs = (const struct pt_regs *)regs->regs[0];

    atomic_inc(&n_statx_entry);
    st->where = 's';
    st->ubuf = uregs ? (unsigned long)uregs->regs[4] : 0;
    return 0;
}

static int sus_mount_statx_entry_do(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_kretprobe_state *st = (struct sus_mount_kretprobe_state *)ri->data;

    atomic_inc(&n_statx_entry);
    st->where = 'd';
    st->ubuf = regs->regs[4];
    return 0;
}

static int sus_mount_statx_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_kretprobe_state *st = (struct sus_mount_kretprobe_state *)ri->data;
    unsigned long ubuf = st->ubuf;
    u64 id = 0, shown;
    int new_id;

    atomic_inc(&n_statx_ret);
    if ((long)regs_return_value(regs) != 0) {
        atomic_inc(&n_statx_err);
        return 0;
    }
    if (!ubuf) {
        /* Named, because "which landing point had no pointer" is the difference
         * between a wrong register and a wrong understanding of the call. */
        atomic_inc(&n_statx_nobuf);
        pr_info_ratelimited("sus_mount: statx landing point %c had no buffer\n",
                            st->where);
        return 0;
    }
    if (sus_mount_is_su_domain())
        return 0;

    atomic_inc(&n_statx_hits);
    if (copy_from_user(&id, (void __user *)(ubuf + offsetof(struct statx, stx_mnt_id)),
                       sizeof(id))) {
        atomic_inc(&n_statx_copyfail);
        return 0;
    }
    new_id = sus_mount_shown_for((int)id);
    if (new_id <= 0) {
        atomic_inc(&n_statx_nomap);
        return 0;
    }
    shown = (u64)new_id;
    if (copy_to_user((void __user *)(ubuf + offsetof(struct statx, stx_mnt_id)),
                     &shown, sizeof(shown))) {
        atomic_inc(&n_statx_copyfail);
        return 0;
    }
    atomic_inc(&n_statx_rewrites);
    return 0;
}

static struct kretprobe kr_statx = {
    .kp.symbol_name = "__arm64_sys_statx",
    .entry_handler = sus_mount_statx_entry_sys,
    .handler = sus_mount_statx_ret,
    .data_size = sizeof(struct sus_mount_kretprobe_state),
    .maxactive = 16,
};
static bool kr_statx_ok;

static struct kretprobe kr_statx_do = {
    .kp.symbol_name = "do_statx",
    .entry_handler = sus_mount_statx_entry_do,
    .handler = sus_mount_statx_ret,
    .data_size = sizeof(struct sus_mount_kretprobe_state),
    .maxactive = 16,
};
static bool kr_statx_do_ok;

/* Reachability/effect counters, one line per hook: "installed" says nothing about
 * whether the rewrite ever happened. */
static int sus_mount_stat_show(char *buf, const struct kernel_param *kp)
{
    return scnprintf(buf, PAGE_SIZE,
                     "idmap=%d  hide=%d su_domain=%d\n"
                     "fdinfo: entry=%d hits=%d rewrites=%d nolabel=%d\n"
                     "statx: entry=%d ret=%d hits=%d rewrites=%d nobuf=%d err=%d copyfail=%d nomap=%d "
                     "(sys=%d do=%d)\n",
                     n_idmap, mount_registered, (int)sus_mount_is_su_domain(),
                     atomic_read(&n_fdinfo_entry), atomic_read(&n_fdinfo_hits),
                     atomic_read(&n_fdinfo_rewrites),
                     atomic_read(&n_fdinfo_nolabel),
                     atomic_read(&n_statx_entry), atomic_read(&n_statx_ret),
                     atomic_read(&n_statx_hits), atomic_read(&n_statx_rewrites),
                     atomic_read(&n_statx_nobuf), atomic_read(&n_statx_err),
                     atomic_read(&n_statx_copyfail), atomic_read(&n_statx_nomap),
                     (int)kr_statx_ok, (int)kr_statx_do_ok);
}
static const struct kernel_param_ops sus_mount_stat_ops = {
    .get = sus_mount_stat_show,
};
module_param_cb(mount_stat, &sus_mount_stat_ops, NULL, 0400);

static int sus_mount_show_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vfsmount *mnt = (struct vfsmount *)regs->regs[1];
    struct mount *r;

    if (!mnt)
        return 0;
    r = real_mount(mnt);
    /* Cheap test first: only the handful of mounts in the KSU id range pay for
     * the domain lookup below. */
    if ((unsigned int)r->mnt_id < sus_mount_min_mnt_id())
        return 0;
    /* P2-12 domain gate, upstream patch:1561-1585: the su/ksu domain is not
     * touched at all, it must be able to see its own mounts. */
    if (sus_mount_is_su_domain())
        return 0;
    regs->pc = regs->regs[30];   /* skip this mount line */
    /* These show_* callbacks return int and x0 still holds seq_file*.
     * seq_read() treats a negative return as a hard error, so a stray high
     * bit here would break the whole read; upstream's equivalent site
     * explicitly returns 0. */
    regs->regs[0] = 0;
    return 1;
}

static struct kprobe kp_vfsstat = {
    .symbol_name = "show_vfsstat",
    .pre_handler = sus_mount_show_pre,
};

static struct kprobe kp_mountinfo = {
    .symbol_name = "show_mountinfo",
    .pre_handler = sus_mount_show_pre,
};

/* /proc/mounts and /proc/<pid>/mounts go through show_vfsmnt - a DIFFERENT
 * function from show_vfsstat (which serves mountstats).  Missing this hook left
 * /proc/mounts completely unhidden while mountinfo was filtered.  Upstream hooks
 * all three (patch:1402 susfs_show_vfsmnt, :1439 susfs_show_mountinfo, :1504
 * susfs_show_vfsstat). */
static struct kprobe kp_vfsmnt = {
    .symbol_name = "show_vfsmnt",
    .pre_handler = sus_mount_show_pre,
};

static bool sus_mount_is_adb_devname(const char *devname)
{
    if (!devname)
        return false;
    return strstr(devname, "/data/adb/") != NULL;
}

static bool sus_mount_is_adb_mountpoint(const char *path)
{
    if (!path)
        return false;
    return strstr(path, "/data/adb/modules") != NULL ||
           strstr(path, "/data/adb/ksu") != NULL ||
           strstr(path, "/data/adb/magisk") != NULL;
}

/* Retro-fit upstream's "KSU mounts carry an id >= DEFAULT_KSU_MNT_ID" onto the
 * mounts that already exist.  Process context only (kmalloc + d_path +
 * ida_alloc_range with GFP_KERNEL); called from module load and from the
 * supercall enable path.
 *
 * Upstream never needs this: it allocates the big id while the mount is being
 * created (susfs_alloc_non_unshare_ksu_vfsmnt(), patch:676-693, whose
 * ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID, GFP_KERNEL) is the same
 * allocation we do here, just at a different moment).  Two properties matter:
 *   - the id is genuinely allocated from mnt_id_ida, so the ida_free() the
 *     kernel runs in mnt_free_id() (fs/namespace.c:136-139) when the mount is
 *     finally freed is paired and does not WARN (lib/idr.c:523-525).  This is
 *     the whole reason we do not invent the number;
 *   - nothing else rewrites the field, so the assignment sticks until the mount
 *     is gone (which is what upstream assumes as well), and because the id now
 *     belongs to the ida it is reused after the mount is freed - normal
 *     allocator behaviour, not a leak.
 */
static int sus_mount_mark_ksu_mounts(void)
{
    struct mnt_namespace *ns;
    struct list_head *pos;
    char *buf;
    unsigned long min;
    int marked = 0;
    unsigned int seen = 0;
    int scan_logged = 0;
    unsigned int n_devname = 0, n_dpath_ok = 0, n_dpath_err = 0;
    unsigned int n_skipped_ns = 0, n_skipped_marked = 0;
    bool hit_cap = false;
    bool failed = false;

    /* Fail closed: without all three symbols we cannot own a real id, and a
     * self-made id would leave an ida_free WARN behind on umount. */
    if (!sus_mount_ida_ready()) {
        pr_warn("sus_mount: NOT marking: mnt_id_ida=%d ida_alloc_range=%d ida_free=%d must all resolve; min_mnt_id stays false, so the feature does nothing\n",
                !!sus_mount_mnt_id_ida, !!pfn_ida_alloc_range, !!pfn_ida_free);
        return -ENOSYS;
    }

    if (!current->nsproxy || !current->nsproxy->mnt_ns) {
        pr_warn("sus_mount: current has no mnt_ns, cannot scan for KSU mounts\n");
        return -ENOENT;
    }
    ns = current->nsproxy->mnt_ns;

    /* P3: clamp the tunable (a value of 0/1 would match every mount line). */
    if (param_min_mnt_id < SUS_MOUNT_MIN_SANE_MNT_ID) {
        pr_warn("sus_mount: min_mnt_id=%lu is below %d, clamping to %llu\n",
                param_min_mnt_id, SUS_MOUNT_MIN_SANE_MNT_ID, DEFAULT_KSU_MNT_ID);
        param_min_mnt_id = DEFAULT_KSU_MNT_ID;
    }
    min = sus_mount_min_mnt_id();

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        pr_warn("sus_mount: kmalloc(PATH_MAX) failed, no KSU mount marked\n");
        return -ENOMEM;
    }

    /* fs/mount.h documents the traversal protocol as "namespace_sem for read AND
     * ns_lock" (fs/namespace.c:704-713, :4484-4540).  namespace_sem is static in
     * fs/namespace.c and down_read() is an inline over rwsem internals, so an
     * out-of-tree module can only take the ns_lock half:
     *   - ns_lock keeps us out of the kernel's own list readers and of every
     *     list mutation that takes it (list_add/list_del under ns_lock);
     *   - the iteration bound above covers the only mutation that does not take
     *     ns_lock (umount_tree()'s list_del_init under namespace_sem);
     *   - rcu_read_lock keeps a mount that is being torn down alive: mounts that
     *     were ever on this list are freed through call_rcu() in
     *     cleanup_mnt() (fs/namespace.c:1144-1145), so a stale pointer we picked
     *     up from the list cannot be reused under us.
     * Nothing called while the lock is held sleeps: d_path() only takes the
     * rename/mount seqlocks, dentry locks and current->fs->lock, and printk with
     * a spinlock held is normal.  Lock order ns_lock -> (mount_lock, rename_lock,
     * fs->lock) has no reverse path in the tree. */
    rcu_read_lock();
    spin_lock(&ns->ns_lock);
    for (pos = ns->list.next; pos != &ns->list; pos = pos->next) {
        struct path mnt_path;
        struct mount *r;
        const char *shown;
        char *dp;
        int new_id;

        if (seen++ >= SUS_MOUNT_MAX_SCAN) {
            hit_cap = true;
            break;
        }
        r = list_entry(pos, struct mount, mnt_list);
        /* proc_mounts cursors are fake mounts anchored in this same list
         * (fs/namespace.c:678-681 mnt_is_cursor(), include/linux/mount.h:70). */
        if (r->mnt_ns != ns || (r->mnt.mnt_flags & MNT_CURSOR)) {
            n_skipped_ns++;
            continue;
        }
        /* Anything already carrying a KSU-range id: this is the idempotency guard
         * for a re-enable (or an enable after the load-time scan, where a second
         * id for the same mount would leak the first one for the mount's
         * lifetime) AND the cover for KernelSU's own mounts, which this kernel
         * already hands such an id to - on this device exactly one, the
         * meta-overlayfs loop mount at 2000000000.  Their line is skipped by that
         * id alone (no marking needed), so they need the very same "the id the
         * app is allowed to see" mapping, or fdinfo/statx keep printing a number
         * mountinfo no longer lists.  Compares against the constant, not the
         * tunable, see SUS_MOUNT_KSU_ID_MIN. */
        if ((unsigned int)r->mnt_id >= SUS_MOUNT_KSU_ID_MIN) {
            n_skipped_marked++;
            sus_mount_idmap_add((int)r->mnt_id, sus_mount_shown_id(r));
            continue;
        }

        if (sus_mount_is_adb_devname(r->mnt_devname)) {
            n_devname++;
            shown = r->mnt_devname;
        } else {
            /* meta-overlayfs style: the source is /dev/block/loopNN, so only the
             * mount point says /data/adb/... .  d_path() of {mnt, mnt_root} is
             * the mountpoint path show_mountinfo() prints. */
            mnt_path.mnt = &r->mnt;
            mnt_path.dentry = r->mnt.mnt_root;
            dp = sus_mount_d_path(&mnt_path, buf, PATH_MAX);
            /* Diagnostic while the matching rule is being validated: the first
             * few mounts show what d_path() actually renders for them. */
            if (scan_logged < 400) {
                scan_logged++;
                SUSFS_LOGI("sus_mount: scan %s -> %s\n", r->mnt_devname,
                        IS_ERR_OR_NULL(dp) ? "(d_path failed)" : dp);
            }
            if (IS_ERR_OR_NULL(dp)) {
                n_dpath_err++;
                continue;
            }
            n_dpath_ok++;
            if (!sus_mount_is_adb_mountpoint(dp))
                continue;
            shown = dp;
        }

        /* A real id out of the kernel's mnt_id_ida: never write a bogus value
         * into mnt_id, and never invent one (a hand-made id would make the
         * kernel's paired ida_free() WARN on umount). */
        new_id = sus_mount_ida_alloc();
        if (new_id < 0) {
            pr_warn("sus_mount: ida_alloc_range failed %d, stopping (remaining mounts left unmarked)\n",
                    new_id);
            failed = true;
            break;
        }
        if (new_id < (int)DEFAULT_KSU_MNT_ID) {
            /* Below our floor, i.e. the ida handed out something outside the
             * requested [DEFAULT_KSU_MNT_ID, INT_MAX-1] range: the resolved
             * mnt_id_ida is not what we think it is.  Stop before writing. */
            pr_warn("sus_mount: ida_alloc_range returned %d (< %llu) - resolved mnt_id_ida is suspect, stopping\n",
                    new_id, DEFAULT_KSU_MNT_ID);
            failed = true;
            break;
        }
        SUSFS_LOGI("sus_mount: marked mnt_id %d -> %d (%s, devname %s)\n",
                r->mnt_id, new_id, shown,
                r->mnt_devname ? r->mnt_devname : "none");
        r->mnt_id = new_id;
        /* After the id is replaced, exactly like upstream: the climb starts at a
         * mount that now carries a KSU-range id and stops at the first ancestor
         * that does not - i.e. the id mountinfo still prints for the host. */
        sus_mount_idmap_add(new_id, sus_mount_shown_id(r));
        marked++;
    }
    spin_unlock(&ns->ns_lock);
    rcu_read_unlock();

    kfree(buf);

    if (hit_cap)
        pr_warn("sus_mount: walk stopped after %u entries (cap %d), result may be incomplete\n",
                seen, SUS_MOUNT_MAX_SCAN);
    if (failed)
        pr_warn("sus_mount: marking stopped early (see the warning above), %d mount(s) marked\n",
                marked);
    if (marked)
        SUSFS_LOGI("sus_mount: %d KSU mount(s) marked with real mnt_id_ida ids (>= %llu)\n",
                marked, DEFAULT_KSU_MNT_ID);
    else
        SUSFS_LOGI("sus_mount: 0 KSU mounts marked (nothing under /data/adb matched in this mnt ns, hide threshold %lu)\n",
                min);
    SUSFS_LOGI("sus_mount: scan stats: seen=%u devname_hits=%u dpath_ok=%u dpath_err=%u skipped(other ns/cursor)=%u skipped(already marked)=%u marked=%d\n",
            seen, n_devname, n_dpath_ok, n_dpath_err, n_skipped_ns,
            n_skipped_marked, marked);
    return marked;
}

int susfs_sus_mount_init(void)
{
    int err;

    pfn_security_cred_getsecid =
        (void *)find_kernel_symbol_exact("security_cred_getsecid");
    pfn_d_path = (void *)find_kernel_symbol_exact("d_path");
    sus_mount_mnt_id_ida = (struct ida *)find_kernel_symbol_exact("mnt_id_ida");
    pfn_ida_alloc_range = (void *)find_kernel_symbol_exact("ida_alloc_range");
    pfn_ida_free = (void *)find_kernel_symbol_exact("ida_free");

    err = security_secctx_to_secid(param_su_ctx, strlen(param_su_ctx), &su_sid);
    if (err) {
        pr_warn("sus_mount: secctx_to_secid(%s) failed %d\n", param_su_ctx, err);
        su_sid = 0;
    }

    if (param_min_mnt_id < SUS_MOUNT_MIN_SANE_MNT_ID) {
        pr_warn("sus_mount: min_mnt_id=%lu is below %d, clamping to %llu\n",
                param_min_mnt_id, SUS_MOUNT_MIN_SANE_MNT_ID, DEFAULT_KSU_MNT_ID);
        param_min_mnt_id = DEFAULT_KSU_MNT_ID;
    }

    SUSFS_LOGI("sus_mount: su ctx \"%s\" -> sid %u (stock KernelSU uses \"u:r:su:s0\", override with susfs_guard_lkm.su_ctx)\n",
            param_su_ctx, su_sid);
    if (!pfn_security_cred_getsecid)
        pr_warn("sus_mount: security_cred_getsecid not found - no su-domain gating, KSU mounts will be hidden from EVERY process including su\n");
    if (!pfn_d_path)
        pr_warn("sus_mount: d_path not found - only mnt_devname is checked, meta-overlayfs style mounts will NOT be marked\n");
    /* The id side must own real ids; each missing symbol is named explicitly and
     * only disables the marking (the hook itself can still be installed). */
    if (!sus_mount_mnt_id_ida)
        pr_warn("sus_mount: mnt_id_ida not found - KSU mounts will NOT be marked, threshold stays false (feature does nothing)\n");
    if (!pfn_ida_alloc_range)
        pr_warn("sus_mount: ida_alloc_range not found - KSU mounts will NOT be marked, threshold stays false (feature does nothing)\n");
    if (!pfn_ida_free)
        pr_warn("sus_mount: ida_free not found - KSU mounts will NOT be marked, threshold stays false (feature does nothing)\n");

    /* upstream defaults this OFF (static key false) so zygisk can see sus
     * mounts during post-fs-data; the LKM mirrors that: no hook until
     * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS enables it.  The id assignment
     * itself is not gated on that flag - the hook compares ids, so the mounts
     * have to carry KSU ids before it is switched on (and the next enable
     * rescans anyway, which picks up mounts created since load). */
    SUSFS_LOGI("sus_mount: disabled by default (enable via CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS)\n");
    (void)sus_mount_mark_ksu_mounts();
    return 0;
}

void susfs_sus_mount_exit(void)
{
    if (mount_registered) {
        unregister_kprobe(&kp_mountinfo);
        unregister_kprobe(&kp_vfsstat);
        unregister_kprobe(&kp_vfsmnt);
        if (kr_fdinfo_ok) {
            unregister_kretprobe(&kr_fdinfo);
            kr_fdinfo_ok = false;
        }
        if (kr_statx_ok) {
            unregister_kretprobe(&kr_statx);
            kr_statx_ok = false;
        }
        if (kr_statx_do_ok) {
            unregister_kretprobe(&kr_statx_do);
            kr_statx_do_ok = false;
        }
        mount_registered = false;
    }
    /* Marked mnt_ids are deliberately NOT restored: upstream assigns an id once
     * per mount and never rewrites it, so a marked id stays for the mount's
     * lifetime (and a later enable only has to scan for new mounts).  The id
     * itself goes back to mnt_id_ida through the kernel's own mnt_free_id()
     * when the mount is finally freed - we never free it ourselves. */
}

static int sus_mount_register(void)
{
    int rc;

    if (mount_registered)
        return 0;
    rc = register_kprobe(&kp_vfsstat);
    if (rc)
        return rc;
    rc = register_kprobe(&kp_mountinfo);
    if (rc) {
        unregister_kprobe(&kp_vfsstat);
        return rc;
    }
    rc = register_kprobe(&kp_vfsmnt);
    if (rc) {
        unregister_kprobe(&kp_mountinfo);
        unregister_kprobe(&kp_vfsstat);
        return rc;
    }
    /* The two id rewrites are optional on their own: without them the mount
     * lines are still hidden, so a missing symbol must not take the rest down -
     * but each failure is named, because it leaves the ids visible in exactly
     * the place upstream rewrites them. */
    rc = register_kretprobe(&kr_fdinfo);
    if (rc)
        pr_warn("sus_mount: register_kretprobe(seq_show) failed %d - fdinfo keeps printing the real mnt_id\n", rc);
    else
        kr_fdinfo_ok = true;
    rc = register_kretprobe(&kr_statx);
    if (rc) {
        pr_warn("sus_mount: register_kretprobe(__arm64_sys_statx) failed %d - statx keeps returning the real stx_mnt_id\n", rc);
    } else {
        kr_statx_ok = true;
    }
    rc = register_kretprobe(&kr_statx_do);
    if (rc) {
        pr_warn("sus_mount: register_kretprobe(do_statx) failed %d - the second statx landing point is not armed\n", rc);
    } else {
        kr_statx_do_ok = true;
    }
    mount_registered = true;
    return 0;
}

/* supercall: CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS */
void susfs_sus_mount_supercall(void __user **arg)
{
    struct st_susfs_hide_sus_mnts_for_non_su_procs info = {0};
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    if (info.enabled) {
        rc = sus_mount_register();
        if (rc) {
            info.err = rc;
            goto out;
        }
        /* Only now does the threshold matter, so mark the KSU mounts (also
         * catches everything mounted since the module was loaded).
         *
         * A failed scan is REPORTED, not just logged: with no mount carrying a
         * KSU-range id the threshold test never matches, so nothing is hidden -
         * mountinfo, /proc/mounts, fdinfo and statx all keep showing the mounts.
         * Answering err=0 there is the "enabled, does nothing" failure mode a
         * caller cannot see; the hook staying live does not change that.  (A scan
         * that found zero KSU mounts on purpose is not a failure: that is rc==0.)
         */
        rc = sus_mount_mark_ksu_mounts();
        if (rc < 0) {
            pr_warn("sus_mount: scan on enable failed %d - hook is live but no mount was marked, reporting the failure to userspace\n",
                    rc);
            info.err = rc;
            goto out;
        }
    } else if (mount_registered) {
        unregister_kprobe(&kp_mountinfo);
        unregister_kprobe(&kp_vfsstat);
        unregister_kprobe(&kp_vfsmnt);
        if (kr_fdinfo_ok) {
            unregister_kretprobe(&kr_fdinfo);
            kr_fdinfo_ok = false;
        }
        if (kr_statx_ok) {
            unregister_kretprobe(&kr_statx);
            kr_statx_ok = false;
        }
        if (kr_statx_do_ok) {
            unregister_kretprobe(&kr_statx_do);
            kr_statx_do_ok = false;
        }
        mount_registered = false;
    }
    info.err = 0;
    SUSFS_LOGI("sus_mount: %s (supercall)\n", info.enabled ? "hide" : "unhide");
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_mount supercall copy_to_user failed\n");
}
