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
 *     show_mountinfo() prints - is under /data/adb (catches meta-overlayfs, whose
 *     source is a loop device: "/dev/block/loop48
 *     /data/adb/modules/meta-overlayfs/mnt ext4 rw,...").
 * Marked ids are never restored on disable, matching upstream, where an id is
 * assigned once at mount time and stays for the mount's lifetime.
 *
 * ---- the namespace that matters, and why identity is remembered as well
 *
 * KernelSU mounts module content into the ZYGOTE's mount namespace, because that
 * is the namespace every app is forked into.  The same filesystem is therefore a
 * different mount OBJECT there, with an id of its own - measured on this device:
 * /data/adb/modules/meta-overlayfs/mnt is id 2000000000 in the init namespace and
 * id 1111 in the zygote's.  Marking is what creates the big id, so it could only
 * cover the namespaces that existed when it ran; the id test alone then hid the
 * line in one view and left it in the app's own mount table - the one a checker
 * actually reads.
 *
 * The fix is identity, not a wider scan: sweeping every namespace from the task
 * list would mean walking another namespace's mount list, and only the ns_lock
 * half of that protocol is reachable from a module (namespace_sem is static in
 * fs/namespace.c) - a foreign namespace mounts and unmounts while we walk it,
 * which is exactly the class of thing that takes a device down.  Instead the
 * mount's IDENTITY is remembered by the scan that already runs safely in the
 * caller's namespace:
 *
 *   - superblock device + root dentry (both belong to the filesystem, so the same
 *     filesystem mounted in the zygote is matched), plus a path-shaped source
 *     string for equality;
 *   - the hide hooks accept identity as well as a KSU-range id, and hiding an
 *     identity-matched mount learns its id into the same id -> shown-id mapping, so
 *     fdinfo/statx keep naming a mount line the caller can still see.
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

/* Hand an unused id back to the same ida it came from.  MUST go through a
 * __nocfi function, like every other call this module makes through a resolved
 * kernel symbol: an indirect call from a normally-instrumented function is
 * type-checked by clang CFI, and an out-of-tree module's type hash for a kernel
 * prototype does not match the kernel's own - measured, and expensive to learn:
 *
 *   Kernel panic - not syncing: CFI failure (target: ida_free+0x0/0x480)
 *   Call trace: sus_mount_mark_ksu_mounts+0x9b0 [susfs_guard_lkm]
 *
 * (The first version of this helper was missing the annotation.  The allocation
 * side never hit it because sus_mount_ida_alloc() is __nocfi.) */
static __nocfi void sus_mount_ida_release(int id)
{
    pfn_ida_free(sus_mount_mnt_id_ida, (unsigned int)id);
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
 * time all we have is the id (kprobe context, no sleeping, no lookups).
 *
 * That table is the one piece of state whose key the kernel can hand to somebody
 * else: mnt ids are allocated from mnt_id_ida and returned there by mnt_free_id()
 * when a mount dies, so a number learned for OUR mount can later belong to a
 * completely unrelated one, and a stale hit would rewrite an innocent mount's id
 * (the app would then see, for its own fd, a number that names another mount's
 * line).  Measured on this device: a freed mnt id IS handed out again immediately
 * (mount tmpfs, note the id, umount, mount again - same id), so this is not a
 * theoretical window.  Each entry therefore carries the s_dev it was learned on,
 * and is invalidated in three places, in the order the cases matter:
 *
 *   - superblock teardown: the mount's filesystem is being unmounted, so the entry
 *     can only ever match a recycled id from now on.  A kprobe on
 *     generic_shutdown_super() drops every entry with that s_dev, which is also
 *     the earliest point where nothing can have taken the freed id yet.
 *   - sighting: every hide hook walks a namespace's mount list and sees each mount
 *     with its CURRENT id and whether it is ours.  A mount that is NOT ours and
 *     carries an id we have an entry for proves that id was recycled, so the entry
 *     is dropped right there (sus_mount_idmap_drop()).  Authoritative, not a guess,
 *     and it is what lets the table stay fixed-size: freed slots are reused.
 *   - refresh: seeing one of OUR mounts again rewrites its entry, so the pair is
 *     current for every mount whose line a reader actually enumerated - which is
 *     exactly the case where a cross-check against fdinfo is possible at all.
 *   - what is left is an id recycled while nobody reads a mount table at all: the
 *     entry is then only ever consulted by the rewrites, and no reader holds a
 *     mount list to compare the rewritten number against.
 *
 * A shown_id needs no expiry of its own: it is an ancestor of its mount, and an
 * ancestor cannot be unmounted while a child mount is still alive. */
#define SUS_MOUNT_IDMAP_MAX 64

/* sus_id == 0 marks a free slot; mnt ids are never 0. */
struct sus_mount_idmap_entry {
    int sus_id;
    int shown_id;
    dev_t s_dev;	/* the superblock the mount lived on (see the drop note) */
};

static struct sus_mount_idmap_entry mount_idmap[SUS_MOUNT_IDMAP_MAX];
static int n_idmap;
static DEFINE_SPINLOCK(idmap_lock);
static atomic_t n_idmap_recycled = ATOMIC_INIT(0);	/* stale entries dropped */
static atomic_t n_idmap_dropped_dev = ATOMIC_INIT(0);	/* dropped at sb teardown */

static atomic_t n_fdinfo_hits = ATOMIC_INIT(0);
static atomic_t n_fdinfo_rewrites = ATOMIC_INIT(0);
static atomic_t n_statx_hits = ATOMIC_INIT(0);
static atomic_t n_statx_rewrites = ATOMIC_INIT(0);

static void sus_mount_idmap_add(int sus_id, int shown_id, dev_t s_dev)
{
    unsigned long flags;
    int i, slot = -1;

    if (sus_id <= 0 || shown_id <= 0)
        return;
    spin_lock_irqsave(&idmap_lock, flags);
    /* The same mount is seen again on every enable (and by both ways in below),
     * so an entry that is already there must not be appended twice: the table is
     * fixed size and a re-enable loop would fill it with copies. */
    for (i = 0; i < n_idmap; i++) {
        if (mount_idmap[i].sus_id == sus_id) {
            mount_idmap[i].shown_id = shown_id;
            mount_idmap[i].s_dev = s_dev;
            goto out;
        }
        if (!mount_idmap[i].sus_id && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        if (n_idmap >= SUS_MOUNT_IDMAP_MAX)
            goto out;
        slot = n_idmap++;
    }
    mount_idmap[slot].sus_id = sus_id;
    mount_idmap[slot].shown_id = shown_id;
    mount_idmap[slot].s_dev = s_dev;
out:
    spin_unlock_irqrestore(&idmap_lock, flags);
}

/* Every entry whose mount lived on @s_dev is worthless now: that superblock is
 * being shut down (see the note on sus_mount_ident_drop_dev()). */
static void sus_mount_idmap_drop_dev(dev_t s_dev)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&idmap_lock, flags);
    for (i = 0; i < n_idmap; i++) {
        if (mount_idmap[i].sus_id && mount_idmap[i].s_dev == s_dev) {
            mount_idmap[i].sus_id = 0;
            mount_idmap[i].shown_id = 0;
            atomic_inc(&n_idmap_dropped_dev);
        }
    }
    spin_unlock_irqrestore(&idmap_lock, flags);
}

/* The id in @sus_id currently belongs to a mount that is NOT ours, so whatever we
 * learned for it is about a mount that no longer exists: a recycled id.  Called
 * from the hide hooks, which is where that fact is observable. */
static void sus_mount_idmap_drop(int sus_id)
{
    unsigned long flags;
    int i;

    if (sus_id <= 0)
        return;
    spin_lock_irqsave(&idmap_lock, flags);
    for (i = 0; i < n_idmap; i++) {
        if (mount_idmap[i].sus_id == sus_id) {
            mount_idmap[i].sus_id = 0;
            mount_idmap[i].shown_id = 0;
            atomic_inc(&n_idmap_recycled);
            break;
        }
    }
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

/* ---- "is this mount one of ours", by IDENTITY and not only by id ----
 *
 * The id test is a property of ONE mount object in ONE namespace, and the id only
 * exists because the marking scan put it there.  A mount that KernelSU created
 * inside the app/zygote namespace carries whatever id the stock allocator gave it
 * - measured on this device: the meta-overlayfs mount at
 * /data/adb/modules/meta-overlayfs/mnt has id 2000000000 in the init namespace and
 * id 1111 in the zygote's, so the id test hid the line in one view and left it in
 * the other.  That is the view that matters: an app is forked from zygote, so the
 * zygote namespace IS the app's own mount table, and a checker that reads its own
 * mountinfo (or /proc/<zygote>/mountinfo) saw a normal-looking mount for a module
 * path.
 *
 * So the identity of a mount is remembered as well, in the three things that
 * survive a namespace boundary - the mount OBJECT does not, but its filesystem
 * does:
 *
 *   s_dev + root ino    : exact and cheap (two compares).  The root dentry is
 *                         shared by every mount of the same superblock, and its
 *                         inode number cannot match an unrelated mount: a second
 *                         tmpfs instance has its own root dentry and inode.
 *                         The NUMBER is stored, not the dentry pointer: a pointer
 *                         kept across the mount's life would have to either hold a
 *                         reference (dget pins the dentry, hence the inode - and a
 *                         record whose filesystem is later unmounted then keeps
 *                         that inode alive past its superblock's shutdown; measured
 *                         on this device: rmmod of that build dput()'d it and
 *                         panicked in shmem_evict_inode, "Oops: Fatal exception")
 *                         or be used unlocked after the mount is gone.  Reading the
 *                         live mount's root inode number at compare time has
 *                         neither problem and needs no release step on unload.
 *   mnt_devname         : equality only when it is a path (starts with '/'), so a
 *                         recorded "tmpfs"/"overlay" cannot hide every mount of
 *                         that kind.
 *
 * Only mounts the scan ACCEPTS are recorded, so this never widens into "hide
 * anything that looks similar".
 *
 * A record is valid only while its filesystem is mounted, and the numbers it is
 * keyed by are reusable (measured: the tmpfs mounted, recorded and unmounted by
 * this test left s_dev 0:304 and root inode 1 behind, and the very next tmpfs mount
 * got both - i.e. a stale record matched an unrelated filesystem and hid it).  So a
 * kprobe on generic_shutdown_super() drops every record whose s_dev is going away
 * (sus_mount_ident_drop_dev()), and the record survives exactly as long as its
 * superblock - which is the case the identity test exists for. */
#define SUS_MOUNT_DEVNAME_MAX 64
#define SUS_MOUNT_IDENT_MAX 32
/* Defined with the scan helpers further down; the identity test needs it here. */
static bool sus_mount_is_adb_devname(const char *devname);

struct sus_mount_ident {
    dev_t s_dev;
    unsigned long root_ino;	/* 0 = free slot */
    bool devname_is_path;
    /* strscpy() truncates a longer devname; without this flag the record could
     * never match its own live mount again (strcmp of a truncated copy against the
     * full string is always unequal), which silently disabled this fallback. */
    bool devname_truncated;
    char devname[SUS_MOUNT_DEVNAME_MAX];
};

static struct sus_mount_ident mount_ident[SUS_MOUNT_IDENT_MAX];
static int n_ident;
static DEFINE_SPINLOCK(ident_lock);
static atomic_t n_ident_hits = ATOMIC_INIT(0);		/* hidden by identity, not by id */
static atomic_t n_ident_learned = ATOMIC_INIT(0);	/* ids learned while hiding */
static atomic_t n_ident_full = ATOMIC_INIT(0);		/* records that found no slot */
static atomic_t n_ident_dropped_dev = ATOMIC_INIT(0);	/* records dropped at sb teardown */
static atomic_t n_sb_down = ATOMIC_INIT(0);		/* superblocks seen shut down */

static int mount_dbg;
module_param_named(mount_dbg, mount_dbg, int, 0644);
/* Diagnostic: name the fields the identity test compares, for the first few mounts
 * the hide hook looks at, so "why did identity not match" is answerable from dmesg
 * instead of guessed. */
static atomic_t n_dbg_logged = ATOMIC_INIT(0);

/* Process context.  Takes no reference on anything (see the note above): the
 * record is three numbers and a string, so a record whose mount is long gone costs
 * nothing and cannot keep a filesystem alive. */
static void sus_mount_ident_add(struct mount *r)
{
    const char *devname = r->mnt_devname;
    struct dentry *root = r->mnt.mnt_root;
    unsigned long ino;
    unsigned long flags;
    int i, slot = -1;

    if (!root || !root->d_inode)
        return;
    ino = root->d_inode->i_ino;
    if (!ino)
        return;

    spin_lock_irqsave(&ident_lock, flags);
    /* Re-check under the lock: two scans cannot both append.  A second scan of the
     * same mounts (a re-enable) finds them here and stops. */
    for (i = 0; i < n_ident; i++) {
        if (mount_ident[i].s_dev == r->mnt.mnt_sb->s_dev &&
            mount_ident[i].root_ino == ino)
            goto out;
        if (!mount_ident[i].root_ino && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        if (n_ident >= SUS_MOUNT_IDENT_MAX) {
            /* Silent truncation is exactly the kind of "registered but not
             * effective" failure this project keeps finding, so say it once. */
            if (atomic_inc_return(&n_ident_full) == 1)
                pr_warn("sus_mount: identity table full (%d), %s is NOT recognised in other namespaces\n",
                        SUS_MOUNT_IDENT_MAX,
                        devname ? devname : "(no devname)");
            goto out;
        }
        slot = n_ident;
        smp_store_release(&n_ident, n_ident + 1);
    }
    {
        struct sus_mount_ident *e = &mount_ident[slot];

        e->s_dev = r->mnt.mnt_sb->s_dev;
        e->devname_is_path = devname && devname[0] == '/';
        if (e->devname_is_path) {
            e->devname_truncated = strlen(devname) >= sizeof(e->devname);
            strscpy(e->devname, devname, sizeof(e->devname));
        } else {
            e->devname[0] = '\0';
        }
        if (mount_dbg)
            SUSFS_LOGI("sus_mount: ident[%d] s_dev=%u root_ino=%lu devname=%s\n",
                    slot, (unsigned int)e->s_dev, ino,
                    e->devname_is_path ? e->devname : "(not path-shaped)");
        /* Set LAST: root_ino != 0 is what makes the record live for the readers. */
        smp_store_release(&e->root_ino, ino);
    }
out:
    spin_unlock_irqrestore(&ident_lock, flags);
}

/* Interrupt-context safe (kprobe pre_handler): read-only, no sleeping. */
static bool sus_mount_ident_match(struct mount *r)
{
    int n = smp_load_acquire(&n_ident);
    const char *devname = r->mnt_devname;
    struct dentry *root = r->mnt.mnt_root;
    unsigned long ino = (root && root->d_inode) ? root->d_inode->i_ino : 0;
    int i;

    for (i = 0; i < n; i++) {
        const struct sus_mount_ident *e = &mount_ident[i];
        unsigned long e_ino = smp_load_acquire(&e->root_ino);

        if (e_ino && e_ino == ino && e->s_dev == r->mnt.mnt_sb->s_dev)
            return true;
        if (e->devname_is_path && devname &&
            (e->devname_truncated
                 ? !strncmp(e->devname, devname, sizeof(e->devname) - 1)
                 : !strcmp(e->devname, devname)))
            return true;
    }
    return false;
}

/**
 * sus_mount_ident_drop_dev() - forget every record that lived on @s_dev
 *
 * Called from a kprobe on generic_shutdown_super(), i.e. the moment a superblock
 * is torn down - which is the only moment that makes these records wrong rather
 * than merely old.  Without it a record outlives its filesystem, and the numbers
 * it is keyed by are exactly the recyclable ones (measured on this device: a fresh
 * tmpfs got the same s_dev 0:304 AND the same root inode number 1 as the tmpfs
 * mounted, recorded and unmounted just before it, so a stale record matched a
 * completely unrelated filesystem and hid it).  Letting the record die with its
 * superblock closes that hole at the source, while keeping the record for as long
 * as the filesystem is mounted - which is the case the identity test exists for
 * (the same fs mounted in a namespace the scan cannot reach).
 *
 * Process context (umount/sb shutdown), takes only our own spinlock, never sleeps.
 */
static void sus_mount_ident_drop_dev(dev_t s_dev)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&ident_lock, flags);
    for (i = 0; i < n_ident; i++) {
        if (smp_load_acquire(&mount_ident[i].root_ino) && mount_ident[i].s_dev == s_dev) {
            smp_store_release(&mount_ident[i].root_ino, 0);
            atomic_inc(&n_ident_dropped_dev);
        }
    }
    spin_unlock_irqrestore(&ident_lock, flags);
}

/* generic_shutdown_super(struct super_block *sb) - fs/super.c, EXPORT_SYMBOL, so
 * it is a real function in kallsyms and not an inlined call site.  Runs before the
 * device number is handed back (free_anon_bdev()/blkdev_put() happen in
 * kill_anon_super()/kill_block_super() after this returns), so a record cannot
 * survive into the window where a new filesystem holds the same s_dev. */
static int sus_mount_sb_down_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct super_block *sb = (struct super_block *)regs->regs[0];

    atomic_inc(&n_sb_down);
    if (!sb)
        return 0;
    sus_mount_ident_drop_dev(sb->s_dev);
    sus_mount_idmap_drop_dev(sb->s_dev);
    return 0;
}

static struct kprobe kp_sb_down = {
    .symbol_name = "generic_shutdown_super",
    .pre_handler = sus_mount_sb_down_pre,
};
static bool kp_sb_down_ok;

/* Is this mount one of KernelSU's?  Two tests, cheapest first:
 *   - the id range, which is upstream's rule and what the marking scan produces;
 *   - the identity recorded by that scan, which is what catches the same mount in
 *     a namespace the scan could not reach (see the note above). */
static bool sus_mount_is_ours(struct mount *r)
{
    if ((unsigned int)r->mnt_id >= SUS_MOUNT_KSU_ID_MIN)
        return true;
    if (sus_mount_is_adb_devname(r->mnt_devname))
        return true;
    return sus_mount_ident_match(r);
}

/* The id the caller is allowed to see for a mount we hide: the first ancestor
 * that is not ours.  Starts at the PARENT when the mount itself is not in the id
 * range, because an identity-recognised mount keeps a normal id and would
 * otherwise report its own (hidden) number. */
static int sus_mount_shown_id_from(struct mount *mnt)
{
    if (mnt && (unsigned int)mnt->mnt_id < SUS_MOUNT_KSU_ID_MIN)
        mnt = mnt->mnt_parent;
    while (mnt && mnt->mnt_parent && mnt != mnt->mnt_parent &&
           sus_mount_is_ours(mnt))
        mnt = mnt->mnt_parent;
    return mnt ? (int)mnt->mnt_id : 0;
}

/* Remember the id -> shown-id pair for a mount we are about to hide, so the
 * fdinfo/statx faces rewrite the very same id the app would otherwise see.  The
 * hide hooks are the only place that has a mount pointer in an app's namespace,
 * so learning here is what keeps "the line is gone" and "the number in fdinfo
 * names a line that exists" consistent for namespaces the scan never saw. */
static void sus_mount_note_id(struct mount *r)
{
    int shown;

    if (sus_mount_shown_for((int)r->mnt_id))
        return;
    shown = sus_mount_shown_id_from(r);
    if (shown > 0 && shown != (int)r->mnt_id) {
        sus_mount_idmap_add((int)r->mnt_id, shown, r->mnt.mnt_sb->s_dev);
        atomic_inc(&n_ident_learned);
    }
}

/* ---- namespaces created AFTER the enable ----
 *
 * Marking is a property of one mount object in one namespace and it does NOT
 * travel: fs/namespace.c:1054 clone_mnt() builds the copy with alloc_vfsmnt()
 * (:196), which calls mnt_alloc_id() (:126) - every mount in a namespace copied by
 * fork/unshare gets a BRAND NEW id, as measured on this device (the copy of the
 * marked mount has no 2e9 id at all).  So after an app unshares, or after zygote
 * restarts, nothing in that namespace carries a marked id.
 *
 * Hiding still works - the identity test (superblock + root inode) is namespace
 * independent and does not care about ids (measured: the module mount and a
 * recorded tmpfs are both hidden inside a freshly cloned namespace).  What does NOT
 * work before this kretprobe existed is the fdinfo/statx face: the rewrite feeds on
 * the id table, that table only learns an id when somebody READS a mount table, so
 * a process that opens a file in the new namespace and reads /proc/self/fdinfo/N
 * first gets an id its own mountinfo does not list (measured: mnt_id=29127,
 * listed_in_my_mountinfo=0 - the "fdinfo names a mount that is not there" pattern),
 * and only the first mount-table read makes it consistent (29117, listed=1).
 * Upstream has no such window: it assigns the big id at mount creation, so the copy
 * is marked from the start.
 *
 * So: when a namespace is copied, learn the ids of every mount in the NEW tree that
 * we would hide, right there.
 *
 * Safety of walking that tree (this is the trap that once panicked this device):
 *   - we only ever walk a namespace this task has just built and that is not yet
 *     installed anywhere: copy_mnt_ns() returns to create_new_namespaces()/
 *     unshare_nsproxy_namespaces(), and the nsproxy is switched in afterwards
 *     (switch_task_namespaces), so no other task can add or remove a mount in it.
 *     namespace_sem is released inside copy_mnt_ns() (fs/namespace.c:3490
 *     namespace_unlock()), and it is not needed for a tree nobody else can reach.
 *   - the flags are checked first: without CLONE_NEWNS copy_mnt_ns() returns the
 *     CURRENT namespace (fs/namespace.c:3436) - that is the plain fork path, which
 *     runs constantly, and walking a live namespace there would be exactly the bug
 *     that took the device down before.
 *   - no allocation and no sleeping: the id table is fixed size (the scan's id
 *     batch trick is not needed here because we allocate no ids). */
static atomic_t n_clone_walks = ATOMIC_INIT(0);
static atomic_t n_clone_learned = ATOMIC_INIT(0);

static void sus_mount_learn_ns(struct mnt_namespace *ns)
{
    struct list_head *pos;
    int learned = 0;

    spin_lock(&ns->ns_lock);
    for (pos = ns->list.next; pos != &ns->list; pos = pos->next) {
        struct mount *r = list_entry(pos, struct mount, mnt_list);
        int shown;

        if (r->mnt_ns != ns || (r->mnt.mnt_flags & MNT_CURSOR))
            continue;
        if (!sus_mount_is_ours(r))
            continue;
        if (sus_mount_shown_for((int)r->mnt_id))
            continue;
        shown = sus_mount_shown_id_from(r);
        if (shown > 0 && shown != (int)r->mnt_id) {
            sus_mount_idmap_add((int)r->mnt_id, shown, r->mnt.mnt_sb->s_dev);
            learned++;
        }
    }
    spin_unlock(&ns->ns_lock);
    atomic_inc(&n_clone_walks);
    if (learned)
        atomic_add(learned, &n_clone_learned);
}

struct sus_mount_clone_state {
    unsigned long flags;
};

static int sus_mount_clone_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_clone_state *st = (struct sus_mount_clone_state *)ri->data;

    st->flags = regs->regs[0];
    return 0;
}

static int sus_mount_clone_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sus_mount_clone_state *st = (struct sus_mount_clone_state *)ri->data;
    struct mnt_namespace *ns = (struct mnt_namespace *)regs_return_value(regs);

    if (!(st->flags & CLONE_NEWNS))
        return 0;			/* plain fork: the current namespace, not a copy */
    if (IS_ERR_OR_NULL(ns))
        return 0;
    sus_mount_learn_ns(ns);
    return 0;
}

/* copy_mnt_ns() is not static (fs/namespace.c:3424) and is on every namespace
 * creation path (fork with CLONE_NEWNS, unshare, clone3). */
static struct kretprobe kr_clone_ns = {
    .kp.symbol_name = "copy_mnt_ns",
    .entry_handler = sus_mount_clone_entry,
    .handler = sus_mount_clone_ret,
    .data_size = sizeof(struct sus_mount_clone_state),
    .maxactive = 16,
};
static bool kr_clone_ns_ok;

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
    /* Not dereferenced here - the return handler checks it - but an implausible
     * value means this kretprobe sits on a function that does not take a seq_file,
     * and the rewrite below would then read an unrelated object. */
    st->m = susfs_ptr_plausible((void *)regs->regs[0])
               ? (struct seq_file *)regs->regs[0] : NULL;
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

/* Live entries, not slots: after an invalidation the slot is free but the slot
 * count stays where it was, and a diagnostic that reads "idmap=6" while only two
 * entries are usable is the kind of number this project keeps catching. */
static int sus_mount_idmap_live(void)
{
    unsigned long flags;
    int i, live = 0;

    spin_lock_irqsave(&idmap_lock, flags);
    for (i = 0; i < n_idmap; i++)
        if (mount_idmap[i].sus_id)
            live++;
    spin_unlock_irqrestore(&idmap_lock, flags);
    return live;
}

static int sus_mount_ident_live(void)
{
    unsigned long flags;
    int i, live = 0;

    spin_lock_irqsave(&ident_lock, flags);
    for (i = 0; i < READ_ONCE(n_ident); i++)
        if (smp_load_acquire(&mount_ident[i].root_ino))
            live++;
    spin_unlock_irqrestore(&ident_lock, flags);
    return live;
}

/* Reachability/effect counters, one line per hook: "installed" says nothing about
 * whether the rewrite ever happened. */
static int sus_mount_stat_show(char *buf, const struct kernel_param *kp)
{
    return scnprintf(buf, PAGE_SIZE,
                     "idmap=%d/%d  ident=%d/%d  hide=%d su_domain=%d\n"
                     "ident: hits=%d learned_ids=%d full=%d dropped_dev=%d\n"
                     "idmap: recycled_dropped=%d dropped_dev=%d\n"
                     "sb: down=%d (probe=%d)\n"
                     "clone: walks=%d learned=%d (probe=%d)\n"
                     "fdinfo: entry=%d hits=%d rewrites=%d nolabel=%d\n"
                     "statx: entry=%d ret=%d hits=%d rewrites=%d nobuf=%d err=%d copyfail=%d nomap=%d "
                     "(sys=%d do=%d)\n",
                     sus_mount_idmap_live(), n_idmap,
                     sus_mount_ident_live(), READ_ONCE(n_ident), mount_registered,
                     (int)sus_mount_is_su_domain(),
                     atomic_read(&n_ident_hits), atomic_read(&n_ident_learned),
                     atomic_read(&n_ident_full),
                     atomic_read(&n_ident_dropped_dev),
                     atomic_read(&n_idmap_recycled),
                     atomic_read(&n_idmap_dropped_dev),
                     atomic_read(&n_sb_down), (int)kp_sb_down_ok,
                     atomic_read(&n_clone_walks), atomic_read(&n_clone_learned),
                     (int)kr_clone_ns_ok,
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

    if (!susfs_ptr_plausible(mnt))
        return 0;
    r = real_mount(mnt);
    /* Cheap path first, and NOT only the id: a KSU mount in a namespace the
     * marking scan never reached (the zygote's, hence every app's) keeps a normal
     * id - see the identity note above sus_mount_is_ours(). */
    if (!sus_mount_is_ours(r)) {
        /* This mount is not ours but carries this id right now, which is proof the
         * id was recycled if we ever learned it (see the idmap note above). */
        sus_mount_idmap_drop((int)r->mnt_id);
        /* mount_dbg: say why - the id, s_dev, root dentry and source are exactly
         * what sus_mount_is_ours() compared. */
        if (mount_dbg && atomic_inc_return(&n_dbg_logged) <= 40)
            SUSFS_LOGI("sus_mount: hook: NOT ours id=%d s_dev=%u root=%px devname=%s\n",
                    r->mnt_id, (unsigned int)r->mnt.mnt_sb->s_dev,
                    r->mnt.mnt_root, r->mnt_devname ? r->mnt_devname : "none");
        return 0;
    }
    /* P2-12 domain gate, upstream patch:1561-1585: the su/ksu domain is not
     * touched at all, it must be able to see its own mounts. */
    if (sus_mount_is_su_domain())
        return 0;
    sus_mount_note_id(r);
    atomic_inc(&n_ident_hits);
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
    /* Anchored, not a substring search: an app can create a directory whose name
     * contains "/data/adb/", and a devname such as "/mnt/media_rw/x/data/adb/y" is
     * not a KernelSU mount.  Matching those hid unrelated mounts (and handed them a
     * KSU-range id) - an over-hide, which is the loud direction for a detector. */
    return strncmp(devname, "/data/adb/", 10) == 0;
}

static bool sus_mount_is_adb_mountpoint(const char *path)
{
    if (!path)
        return false;
    /* Every KernelSU mount lives under /data/adb (its module store), so the
     * mountpoint test is the same one the devname test uses.  It used to be
     * narrowed to modules/ksu/magisk, which missed the mounts whose source is a
     * block device AND whose mountpoint is not one of those three - a tmpfs or an
     * image mounted at /data/adb/<name> was simply not recognised, and stayed
     * visible in every namespace (measured: /data/adb/mnt_leak, id 24832). */
    return strncmp(path, "/data/adb/", 10) == 0;
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

/* One namespace's mount list.  Split out of the driver below because the same work
 * now has to happen in every reachable namespace, and the traversal protocol is
 * per namespace.
 *
 * fs/mount.h documents that protocol as "namespace_sem for read AND ns_lock"
 * (fs/namespace.c:704-713, :4484-4540).  namespace_sem is static in
 * fs/namespace.c and down_read() is an inline over rwsem internals, so an
 * out-of-tree module can only take the ns_lock half:
 *   - ns_lock keeps us out of the kernel's own list readers and of every list
 *     mutation that takes it (list_add/list_del under ns_lock);
 *   - the iteration bound covers the only mutation that does not take ns_lock
 *     (umount_tree()'s list_del_init under namespace_sem);
 *   - rcu_read_lock keeps a mount that is being torn down alive: mounts that were
 *     ever on this list are freed through call_rcu() in cleanup_mnt()
 *     (fs/namespace.c:1144-1145), so a stale pointer picked up here cannot be
 *     reused under us.
 *
 * ID ALLOCATION happens BEFORE the lock, in a small batch: ida_alloc_range() with
 * GFP_KERNEL may allocate a radix node and therefore sleep, and this loop runs
 * with a spinlock held.  A batch that is not fully used is handed back to the ida
 * afterwards (allocated and freed through the same ida, so the pairing the kernel
 * expects stays intact). */
#define SUS_MOUNT_ID_BATCH 8

static int sus_mount_scan_ns(struct mnt_namespace *ns, char *buf, unsigned long min)
{
    int batch[SUS_MOUNT_ID_BATCH];
    int n_batch = 0, used = 0;
    struct list_head *pos;
    unsigned int seen = 0;
    int scan_logged = 0;
    int marked = 0;
    unsigned int n_devname = 0, n_dpath_ok = 0, n_dpath_err = 0;
    unsigned int n_skipped_ns = 0, n_skipped_marked = 0;
    bool hit_cap = false;
    bool failed = false;
    int i;

    for (i = 0; i < SUS_MOUNT_ID_BATCH; i++) {
        int id = sus_mount_ida_alloc();

        if (id < 0)
            break;
        if (id < (int)DEFAULT_KSU_MNT_ID) {
            /* Below our floor: the resolved mnt_id_ida is not what we think it is.
             * Hand this id back and stop allocating. */
            sus_mount_ida_release(id);
            break;
        }
        batch[n_batch++] = id;
    }
    if (!n_batch) {
        pr_warn("sus_mount: could not allocate KSU-range ids for ns %p - that namespace is left unmarked\n",
                ns);
        return 0;
    }

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
         * id alone (no marking needed), so they need the very same "the id the app
         * is allowed to see" mapping, or fdinfo/statx keep printing a number
         * mountinfo no longer lists.  Compares against the constant, not the
         * tunable, see SUS_MOUNT_KSU_ID_MIN.
         *
         * The identity is remembered as well: this namespace's mount is a different
         * OBJECT from the one the same filesystem has in the next namespace, so
         * without a record the next namespace's copy cannot be recognised once its
         * id is out of the range (measured: 2000000000 here, 1111 in the zygote's). */
        if ((unsigned int)r->mnt_id >= SUS_MOUNT_KSU_ID_MIN) {
            n_skipped_marked++;
            sus_mount_idmap_add((int)r->mnt_id, sus_mount_shown_id(r), r->mnt.mnt_sb->s_dev);
            sus_mount_ident_add(r);
            continue;
        }

        if (sus_mount_is_adb_devname(r->mnt_devname)) {
            n_devname++;
            shown = r->mnt_devname;
        } else {
            /* meta-overlayfs style: the source is /dev/block/loopNN, so only the
             * mount point says /data/adb/... .  d_path() of {mnt, mnt_root} is the
             * mountpoint path show_mountinfo() prints. */
            mnt_path.mnt = &r->mnt;
            mnt_path.dentry = r->mnt.mnt_root;
            dp = sus_mount_d_path(&mnt_path, buf, PATH_MAX);
            /* Diagnostic while the matching rule is being validated: the first few
             * mounts show what d_path() actually renders for them. */
            if (scan_logged < 40) {
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

        if (used >= n_batch) {
            pr_warn("sus_mount: id batch exhausted in ns %p, remaining mounts left unmarked\n",
                    ns);
            failed = true;
            break;
        }
        new_id = batch[used++];
        SUSFS_LOGI("sus_mount: marked mnt_id %d -> %d (%s, devname %s)\n",
                r->mnt_id, new_id, shown,
                r->mnt_devname ? r->mnt_devname : "none");
        r->mnt_id = new_id;
        /* After the id is replaced, exactly like upstream: the climb starts at a
         * mount that now carries a KSU-range id and stops at the first ancestor
         * that does not - i.e. the id mountinfo still prints for the host. */
        sus_mount_idmap_add(new_id, sus_mount_shown_id(r), r->mnt.mnt_sb->s_dev);
        /* And the identity, so the same filesystem mounted in another namespace
         * (where this scan cannot reach) is recognised by the hide hooks. */
        sus_mount_ident_add(r);
        marked++;
    }
    spin_unlock(&ns->ns_lock);
    rcu_read_unlock();

    /* Hand back whatever the batch did not use. */
    for (i = used; i < n_batch; i++)
        sus_mount_ida_release(batch[i]);

    if (hit_cap)
        pr_warn("sus_mount: walk of ns %p stopped after %u entries (cap %d), result may be incomplete\n",
                ns, seen, SUS_MOUNT_MAX_SCAN);
    if (failed)
        pr_warn("sus_mount: marking in ns %p stopped early, %d mount(s) marked\n",
                ns, marked);
    SUSFS_LOGI("sus_mount: ns %p: seen=%u devname_hits=%u dpath_ok=%u dpath_err=%u skipped(other ns/cursor)=%u skipped(already marked)=%u marked=%d ids_alloc=%d\n",
            ns, seen, n_devname, n_dpath_ok, n_dpath_err, n_skipped_ns,
            n_skipped_marked, marked, n_batch);
    return marked;
}

static int sus_mount_mark_ksu_mounts(void)
{
    char *buf;
    unsigned long min;
    int marked;

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

    /* ONE namespace: the caller's.  A sweep over every namespace reachable from
     * the task list was tried and is NOT done here, because walking another
     * namespace's mount list is only safe under namespace_sem - which is static in
     * fs/namespace.c and therefore out of reach for this module (see the protocol
     * note above sus_mount_scan_ns).  Only the ns_lock half could be taken, and a
     * foreign namespace mounts and unmounts while we walk it.
     *
     * The zygote's copy of a KSU mount (the one every app inherits) is reached
     * through the identity table instead: same superblock, same root dentry, and
     * the hide hooks accept that as well as a KSU-range id, with no cross-namespace
     * walk at all.  That is what closes the leak this file's header describes. */
    marked = sus_mount_scan_ns(current->nsproxy->mnt_ns, buf, min);

    kfree(buf);

    if (marked)
        SUSFS_LOGI("sus_mount: %d KSU mount(s) marked with real mnt_id_ida ids (>= %llu), %d identity record(s) cached\n",
                marked, DEFAULT_KSU_MNT_ID, READ_ONCE(n_ident));
    else
        SUSFS_LOGI("sus_mount: 0 KSU mounts marked (nothing under /data/adb matched in this mnt ns, hide threshold %lu)\n",
                min);
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

/* One unregister path for both callers (module exit and the disable supercall):
 * two copies drifted apart once already in this project, leaving a hook armed
 * after "disabled". */
static void sus_mount_unregister(void)
{
    if (!mount_registered)
        return;
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
    if (kp_sb_down_ok) {
        unregister_kprobe(&kp_sb_down);
        kp_sb_down_ok = false;
    }
    if (kr_clone_ns_ok) {
        unregister_kretprobe(&kr_clone_ns);
        kr_clone_ns_ok = false;
    }
    mount_registered = false;
}

void susfs_sus_mount_exit(void)
{
    unsigned long flags;

    sus_mount_unregister();
    /* Marked mnt_ids are deliberately NOT restored: upstream assigns an id once
     * per mount and never rewrites it, so a marked id stays for the mount's
     * lifetime (and a later enable only has to scan for new mounts).  The id
     * itself goes back to mnt_id_ida through the kernel's own mnt_free_id()
     * when the mount is finally freed - we never free it ourselves. */

    /* Nothing to release: an identity record is numbers and a string, it holds no
     * reference on the dentry or the superblock (see the note above), precisely so
     * an unmounted module image cannot be kept alive by this table.  The records
     * themselves stay; after exit nothing compares against them (the hide hooks are
     * unregistered above) and a later enable re-learns them. */
    WRITE_ONCE(n_ident, 0);

    /* The id map, on the other hand, IS dropped: it is keyed by an id the kernel
     * recycles, and for as long as the module is disabled nothing observes a
     * recycle.  A re-enable re-learns every pair from the mounts it scans. */
    spin_lock_irqsave(&idmap_lock, flags);
    memset(mount_idmap, 0, sizeof(mount_idmap));
    n_idmap = 0;
    spin_unlock_irqrestore(&idmap_lock, flags);
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
    /* Optional too, but it is the ONLY thing that invalidates a record when its
     * filesystem is unmounted, and the numbers the records are keyed by do get
     * reused (measured).  A missing symbol means records can outlive their fs and
     * falsely match another one, so say so instead of quietly degrading. */
    rc = register_kprobe(&kp_sb_down);
    if (rc)
        pr_warn("sus_mount: register_kprobe(generic_shutdown_super) failed %d - records are NOT dropped when their filesystem is unmounted, a reused s_dev can match an unrelated mount\n",
                rc);
    else
        kp_sb_down_ok = true;
    /* Optional as well: without it a namespace copied after the enable keeps
     * working for the mount TABLE (identity hides the lines) but fdinfo/statx stay
     * inconsistent until somebody reads a mount table in that namespace. */
    rc = register_kretprobe(&kr_clone_ns);
    if (rc)
        pr_warn("sus_mount: register_kretprobe(copy_mnt_ns) failed %d - ids of mounts in a namespace copied later are only learned when its mount table is read\n",
                rc);
    else
        kr_clone_ns_ok = true;
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
        sus_mount_unregister();
    }
    info.err = 0;
    SUSFS_LOGI("sus_mount: %s (supercall)\n", info.enabled ? "hide" : "unhide");
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_mount supercall copy_to_user failed\n");
}
