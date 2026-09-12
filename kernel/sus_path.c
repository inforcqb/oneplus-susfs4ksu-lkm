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
 *     for testing from a root shell);
 *   - a path registered before it exists is kept and hidden once it appears,
 *     which is upstream's CMD_SUSFS_ADD_SUS_PATH_LOOP / LH_SUS_PATH_LOOP
 *     behaviour (see sus_path_resolve_pending()).
 *
 * Upstream's FUSE_SUPER_MAGIC branch (susfs.c:71-84, :151-166, :195-212) has no
 * equivalent here on purpose - see the note above sus_path_inode_hidden().
 */
#include <linux/module.h>
#include <linux/delay.h>	/* ndelay, for the timing cover */
#include <linux/random.h>	/* prandom_u32_max, for its jitter */
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
#include <linux/compat.h>
#include <linux/workqueue.h>	/* compat_ptr(), for 32-bit callers */
#include <linux/mutex.h>	/* serialises the first rule's arming */
#include <linux/limits.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact, for optional compat probes */

#include "lsm_hook.h"

/* Bounce buffer for the dirent rewrite.  One record at a time is moved
 * through it, so the size of a LISTING is not a limit - only the size of a
 * single record is.  A record that does not fit is left in place, i.e. not
 * filtered, and the rewrite stops there; that is counted and logged. */
#define DIRENT_BUF_SIZE 65536
#define SUS_PATH_MAX_ENTRIES 8192
/* Deferred resolution of rules whose path does not exist yet - upstream's
 * CMD_SUSFS_ADD_SUS_PATH_LOOP semantics, see sus_path_resolve_pending().
 * While at least one rule is unresolved: retry every SUS_PATH_PENDING_RETRY_S
 * seconds, stop retrying on the timer after SUS_PATH_PENDING_TRIES attempts
 * (the rule itself stays registered and keeps hiding the path), and never do
 * more than SUS_PATH_PENDING_BUDGET lookups in one pass. */
#define SUS_PATH_PENDING_RETRY_S 2
#define SUS_PATH_PENDING_TRIES 60
#define SUS_PATH_PENDING_BUDGET 128
/* Longest registered path, for the string-level hooks.  256 matches the ABI's
 * target_pathname field. */
#define SUS_PATH_LEN 256

/* arm64 compat (32-bit) syscall numbers.  Not reachable through asm/unistd.h in
 * this build, so spelled out per arch/arm64/include/asm/unistd32.h:
 * getdents64 (217) maps to the NATIVE sys_getdents64 there, getdents (141) is the
 * separate compat body - which is why only the latter needed its own probe. */
#define __NR_compat_getdents64 217
#define __NR_compat_getdents 141

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/*
 * One registered path.
 *
 * Kept for two independent mechanisms:
 *   - the dirent filter hides the directory entry (by dev+ino+name) on every
 *     listing ABI this kernel can reach (see the probe block below);
 *   - the LSM hooks reject path-based access outright (by the ihold'ed inode
 *     pointer, which is what upstream's AS_FLAGS_SUS_PATH inode flag achieves).
 *
 * dev is kept for diagnostics only: the dirent filter only ever sees the buffer,
 * never the listing's fd or superblock.
 */
struct sus_path_entry {
    struct list_head list;
    /* ihold'ed once the path resolved, NULL while the rule is PENDING, i.e.
     * registered for a path that does not exist yet (upstream's _LOOP variant).
     * A pending entry holds no inode and no struct path, so a path that never
     * appears cannot pin anything. */
    struct inode *inode;
    u64 dev;
    u64 ino;
    char name[NAME_MAX + 1];
    /* The path as it was registered, for the string-level hooks below: the
     * lookup entry points hand us the caller's own path string, not an inode.
     * Stored without a trailing slash, path_len == strlen(path). */
    char path[SUS_PATH_LEN];
    unsigned int path_len;
    /* Resolution pass that last tried this entry (0 = never).  It is what stops
     * one pass from retrying the same unresolved rule over and over, without
     * having to hold a pointer across the sleepable kern_path(). */
    unsigned int pass;
    /* This rule is one of the module's own control nodes (/proc/susfs_*): hide
     * it from every non-root caller, not only from apps - see
     * sus_path_entry_gate_any() / sus_path_entry_gate_inode(). */
    bool self_protect;
    /* The mode the inode had before this rule relaxed it, or 0 when the rule did
     * not touch it (see sus_path_relax_mode()). */
    umode_t orig_mode;
};

/* Let DAC through, so that the LSM layer is the only thing that can refuse.
 *
 * DAC runs before the LSM chain, and a file whose mode denies the caller is
 * answered EACCES there - before any LSM hook is called, so a hidden path could
 * not be turned into ENOENT.  Rather than pay for a brk on every permission check
 * (the old DAC probes), the mode is relaxed once, here, when the rule is
 * registered: this is the one moment where the inode is already in hand, and it
 * costs nothing afterwards.
 *
 * It is not disguised back on the way out: only non-root callers are hidden at
 * all, and root is not a party this module hides from, so whoever can see the
 * relaxed mode can see the file anyway.
 *
 * The inode is ihold'ed for as long as the rule lives, so it cannot be evicted and
 * re-read from disk with the original mode - one write is enough. */
static void sus_path_relax_mode(struct sus_path_entry *e)
{
    umode_t mode;

    if (!e->inode)
        return;

    mode = READ_ONCE(e->inode->i_mode);
    if ((mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0777)
        return;                 /* already open, or another rule did it */

    e->orig_mode = mode;
    WRITE_ONCE(e->inode->i_mode, (mode & ~(umode_t)(S_IRWXU | S_IRWXG | S_IRWXO)) | 0777);
}

static void sus_path_restore_mode(struct sus_path_entry *e)
{
    if (!e->inode || !e->orig_mode)
        return;

    WRITE_ONCE(e->inode->i_mode, e->orig_mode);
    e->orig_mode = 0;
}

static void sus_path_entry_set_path(struct sus_path_entry *e, const char *path);

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);
static unsigned int sus_path_count;

/* Rules waiting for their path to appear.  Counted so that every fast path can
 * bail out at once when there is nothing to resolve; guarded by sus_path_lock. */
static atomic_t sus_path_n_pending = ATOMIC_INIT(0);
static unsigned int sus_path_pass_gen;      /* guarded by sus_path_lock */
static atomic_t sus_path_pending_tries = ATOMIC_INIT(0);
/* One resolution pass at a time: the supercall and the retry timer would
 * otherwise race on the same entries (and on the per-entry pass marker). */
static DEFINE_MUTEX(sus_path_pending_lock);

static void sus_path_pending_work(struct work_struct *w);
static DECLARE_DELAYED_WORK(sus_path_pending_wq, sus_path_pending_work);

/* legacy/debug: hide a single exact filename everywhere (empty = disabled) */
static char hide_name[NAME_MAX + 1];
module_param_string(hide_name, hide_name, sizeof(hide_name), 0644);

static char *dirent_tmp;
/* Isolation test: with no_extra=1 the LSM replacement and the dirent filter are
 * not registered at all. */
static int no_extra;
module_param(no_extra, int, 0644);

/* Guards dirent_tmp.  It is a single global scratch buffer shared by every
 * dirent filter exit, and the probes can fire concurrently on several CPUs:
 * without this, two listings compact into the same buffer and one process can
 * get another directory's entries.  sus_path_lock cannot be reused - it is taken
 * inside the traversal by sus_path_is_hidden(). */
static DEFINE_SPINLOCK(sus_path_buf_lock);

/* dirent rewrites that had to stop early (a record too large for the bounce
 * buffer, or a uaccess fault while rewriting).  Both used to be silent; the
 * counter and the ratelimited log are what makes "the listing did not get
 * filtered" visible instead of just producing a longer listing. */
static atomic_t n_dirent_rewrite_fail = ATOMIC_INIT(0);
/* How often a whole chunk turned out to be hidden and had to be answered with a
 * placeholder record instead of EOF - see sus_path_filter(). */
static atomic_t n_dirent_all_hidden = ATOMIC_INIT(0);

/* ---- the resolver's own exemption ----
 *
 * Every layer below answers "hidden" to whoever asks, and the background
 * resolution of a pending rule has to ask the VFS itself (kern_path).  That walk
 * passes through our own hooks once the rule HAS an inode, so the walk would be
 * answered -ENOENT and a re-resolution could never succeed.  Measured on the
 * device: without the exemption the walk is refused and the rule stays pending
 * forever.  Upstream has no such trap because its hiding is
 * a flag set on an inode rather than a refusal to answer, and because it walks
 * from the workqueue under override_creds(ksu_cred) (susfs.c:139, reverted at
 * susfs.c:171) - see sus_path_override_creds() below, which mirrors that.
 *
 * So exactly one task is exempt: the task inside the resolve call, i.e. the one
 * that stored itself here.  The exemption is per-task by construction, so every
 * other process keeps being hidden for the whole window, and it is cleared
 * immediately after kern_path() returns, on every path.  The exempt task is the
 * root supercall caller (task_work) or a workqueue worker (retry timer).
 */
static struct task_struct *sus_path_resolver;

static inline bool sus_path_is_resolver(void)
{
    return READ_ONCE(sus_path_resolver) == current;
}

/* Upstream resolves its _LOOP list from a workqueue worker too, and it does it
 * under override_creds(ksu_cred) (susfs.c:139 ... revert_creds() at :171): the
 * creds a worker walks with are not the ones the path is supposed to be visible
 * to, and everything that decides on the caller - SELinux, DAC and our own gate
 * - can tell the difference.
 *
 * Measured on device: a kworker walks as uid 0 in the kernel domain, so a plain
 * kern_path("/data/local/tmp/...") comes back -EACCES and the rule stays pending
 * forever (pend: last-rc=-13).  Upstream's answer is ksu_cred, but that symbol
 * lives in the `kernelsu` module and find_kernel_symbol_exact() deliberately
 * refuses module symbols ("ignore symbol ... of module ...") - so rather than
 * depend on KernelSU internals, the creds of whoever registered the rule are
 * saved (a reference is held) and the walk borrows those: that process is by
 * definition one that can reach the path, since it is the one being told to hide
 * it.  Exactly one stored reference, released on unload. */
static const struct cred *sus_path_pending_cred;
static DEFINE_MUTEX(sus_path_cred_lock);
static atomic_t sus_path_used_caller_cred = ATOMIC_INIT(0);

/* Called from the supercall (process context) when a rule is registered pending. */
static void sus_path_save_caller_cred(void)
{
    const struct cred *new = get_cred(current_cred());
    const struct cred *old;

    mutex_lock(&sus_path_cred_lock);
    old = sus_path_pending_cred;
    sus_path_pending_cred = new;
    mutex_unlock(&sus_path_cred_lock);
    if (old)
        put_cred(old);
}

static const struct cred *sus_path_override_creds(void)
{
    const struct cred *cred;

    mutex_lock(&sus_path_cred_lock);
    cred = sus_path_pending_cred;
    if (cred)
        get_cred(cred);
    mutex_unlock(&sus_path_cred_lock);
    if (!cred)
        return NULL;

    atomic_inc(&sus_path_used_caller_cred);
    return override_creds(cred);
}

static void sus_path_revert_creds(const struct cred *saved)
{
    if (saved)
        revert_creds(saved);
}

static void sus_path_drop_caller_cred(void)
{
    const struct cred *old;

    mutex_lock(&sus_path_cred_lock);
    old = sus_path_pending_cred;
    sus_path_pending_cred = NULL;
    mutex_unlock(&sus_path_cred_lock);
    if (old)
        put_cred(old);
}

/* What the pending machinery did, for hide_list: "pending never drops" has to be
 * distinguishable from "the timer never ran" and from "the walk itself fails". */
static atomic_t sus_path_pend_passes = ATOMIC_INIT(0);      /* resolve passes run */
static atomic_t sus_path_pend_ticks = ATOMIC_INIT(0);       /* timer ticks run */
static atomic_t sus_path_pend_walks = ATOMIC_INIT(0);       /* walks that succeeded */
static atomic_t sus_path_pend_lost = ATOMIC_INIT(0);        /* walk ok, rule gone */
static atomic_t sus_path_pend_last_rc = ATOMIC_INIT(0);     /* last walk result */
static atomic_t sus_path_pend_logged_rc = ATOMIC_INIT(1);   /* rc already reported */

/* ---- gates ----
 *
 * Defined up here because every decision layer below - the dirent filter, the
 * inode lookups and the path-string matcher - has to ask the same question. */

/* Upstream gates on susfs_is_current_proc_umounted_app() && is_i_uid_not_allowed():
 * only app processes, and never a file owned by the caller.  TIF_PROC_UMOUNTED is
 * a SUSFS-specific thread flag this LKM does not have, so uid >= 10000 is the
 * proxy.  hide_from_apps=0 applies the hidden set to every process including
 * root - handy when testing from an adb shell. */
static int hide_from_apps = 1;
module_param(hide_from_apps, int, 0644);

/* UID half of the upstream gate.  Separate because a rule that has not resolved
 * its path yet (PENDING, inode == NULL) has no inode to ask about ownership - see
 * sus_path_entry_gate_any(). */
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

/* Per-rule gate.
 *
 * A rule flagged self_protect is one of this module's own control nodes.  Those
 * have to be invisible to EVERY non-root caller, not just to apps: the ordinary
 * gate is uid >= 10000, so a probe running as system (1000) or shell (2000)
 * would read /proc/susfs_kstat straight out of the listing - exactly the trace
 * this module exists to avoid.  Root keeps access so the operator can manage the
 * module.
 *
 * Ordinary rules keep the upstream semantics untouched. */
static inline bool sus_path_entry_gate_inode(const struct sus_path_entry *e,
                                             struct inode *inode)
{
    if (e->self_protect)
        return current_uid().val != 0;
    return sus_path_gate_ok(inode);
}

/* The gate for the layers that match by (ino, name) or by path string rather
 * than by the inode being accessed: the dirent filter and the path-string
 * matcher.
 *
 * They used to apply the uid half only, which made them answer differently from
 * the LSM layer for the one case upstream's gate is really about: a file owned
 * by the calling app.  Registering such a file made it disappear from the
 * listing while stat()/open() still succeeded - a listing that omits a file the
 * caller can open is a far louder signal than either behaviour alone.
 *
 * The rule keeps its inode ihold()ed, so the ownership question can be asked of
 * that very inode here: no cached uid, and a chown() of the hidden file moves
 * both layers together.  A rule whose path has not resolved yet has no inode and
 * falls back to the uid half (the LSM layer cannot see it either, because
 * nothing exists at that path yet to be accessed). */
static inline bool sus_path_entry_gate_any(const struct sus_path_entry *e)
{
    if (e->self_protect)
        return current_uid().val != 0;
    if (!e->inode)
        return sus_path_gate_uid_ok();
    return sus_path_gate_ok(e->inode);
}

static bool sus_path_is_hidden(u64 ino, const char *name)
{
    struct sus_path_entry *e;
    bool hidden = false;

    /* The one task resolving a pending rule is never answered "hidden": its own
     * walk would otherwise be refused by this very table (see the block above
     * sus_path_resolver).  Per-task, so nothing else changes. */
    if (sus_path_is_resolver())
        return false;

    /* A dirent is identified by (d_ino, name) and nothing else here - the dirent
     * filter never sees the fd or the superblock.  A rule whose inode reports 0
     * therefore has no identity to match: d_ino 0 is what some filesystems use for
     * "unknown", so matching it by name alone would hide unrelated entries.  Such a
     * rule is hidden by the by-inode layers only - see sus_path_supercall(). */
    if (ino) {
        spin_lock(&sus_path_lock);
        list_for_each_entry(e, &sus_path_list, list) {
            if (e->ino && e->ino == ino && !strcmp(e->name, name) &&
                sus_path_entry_gate_any(e)) {
                hidden = true;
                break;
            }
        }
        spin_unlock(&sus_path_lock);
    }

    if (!hidden && hide_name[0])
        hidden = !strcmp(name, hide_name);

    return hidden;
}

/* ---- deferred resolution: upstream's CMD_SUSFS_ADD_SUS_PATH_LOOP ----
 *
 * Upstream's _LOOP command does NOT resolve the path when the rule is added.
 * susfs_add_sus_path_loop() (susfs.c:99-132) checks for an empty string only,
 * strscpy()s the path into a st_susfs_sus_path_list node and puts it on
 * LH_SUS_PATH_LOOP; the path is resolved much later by
 * susfs_run_sus_path_loop() (susfs.c:134-172), which walks that list with
 * kern_path(path, 0, ...) and sets AS_FLAGS_SUS_PATH on the inode it finds.
 * Nothing triggers it from the kernel timer side: susfs_run_extra_works()
 * (susfs.c:1451-1457) is scheduled by ksu_handle_extra_susfs_work()
 * (KernelSU/10_enable_susfs_for_ksu.patch:1599-1607) each time zygote spawns an
 * app that gets marked TIF_PROC_UMOUNTED (patch:1669, patch:1719), and the
 * entries are never removed from the list, so every spawn retries all of them.
 *
 * The semantics that matter: "registered now, hidden as soon as the path shows
 * up" - for /data/adb/modules/... at boot, or an inode that did not exist yet.
 * There is no attempt limit and no timeout upstream; the trigger is an event.
 *
 * The LKM has no zygote hook, so the equivalent is:
 *   - the rule is registered immediately with inode == NULL ("pending").  A
 *     pending rule has no inode, so NOTHING hides it yet: the dirent filter needs
 *     (ino, name) and the LSM slots need the inode.  What it does have is a place
 *     in the table, so the path is hidden from the moment this loop resolves it;
 *   - sus_path_resolve_pending() retries the lookup in sleepable context: from
 *     sus_path_supercall() (every add is a retry opportunity, which is what the
 *     tool produces naturally when it registers a batch of rules) and from a
 *     bounded retry timer;
 *   - the resolving task is exempt from our own hiding and walks with KernelSU's
 *     creds, because the walk of a registered path is exactly what every layer
 *     below would refuse (sus_path_resolver, sus_path_override_creds(); upstream
 *     needs the creds half of this for its own workqueue walk, susfs.c:139).
 *
 * A rule that is still missing after the timer gives up hides NOTHING until it
 * resolves: there is no string layer to fall back on (the entry layers were
 * deleted - see sus_path_init()).  The next add re-arms the timer, and re-adding
 * the same path after it exists completes the pending entry on the spot.
 */

/* Basename of a registered path: what the getdents64 filter compares d_name
 * against, and what the table shows while the inode is unknown.  Stored paths
 * never have a trailing slash (sus_path_entry_set_path), so the text after the
 * last '/' is the whole name. */
static void sus_path_basename(const char *path, char *dst, size_t size)
{
    const char *slash = strrchr(path, '/');

    if (slash && slash[1])
        path = slash + 1;
    strscpy(dst, path, size);
}

static int sus_path_resolve_pending(void)
{
    char path[SUS_PATH_LEN];
    unsigned int gen;
    int budget = SUS_PATH_PENDING_BUDGET;
    int resolved = 0;

    if (!atomic_read(&sus_path_n_pending))
        return 0;
    /* Whoever loses the race simply finds the work already done.  trylock, so
     * the supercall never blocks behind a pass that is sleeping in kern_path(). */
    if (!mutex_trylock(&sus_path_pending_lock))
        return 0;
    atomic_inc(&sus_path_pend_passes);

    /* Pass marker.  0 means "never attempted", so generation 0 is skipped. */
    spin_lock(&sus_path_lock);
    gen = ++sus_path_pass_gen;
    if (!gen)
        gen = ++sus_path_pass_gen;
    spin_unlock(&sus_path_lock);

    while (budget-- > 0) {
        struct sus_path_entry *e, *slot;
        struct inode *inode = NULL;
        const struct cred *saved;
        struct path p;
        char name[NAME_MAX + 1];
        bool published = false;
        int rc;

        path[0] = '\0';
        spin_lock(&sus_path_lock);
        slot = NULL;
        list_for_each_entry(e, &sus_path_list, list) {
            if (!e->inode && e->pass != gen) {
                memcpy(path, e->path, e->path_len + 1);
                e->pass = gen;
                slot = e;
                break;
            }
        }
        spin_unlock(&sus_path_lock);
        if (!slot)
            break;              /* every pending rule was attempted */

        name[0] = '\0';

        /* Exempt THIS task (and only it) from our own hiding for the duration of
         * the walk, and walk with KernelSU's creds like upstream does.  Both are
         * cleared/undone immediately, whatever the walk answers - the exemption
         * is per-task, so every other process keeps being hidden throughout. */
        WRITE_ONCE(sus_path_resolver, current);
        saved = sus_path_override_creds();
        rc = kern_path(path, LOOKUP_FOLLOW, &p);
        sus_path_revert_creds(saved);
        WRITE_ONCE(sus_path_resolver, NULL);

        atomic_set(&sus_path_pend_last_rc, rc);
        if (!rc) {
            atomic_inc(&sus_path_pend_walks);
            inode = d_inode(p.dentry);
            if (inode) {
                strscpy(name, p.dentry->d_name.name, sizeof(name));
                /* Hold it before path_put() can drop the last dentry reference
                 * and evict it; the pointer is published only afterwards. */
                ihold(inode);
            }
            path_put(&p);
        } else if (rc != atomic_read(&sus_path_pend_logged_rc)) {
            /* Report each distinct answer once: a rule that never resolves has
             * to be distinguishable from a timer that never ran, and the answer
             * (-ENOENT, -EACCES, -ENOTDIR) says which of the two it is without
             * putting the hidden path itself into the log. */
            atomic_set(&sus_path_pend_logged_rc, rc);
            SUSFS_LOGI("sus_path: pending walk rc=%d (%d pending, pass %u)\n",
                    rc, atomic_read(&sus_path_n_pending), gen);
        }

        /* The entry is re-found rather than used across the sleep: the table can
         * be changed while we are away (another add, or module exit tearing it
         * all down), so the only thing carried over is the path string - and a
         * pass marker that no other pass can have set on a fresh entry. */
        spin_lock(&sus_path_lock);
        slot = NULL;
        list_for_each_entry(e, &sus_path_list, list) {
            if (e->pass == gen && !e->inode && !strcmp(e->path, path)) {
                slot = e;
                break;
            }
        }
        if (slot && inode) {
            slot->dev = (u64)inode->i_sb->s_dev;
            slot->ino = (u64)inode->i_ino;
            strscpy(slot->name, name, sizeof(slot->name));
            slot->inode = inode;
            inode = NULL;               /* the table holds the reference now */
            atomic_dec(&sus_path_n_pending);
            resolved++;
            published = true;
        }
        spin_unlock(&sus_path_lock);

        if (inode) {
            iput(inode);                /* the rule is gone, or already resolved */
        } else if (slot && published) {
            /* Relaxed outside the lock: the inode is published and ihold'ed now, so
             * it cannot go away under us. */
            spin_lock(&sus_path_lock);
            sus_path_relax_mode(slot);
            spin_unlock(&sus_path_lock);
        } else if (!rc) {
            atomic_inc(&sus_path_pend_lost);    /* walk ok, nothing to publish */
        }
    }

    if (resolved)
        SUSFS_LOGI("sus_path: resolved %d pending rule(s), %d still unresolved\n",
                resolved, atomic_read(&sus_path_n_pending));

    mutex_unlock(&sus_path_pending_lock);
    return resolved;
}

/* A rule was registered for a path that is not there yet.  Try once right away
 * (the failing lookup was microseconds ago, but an earlier add in the same batch
 * may be what made this rule necessary), then let the timer keep trying.
 * Called from sus_path_supercall()'s task_work, i.e. process context. */
static void sus_path_pending_arm(void)
{
    if (!atomic_read(&sus_path_n_pending))
        return;

    sus_path_resolve_pending();
    if (!atomic_read(&sus_path_n_pending))
        return;

    atomic_set(&sus_path_pending_tries, 0);
    schedule_delayed_work(&sus_path_pending_wq, SUS_PATH_PENDING_RETRY_S * HZ);
}

/* Retry timer.  Bounded on purpose: upstream's equivalent runs once per app
 * spawn, which is a free trigger, while this one costs a periodic work item -
 * and a rule whose path never appears must not keep it alive forever.
 *
 * A tick that cannot resolve anything is not silent any more: the walk's own
 * result is logged once per distinct value by sus_path_resolve_pending(), and
 * hide_list carries the pass/tick/walk counters, so "the timer never ran" and
 * "the walk keeps failing" are told apart without guessing. */
static void sus_path_pending_work(struct work_struct *w)
{
    int resolved;

    atomic_inc(&sus_path_pend_ticks);
    resolved = sus_path_resolve_pending();

    if (!atomic_read(&sus_path_n_pending))
        return;                 /* every rule has its inode now */

    if (resolved > 0)
        atomic_set(&sus_path_pending_tries, 0);     /* progress: keep trying */

    if (atomic_inc_return(&sus_path_pending_tries) > SUS_PATH_PENDING_TRIES) {
        SUSFS_LOGI("sus_path: %d rule(s) still pending after %d retries (last walk rc=%d) - retry timer stops; they hide nothing until they resolve, the next add tries again\n",
                atomic_read(&sus_path_n_pending), SUS_PATH_PENDING_TRIES,
                atomic_read(&sus_path_pend_last_rc));
        return;
    }
    schedule_delayed_work(&sus_path_pending_wq, SUS_PATH_PENDING_RETRY_S * HZ);
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

/* ---- name-based operations ----
 *
 * unlink/rmdir/rename/link never permission-check the FILE: they check the PARENT
 * directory (may_delete/may_create), so inode_permission never sees the target and
 * an app that can write the containing directory can delete or rename a hidden file
 * straight out of hiding - the code below used to say so and leave it at that.
 *
 * The kernel already has a hook for each of those operations, and each gets the
 * target's dentry, so the same inode match answers them:
 *
 *     vfs_unlink -> security_inode_unlink(dir, dentry)
 *     vfs_rmdir  -> security_inode_rmdir(dir, dentry)
 *     vfs_rename -> security_inode_rename(old_dir, old_dentry, new_dir, new_dentry)
 *     vfs_link   -> security_inode_link(old_dentry, dir, new_dentry)
 *
 * Upstream does this earlier, inside namei, which also covers the case of a parent
 * directory that itself denies the caller.  Being after DAC is enough for the case
 * that matters here (a writable parent) and costs nothing otherwise.
 *
 * The create family (inode_create/mkdir/mknod/symlink) is deliberately not here:
 * the target does not exist yet, so there is no inode to match against. */
static int sus_path_inode_unlink(struct inode *dir, struct dentry *dentry);
static int sus_path_inode_rmdir(struct inode *dir, struct dentry *dentry);
static int sus_path_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				 struct inode *new_dir, struct dentry *new_dentry);
static int sus_path_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry);

static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_unlink),
					   typeof(&sus_path_inode_unlink)),
	      "inode_unlink hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_rmdir),
					   typeof(&sus_path_inode_rmdir)),
	      "inode_rmdir hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_rename),
					   typeof(&sus_path_inode_rename)),
	      "inode_rename hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_link),
					   typeof(&sus_path_inode_link)),
	      "inode_link hook signature mismatch");

static struct ksu_lsm_hook sus_path_unlink_hook = KSU_LSM_HOOK_INIT(
	inode_unlink, "selinux_inode_unlink", (void *)sus_path_inode_unlink, 0);

static struct ksu_lsm_hook sus_path_rmdir_hook = KSU_LSM_HOOK_INIT(
	inode_rmdir, "selinux_inode_rmdir", (void *)sus_path_inode_rmdir, 0);

static struct ksu_lsm_hook sus_path_rename_hook = KSU_LSM_HOOK_INIT(
	inode_rename, "selinux_inode_rename", (void *)sus_path_inode_rename, 0);

static struct ksu_lsm_hook sus_path_link_hook = KSU_LSM_HOOK_INIT(
	inode_link, "selinux_inode_link", (void *)sus_path_inode_link, 0);

/* ---- metadata and attribute operations ----
 *
 * These syscalls reach the kernel through namei and then stop before any check we
 * otherwise hook, so a hidden file could still be probed - and in the setattr case
 * even modified - while answering "permission denied" rather than "no such file".
 * Each of them has an LSM hook that carries the dentry (or the path), so the same
 * inode match answers all of them; no entry-layer work needed.
 *
 *   statfs/fstatfs        -> security_sb_statfs(dentry)
 *   chmod/chown/truncate/utimes -> security_inode_setattr(dentry, iattr)
 *   getxattr/listxattr    -> security_inode_getxattr / _listxattr(dentry, ...)
 *   setxattr/removexattr  -> security_inode_setxattr / _removexattr(...)
 *   inotify_add_watch, fanotify_mark -> security_path_notify(path, ...)
 *
 * inode_setattr is the one that also closes the error-code leak: without it an app
 * got EPERM or EACCES from the owner check, which says the file exists. */
static int sus_path_sb_statfs(struct dentry *dentry);
static int sus_path_inode_setattr(struct dentry *dentry, struct iattr *attr);
static int sus_path_inode_getxattr(struct dentry *dentry, const char *name);
static int sus_path_inode_listxattr(struct dentry *dentry);
static int sus_path_inode_setxattr(struct user_namespace *mnt_userns,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags);
static int sus_path_inode_removexattr(struct user_namespace *mnt_userns,
				      struct dentry *dentry, const char *name);
static int sus_path_path_notify(const struct path *path, u64 mask,
				unsigned int obj_type);

static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(sb_statfs),
					   typeof(&sus_path_sb_statfs)),
	      "sb_statfs hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_setattr),
					   typeof(&sus_path_inode_setattr)),
	      "inode_setattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_getxattr),
					   typeof(&sus_path_inode_getxattr)),
	      "inode_getxattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_listxattr),
					   typeof(&sus_path_inode_listxattr)),
	      "inode_listxattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_setxattr),
					   typeof(&sus_path_inode_setxattr)),
	      "inode_setxattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_removexattr),
					   typeof(&sus_path_inode_removexattr)),
	      "inode_removexattr hook signature mismatch");
static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(path_notify),
					   typeof(&sus_path_path_notify)),
	      "path_notify hook signature mismatch");

static struct ksu_lsm_hook sus_path_statfs_hook = KSU_LSM_HOOK_INIT(
	sb_statfs, "selinux_sb_statfs", (void *)sus_path_sb_statfs, 0);

static struct ksu_lsm_hook sus_path_setattr_hook = KSU_LSM_HOOK_INIT(
	inode_setattr, "selinux_inode_setattr", (void *)sus_path_inode_setattr, 0);

static struct ksu_lsm_hook sus_path_getxattr_hook = KSU_LSM_HOOK_INIT(
	inode_getxattr, "selinux_inode_getxattr", (void *)sus_path_inode_getxattr, 0);

static struct ksu_lsm_hook sus_path_listxattr_hook = KSU_LSM_HOOK_INIT(
	inode_listxattr, "selinux_inode_listxattr", (void *)sus_path_inode_listxattr, 0);

static struct ksu_lsm_hook sus_path_setxattr_hook = KSU_LSM_HOOK_INIT(
	inode_setxattr, "selinux_inode_setxattr", (void *)sus_path_inode_setxattr, 0);

static struct ksu_lsm_hook sus_path_removexattr_hook = KSU_LSM_HOOK_INIT(
	inode_removexattr, "selinux_inode_removexattr", (void *)sus_path_inode_removexattr, 0);

static struct ksu_lsm_hook sus_path_notify_hook = KSU_LSM_HOOK_INIT(
	path_notify, "selinux_path_notify", (void *)sus_path_path_notify, 0);

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
 * process including root - handy when testing from an adb shell.
 *
 * Declared up here because the gates near the top of the file read it. */

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

/*
 * Inode identity is the whole criterion here, and there is deliberately NO FUSE
 * branch - do not "port" upstream's one (susfs.c:71-84 in add, :151-166 in
 * susfs_run_sus_path_loop(), :195-212 in susfs_is_inode_sus_path()).
 *
 * What upstream does there: if the inode's superblock is FUSE_SUPER_MAGIC it
 * takes fi = get_fuse_inode(inode) and sets AS_FLAGS_SUS_PATH on
 * fi->inode.i_mapping->flags and on inode->i_mapping->flags - i.e. it writes the
 * same word twice, because get_fuse_inode() is container_of(inode, struct
 * fuse_inode, inode) (this tree: fs/fuse/fuse_i.h:973-976) over an inode that is
 * embedded in that very struct (fuse_i.h:124-126), and upstream's `inode` comes
 * from d_backing_inode(), which in 5.15 is literally `dentry->d_inode` (this
 * tree: include/linux/dcache.h:560-565).  So &fi->inode == inode and
 * fi->inode.i_mapping == inode->i_mapping: there is no wrapper inode and no
 * second mapping to flag.  The branch's only remaining effects are the
 * i_mapping NULL check (identical to the generic one two lines above it,
 * susfs.c:65-69) and a log line with fi->nodeid.
 *
 * Why that is a no-op for this LKM: we do not store a bit in an inode's address
 * space, we store the `struct inode *` itself and hold a reference to it
 * (sus_path_inode_hidden() compares pointers).  Upstream's flag is just as
 * object-scoped as our pointer is - inode->i_mapping is per inode object - and
 * ihold() means the address can never be recycled into an unrelated inode.  For
 * the same reason a FUSE passthrough mount needs nothing special: its dentries
 * resolve to the FUSE inode (or, through /mnt/pass_through/..., to the backing
 * inode), each spelling is the object it resolves to, and upstream flags exactly
 * the same object for that spelling - it does not touch fi->backing_inode
 * either.  What covered the OTHER spellings of the same file was the path-string
 * layer, which has since been deleted; the inode match covers them by itself
 * (symlink, hard link, .., // and /proc/self/root/... all resolve to that inode).
 * One FUSE property upstream's branch does not buy it either is the dirent
 * filter: upstream maps a dirent's d_ino back to an inode with
 * ilookup(buf->sb, ino), but a FUSE inode is hashed by nodeid (or by the backing
 * inode pointer when CONFIG_FUSE_BPF=y passthrough is in use - fs/fuse/inode.c:
 * 449-455, and this kernel's gki_defconfig sets CONFIG_FUSE_BPF=y) while
 * inode->i_ino is the daemon's attr.ino (fs/fuse/inode.c:250) and the dirent's
 * d_ino is whatever the daemon put in its readdir reply.  When those disagree,
 * upstream finds no inode and skips the entry unfiltered (patch:1752-1760) -
 * which is exactly the precondition our (d_ino, name) comparison has.  A shared
 * limitation, not a gap this port opened, and a name-only fallback would hide
 * same-named entries elsewhere in the same superblock, so none is added.
 */
static bool sus_path_inode_hidden(struct inode *inode)
{
    struct sus_path_entry *e;
    bool hidden = false;

    if (!inode || !READ_ONCE(sus_path_count))
        return false;

    /* See sus_path_resolver: the task resolving a pending rule must not be
     * answered by its own table, or its walk of that very path is refused. */
    if (sus_path_is_resolver())
        return false;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list) {
        if (e->inode == inode && sus_path_entry_gate_inode(e, inode)) {
            hidden = true;
            break;
        }
    }
    spin_unlock(&sus_path_lock);

    return hidden;
}

/* The gates live near the top of the file (see "---- gates ----"): every
 * decision layer needs them. */

static int sus_path_inode_getattr(const struct path *path)
{
    int (*orig)(const struct path *) = (void *)sus_path_getattr_hook.original;
    struct inode *inode;

    if (path && path->dentry) {
        inode = d_inode(path->dentry);
        if (sus_path_inode_hidden(inode)) {
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

    if (sus_path_inode_hidden(inode)) {
        atomic_inc(&n_enoent_perm);
        return -ENOENT;
    }
    if (!orig)
        return 0;
    return orig(inode, mask);
}

/* The name-based ops share one counter: they answer the same question ("may this
 * name be used at all") and the interesting fact is that they fire at all. */
static atomic_t n_enoent_nameop = ATOMIC_INIT(0);

/* A negative dentry has no inode, which is exactly the "not hidden" answer. */
static bool sus_path_dentry_hidden(const struct dentry *dentry)
{
    struct inode *inode;

    if (!dentry)
        return false;
    inode = d_inode(dentry);
    return inode && sus_path_inode_hidden(inode);
}

static int sus_path_nameop_hit(void)
{
    atomic_inc(&n_enoent_nameop);
    return -ENOENT;
}

static int sus_path_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int (*orig)(struct inode *, struct dentry *) = (void *)sus_path_unlink_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_nameop_hit();
    if (!orig)
        return 0;
    return orig(dir, dentry);
}

static int sus_path_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int (*orig)(struct inode *, struct dentry *) = (void *)sus_path_rmdir_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_nameop_hit();
    if (!orig)
        return 0;
    return orig(dir, dentry);
}

static int sus_path_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				 struct inode *new_dir, struct dentry *new_dentry)
{
    int (*orig)(struct inode *, struct dentry *, struct inode *, struct dentry *) =
        (void *)sus_path_rename_hook.original;

    /* Both ends matter: moving a hidden file out of hiding is the obvious one, and
     * overwriting a hidden file through its target name is the other. */
    if (sus_path_dentry_hidden(old_dentry) || sus_path_dentry_hidden(new_dentry))
        return sus_path_nameop_hit();
    if (!orig)
        return 0;
    return orig(old_dir, old_dentry, new_dir, new_dentry);
}

static int sus_path_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
    int (*orig)(struct dentry *, struct inode *, struct dentry *) =
        (void *)sus_path_link_hook.original;

    /* A hard link is a second name for the same inode - create one while the file
     * is hidden and the new name is not. */
    if (sus_path_dentry_hidden(old_dentry))
        return sus_path_nameop_hit();
    if (!orig)
        return 0;
    return orig(old_dentry, dir, new_dentry);
}

/* Metadata/attribute hits are counted apart from the name operations: the first
 * says "the name is not usable", the second "the object cannot be probed or
 * changed", and they fail for different reasons (see the block above). */
static atomic_t n_enoent_meta = ATOMIC_INIT(0);

static int sus_path_meta_hit(void)
{
    atomic_inc(&n_enoent_meta);
    return -ENOENT;
}

static int sus_path_sb_statfs(struct dentry *dentry)
{
    int (*orig)(struct dentry *) = (void *)sus_path_statfs_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(dentry);
}

static int sus_path_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int (*orig)(struct dentry *, struct iattr *) = (void *)sus_path_setattr_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(dentry, attr);
}

static int sus_path_inode_getxattr(struct dentry *dentry, const char *name)
{
    int (*orig)(struct dentry *, const char *) = (void *)sus_path_getxattr_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(dentry, name);
}

static int sus_path_inode_listxattr(struct dentry *dentry)
{
    int (*orig)(struct dentry *) = (void *)sus_path_listxattr_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(dentry);
}

static int sus_path_inode_setxattr(struct user_namespace *mnt_userns,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
    int (*orig)(struct user_namespace *, struct dentry *, const char *,
                const void *, size_t, int) = (void *)sus_path_setxattr_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(mnt_userns, dentry, name, value, size, flags);
}

static int sus_path_inode_removexattr(struct user_namespace *mnt_userns,
				      struct dentry *dentry, const char *name)
{
    int (*orig)(struct user_namespace *, struct dentry *, const char *) =
        (void *)sus_path_removexattr_hook.original;

    if (sus_path_dentry_hidden(dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(mnt_userns, dentry, name);
}

static int sus_path_path_notify(const struct path *path, u64 mask, unsigned int obj_type)
{
    int (*orig)(const struct path *, u64, unsigned int) =
        (void *)sus_path_notify_hook.original;

    /* inotify_add_watch and fanotify_mark arrive here; the callers do not run an
     * inode permission check on the target itself. */
    if (path && sus_path_dentry_hidden(path->dentry))
        return sus_path_meta_hit();
    if (!orig)
        return 0;
    return orig(path, mask, obj_type);
}

/* Every hook below the LSM layer is only worth its cost once something is
 * actually registered: kprobe/kretprobe entry costs a brk trap per hit, and the
 * dirent kretprobe costs a trap on every listing.  With no rules there is
 * nothing to answer, so they are armed on the first rule and torn down when the
 * module goes - the same "no rules, no cost" effect as nop'ing a patched call
 * site, but through the kernel's own register/unregister paths (unregistering a
 * kprobe restores the original instruction) instead of hand-written text
 * patching.
 *
 * The LSM hooks are exempt: they are pointer swaps, already cost-free. */
static bool hooks_armed;
/* Secondary LSM hooks that could not be registered: the core two are fatal, these
 * only mean one class of operation is uncovered - so they are reported through
 * hide_list as well as the log. */
static int n_lsm_ext_fail;
static const char *first_lsm_ext_fail;
/* Serialises the first rule's arming.  The hook table it fills is global state:
 * two rules arriving at once (a supercall task_work and a module_init caller)
 * would both pass the hooks_armed check, and the second arm would stack a second
 * layer on top of the first one's. */
static DEFINE_MUTEX(sus_path_arm_lock);

/* ---- the listing filter ----
 *
 * The filter has to run AFTER the kernel has built the directory chain, and no LSM
 * hook can do it: the chain is built inside the filesystem, entry by entry, with no
 * per-entry callback a module can reach.  That leaves the syscall body itself.
 *
 * WHICH bodies are reachable was read off this kernel's tables rather than assumed
 * (include/uapi/asm-generic/unistd.h, arch/arm64/include/asm/unistd32.h):
 *
 *   getdents64, native 61     -> __arm64_sys_getdents64   -> __do_sys_getdents64
 *   getdents64, AArch32 217   -> the SAME native wrapper (the 32-bit table maps
 *                                217 to sys_getdents64, not to a compat one)
 *   getdents,   AArch32 141   -> __arm64_compat_sys_getdents -> __do_compat_sys_getdents
 *
 * and two more that upstream covers through its fill callbacks but which no table
 * here can reach, so a probe on them could never fire and none is installed:
 *
 *   __do_sys_getdents              - the native table has no __NR_getdents
 *   __arm64_compat_sys_old_readdir - "89 was sys_readdir"; the AArch32 table has
 *                                    no entry for it either
 *
 * (That is why the missing coverage was one ABI, not four: 32-bit getdents64 shares
 * the native body, which is what the first version of this probe already covered.)
 *
 * A global sys_exit tracepoint does the same job - that is what this used to be -
 * but it fires for EVERY syscall of every process and then compares the number,
 * which measured 28 ns on calls that have nothing to do with listings (getpid:
 * 113 -> 141 ns).  A kretprobe is paid for only by listings.
 *
 * The entry handler stashes the caller's buffer: by the time the return handler
 * runs, the argument registers are gone.  For a 32-bit caller the register holds
 * the zero-extended user pointer, which is the address to use as is (the wrapper
 * de-louses it, __SC_DELOUSE in linux/syscalls.h). */
struct sus_path_dirent_args {
    unsigned long buf;
};

/* Record layouts.  Both reachable ABIs are NUL-terminated with an explicit
 * d_reclen, so nothing here needs the d_namlen/computed-length variant that
 * old_readdir would have needed. */
struct sus_dirent64_compat {
    u32 d_ino;
    u32 d_off;
    unsigned short d_reclen;
    char d_name[];
};

enum {
    SUS_DIRENT_L64 = 0,     /* struct linux_dirent64      (native and AArch32 61/217) */
    SUS_DIRENT_COMPAT,      /* struct compat_linux_dirent (AArch32 141)              */
    SUS_DIRENT_N,
};

struct sus_dirent_layout {
    unsigned char id;
    unsigned char ino_size;     /* 8 native, 4 compat */
    unsigned char name_off;     /* offset of d_name */
    unsigned char reclen_off;   /* offset of d_reclen */
};

static const struct sus_dirent_layout sus_dirent_l64 = {
    .id = SUS_DIRENT_L64,
    .ino_size = 8,
    .name_off = offsetof(struct linux_dirent64, d_name),
    .reclen_off = offsetof(struct linux_dirent64, d_reclen),
};

static const struct sus_dirent_layout sus_dirent_compat = {
    .id = SUS_DIRENT_COMPAT,
    .ino_size = 4,
    .name_off = offsetof(struct sus_dirent64_compat, d_name),
    .reclen_off = offsetof(struct sus_dirent64_compat, d_reclen),
};

/* "Did this ABI reach us at all" is a different claim from "did we hide
 * something", and only the pair can tell a dead probe from a working one: the
 * AArch32 layout is the one that cannot be exercised by a 64-bit test tool. */
static atomic_t n_dirent_calls[SUS_DIRENT_N];

static long sus_path_filter(unsigned long buf, long count,
                            const struct sus_dirent_layout *lay);

/* One kretprobe per ABI.  The return handler has to know its layout, and
 * struct kretprobe_instance has no back-pointer to the probe on 5.15, so the
 * layout is baked in by the macro rather than looked up per instance. */
#define SUS_PATH_DIRENT_PROBE(sym, layname)                                     \
    static int kr_##layname##_entry(struct kretprobe_instance *ri,              \
                                    struct pt_regs *regs)                       \
    {                                                                          \
        struct sus_path_dirent_args *a = (struct sus_path_dirent_args *)ri->data; \
                                                                               \
        a->buf = regs_get_kernel_argument(regs, 1);                            \
        return 0;                                                              \
    }                                                                          \
                                                                               \
    static int kr_##layname##_ret(struct kretprobe_instance *ri,               \
                                  struct pt_regs *regs)                        \
    {                                                                          \
        const struct sus_path_dirent_args *a =                                 \
            (const struct sus_path_dirent_args *)ri->data;                     \
        long ret = regs_return_value(regs);                                    \
                                                                               \
        if (ret <= 0 || !a->buf)                                               \
            return 0;                                                          \
        atomic_inc(&n_dirent_calls[sus_dirent_##layname.id]);                  \
        if (!READ_ONCE(sus_path_count) && !hide_name[0])                       \
            return 0;                                                          \
                                                                               \
        regs_set_return_value(regs,                                            \
                              sus_path_filter(a->buf, ret, &sus_dirent_##layname)); \
        return 0;                                                              \
    }                                                                          \
                                                                               \
    static struct kretprobe krp_##layname = {                                  \
        .kp.symbol_name = sym,                                                 \
        .entry_handler = kr_##layname##_entry,                                 \
        .handler = kr_##layname##_ret,                                         \
        .data_size = sizeof(struct sus_path_dirent_args),                      \
        .maxactive = 64,                                                       \
    }

SUS_PATH_DIRENT_PROBE("__do_sys_getdents64", l64);
SUS_PATH_DIRENT_PROBE("__do_compat_sys_getdents", compat);

static bool dirent_probe_registered[SUS_DIRENT_N];

static void sus_path_dirent_register(void)
{
    struct kretprobe *probes[SUS_DIRENT_N] = { &krp_l64, &krp_compat };
    int i, c = 0;

    for (i = 0; i < SUS_DIRENT_N; i++) {
        int rc = register_kretprobe(probes[i]);

        if (rc) {
            /* This is the one thing the LSM slots cannot do, so say so: without it
             * a hidden entry shows up in every listing. */
            pr_warn("sus_path: kretprobe(%s) failed %d - that ABI's listings are not filtered\n",
                    probes[i]->kp.symbol_name, rc);
            continue;
        }
        dirent_probe_registered[i] = true;
        c++;
    }
    if (c)
        SUSFS_LOGI("sus_path: listing filter armed (%d/%d ABIs: getdents64 native+AArch32, getdents AArch32)\n",
                c, (int)SUS_DIRENT_N);
}

static void sus_path_dirent_unregister(void)
{
    struct kretprobe *probes[SUS_DIRENT_N] = { &krp_l64, &krp_compat };
    int i;

    for (i = 0; i < SUS_DIRENT_N; i++) {
        if (!dirent_probe_registered[i])
            continue;
        unregister_kretprobe(probes[i]);
        dirent_probe_registered[i] = false;
    }
}

static void sus_path_hooks_arm(void)
{
    mutex_lock(&sus_path_arm_lock);
    if (hooks_armed || !READ_ONCE(sus_path_count)) {
        mutex_unlock(&sus_path_arm_lock);
        return;
    }

    hooks_armed = true;

    /* Two layers, and neither of them is a syscall entry:
     *
     *   the LSM slots (registered with the module, above) decide every path-based
     *   access by inode - which is ABI-independent, so 32-bit callers are covered
     *   by the same slots, and it cannot be dodged with a different spelling,
     *   a symlink, a hard link or a bind mount;
     *
     *   the dirent kretprobes do the listing filter, which no LSM hook can do:
     *   the directory chain is built inside the filesystem and there is no
     *   per-entry callback a module can hook.
     *
     * Nothing else is needed.  Entry-layer hooks (syscall table replacement or
     * kprobes) matched the caller's path STRING, which the LSM match already
     * covers more thoroughly, and every one of those syscalls ends up in an inode
     * permission or attribute check anyway - so they were paying a per-call cost
     * for coverage that was already there.
     *
     * The layers that used to be armed on top of this - the syscall-entry kprobes,
     * the path-string probes (filename_lookup / do_filp_open / user_path_at_empty),
     * the getname kretprobes, the DAC probes and the candidate diagnostic scan -
     * are DELETED, not merely disabled: none of them was registered in the default
     * configuration, and a hook that cannot fire is worse than no hook, because it
     * reads as coverage.  See the note above sus_path_init().
     *
     * no_extra is the isolation switch: no LSM, no dirent filter. */
    if (!no_extra)
        sus_path_dirent_register();
    else
        pr_warn("sus_path: no_extra - dirent filter off\n");

    SUSFS_LOGI("sus_path: hooks armed (LSM + dirent kretprobes)\n");
    mutex_unlock(&sus_path_arm_lock);
}

/* Rewrite the dirent chain the kernel just produced, dropping the entries whose
 * (d_ino, name) pair is registered; returns the byte count the caller may parse.
 *
 * Records are moved one at a time through dirent_tmp, from the read position
 * `offset` to the write position `written`.  Since a record is only ever moved
 * to an address at or before its own, the destination can never overwrite a
 * record that has not been read yet, and the listing does not have to fit in the
 * buffer at all - which is what makes a listing larger than DIRENT_BUF_SIZE work
 * (the old code gave up and returned the untouched listing once the 64 KB
 * scratch buffer was full).
 *
 * The returned value always describes what is really in the caller's buffer:
 *
 *   - rewrite completed -> the compacted length, i.e. 0 when every entry was
 *     hidden and `count` when none was (in that case nothing was moved, since
 *     written == offset all the way through);
 *   - uaccess failure -> the bytes that were handed back whole, which is a valid
 *     and complete record chain; the records beyond it are simply read again on
 *     the caller's next getdents64 (a short read is normal there);
 *   - uaccess failure before a single record was written back -> `count`, i.e.
 *     "nothing was filtered", because the buffer still holds the kernel's chain.
 *
 * That last distinction is the fix for the old behaviour: a failed write-back
 * returned `count` while the buffer already held a *partially* compacted chain,
 * so the caller was told to parse bytes that were no longer records. */
static long sus_path_filter(unsigned long buf, long count,
                            const struct sus_dirent_layout *lay)
{
    long offset = 0;        /* read position in the caller's chain */
    long written = 0;       /* bytes of the compacted chain already handed back */
    unsigned short head_reclen = 0;     /* first record's length, for the placeholder */
    bool failed = false;
    char *tmp;

    spin_lock(&sus_path_buf_lock);

    /* uaccess under a spinlock may not fault: if the page is not resident the
     * copy would sleep right here.  Disabled, a faulting copy simply fails, and
     * every failure path below answers "no filtering" rather than guessing. */
    pagefault_disable();

    tmp = dirent_tmp;
    if (!tmp) {
        pagefault_enable();
        spin_unlock(&sus_path_buf_lock);
        return count;
    }

    while (offset < count) {
        unsigned long long ino = 0;
        unsigned short reclen;
        char name[NAME_MAX + 1];
        long nlen;
        bool hide;

        if (copy_from_user(&reclen, (void __user *)(buf + offset + lay->reclen_off),
                           sizeof(reclen))) {
            failed = true;
            break;
        }
        /* d_reclen is filesystem-supplied: bound it before it is used as a
         * copy length, as a step, and before the bounce buffer is indexed. */
        if (reclen < lay->name_off + 1 ||
            offset + reclen > count ||
            reclen > DIRENT_BUF_SIZE) {
            failed = true;
            break;
        }

        /* The ino is the record's only fixed-width, ABI-dependent field: 8 bytes
         * in linux_dirent64, 4 in the AArch32 compat record.  A 32-bit record
         * exists only when the number fit (compat_filldir answers -EOVERFLOW
         * otherwise), so the low 4 bytes are the whole value. */
        if (lay->ino_size == 8) {
            if (copy_from_user(&ino, (void __user *)(buf + offset), sizeof(u64))) {
                failed = true;
                break;
            }
        } else {
            u32 ino32;

            if (copy_from_user(&ino32, (void __user *)(buf + offset), sizeof(ino32))) {
                failed = true;
                break;
            }
            ino = ino32;
        }

        nlen = strnlen_user((void __user *)(buf + offset + lay->name_off),
                            sizeof(name) - 1);
        if (nlen == 0) {            /* no readable NUL in the name field */
            failed = true;
            break;
        }
        if (nlen >= sizeof(name))   /* longer than NAME_MAX: cannot match */
            nlen = sizeof(name) - 1;
        if (nlen > reclen - lay->name_off) {
            failed = true;
            break;
        }
        if (copy_from_user(name, (void __user *)(buf + offset + lay->name_off), nlen)) {
            failed = true;
            break;
        }
        name[nlen] = 0;
        if (!head_reclen)
            head_reclen = reclen;

        hide = sus_path_is_hidden((u64)ino, name);
        /* No gate here any more: sus_path_is_hidden() applies the per-rule gate
         * itself (and has to, or the module's own /proc nodes would still show
         * up for uid 1000/2000). */

        if (hide) {
            /* Dropped.  Every record after it moves down by its length, so the
             * remaining records can no longer stay where they are. */
            offset += reclen;
            continue;
        }

        /* A record only needs the bounce buffer once something ahead of it was
         * dropped; until then written == offset and it is already in place. */
        if (written != offset) {
            if (copy_from_user(tmp, (void __user *)(buf + offset), reclen)) {
                failed = true;
                break;
            }
            if (copy_to_user((void __user *)(buf + written), tmp, reclen)) {
                failed = true;
                break;
            }
        }
        written += reclen;
        offset += reclen;
    }

    pagefault_enable();
    spin_unlock(&sus_path_buf_lock);

    if (failed) {
        atomic_inc(&n_dirent_rewrite_fail);
        pr_warn_ratelimited("sus_path: dirent rewrite stopped at %ld/%ld bytes (returned %ld)\n",
                            offset, count, written ? written : count);
        if (!written)
            return count;       /* nothing was written back: claim no filtering */
    }

    /* Everything in this chunk was hidden, and returning 0 here would be read as
     * end-of-directory: the caller stops, and the visible entries in the next
     * chunk are never seen at all.
     *
     * So one record is left behind as a placeholder - d_ino = 0 with an empty
     * name.  readdir() skips records whose d_ino is 0 (bionic does), which makes
     * the caller ask again and reach the entries that do exist; a caller parsing
     * the buffer by hand sees an entry without a name, which is still better than
     * a directory that ends early.  The hidden name is gone from the buffer
     * either way. */
    if (!failed && count > 0 && written == 0) {
        char zero_ino[8] = {0};
        char nul = '\0';

        /* head_reclen is the first record's own length, read above with this
         * ABI's layout - the buffer still holds it untouched, because written
         * == 0 means nothing was moved. */
        if (head_reclen >= lay->name_off + 1 && head_reclen <= count &&
            !copy_to_user((void __user *)buf, zero_ino, lay->ino_size) &&
            !copy_to_user((void __user *)(buf + lay->name_off), &nul, 1)) {
            atomic_inc(&n_dirent_all_hidden);
            return head_reclen;
        }
        /* Could not build the placeholder: filtering would be worse than not
         * filtering, because the caller would lose the chunk entirely. */
        atomic_inc(&n_dirent_rewrite_fail);
        return count;
    }

    return written;
}


/* read-only view of the registered paths, for verification */
static int sus_path_show_list(char *buf, const struct kernel_param *kp)
{
    struct sus_path_entry *e;
    int n = 0;

    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "hide_from_apps=%d  enoent: getattr=%d perm=%d nameop=%d meta=%d\n",
                   hide_from_apps, atomic_read(&n_enoent_getattr),
                   atomic_read(&n_enoent_perm), atomic_read(&n_enoent_nameop),
                   atomic_read(&n_enoent_meta));
    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "dirent: rewrite-fail=%d  all-hidden=%d  pending=%d  calls(l64=%d compat=%d)\n",
                   atomic_read(&n_dirent_rewrite_fail),
                   atomic_read(&n_dirent_all_hidden),
                   atomic_read(&sus_path_n_pending),
                   atomic_read(&n_dirent_calls[SUS_DIRENT_L64]),
                   atomic_read(&n_dirent_calls[SUS_DIRENT_COMPAT]));
    if (n_lsm_ext_fail)
        n += scnprintf(buf + n, PAGE_SIZE - n,
                       "lsm: %d secondary hook(s) FAILED (first: %s) - that operation is not covered\n",
                       n_lsm_ext_fail, first_lsm_ext_fail);
    /* Everything the pending machinery did, so that "still pending" can be read
     * for what it is: passes/ticks == 0 means the retry never ran at all, walks
     * > 0 with pending > 0 means the walk kept failing (last-rc says how), and
     * lost > 0 would mean a walk succeeded with no rule left to publish it. */
    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "pend: passes=%d ticks=%d walks=%d lost=%d last-rc=%d caller-cred=%d\n",
                   atomic_read(&sus_path_pend_passes),
                   atomic_read(&sus_path_pend_ticks),
                   atomic_read(&sus_path_pend_walks),
                   atomic_read(&sus_path_pend_lost),
                   atomic_read(&sus_path_pend_last_rc),
                   (int)(sus_path_pending_cred != NULL));

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list)
        n += scnprintf(buf + n, PAGE_SIZE - n,
                       "dev=%llu ino=%llu name=%s%s\n",
                       e->dev, e->ino, e->name,
                       e->inode ? "" : " (pending: no inode yet)");
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
static int sus_path_add_hidden_ex(const char *path, bool self_protect)
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
	e->pass = 0;
	e->self_protect = self_protect;
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
	sus_path_relax_mode(e);
	spin_unlock(&sus_path_lock);

	SUSFS_LOGI("sus_path: hidden (built-in) '%s'%s\n", path,
		self_protect ? " (self-protected: hidden from every non-root caller)" : "");
	sus_path_hooks_arm();
	return 0;
}

/* Register one of the module's own control nodes.  Same table, but the rule is
 * flagged so the gate hides it from every non-root caller rather than only from
 * apps - see sus_path_entry_gate_any(). */
int sus_path_add_self_hidden(const char *path)
{
	return sus_path_add_hidden_ex(path, true);
}

int sus_path_add_hidden(const char *path)
{
	return sus_path_add_hidden_ex(path, false);
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

    /* kvmalloc, not kmalloc: 64 KB of physically contiguous order-4 memory is
     * simply not available on a phone that has been up for a while (measured:
     * MemFree 394 MB, and kmalloc_order failed with a WARN in its call trace),
     * and vmalloc memory is just as usable here - the buffer is only touched from
     * the getdents64 filter, which never faults on it.  A failure is not fatal
     * either: it only leaves directory listings unfiltered, so the rest of the
     * layers still come up. */
    dirent_tmp = kvmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
    if (!dirent_tmp)
        pr_warn("sus_path: dirent scratch buffer unavailable, listings will not be filtered\n");

    /* The dirent kretprobes are armed by sus_path_hooks_arm() once a rule exists:
     * with nothing registered there is nothing to answer, so they cost nothing
     * until then. */
    SUSFS_LOGI("sus_path: hooks deferred until the first rule\n");

    if (no_extra) {
        SUSFS_LOGI("sus_path: no_extra=1 - the LSM layer and the dirent filter are OFF (isolation test)\n");
        return 0;
    }

    /* LSM hooks: reject path-based access to registered inodes outright.
     *
     * These two ARE the mechanism: a registered path is hidden only because this
     * layer answers ENOENT.  Failing to register them used to be a warning with a
     * zero return, so add_sus_path() reported success while nothing was hidden at
     * all.  Loading now fails instead - the caller has to know. */
    rc = ksu_register_lsm_hook(&sus_path_getattr_hook);
    if (rc) {
        pr_err("sus_path: getattr hook failed %d - nothing would be hidden, refusing to load\n", rc);
        return rc;
    }
    SUSFS_LOGI("sus_path: getattr hook armed, orig=%ps\n", sus_path_getattr_hook.original);

    rc = ksu_register_lsm_hook(&sus_path_perm_hook);
    if (rc) {
        pr_err("sus_path: perm hook failed %d - nothing would be hidden, refusing to load\n", rc);
        ksu_unregister_lsm_hook(&sus_path_getattr_hook);
        return rc;
    }
    SUSFS_LOGI("sus_path: perm hook armed, orig=%ps\n", sus_path_perm_hook.original);

    /* Name-based and metadata operations: without these, an app that can write the
     * parent directory can delete or rename a hidden file, and a hidden file can
     * still be probed or modified through statfs/xattr/inotify - or answered with
     * EPERM/EACCES, which says it exists. */
    {
        struct ksu_lsm_hook *extra[] = {
            &sus_path_unlink_hook, &sus_path_rmdir_hook,
            &sus_path_rename_hook, &sus_path_link_hook,
            &sus_path_statfs_hook, &sus_path_setattr_hook,
            &sus_path_getxattr_hook, &sus_path_listxattr_hook,
            &sus_path_setxattr_hook, &sus_path_removexattr_hook,
            &sus_path_notify_hook,
        };
        int i;

        for (i = 0; i < (int)ARRAY_SIZE(extra); i++) {
            rc = ksu_register_lsm_hook(extra[i]);
            if (rc) {
                /* Not fatal - the core two slots are up, so a hidden path is still
                 * hidden - but it means one class of operation is NOT covered
                 * (deleting it, or probing it through statfs/xattr/inotify), so it
                 * is counted and named in hide_list rather than only logged. */
                if (!n_lsm_ext_fail)
                    first_lsm_ext_fail = extra[i]->head_name;
                n_lsm_ext_fail++;
                pr_warn("sus_path: %s hook failed %d - that operation will not be covered\n",
                        extra[i]->head_name, rc);
            } else {
                SUSFS_LOGI("sus_path: %s hook armed, orig=%ps\n",
                        extra[i]->head_name, extra[i]->original);
            }
        }
        if (n_lsm_ext_fail)
            pr_warn("sus_path: %d/%d secondary hooks failed (first: %s)\n",
                    n_lsm_ext_fail, (int)ARRAY_SIZE(extra), first_lsm_ext_fail);
    }

    /* The DAC probes that used to be armed from sus_path_hooks_arm() are DELETED,
     * not disabled.  They existed for one case: DAC runs before the LSM chain, so
     * a file whose mode denies the caller gets EACCES before any LSM hook can turn
     * it into ENOENT.  That case is handled where it starts instead - a registered
     * rule relaxes its target's mode once (sus_path_relax_mode()), so DAC passes
     * and the LSM layer is the only thing that can refuse.  Two brk traps on every
     * inode_permission/generic_permission bought nothing on top of that.
     *
     * Two other layers are gone the same way, and for the same reason (registered
     * hooks that could never fire while the LSM layer answers first - they were the
     * pre-LSM fallback): the syscall-entry kprobes (openat/openat2/statx/readlinkat/
     * execve and their 32-bit counterparts) and the path-string probes
     * (filename_lookup / do_filp_open / user_path_at_empty) with the getname
     * kretprobes that fed them.  Their history is in TECHNICAL_NOTES.md, including
     * the FPAC panic that one of them caused - kept there rather than as dead code
     * here, because a hook that cannot fire reads as coverage. */
    return 0;
}

void sus_path_exit(void)
{
    struct sus_path_entry *e, *tmp;
    LIST_HEAD(doomed);

    /* Unregister the hooks FIRST: after this nothing can match, so the entries
     * (and their inode references) can be torn down safely.  The dirent kretprobes
     * are the only hooks armed after init; everything else here is an LSM slot. */
    sus_path_dirent_unregister();

    /* The retry timer must be off, and no resolution pass may be in flight while
     * the table is emptied below: a pass re-finds its entry under the lock and
     * never frees anything, but it may not run past the teardown either.  It is
     * a trylock in the pass, so this can never deadlock against it. */
    cancel_delayed_work_sync(&sus_path_pending_wq);
    mutex_lock(&sus_path_pending_lock);
    mutex_unlock(&sus_path_pending_lock);
    /* No walk can be in flight now, so the borrowed creds are ours to release. */
    sus_path_drop_caller_cred();
    if (sus_path_perm_hook.entry)
        ksu_unregister_lsm_hook(&sus_path_perm_hook);
    {
        struct ksu_lsm_hook *extra[] = {
            &sus_path_unlink_hook, &sus_path_rmdir_hook,
            &sus_path_rename_hook, &sus_path_link_hook,
            &sus_path_statfs_hook, &sus_path_setattr_hook,
            &sus_path_getxattr_hook, &sus_path_listxattr_hook,
            &sus_path_setxattr_hook, &sus_path_removexattr_hook,
            &sus_path_notify_hook,
        };
        int i;

        for (i = 0; i < (int)ARRAY_SIZE(extra); i++) {
            if (extra[i]->entry)
                ksu_unregister_lsm_hook(extra[i]);
        }
    }
    if (sus_path_getattr_hook.entry)
        ksu_unregister_lsm_hook(&sus_path_getattr_hook);

    kvfree(dirent_tmp);
    dirent_tmp = NULL;

    spin_lock(&sus_path_lock);
    list_splice_init(&sus_path_list, &doomed);
    sus_path_count = 0;
    atomic_set(&sus_path_n_pending, 0);
    spin_unlock(&sus_path_lock);

    /* iput outside the lock: it can sleep and evict the inode.  The mode each rule
     * relaxed is put back first - and before the inode is released, because the
     * relaxed value only lives in memory: once the last reference is gone there is
     * no way to tell a relaxed mode from a real one. */
    list_for_each_entry_safe(e, tmp, &doomed, list) {
        list_del(&e->list);
        sus_path_restore_mode(e);
        if (e->inode)
            iput(e->inode);
        kfree(e);
    }
}

/* supercall: CMD_SUSFS_ADD_SUS_PATH (0x55550) / CMD_SUSFS_ADD_SUS_PATH_LOOP (0x55553)
 *
 * Upstream keeps the two apart:
 *   susfs_add_sus_path()       needs the path to exist - kern_path() with
 *                              LOOKUP_FOLLOW, and the lookup error is the
 *                              command's answer (susfs.c:58-62);
 *   susfs_add_sus_path_loop()  checks for an empty string only, stores the path
 *                              in LH_SUS_PATH_LOOP and resolves it later
 *                              (susfs.c:99-132 and susfs_run_sus_path_loop(),
 *                              susfs.c:134-172 - see the block above
 *                              sus_path_resolve_pending()).
 *
 * The dispatcher hands both commands to this one function and now says which one
 * arrived, because upstream's two commands answer a missing path differently:
 *
 *   CMD_SUSFS_ADD_SUS_PATH       kern_path() failure is the command's answer
 *                                (-ENOENT, susfs.c:58-62) - nothing is registered
 *   CMD_SUSFS_ADD_SUS_PATH_LOOP  empty-string check only, then "hidden from the
 *                                moment it appears" (susfs.c:99-132)
 *
 * Treating both as pending made the plain command answer 0 for a path that does
 * not exist, so a caller other than the stock tool (which realpath()s first)
 * believed a rule was installed that upstream would have rejected.
 *
 * A pending rule is not dead weight: it holds its place in the table, so the path is
 * hidden from the moment the background walk resolves its inode.  What the pending
 * state delays is every layer - the LSM slots (by inode) and the dirent filter
 * ((ino, name)) - because none of them can match an inode that does not exist yet. */
 * the inode resolves. */
void sus_path_supercall(unsigned int cmd, void __user **arg)
{
    struct st_susfs_sus_path info = {0};
    struct sus_path_entry *e;
    struct path path = {0};
    struct inode *inode = NULL;
    bool pending_ok = (cmd == CMD_SUSFS_ADD_SUS_PATH_LOOP);
    u64 dev = 0;
    u64 ino = 0;
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
    if (!rc) {
        inode = d_inode(path.dentry);
        if (!inode) {
            path_put(&path);
            rc = -ENOENT;
        }
    }
    if (rc && rc != -ENOENT) {
        pr_warn("sus_path: failed opening '%s' (%d)\n", info.target_pathname, rc);
        info.err = rc;
        goto out;
    }
    /* Upstream's plain ADD_SUS_PATH reports a missing path: its
     * `err = kern_path(...)` IS the answer (fs/susfs.c:58-62).  Only the _LOOP
     * variant accepts "not there yet" and resolves it later.  (Note that this
     * kern_path() also runs into our own rule when the path is already hidden -
     * upstream is no different, its rejection lives in walk_component(), so a
     * caller that hides a path first and then tries to register something else on
     * it gets the same -ENOENT from both implementations.) */
    if (rc == -ENOENT && !pending_ok) {
        SUSFS_LOGI("sus_path: '%s' does not exist and this is ADD_SUS_PATH (not _LOOP): reporting -ENOENT like upstream\n",
                info.target_pathname);
        info.err = -ENOENT;
        goto out;
    }

    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        if (inode)
            path_put(&path);
        info.err = -ENOMEM;
        goto out;
    }

    e->dev = 0;
    e->ino = 0;
    e->inode = NULL;
    e->pass = 0;
    e->name[0] = '\0';

    if (inode) {
        dev = (u64)inode->i_sb->s_dev;
        ino = (u64)inode->i_ino;
        e->dev = dev;
        e->ino = ino;
        e->inode = inode;
        /* Hold the inode: the LSM hooks match on this pointer, and the dentry is
         * about to be released by path_put(), which would otherwise be free to
         * evict it and let the address be reused. */
        ihold(inode);
        strscpy(e->name, path.dentry->d_name.name, sizeof(e->name));
    }
    sus_path_entry_set_path(e, info.target_pathname);
    if (!inode)
        /* No dentry to take the name from yet: the basename of the registered
         * path is what the table shows until the lookup succeeds (it is then
         * replaced by the real dentry name, which is what the dirent filter has
         * to compare - following a symlink changes it). */
        sus_path_basename(e->path, e->name, sizeof(e->name));
    INIT_LIST_HEAD(&e->list);
    if (inode)
        path_put(&path);

    spin_lock(&sus_path_lock);
    if (sus_path_count >= SUS_PATH_MAX_ENTRIES) {
        spin_unlock(&sus_path_lock);
        if (e->inode)
            iput(e->inode);
        kfree(e);
        info.err = -ENOSPC;
        goto out;
    }
    {
        struct sus_path_entry *cur;

        list_for_each_entry(cur, &sus_path_list, list) {
            /* Same inode: upstream's set_bit() is idempotent.  Same
             * still-unresolved path: nothing to add but the retry marker. */
            if ((inode && cur->inode == inode) ||
                (!inode && !cur->inode && !strcmp(cur->path, e->path))) {
                spin_unlock(&sus_path_lock);
                if (e->inode)
                    iput(e->inode);
                kfree(e);
                info.err = 0;   /* already registered, upstream is idempotent */
                goto out;
            }
            /* The rule is there as a pending one and this add is what resolved
             * it: complete that entry instead of registering a second one for
             * the same path (a boot script that runs twice would otherwise
             * leave one resolved and one pending entry behind).  Re-adding a
             * path is therefore also the manual way to force the resolution. */
            if (inode && !cur->inode && !strcmp(cur->path, e->path)) {
                cur->dev = dev;
                cur->ino = ino;
                strscpy(cur->name, e->name, sizeof(cur->name));
                cur->inode = e->inode;      /* the reference moves over */
                e->inode = NULL;
                atomic_dec(&sus_path_n_pending);
                sus_path_relax_mode(cur);   /* it was pending, so it never ran */
                spin_unlock(&sus_path_lock);
                kfree(e);
                info.err = 0;
                SUSFS_LOGI("sus_path: hide '%s' (pending rule completed by this add, dev=%llu ino=%llu)\n",
                        info.target_pathname, dev, ino);
                goto out;
            }
        }
    }
    list_add_tail(&e->list, &sus_path_list);
    sus_path_count++;
    if (!inode)
        atomic_inc(&sus_path_n_pending);
    else
        sus_path_relax_mode(e);
    spin_unlock(&sus_path_lock);

    if (inode && !ino) {
        /* Stay factual about what an ino-0 filesystem costs: upstream needs no
         * inode number at all (it hides by the AS_FLAGS_SUS_PATH bit on
         * inode->i_mapping) and its dirent filter does ilookup(sb, d_ino), which
         * finds nothing for ino 0 either.  So neither implementation filters the
         * listing here; the by-inode layers still hide the path, and a name-based
         * fallback would hide unrelated entries that happen to report d_ino 0 as well. */
         * happen to report d_ino 0 as well. */
        pr_warn("sus_path: '%s' reports ino 0 - hidden by inode, but a directory listing cannot be filtered for it\n",
                info.target_pathname);
    }

    if (!dirent_tmp) {
        /* Retry once: the first attempt may have run before the system was
         * settled.  Still not fatal - the rule is registered either way, and the
         * entry layers below are what answer the access. */
        dirent_tmp = kvmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
        if (!dirent_tmp)
            pr_warn("sus_path: dirent scratch buffer still unavailable, listing for '%s' stays unfiltered\n",
                    info.target_pathname);
    }

    /* First rule: arm the dirent kretprobes.  Idempotent, and safe to call with a
     * rule already in the list. */
    sus_path_hooks_arm();

    if (!inode) {
        SUSFS_LOGI("sus_path: hide '%s' (pending: the path does not exist yet - it is hidden once the background walk resolves its inode)\n",
                info.target_pathname);
        /* The walk happens later, in a worker whose own creds cannot reach a
         * path under /data (measured: -EACCES), so remember the creds of the
         * process that registered the rule - it is by definition able to. */
        sus_path_save_caller_cred();
        /* The retry path: this add is itself the first retry opportunity (the
         * failing lookup was microseconds ago, but an earlier add in the same
         * batch may be what the rule waits for), then the bounded timer keeps
         * trying.  Upstream re-resolves on every zygote-spawned app instead,
         * which is an event this kernel does not hand us. */
        sus_path_pending_arm();
    } else {
        SUSFS_LOGI("sus_path: hide '%s' (dev=%llu ino=%llu)\n",
                info.target_pathname, dev, ino);
    }

    info.err = 0;
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_path __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_path supercall copy_to_user failed\n");
}
