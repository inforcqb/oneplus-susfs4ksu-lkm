// SPDX-License-Identifier: GPL-2.0
/*
 * sus_map.c - hide mmapped real files from /proc/<pid>/maps (SUSFS SUS_MAP).
 *
 * Upstream SUSFS sets AS_FLAGS_SUS_MAP on the inode's address_space flags and
 * makes show_map_vma() / show_smap() skip the line, the smaps_rollup() loop skip
 * the vma it is accumulating, and pagemap_read() skip the chunk that covers such
 * a vma.  An LKM cannot add a flag bit, so there are two layers here:
 *
 *   1. the listing layer - kprobes on show_map_vma() and show_smap(), where the
 *      vma is argument #2: when its backing file inode is in the rule set, skip
 *      the line by returning early (regs->pc = x30);
 *   2. the page-walk layer - one kprobe on walk_page_range(), which is what the
 *      two listings an LKM cannot reach at the listing level (smaps_rollup and
 *      pagemap) go through; see "the page-walk layer" below.
 *
 * show_map_vma(m, vma) / show_smap(m, v): vma is arg #2 (regs->regs[1]);
 * returning non-zero from the pre_handler makes the arm64 kprobe core skip
 * singlestep and continue at the modified pc (same trick kprg uses).
 *
 * smaps_rollup is deliberately NOT probed directly - see "the sentinel" below.
 *
 * The skip is gated exactly like upstream's, so only processes the gate treats
 * as apps see the line dropped and root/init keep seeing the real mapping - see
 * "the read gate" below.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>		/* struct mm_struct, mm->mmap */
#include <linux/mm_types.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/err.h>		/* IS_ERR/ERR_PTR for the getlink hook */
#include <linux/cred.h>		/* current_uid(), for the read gate */
#include <linux/spinlock.h>	/* serialises rule publication */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact, for the walk ops */

#define SUS_MAP_MAX 64

struct sus_map_entry {
    unsigned long target_ino;
    dev_t target_dev;
};

static struct sus_map_entry map_entries[SUS_MAP_MAX];
static int nmap;

/* Serialises rule PUBLICATION only, and the reader stays lock-free on purpose:
 * entries are append-only and never rewritten in place (unlike kstat's, which
 * are replaced wholesale, hence its reader-side snapshot under a spinlock), so
 * a release/acquire pair on nmap is enough for sus_map_lookup() to see either a
 * fully filled entry or none at all - and it is what it has to be on arm64,
 * where plain WRITE_ONCE/READ_ONCE would let the count become visible before
 * the entry it publishes.
 *
 * What the lock is really for: two concurrent supercalls - each dispatched from
 * its own task's task_work - would otherwise read the same nmap, fill the same
 * slot and silently drop one rule while both report success to userspace. */
static DEFINE_SPINLOCK(map_table_lock);

/* temporary interface: insmod susfs_guard_lkm.ko map_ino=<n> hides that inode */
static unsigned long param_map_ino;
module_param_named(map_ino, param_map_ino, ulong, 0644);

/* dev==0 means "any filesystem" (only reachable through the map_ino parameter,
 * which cannot know the device).  `path` may be NULL/empty (same parameter). */
static int sus_map_add_full(unsigned long ino, dev_t dev)
{
    unsigned long flags;
    int rc = 0;

    if (!ino)
        return -EINVAL;

    /* Bounds check and fill under the lock, then publish: see map_table_lock. */
    spin_lock_irqsave(&map_table_lock, flags);
    if (nmap < SUS_MAP_MAX) {
        map_entries[nmap].target_ino = ino;
        map_entries[nmap].target_dev = dev;
        smp_store_release(&nmap, nmap + 1);
    } else {
        rc = -ENOSPC;
    }
    spin_unlock_irqrestore(&map_table_lock, flags);
    return rc;
}

static void sus_map_add(unsigned long ino)
{
    sus_map_add_full(ino, 0);
}

static bool sus_map_lookup(unsigned long ino, dev_t dev)
{
    int n = smp_load_acquire(&nmap);
    int i;

    for (i = 0; i < n; i++) {
        if (map_entries[i].target_ino != ino)
            continue;
        if (map_entries[i].target_dev && map_entries[i].target_dev != dev)
            continue;
        return true;
    }
    return false;
}

/* ---- the read gate ----
 *
 * Upstream hides the line behind SUSFS_IS_INODE_SUS_MAP(), which ends in
 * susfs_is_current_proc_umounted_app() - i.e. app processes only, so root/init
 * still see the real mapping.  Without the gate this LKM hid the line from
 * everyone, which is a wider behaviour than upstream and a fidelity gap
 * (AUDIT_FINDINGS.md P2 #15).
 *
 * That upstream predicate is (test_thread_flag(TIF_PROC_UMOUNTED) &&
 * current_uid().val >= 10000), and TIF_PROC_UMOUNTED cannot be reproduced in
 * this LKM: KernelSU sets it only when the SUSFS integration is compiled into
 * the kernel, which this device's kernel is not (see AUDIT_FINDINGS.md, "已确认
 * 无法在 LKM 内复刻").  uid >= 10000 is the project-wide proxy, identical to
 * susfs_kstat_gate_ok() in susfs_kstat.c (commit 543b369) and to sus_path's.
 *
 * Configuration stays ungated: the supercall and the map_ino parameter are rule
 * management, not a read path. */
static bool sus_map_gate_ok(void)
{
    return current_uid().val >= 10000;
}

/* One handler for show_map_vma (maps) and show_smap (smaps).
 *
 * Both are seq_operations .show callbacks, i.e. they receive (struct seq_file *m,
 * struct vm_area_struct *v) and emit only what they are given - a show callback
 * returning 0 means "handled, nothing printed", NOT "end of iteration" (seq_read
 * ignores the value), which is exactly what upstream does inside those functions
 * with its SUS_MAP check.
 *
 * smaps is the one that matters most: maps was already covered, but
 * /proc/<pid>/smaps named the same files again, path and all.
 *
 * ---- the sentinel ----
 *
 * smaps_rollup is the third listing upstream filters and the one this handler
 * must NOT be pointed at.  show_smaps_rollup() is reached through single_open(),
 * whose single_start() hands .show the iterator sentinel (void *)1 instead of a
 * vma, and the function ignores its v argument entirely (it walks priv->mm->mmap
 * itself).  Dereferencing that sentinel is not theoretical: with the probe
 * registered, `cat /proc/<pid>/smaps_rollup` as an app took vma->vm_file at
 * offset 0xa0 -> ldr from 0xa1 -> "Unable to handle kernel NULL pointer
 * dereference at virtual address 00000000000000a1", pc sus_map_skip_vma_pre+0x3c,
 * then a panic (last_kmsg, 41346.347).
 *
 * It also cannot be replicated from a kprobe at all: upstream skips the vma
 * *inside* the rollup loop, and smap_gather_stats() is inlined by LTO here (it is
 * absent from /proc/kallsyms), so the only call that could be intercepted is
 * walk_page_range(), which carries no vma and is used by every other page walk.
 * See TECHNICAL_NOTES.md, "sus_map 与 smaps_rollup". */
static int sus_map_skip_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma;
    struct inode *inode;

    /* Cheapest test first: for a root/init reader - the entire point of the
     * gate - we return before touching the vma or its inode. */
    if (!sus_map_gate_ok())
        return 0;

    vma = (struct vm_area_struct *)regs->regs[1];
    /* Defence in depth against the sentinel above: a vma is always a slab object
     * in the linear map, so anything below one page is not one.  Keep this even
     * though no armed probe passes anything else - it is what turns a future
     * mis-registration into a lost filter instead of a panic. */
    if ((unsigned long)vma < PAGE_SIZE)
        return 0;
    if (!vma->vm_file)
        return 0;
    inode = file_inode(vma->vm_file);
    if (!inode)
        return 0;
    if (sus_map_lookup(inode->i_ino, inode->i_sb->s_dev)) {
        /* ratelimited, like sus_path's hit logs; the path is not stored in the
         * rule, so ino/dev identify it */
        pr_info_ratelimited("sus_map: hid %s line (ino=%lu dev=%lu uid=%u)\n",
                            kp->symbol_name, inode->i_ino,
                            (unsigned long)inode->i_sb->s_dev,
                            current_uid().val);
        regs_set_return_value(regs, 0);
        /* skip this vma: return early via the saved return address */
        regs->pc = regs->regs[30];
        return 1;
    }
    return 0;
}

static struct kprobe kp_map = {
    .symbol_name = "show_map_vma",
    .pre_handler = sus_map_skip_vma_pre,
};

static struct kprobe kp_map_smap = {
    .symbol_name = "show_smap",
    .pre_handler = sus_map_skip_vma_pre,
};

/* ---- the page-walk layer: smaps_rollup and pagemap ----
 *
 * The two listings the listing layer cannot reach are exactly the two where
 * upstream tests a vma it already holds as a local:
 *
 *   show_smaps_rollup()  ->  for (vma = priv->mm->mmap; vma;) { ... skip ... }
 *   pagemap_read()       ->  vma = vma_lookup(mm, start_vaddr); ... skip chunk
 *
 * Neither test is reachable from a kprobe (the locals do not exist at any
 * function boundary, smap_gather_stats() is inlined by LTO, and pagemap_read()
 * only has the vma after it has taken mmap_lock inside the function).  What both
 * *do* share is a call to one exported primitive, with an mm_walk_ops that
 * identifies the caller uniquely:
 *
 *   smap_gather_stats():  walk_page_range(vma->vm_mm, ..., &smaps_walk_ops | &smaps_shmem_walk_ops, mss)
 *   pagemap_read():       walk_page_range(mm, start, end, &pagemap_ops, &pm)
 *
 * All three ops are used by nothing else, every one of those callers holds
 * mmap_lock for read (walk_page_range() itself asserts that), and the effect of
 * skipping the call is upstream's effect: for rollup the vma contributes nothing
 * to the accumulated mss, for pagemap the chunk is simply not filled and
 * pagemap_read() copies what it has (its `ret = walk_page_range(...)` sees 0,
 * which is what upstream leaves behind as well).
 *
 * The ops addresses are data symbols, so they come from kallsyms by name - the
 * same mechanism sus_mount uses for mnt_id_ida.  If none of them resolves, the
 * probe is not registered at all and the two listings stay unfiltered (logged).
 *
 * Cost: the probe sits on a primitive the whole kernel shares, so it must bail
 * out on everything else in one load and three compares - the ops test is first,
 * before the gate or any structure is touched.
 *
 * Which primitive the two callers actually use is not something this file gets
 * to assume: walk_page_vma() exists as a separate symbol, and with
 * CONFIG_LTO_CLANG_FULL either call site may have been inlined into its caller
 * (in which case no probe can see it - the same wall smap_gather_stats() hit).
 * So both symbols are probed, and walk_dbg=1 records every distinct ops pointer
 * that reaches them together with its call count (walk_ops), which is how the
 * real caller is identified instead of guessed. */
static const void *sus_map_ops_smaps;
static const void *sus_map_ops_smaps_shmem;
static const void *sus_map_ops_pagemap;
static bool sus_map_walk_ops_done;
static atomic_t n_walk_skip = ATOMIC_INIT(0);
static atomic_t n_walk_seen = ATOMIC_INIT(0);		/* walk_page_range calls */
static atomic_t n_walk_seen_vma = ATOMIC_INIT(0);	/* walk_page_vma calls  */
/* Why a walk that reached the probe was not skipped, one counter per step of the
 * resolution - "the probe did not match" has four very different causes and only
 * the counters can tell them apart. */
static atomic_t n_walk_ops_hit = ATOMIC_INIT(0);	/* ops was ours */
static atomic_t n_walk_scan_fail = ATOMIC_INIT(0);	/* no vma for (mm,start) */
static atomic_t n_walk_nofile = ATOMIC_INIT(0);		/* vma has no vm_file */
static atomic_t n_walk_nomatch = ATOMIC_INIT(0);	/* inode is not a rule */
static atomic_t n_walk_dbg_left = ATOMIC_INIT(4);
/* map_files symlink resolutions that were turned into ENOENT. */
static atomic_t n_map_files_hides = ATOMIC_INIT(0);
/* Reachability of that hook, split the way the walk probe had to be: "the probe
 * ran" and "the probe matched" are different claims. */
static atomic_t n_getlink_calls = ATOMIC_INIT(0);
static atomic_t n_getlink_skip = ATOMIC_INIT(0);
static atomic_t n_getlink_nomatch = ATOMIC_INIT(0);

/* walk_dbg: name every ops pointer that reaches the two primitives, once per
 * distinct value.  Off by default - it costs a linear scan per call. */
static int walk_dbg;
module_param_named(walk_dbg, walk_dbg, int, 0644);

#define WALK_OPS_MAX 8
static const void *walk_seen_ops[WALK_OPS_MAX];
static atomic_t walk_seen_cnt[WALK_OPS_MAX];
static int walk_seen_n;

static void sus_map_note_ops(const void *ops)
{
    int i, n = READ_ONCE(walk_seen_n);

    for (i = 0; i < n; i++) {
        if (READ_ONCE(walk_seen_ops[i]) == ops) {
            atomic_inc(&walk_seen_cnt[i]);
            return;
        }
    }
    if (n >= WALK_OPS_MAX)
        return;
    WRITE_ONCE(walk_seen_ops[n], ops);
    atomic_inc(&walk_seen_cnt[n]);
    smp_store_release(&walk_seen_n, n + 1);
    SUSFS_LOGI("sus_map: walk ops[%d] = %pS\n", n, ops);
}

static int sus_map_walk_ops_show(char *buf, const struct kernel_param *kp)
{
    int i, n = 0, cnt = READ_ONCE(walk_seen_n);

    for (i = 0; i < cnt; i++)
        n += scnprintf(buf + n, PAGE_SIZE - n, "%2d %pS\n", i, walk_seen_ops[i]);
    n += scnprintf(buf + n, PAGE_SIZE - n,
                   "counts: page_range=%d page_vma=%d skipped=%d\n",
                   atomic_read(&n_walk_seen), atomic_read(&n_walk_seen_vma),
                   atomic_read(&n_walk_skip));
    for (i = 0; i < cnt; i++)
        n += scnprintf(buf + n, PAGE_SIZE - n, "  [%d] n=%d\n", i,
                       atomic_read(&walk_seen_cnt[i]));
    return n;
}
static const struct kernel_param_ops sus_map_walk_ops_ops = {
    .get = sus_map_walk_ops_show,
};
module_param_cb(walk_ops, &sus_map_walk_ops_ops, NULL, 0400);

static void sus_map_resolve_walk_ops(void)
{
    if (sus_map_walk_ops_done)
        return;
    sus_map_walk_ops_done = true;

    sus_map_ops_smaps = (const void *)find_kernel_symbol_exact("smaps_walk_ops");
    sus_map_ops_smaps_shmem = (const void *)find_kernel_symbol_exact("smaps_shmem_walk_ops");
    sus_map_ops_pagemap = (const void *)find_kernel_symbol_exact("pagemap_ops");

    if (!sus_map_ops_smaps && !sus_map_ops_smaps_shmem && !sus_map_ops_pagemap) {
        pr_warn("sus_map: smaps/pagemap walk ops not found in kallsyms - "
                "smaps_rollup and pagemap stay unfiltered\n");
        return;
    }
    SUSFS_LOGI("sus_map: walk ops smaps=%px smaps_shmem=%px pagemap=%px\n",
            sus_map_ops_smaps, sus_map_ops_smaps_shmem, sus_map_ops_pagemap);
}

static bool sus_map_walk_ops_any(void)
{
    return sus_map_ops_smaps || sus_map_ops_smaps_shmem || sus_map_ops_pagemap;
}

static bool sus_map_walk_ops_ours(const void *ops)
{
    return ops && (ops == sus_map_ops_smaps || ops == sus_map_ops_smaps_shmem ||
                   ops == sus_map_ops_pagemap);
}

/* Shared tail: `vma` is the one the skipped walk would have covered.  Returns
 * true when the call was skipped. */
static bool sus_map_walk_answer(struct kprobe *kp, struct pt_regs *regs,
                                struct vm_area_struct *vma)
{
    struct inode *inode;

    /* Defence in depth, like the vma handler: a real vma is never below a page. */
    if ((unsigned long)vma < PAGE_SIZE)
        return false;
    if (!vma->vm_file) {
        atomic_inc(&n_walk_nofile);
        return false;
    }
    inode = file_inode(vma->vm_file);
    if (!inode) {
        atomic_inc(&n_walk_nofile);
        return false;
    }
    if (!sus_map_lookup(inode->i_ino, inode->i_sb->s_dev)) {
        atomic_inc(&n_walk_nomatch);
        return false;
    }

    atomic_inc(&n_walk_skip);
    pr_info_ratelimited("sus_map: skipped %s walk for ino=%lu dev=%lu uid=%u\n",
                        kp->symbol_name, inode->i_ino,
                        (unsigned long)inode->i_sb->s_dev, current_uid().val);
    /* Both primitives return int 0 for "walked, nothing wrong", and both callers
     * expect that from a skipped walk (upstream's own skip leaves the same value
     * behind).  Leaving x0 = mm would turn pagemap_read()'s `ret` into a kernel
     * pointer and hand it back to read(2). */
    regs_set_return_value(regs, 0);
    regs->pc = regs->regs[30];
    return true;
}

/* walk_dbg >= 2: dump the resolution of the first few walks that got past the ops
 * test, so "no vma for (mm, start)" can be told apart from "the vma is not the
 * one we expected" without guessing. */
static void sus_map_walk_dbg_log(const char *what, struct mm_struct *mm,
                                 unsigned long start, struct vm_area_struct *vma)
{
    if (walk_dbg < 2)
        return;
    if (atomic_dec_if_positive(&n_walk_dbg_left) < 0)
        return;
    SUSFS_LOGI("sus_map: %s mm=%px start=%lx mmap=%px vma=%px %lx-%lx file=%px\n",
            what, mm, start, mm ? mm->mmap : NULL, vma,
            vma ? vma->vm_start : 0UL, vma ? vma->vm_end : 0UL,
            (vma && vma->vm_file) ? vma->vm_file : NULL);
}

/* walk_page_range(mm, start, end, ops, private): the vma has to be resolved from
 * (mm, start), which is what the walk itself would have done - mmap_lock is held
 * for read by every caller of these three ops, so the list this walks cannot be
 * changed underneath it. */
static int sus_map_skip_walk_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const void *ops = (const void *)regs->regs[3];
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long start;

    atomic_inc(&n_walk_seen);
    if (walk_dbg)
        sus_map_note_ops(ops);
    if (!sus_map_walk_ops_ours(ops))
        return 0;

    atomic_inc(&n_walk_ops_hit);
    if (!sus_map_gate_ok())
        return 0;

    mm = (struct mm_struct *)regs->regs[0];
    start = (unsigned long)regs->regs[1];
    if (!mm)
        return 0;

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (start < vma->vm_end)
            break;
    }
    if (!vma || start < vma->vm_start) {
        /* start is in a gap: nothing to hide */
        atomic_inc(&n_walk_scan_fail);
        sus_map_walk_dbg_log("walk_page_range: no vma", mm, start, NULL);
        return 0;
    }
    sus_map_walk_dbg_log("walk_page_range: vma", mm, start, vma);

    return sus_map_walk_answer(kp, regs, vma) ? 1 : 0;
}

/* walk_page_vma(vma, ops, private): same walk, vma handed over directly. */
static int sus_map_skip_walk_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const void *ops = (const void *)regs->regs[1];

    atomic_inc(&n_walk_seen_vma);
    if (walk_dbg)
        sus_map_note_ops(ops);
    if (!sus_map_walk_ops_ours(ops))
        return 0;

    atomic_inc(&n_walk_ops_hit);
    if (!sus_map_gate_ok())
        return 0;

    return sus_map_walk_answer(kp, regs,
                               (struct vm_area_struct *)regs->regs[0]) ? 1 : 0;
}

static struct kprobe kp_map_walk = {
    .symbol_name = "walk_page_range",
    .pre_handler = sus_map_skip_walk_pre,
};

static struct kprobe kp_map_walk_vma = {
    .symbol_name = "walk_page_vma",
    .pre_handler = sus_map_skip_walk_vma_pre,
};

/* ---- /proc/<pid>/mem (and ptrace): the page-fetch primitive ----
 *
 * Upstream's fifth SUS_MAP site is __access_remote_vm() (mm/memory.c, patch:
 * 5667-5687): after taking mmap_read_lock it resolves vma = vma_lookup(mm, addr)
 * ONCE and, inside the transfer loop, breaks out when that vma's file is
 * registered - so a read (or write) that starts inside a hidden mapping
 * transfers nothing at all.
 *
 * The function cannot be hooked usefully at its entry: the lock is taken INSIDE
 * it (mmap_read_lock_killable), and resolving a vma without that lock is a
 * use-after-free waiting for the target process to munmap.  What can be hooked is
 * the primitive the loop calls with the lock already held:
 *
 *   __access_remote_vm()          -> get_user_pages_remote(mm, addr, 1, ...)
 *   process_vm_rw_single_vec()    -> pin_user_pages_remote(mm, pa, ...)   (both
 *                                    *_remote variants require mmap_read_lock)
 *
 * Short-circuiting that call (pre_handler returns 1 after x0 = 0 and pc = lr)
 * makes the caller see "no page transferred": __access_remote_vm breaks out of
 * its loop and returns the bytes it had already moved - 0 when the read starts
 * inside the mapping, which is upstream's result - and process_vm_readv's
 * process_vm_rw_single_vec takes its `pinned_pages <= 0` error path.  Nothing is
 * pinned on the way, because the call never runs.
 *
 * The second primitive is NOT needed for upstream parity: upstream patches
 * __access_remote_vm only, and process_vm_readv does not go through it (measured
 * from this kernel's mm/process_vm_access.c: process_vm_rw_single_vec calls
 * pin_user_pages_remote directly).  It is hooked here because the same short
 * circuit closes it for one more probe, and because "the API that reads another
 * process' memory" is the loudest cross-check there is.
 *
 * Cost control: the handler runs on every *_remote page fetch in the kernel while
 * a rule exists, so the two cheapest tests come first (no rules -> one load;
 * uid < 10000 -> the gate), and find_vma() only runs for callers the gate lets
 * through. */
static atomic_t n_gup_calls = ATOMIC_INIT(0);
static atomic_t n_pin_gup_calls = ATOMIC_INIT(0);
static atomic_t n_vm_hides = ATOMIC_INIT(0);

static struct kprobe kp_gup_remote = {
    .symbol_name = "get_user_pages_remote",
    .pre_handler = sus_map_vm_access_pre,
};

static struct kprobe kp_pin_gup = {
    .symbol_name = "pin_user_pages_remote",
    .pre_handler = sus_map_vm_access_pre,
};

static int sus_map_vm_access_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct mm_struct *mm = (struct mm_struct *)regs->regs[0];
    unsigned long addr = regs->regs[1];
    struct vm_area_struct *vma;
    struct inode *inode;

    if (!smp_load_acquire(&nmap))
        return 0;
    if (!sus_map_gate_ok())
        return 0;
    if (!mm || !addr)
        return 0;

    atomic_inc(kp == &kp_pin_gup ? &n_pin_gup_calls : &n_gup_calls);

    /* Safe without re-taking anything: both callers hold mmap_read_lock, which is
     * what the `*_remote` contract of this primitive means. */
    vma = find_vma(mm, addr);
    if (!vma || !vma->vm_file)
        return 0;
    inode = file_inode(vma->vm_file);
    if (!inode)
        return 0;
    if (!sus_map_lookup(inode->i_ino, inode->i_sb->s_dev))
        return 0;

    atomic_inc(&n_vm_hides);
    regs_set_return_value(regs, 0);     /* "nothing transferred" */
    regs->pc = regs->regs[30];          /* skip the call: nothing is pinned */
    return 1;
}

/* ---- /proc/<pid>/map_files/<start>-<end> ----
 *
 * Each of those entries is a symlink to the file mapped at that range, so `ls -l`
 * and `readlink` name a sus_map-registered file outright - measured: that is how
 * the a4 tests found the address of a mapping the maps listing had already
 * dropped, i.e. this listing undid the hiding.
 *
 * Upstream skips the entry in proc_map_files_readdir() (patch:1088-1095), so for
 * upstream the name never appears at all.  A kprobe cannot skip one entry of a
 * readdir - the decision is made on a local in the middle of that function - so
 * this covers the other half: the symlink still exists, but resolving it answers
 * ENOENT, the same answer a checker gets for a file that is not there.  The
 * residual difference (the range is still listed) is recorded in
 * TECHNICAL_NOTES.md; closing it would need the readdir loop itself.
 *
 * WHICH function to hook is not guessable, and the first attempt got it wrong:
 * `proc_map_files_get_link` (the i_op) registered fine and was never called.  Two
 * facts from this kernel's fs/proc/base.c explain why:
 *
 *   - do_readlinkat() calls i_op->readlink FIRST and only falls back to
 *     vfs_readlink() (-> get_link) when it is NULL.  proc_map_files uses
 *     `.readlink = proc_pid_readlink`, so readlink(2) never touches get_link;
 *     `ls -l` uses readlink(2) too.
 *   - proc_pid_readlink() ends up in the per-inode callback
 *     `ei->op.proc_get_link` = map_files_get_link(dentry, struct path *path) -
 *     which is the one place that hands over the MAPPED file's path.
 *
 * So the hook sits on map_files_get_link and judges by inode (path->dentry),
 * which is exact: no path string to compare, no spelling to get wrong.  It only
 * ever fails a call that would have succeeded - the caller checks its return
 * value and treats a negative one as "no link". */
static int sus_map_maplink_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    /* struct path *path is the output argument; it is only filled in by the time
     * the function returns, so remember it here and read it there. */
    *(unsigned long *)ri->data = regs->regs[1];
    return 0;
}

static int sus_map_maplink_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long outp = *(unsigned long *)ri->data;
    const struct path *p;
    struct inode *inode;

    atomic_inc(&n_getlink_calls);
    if ((long)regs_return_value(regs) != 0 || !outp) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    if (!sus_map_gate_ok()) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    p = (const struct path *)outp;
    if (!p->dentry) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    inode = d_inode(p->dentry);
    if (!inode) {
        atomic_inc(&n_getlink_skip);
        return 0;
    }
    if (!sus_map_lookup(inode->i_ino, inode->i_sb->s_dev)) {
        atomic_inc(&n_getlink_nomatch);
        return 0;
    }

    atomic_inc(&n_map_files_hides);
    pr_info_ratelimited("sus_map: hid map_files symlink to ino=%lu (uid=%u)\n",
                        inode->i_ino, current_uid().val);
    regs_set_return_value(regs, (unsigned long)(long)-ENOENT);
    return 0;
}

static struct kretprobe kr_map_files = {
    .kp.symbol_name = "map_files_get_link",
    .entry_handler = sus_map_maplink_entry,
    .handler = sus_map_maplink_ret,
    .data_size = sizeof(unsigned long),	/* the output struct path * */
    .maxactive = 16,
};
static bool kr_map_files_ok;

/* Kept in one table so init and exit cannot drift apart. */
static struct kprobe *const map_probes[] = {
    &kp_map, &kp_map_smap, &kp_map_walk, &kp_map_walk_vma,
    &kp_gup_remote, &kp_pin_gup,
};
#define N_MAP_PROBES ARRAY_SIZE(map_probes)
static bool map_registered;
static bool map_probe_armed[N_MAP_PROBES];

/* Reachability, not configuration: "the probe is registered" says nothing on a
 * kernel built with CONFIG_LTO_CLANG_FULL, because the call site it is supposed
 * to catch may have been inlined away (walk_page_range() is EXPORT_SYMBOL_GPL,
 * and LTO may still inline the calls inside pagemap_read()/smap_gather_stats()).
 * walk_seen counts every call the probe saw at all, walk_skipped the subset that
 * answered "hidden" - so walk_seen == 0 is the fingerprint of an inlined call
 * site, not of a rule that failed to match. */
static int sus_map_stat_show(char *buf, const struct kernel_param *kp)
{
    int i, armed = 0;

    for (i = 0; i < (int)N_MAP_PROBES; i++)
        armed += map_probe_armed[i] ? 1 : 0;

    return scnprintf(buf, PAGE_SIZE,
                     "rules=%d armed=%d/%d walk_seen=%d walk_vma=%d walk_skipped=%d "
                     "ops_hit=%d scan_fail=%d nofile=%d nomatch=%d getlink: calls=%d skip=%d nomatch=%d hides=%d\n"
                     "vm: gup_calls=%d pin_calls=%d hides=%d\n"
                     "ops: smaps=%px smaps_shmem=%px pagemap=%px\n",
                     nmap, armed, (int)N_MAP_PROBES,
                     atomic_read(&n_walk_seen), atomic_read(&n_walk_seen_vma),
                     atomic_read(&n_walk_skip),
                     atomic_read(&n_walk_ops_hit), atomic_read(&n_walk_scan_fail),
                     atomic_read(&n_walk_nofile), atomic_read(&n_walk_nomatch),
                     atomic_read(&n_getlink_calls), atomic_read(&n_getlink_skip),
                     atomic_read(&n_getlink_nomatch), atomic_read(&n_map_files_hides),
                     atomic_read(&n_gup_calls), atomic_read(&n_pin_gup_calls),
                     atomic_read(&n_vm_hides),
                     sus_map_ops_smaps, sus_map_ops_smaps_shmem,
                     sus_map_ops_pagemap);
}
static const struct kernel_param_ops sus_map_stat_ops = {
    .get = sus_map_stat_show,
};
module_param_cb(map_stat, &sus_map_stat_ops, NULL, 0400);

/* Registers whichever of the probes are not up yet.  Called from init (when a
 * rule already exists) and from the supercall that adds the first rule, so both
 * paths arm exactly the same set. */
static int sus_map_register_probes(void)
{
    int i, n = 0, first_err = 0;

    /* The walk probe is the only one that needs something resolved first. */
    sus_map_resolve_walk_ops();

    for (i = 0; i < (int)N_MAP_PROBES; i++) {
        int rc;

        if (map_probe_armed[i])
            continue;
        if ((map_probes[i] == &kp_map_walk || map_probes[i] == &kp_map_walk_vma) &&
            !sus_map_walk_ops_any())
            continue;
        rc = register_kprobe(map_probes[i]);
        if (rc) {
            pr_warn("sus_map: register_kprobe(%s) failed %d - that listing is not filtered\n",
                    map_probes[i]->symbol_name, rc);
            if (!first_err)
                first_err = rc;
            continue;
        }
        map_probe_armed[i] = true;
        n++;
    }

    if (n)
        SUSFS_LOGI("sus_map: %d/%d probes armed (%d rules)\n",
                n, (int)N_MAP_PROBES, nmap);

    /* The map_files hook is a kretprobe, so it lives outside map_probes[] (which
     * holds struct kprobe *) and is tracked on its own.  Optional like the rest:
     * without it the maps/smaps listings are still filtered. */
    if (!kr_map_files_ok) {
        int rc = register_kretprobe(&kr_map_files);

        if (rc)
            pr_warn("sus_map: register_kretprobe(proc_map_files_get_link) failed %d - readlink on a hidden mapping still names the file\n",
                    rc);
        else
            kr_map_files_ok = true;
    }

    map_registered = map_probe_armed[0];   /* show_map_vma is the required one */
    return map_registered ? 0 : first_err;
}


int susfs_sus_map_init(void)
{
    int rc;

    sus_map_add(param_map_ino);
    if (nmap == 0) {
        SUSFS_LOGI("sus_map: no rules, hook not installed\n");
        return 0;
    }

    /* Every probe is optional on its own: without show_smap the maps listing is
     * still filtered, so one missing symbol must not take the rest down. */
    rc = sus_map_register_probes();
    if (rc)
        return rc;
    return 0;
}

void susfs_sus_map_exit(void)
{
    int i;

    for (i = 0; i < (int)N_MAP_PROBES; i++) {
        if (!map_probe_armed[i])
            continue;
        unregister_kprobe(map_probes[i]);
        map_probe_armed[i] = false;
    }
    if (kr_map_files_ok) {
        unregister_kretprobe(&kr_map_files);
        kr_map_files_ok = false;
    }
    map_registered = false;
    nmap = 0;
}

/* supercall: CMD_SUSFS_ADD_SUS_MAP (resolve path -> ino/dev, register hook) */
void susfs_sus_map_supercall(void __user **arg)
{
    struct st_susfs_sus_map info = {0};
    struct path p;
    struct inode *inode;
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    /* char[256] field that need not be NUL-terminated: reject it before
     * kern_path() can read off the end of our stack copy of the struct. */
    if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {
        info.err = -ENAMETOOLONG;
        goto out;
    }

    rc = kern_path(info.target_pathname, LOOKUP_FOLLOW, &p);
    if (rc) {
        info.err = rc;
        goto out;
    }
    inode = d_backing_inode(p.dentry);
    if (!inode) {
        path_put(&p);
        info.err = -ENOENT;
        goto out;
    }

    if (nmap >= SUS_MAP_MAX) {
        path_put(&p);
        info.err = -ENOSPC;
        goto out;
    }
    /* One call fills both fields.  The old two-step form called sus_map_add(),
     * which returns early when ino==0, and then wrote map_entries[nmap-1]
     * unconditionally - indexing -1 at worst, or corrupting the previous rule's
     * device at best. */
    rc = sus_map_add_full(inode->i_ino, inode->i_sb->s_dev);
    if (rc) {
        path_put(&p);
        info.err = rc;
        goto out;
    }
    SUSFS_LOGI("sus_map: added %s (ino=%lu) via supercall\n",
            info.target_pathname, inode->i_ino);
    path_put(&p);

    /* lazy-register the hooks if this was the first rule */
    if (!map_registered) {
        rc = sus_map_register_probes();
        if (rc) {
            info.err = rc;
            goto out;
        }
    }
    info.err = 0;
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_map __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_map supercall copy_to_user failed\n");
}
