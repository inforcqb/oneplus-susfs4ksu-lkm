// SPDX-License-Identifier: GPL-2.0
/*
 * sus_map.c - hide mmapped real files from /proc/<pid>/maps (SUSFS SUS_MAP).
 *
 * Upstream SUSFS sets AS_FLAGS_SUS_MAP on the inode's address_space flags and
 * makes show_map_vma() / show_smap() skip the line (and the smaps_rollup loop
 * skip the vma).  An LKM cannot add a flag bit, so we keep an ino set and hook
 * show_map_vma and show_smap with a kprobe: when the vma's backing file inode
 * is in the set, skip the line by returning early (regs->pc = x30).
 *
 * show_map_vma(m, vma) / show_smap(m, v): vma is arg #2 (regs->regs[1]);
 * returning non-zero from the pre_handler makes the arm64 kprobe core skip
 * singlestep and continue at the modified pc (same trick kprg uses).
 *
 * smaps_rollup is deliberately NOT probed - see "the sentinel" below.
 *
 * The skip is gated exactly like upstream's, so only processes the gate treats
 * as apps see the line dropped and root/init keep seeing the real mapping - see
 * "the read gate" below.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/cred.h>		/* current_uid(), for the read gate */
#include <linux/spinlock.h>	/* serialises rule publication */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_abi_path_ok */

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
 * which cannot know the device). */
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

/* Kept in one table so init and exit cannot drift apart. */
static struct kprobe *const map_probes[] = {
    &kp_map, &kp_map_smap,
};
#define N_MAP_PROBES ARRAY_SIZE(map_probes)
static bool map_registered;
static bool map_probe_armed[N_MAP_PROBES];

/* Registers whichever of the probes are not up yet.  Called from init (when a
 * rule already exists) and from the supercall that adds the first rule, so both
 * paths arm exactly the same set. */
static int sus_map_register_probes(void)
{
    int i, n = 0, first_err = 0;

    for (i = 0; i < (int)N_MAP_PROBES; i++) {
        int rc;

        if (map_probe_armed[i])
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
        pr_info("sus_map: %d/%d probes armed (%d rules)\n",
                n, (int)N_MAP_PROBES, nmap);
    map_registered = map_probe_armed[0];   /* show_map_vma is the required one */
    return map_registered ? 0 : first_err;
}


int susfs_sus_map_init(void)
{
    int rc;

    sus_map_add(param_map_ino);
    if (nmap == 0) {
        pr_info("sus_map: no rules, hook not installed\n");
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
    pr_info("sus_map: added %s (ino=%lu) via supercall\n",
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
