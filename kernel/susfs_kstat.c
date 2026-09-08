// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kstat.c - spoof kstat fields (SUSFS SUS_KSTAT feature), LKM port.
 *
 * Upstream SUSFS patches the tail of generic_fillattr() (fs/stat.c) to rewrite
 * the kstat.  The LKM equivalent hooks generic_fillattr with a kretprobe and
 * rewrites the stat fields after the function filled them.  The spoof lookup
 * is pure in-memory work (no sleeping), safe in a kretprobe handler.
 *
 * Matching is by inode number (optionally + device).  Rules are added at load
 * time via module params; a full add/update/delete interface comes later.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include "susfs_log.h"

#define KSTAT_SPOOF_INO      (1 << 0)
#define KSTAT_SPOOF_DEV      (1 << 1)
#define KSTAT_SPOOF_NLINK    (1 << 2)
#define KSTAT_SPOOF_SIZE     (1 << 3)
#define KSTAT_SPOOF_BLKSIZE  (1 << 11)
#define KSTAT_SPOOF_BLOCKS   (1 << 10)

#define SUS_KSTAT_MAX 32

struct sus_kstat_entry {
    unsigned long target_ino;
    dev_t target_dev;
    unsigned long spoofed_ino;
    dev_t spoofed_dev;
    unsigned int spoofed_nlink;
    long long spoofed_size;
    long long spoofed_blocks;
    long spoofed_blksize;
    unsigned int flags;
};

static struct sus_kstat_entry kstat_entries[SUS_KSTAT_MAX];
static int nkstat;

/* temporary rule interface: insmod susfs.ko target_ino=<n> spoofed_ino=<m>
 * adds a single ino-spoofing rule (extended to a full add/update interface). */
static unsigned long param_target_ino;
static unsigned long param_spoofed_ino;
module_param_named(target_ino, param_target_ino, ulong, 0644);
module_param_named(spoofed_ino, param_spoofed_ino, ulong, 0644);

static void susfs_kstat_add_ino(unsigned long target_ino, unsigned long spoofed_ino)
{
    if (nkstat >= SUS_KSTAT_MAX || !target_ino)
        return;
    kstat_entries[nkstat].target_ino = target_ino;
    kstat_entries[nkstat].spoofed_ino = spoofed_ino;
    kstat_entries[nkstat].flags = KSTAT_SPOOF_INO;
    nkstat++;
}

static void susfs_kstat_spoof(struct inode *inode, struct kstat *stat)
{
    int i;
    unsigned long ino;
    dev_t dev;

    if (!inode || !stat)
        return;
    ino = inode->i_ino;
    dev = inode->i_sb->s_dev;

    for (i = 0; i < nkstat; i++) {
        struct sus_kstat_entry *e = &kstat_entries[i];
        if (e->target_ino != ino)
            continue;
        if (e->target_dev && e->target_dev != dev)
            continue;
        if (e->flags & KSTAT_SPOOF_INO)
            stat->ino = e->spoofed_ino;
        if (e->flags & KSTAT_SPOOF_DEV)
            stat->dev = e->spoofed_dev;
        if (e->flags & KSTAT_SPOOF_NLINK)
            stat->nlink = e->spoofed_nlink;
        if (e->flags & KSTAT_SPOOF_SIZE)
            stat->size = e->spoofed_size;
        if (e->flags & KSTAT_SPOOF_BLKSIZE)
            stat->blksize = e->spoofed_blksize;
        if (e->flags & KSTAT_SPOOF_BLOCKS)
            stat->blocks = e->spoofed_blocks;
        break;
    }
}

struct kstat_args {
    struct inode *inode;
    struct kstat *stat;
};

static int kr_generic_fillattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kstat_args *a = (struct kstat_args *)ri->data;

    /* generic_fillattr(mnt_userns, inode, stat): direct args, no wrapper nesting */
    a->inode = (struct inode *)regs->regs[1];
    a->stat = (struct kstat *)regs->regs[2];
    return 0;
}

static int kr_generic_fillattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kstat_args *a = (struct kstat_args *)ri->data;

    susfs_kstat_spoof(a->inode, a->stat);
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = "generic_fillattr",
    .entry_handler = kr_generic_fillattr_entry,
    .handler = kr_generic_fillattr_ret,
    .data_size = sizeof(struct kstat_args),
    .maxactive = 64,
};

int susfs_kstat_init(void)
{
    int rc;

    susfs_kstat_add_ino(param_target_ino, param_spoofed_ino);
    rc = register_kretprobe(&krp);
    if (rc)
        pr_warn("register_kretprobe(generic_fillattr) failed %d\n", rc);
    else
        pr_info("kstat spoof armed: %d rules\n", nkstat);
    return 0;
}

void susfs_kstat_exit(void)
{
    unregister_kretprobe(&krp);
    nkstat = 0;
}
