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
#include <linux/path.h>
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
        if (e->target_ino != ino && e->target_ino != stat->ino)
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
    const struct path *path;
    struct kstat *stat;
};

static int kr_vfs_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kstat_args *a = (struct kstat_args *)ri->data;
    struct dentry *d;

    /* vfs_getattr(path, stat, request_mask, query_flags): direct args */
    a->path = (const struct path *)regs->regs[0];
    a->stat = (struct kstat *)regs->regs[1];

    d = (a->path) ? a->path->dentry : NULL;
    if (d && d->d_inode)
        pr_info_ratelimited("GETATTR: name=%.*s i_ino=%lu comm=%s\n",
                (int)d->d_name.len, d->d_name.name, d->d_inode->i_ino,
                current->comm);
    return 0;
}

static int kr_vfs_getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kstat_args *a = (struct kstat_args *)ri->data;
    struct inode *inode;
    bool matched;

    if (!a->path || !a->path->dentry || !a->stat)
        return 0;
    inode = a->path->dentry->d_inode;
    pr_info_ratelimited("KSTAT TRACE getattr: inode=%lu stat=%lu ret=%ld comm=%s\n",
                        inode ? inode->i_ino : 0, a->stat->ino,
                        regs_return_value(regs), current->comm);
    matched = inode && (inode->i_ino == param_target_ino ||
                        a->stat->ino == param_target_ino);
    if (matched)
        pr_info("KSTAT HIT before: inode->i_ino=%lu stat->ino=%lu target=%lu spoof=%lu\n",
            inode->i_ino, a->stat->ino, param_target_ino, param_spoofed_ino);
    susfs_kstat_spoof(inode, a->stat);
    if (matched)
        pr_info("KSTAT HIT after: inode->i_ino=%lu stat->ino=%lu\n",
                inode->i_ino, a->stat->ino);
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = "vfs_getattr",
    .entry_handler = kr_vfs_getattr_entry,
    .handler = kr_vfs_getattr_ret,
    .data_size = sizeof(struct kstat_args),
    .maxactive = 64,
};

static struct kretprobe krp_nosec = {
    .kp.symbol_name = "vfs_getattr_nosec",
    .entry_handler = kr_vfs_getattr_entry,
    .handler = kr_vfs_getattr_ret,
    .data_size = sizeof(struct kstat_args),
    .maxactive = 64,
};

int susfs_kstat_syscall_diag_init(void);
void susfs_kstat_syscall_diag_exit(void);

int susfs_kstat_init(void)
{
    int rc;

    susfs_kstat_add_ino(param_target_ino, param_spoofed_ino);
    if (nkstat == 0) {
        pr_info("kstat spoof: no rules, hook not installed\n");
        return 0;
    }

    rc = register_kretprobe(&krp);
    if (rc)
        pr_warn("register_kretprobe(vfs_getattr) failed %d\n", rc);
    else {
        rc = register_kretprobe(&krp_nosec);
        if (rc) {
            pr_warn("register_kretprobe(vfs_getattr_nosec) failed %d\n", rc);
            unregister_kretprobe(&krp);
        } else {
            pr_info("kstat spoof armed: %d rules\n", nkstat);
        }
    }
    susfs_kstat_syscall_diag_init();
    return 0;
}

void susfs_kstat_exit(void)
{
    susfs_kstat_syscall_diag_exit();
    unregister_kretprobe(&krp_nosec);
    unregister_kretprobe(&krp);
    nkstat = 0;
}

/* ---- temporary syscall diagnosis ---- */
static int kp_statx_pre(struct kprobe *kp, struct pt_regs *regs)
{
    pr_info("SYSCALL statx: comm=%s\n", current->comm);
    return 0;
}

static int kp_newfstatat_pre(struct kprobe *kp, struct pt_regs *regs)
{
    pr_info("SYSCALL newfstatat: comm=%s\n", current->comm);
    return 0;
}

static int kp_fstatat64_pre(struct kprobe *kp, struct pt_regs *regs)
{
    pr_info("SYSCALL fstatat64: comm=%s\n", current->comm);
    return 0;
}

static int kp_fstat_pre(struct kprobe *kp, struct pt_regs *regs)
{
    pr_info("SYSCALL fstat: comm=%s\n", current->comm);
    return 0;
}

static struct kprobe kp_statx = {
    .symbol_name = "__arm64_sys_statx",
    .pre_handler = kp_statx_pre,
};

static struct kprobe kp_newfstatat = {
    .symbol_name = "__arm64_sys_newfstatat",
    .pre_handler = kp_newfstatat_pre,
};

static struct kprobe kp_fstatat64 = {
    .symbol_name = "__arm64_sys_fstatat64",
    .pre_handler = kp_fstatat64_pre,
};

static struct kprobe kp_fstat = {
    .symbol_name = "__arm64_sys_fstat",
    .pre_handler = kp_fstat_pre,
};

int susfs_kstat_syscall_diag_init(void)
{
    register_kprobe(&kp_statx);
    register_kprobe(&kp_newfstatat);
    register_kprobe(&kp_fstatat64);
    register_kprobe(&kp_fstat);
    return 0;
}

void susfs_kstat_syscall_diag_exit(void)
{
    unregister_kprobe(&kp_fstat);
    unregister_kprobe(&kp_fstatat64);
    unregister_kprobe(&kp_newfstatat);
    unregister_kprobe(&kp_statx);
}
