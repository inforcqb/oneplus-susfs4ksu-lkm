// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kstat.c - spoof kstat fields (SUSFS SUS_KSTAT feature), LKM port.
 *
 * On this GKI kernel LTO inlines the whole newfstatat chain
 * (vfs_fstatat -> vfs_statx -> vfs_getattr -> cp_new_stat) into the syscall
 * entry, so VFS-layer kprobes miss.  The reliable hook is the return of
 * __arm64_sys_newfstatat, where the user statbuf is fully written.  Rewrite
 * the requested fields there via copy_to_user (the pages were just written by
 * cp_new_stat, so this cannot fault).
 *
 * Field offsets are arm64 asm-generic struct stat (see include/uapi/asm-generic/stat.h).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/stat.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include "susfs_log.h"

#define KSTAT_SPOOF_INO      (1 << 0)
#define KSTAT_SPOOF_DEV      (1 << 1)
#define KSTAT_SPOOF_NLINK    (1 << 2)
#define KSTAT_SPOOF_SIZE     (1 << 3)
#define KSTAT_SPOOF_BLKSIZE  (1 << 11)
#define KSTAT_SPOOF_BLOCKS   (1 << 10)

#define SUS_KSTAT_MAX 32

/* arm64 asm-generic struct stat offsets */
#define ST_DEV_OFF      0
#define ST_INO_OFF      8
#define ST_NLINK_OFF    20
#define ST_SIZE_OFF     48
#define ST_BLKSIZE_OFF  56
#define ST_BLOCKS_OFF   64

struct sus_kstat_entry {
    unsigned long target_ino;
    unsigned long spoofed_ino;
    unsigned long spoofed_dev;
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

static struct sus_kstat_entry *susfs_kstat_lookup(unsigned long ino)
{
    int i;

    for (i = 0; i < nkstat; i++)
        if (kstat_entries[i].target_ino == ino)
            return &kstat_entries[i];
    return NULL;
}

/* rewrite the requested fields of the user statbuf */
static void susfs_kstat_spoof_statbuf(unsigned long statbuf)
{
    struct sus_kstat_entry *e;
    unsigned long ino = 0;
    unsigned long v;
    unsigned int v32;
    long long v64;

    if (copy_from_user(&ino, (void __user *)(statbuf + ST_INO_OFF), sizeof(ino)))
        return;

    e = susfs_kstat_lookup(ino);
    if (!e)
        return;

    if (e->flags & KSTAT_SPOOF_INO) {
        v = e->spoofed_ino;
        if (copy_to_user((void __user *)(statbuf + ST_INO_OFF), &v, sizeof(v)))
            return;
    }
    if (e->flags & KSTAT_SPOOF_DEV) {
        v = e->spoofed_dev;
        if (copy_to_user((void __user *)(statbuf + ST_DEV_OFF), &v, sizeof(v)))
            return;
    }
    if (e->flags & KSTAT_SPOOF_NLINK) {
        v32 = e->spoofed_nlink;
        if (copy_to_user((void __user *)(statbuf + ST_NLINK_OFF), &v32, sizeof(v32)))
            return;
    }
    if (e->flags & KSTAT_SPOOF_SIZE) {
        v64 = e->spoofed_size;
        if (copy_to_user((void __user *)(statbuf + ST_SIZE_OFF), &v64, sizeof(v64)))
            return;
    }
    if (e->flags & KSTAT_SPOOF_BLKSIZE) {
        v32 = (unsigned int)e->spoofed_blksize;
        if (copy_to_user((void __user *)(statbuf + ST_BLKSIZE_OFF), &v32, sizeof(v32)))
            return;
    }
    if (e->flags & KSTAT_SPOOF_BLOCKS) {
        v64 = e->spoofed_blocks;
        if (copy_to_user((void __user *)(statbuf + ST_BLOCKS_OFF), &v64, sizeof(v64)))
            return;
    }
}

/* sys_exit tracepoint: the user statbuf is fully written by now, and
 * syscall_get_arguments() still returns the original args (verified: args[2]
 * == statbuf), so no per-cpu state is needed.  This is much cheaper on the
 * hot newfstatat path than a kretprobe (jump label vs BRK + trampoline). */
static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)
{
    unsigned long args[6];
    unsigned long statbuf;

    if (syscall_get_nr(current, regs) != __NR_newfstatat)
        return;
    if (ret != 0)
        return;
    syscall_get_arguments(current, regs, args);
    statbuf = args[2];
    if (!statbuf)
        return;
    susfs_kstat_spoof_statbuf(statbuf);
}

/* fallback: some paths (vfs_fstat, statx, direct callers) still reach the
 * exported vfs_getattr copy; rewrite the kernel kstat there too. */
struct vfs_getattr_args {
    const struct path *path;
    struct kstat *stat;
};

static int kr_vfs_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_getattr_args *a = (struct vfs_getattr_args *)ri->data;

    a->path = (const struct path *)regs->regs[0];
    a->stat = (struct kstat *)regs->regs[1];
    return 0;
}

static void susfs_kstat_spoof_kstat(struct inode *inode, struct kstat *stat)
{
    struct sus_kstat_entry *e;

    if (!inode || !stat)
        return;
    e = susfs_kstat_lookup(inode->i_ino);
    if (!e)
        return;
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
}

static int kr_vfs_getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_getattr_args *a = (struct vfs_getattr_args *)ri->data;

    if (regs_return_value(regs) != 0)
        return 0;
    if (!a->path || !a->path->dentry || !a->stat)
        return 0;
    susfs_kstat_spoof_kstat(a->path->dentry->d_inode, a->stat);
    return 0;
}

static struct kretprobe krp_vfs_getattr = {
    .kp.symbol_name = "vfs_getattr",
    .entry_handler = kr_vfs_getattr_entry,
    .handler = kr_vfs_getattr_ret,
    .data_size = sizeof(struct vfs_getattr_args),
    .maxactive = 64,
};

int susfs_kstat_init(void)
{
    int rc;

    susfs_kstat_add_ino(param_target_ino, param_spoofed_ino);
    if (nkstat == 0) {
        pr_info("kstat spoof: no rules, hook not installed\n");
        return 0;
    }

    rc = register_trace_sys_exit(kstat_sys_exit, NULL);
    if (rc)
        pr_warn("register_trace_sys_exit failed %d\n", rc);

    rc = register_kretprobe(&krp_vfs_getattr);
    if (rc)
        pr_warn("register_kretprobe(vfs_getattr) failed %d\n", rc);

    pr_info("kstat spoof armed: %d rules (tracepoint + vfs_getattr fallback)\n", nkstat);
    return 0;
}

void susfs_kstat_exit(void)
{
    unregister_kretprobe(&krp_vfs_getattr);
    unregister_trace_sys_exit(kstat_sys_exit, NULL);
    tracepoint_synchronize_unregister();
    nkstat = 0;
}
