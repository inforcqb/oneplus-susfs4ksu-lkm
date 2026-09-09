// SPDX-License-Identifier: GPL-2.0
/*
 * sus_mount.c - hide KSU mounts from /proc/mounts and /proc/mountinfo.
 *
 * Upstream SUSFS skips the line in show_vfsstat()/show_mountinfo() when
 * mnt_id >= DEFAULT_KSU_MNT_ID (mounts created by the ksu process).  Those
 * show functions are static but live behind proc_ops function pointers, so
 * they are NOT LTO-inlined and remain kprobe-able (verified in kallsyms).
 *
 * The LKM hooks both show functions with a kprobe pre_handler and returns
 * early (regs->pc = x30) when the mount id is in the KSU range.  struct mount
 * / real_mount() come from the private fs/mount.h (its includes are all
 * public headers, so -I$(srctree)/fs is enough).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include "mount.h"      /* fs/mount.h: struct mount + real_mount() */
#include "susfs_log.h"

#define DEFAULT_KSU_MNT_ID 2000000000ULL

static int sus_mount_show_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vfsmount *mnt = (struct vfsmount *)regs->regs[1];
    struct mount *r;

    if (!mnt)
        return 0;
    r = real_mount(mnt);
    if (r->mnt_id >= DEFAULT_KSU_MNT_ID) {
        regs->pc = regs->regs[30];   /* skip this mount line */
        return 1;
    }
    return 0;
}

static struct kprobe kp_vfsstat = {
    .symbol_name = "show_vfsstat",
    .pre_handler = sus_mount_show_pre,
};

static struct kprobe kp_mountinfo = {
    .symbol_name = "show_mountinfo",
    .pre_handler = sus_mount_show_pre,
};

static bool mount_registered;

int susfs_sus_mount_init(void)
{
    int rc;

    rc = register_kprobe(&kp_vfsstat);
    if (rc) {
        pr_warn("register_kprobe(show_vfsstat) failed %d\n", rc);
        return 0;
    }

    rc = register_kprobe(&kp_mountinfo);
    if (rc) {
        pr_warn("register_kprobe(show_mountinfo) failed %d\n", rc);
        unregister_kprobe(&kp_vfsstat);
        return 0;
    }

    mount_registered = true;
    pr_info("sus_mount armed: hide mnt_id >= %llu\n", DEFAULT_KSU_MNT_ID);
    return 0;
}

void susfs_sus_mount_exit(void)
{
    if (mount_registered) {
        unregister_kprobe(&kp_mountinfo);
        unregister_kprobe(&kp_vfsstat);
        mount_registered = false;
    }
}
