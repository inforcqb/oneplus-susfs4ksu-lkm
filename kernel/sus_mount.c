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
#include <linux/uaccess.h>
#include "mount.h"      /* fs/mount.h: struct mount + real_mount() */
#include "susfs_abi.h"
#include "susfs_log.h"

#define DEFAULT_KSU_MNT_ID 2000000000ULL

/* NOTE: upstream SUSFS makes KSU mounts get mnt_id >= DEFAULT_KSU_MNT_ID by
 * patching mnt_alloc_id() to call ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID)
 * for the ksu domain.  This LKM does NOT patch that, so on a stock KernelSU
 * device KSU mounts keep normal (small) mnt_ids.  min_mnt_id is therefore a
 * tunable: set it to the actual KSU mount id range, or adapt the match to a
 * mountpoint/device name list instead of a numeric threshold. */
static unsigned long param_min_mnt_id = DEFAULT_KSU_MNT_ID;
module_param_named(min_mnt_id, param_min_mnt_id, ulong, 0644);

static int sus_mount_show_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vfsmount *mnt = (struct vfsmount *)regs->regs[1];
    struct mount *r;

    if (!mnt)
        return 0;
    r = real_mount(mnt);
    if ((unsigned int)r->mnt_id >= param_min_mnt_id) {
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
    /* upstream defaults this OFF (static key false) so zygisk can see sus
     * mounts during post-fs-data; the LKM mirrors that: no hook until
     * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS enables it. */
    pr_info("sus_mount: disabled by default (enable via CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS)\n");
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
    } else if (mount_registered) {
        unregister_kprobe(&kp_mountinfo);
        unregister_kprobe(&kp_vfsstat);
        mount_registered = false;
    }
    info.err = 0;
    pr_info("sus_mount: %s (supercall)\n", info.enabled ? "hide" : "unhide");
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_mount supercall copy_to_user failed\n");
}
