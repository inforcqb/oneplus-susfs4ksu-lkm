// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_uname.c - spoof uname release/version (SUSFS SPOOF_UNAME feature).
 *
 * Upstream SUSFS patches the body of SYSCALL_DEFINE1(newuname) between the
 * memcpy(utsname) and copy_to_user.  The LKM equivalent hooks
 * __arm64_sys_newuname with a kretprobe and rewrites the release/version
 * fields of the user buffer right before the syscall returns.
 *
 * The target pages were just faulted-in by the original copy_to_user, so the
 * kretprobe handler's copy_to_user cannot fault (no sleep in atomic context).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/string.h>
#include <linux/version.h>
#include "susfs_log.h"

#define SUSFS_UNAME_LEN (__NEW_UTS_LEN + 1)

static char fake_release[SUSFS_UNAME_LEN] = "5.15.180-susfs";
static char fake_version[SUSFS_UNAME_LEN] = "#1 SMP PREEMPT susfs";
static bool uname_spoof_enabled = true;

module_param_string(release, fake_release, sizeof(fake_release), 0644);
module_param_string(version, fake_version, sizeof(fake_version), 0644);
module_param(uname_spoof_enabled, bool, 0644);
MODULE_PARM_DESC(release, "fake uname release");
MODULE_PARM_DESC(version, "fake uname version");
MODULE_PARM_DESC(uname_spoof_enabled, "enable uname spoofing");

struct uname_args {
    struct new_utsname __user *name;
};

static int kr_newuname_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct uname_args *a = (struct uname_args *)ri->data;
    struct pt_regs *user = (struct pt_regs *)regs->regs[0];

    /* this GKI kernel does NOT auto-adjust syscall-wrapper probe regs:
     * regs->regs[0] is the struct pt_regs* argument, not the user arg */
    a->name = (struct new_utsname __user *)user->regs[0];
    return 0;
}

static int kr_newuname_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct uname_args *a = (struct uname_args *)ri->data;

    if (regs_return_value(regs) != 0)
        return 0;
    if (!uname_spoof_enabled || !a->name)
        return 0;

    copy_to_user((char __user *)a->name + offsetof(struct new_utsname, release),
                 fake_release, SUSFS_UNAME_LEN);
    copy_to_user((char __user *)a->name + offsetof(struct new_utsname, version),
                 fake_version, SUSFS_UNAME_LEN);
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = "__arm64_sys_newuname",
    .entry_handler = kr_newuname_entry,
    .handler = kr_newuname_ret,
    .data_size = sizeof(struct uname_args),
    .maxactive = 32,
};

int susfs_uname_init(void)
{
    int rc = register_kretprobe(&krp);

    if (rc)
        pr_warn("register_kretprobe(newuname) failed %d\n", rc);
    else
        pr_info("uname spoof armed: release=%s version=%s\n", fake_release, fake_version);
    return 0;
}

void susfs_uname_exit(void)
{
    unregister_kretprobe(&krp);
}
