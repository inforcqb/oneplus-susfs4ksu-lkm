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
 *
 * Upstream semantics: spoofing is OFF by default (static key false, empty
 * buffer).  It is enabled only when CMD_SUSFS_SET_UNAME is issued, with the
 * caller passing the release/version strings; passing "default" copies the
 * device's CURRENT utsname()->release/version at runtime instead of a
 * hardcoded value.  The kretprobe is therefore registered lazily on first
 * enable, so a loaded-but-unused module costs nothing on the uname hot path.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/string.h>
#include <linux/version.h>
#include "susfs_abi.h"
#include "susfs_log.h"

#define SUSFS_UNAME_LEN (__NEW_UTS_LEN + 1)

static char fake_release[SUSFS_UNAME_LEN];
static char fake_version[SUSFS_UNAME_LEN];
static bool uname_spoof_enabled;

/* optional insmod-time override; supercall is the primary interface */
module_param_string(release, fake_release, sizeof(fake_release), 0644);
module_param_string(version, fake_version, sizeof(fake_version), 0644);
module_param(uname_spoof_enabled, bool, 0644);
MODULE_PARM_DESC(release, "fake uname release (insmod override)");
MODULE_PARM_DESC(version, "fake uname version (insmod override)");
MODULE_PARM_DESC(uname_spoof_enabled, "enable uname spoofing (insmod override)");

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

    if (copy_to_user((char __user *)a->name + offsetof(struct new_utsname, release),
                     fake_release, SUSFS_UNAME_LEN))
        return 0;
    if (copy_to_user((char __user *)a->name + offsetof(struct new_utsname, version),
                     fake_version, SUSFS_UNAME_LEN))
        return 0;
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = "__arm64_sys_newuname",
    .entry_handler = kr_newuname_entry,
    .handler = kr_newuname_ret,
    .data_size = sizeof(struct uname_args),
    .maxactive = 32,
};

static bool uname_registered;

static int uname_register(void)
{
    int rc;

    if (uname_registered)
        return 0;
    rc = register_kretprobe(&krp);
    if (rc)
        return rc;
    uname_registered = true;
    pr_info("uname spoof armed: release=%s version=%s\n",
            fake_release, fake_version);
    return 0;
}

static void uname_unregister(void)
{
    if (!uname_registered)
        return;
    unregister_kretprobe(&krp);
    uname_registered = false;
}

int susfs_uname_init(void)
{
    /* only arm on explicit insmod override (release+version+enabled) */
    if (uname_spoof_enabled && fake_release[0] && fake_version[0]) {
        int rc = uname_register();

        if (rc)
            pr_warn("register_kretprobe(newuname) failed %d\n", rc);
    } else {
        pr_info("uname spoof: disabled (enable via CMD_SUSFS_SET_UNAME)\n");
    }
    return 0;
}

void susfs_uname_exit(void)
{
    uname_unregister();
}

/* supercall: CMD_SUSFS_SET_UNAME */
void susfs_uname_supercall(void __user **arg)
{
    struct st_susfs_uname info = {0};
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }
    if (*info.release == '\0' || *info.version == '\0') {
        info.err = -EFAULT;
        goto out;
    }

    /* debug: dump exact bytes to see why "default" may not match */
    {
        int i;
        pr_info("uname supercall: release=");
        for (i = 0; i < 12; i++)
            pr_cont("%02x ", (unsigned char)info.release[i]);
        pr_cont(" version=");
        for (i = 0; i < 12; i++)
            pr_cont("%02x ", (unsigned char)info.version[i]);
        pr_cont(" rcmp=%d vcmp=%d\n",
                strcmp(info.release, "default"),
                strcmp(info.version, "default"));
    }

    /* "default" copies the device's CURRENT uname at runtime */
    if (!strcmp(info.release, "default"))
        strscpy(fake_release, utsname()->release, sizeof(fake_release));
    else
        strscpy(fake_release, info.release, sizeof(fake_release));
    if (!strcmp(info.version, "default"))
        strscpy(fake_version, utsname()->version, sizeof(fake_version));
    else
        strscpy(fake_version, info.version, sizeof(fake_version));

    uname_spoof_enabled = true;
    rc = uname_register();
    if (rc) {
        info.err = rc;
        goto out;
    }
    info.err = 0;
    pr_info("uname spoof set: release=%s version=%s\n", fake_release, fake_version);
out:
    if (copy_to_user((void __user *)*arg, &info, sizeof(info)))
        pr_warn("uname supercall copy_to_user failed\n");
}
