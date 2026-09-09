// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_spoof.c - kstat spoof via kretprobe on __arm64_sys_newfstatat exit.
 *
 * LTO inlines the whole newfstatat chain (vfs_fstatat -> vfs_statx ->
 * vfs_getattr -> cp_new_stat) into the syscall entry, so the user statbuf is
 * fully written by the time __arm64_sys_newfstatat returns.  Hook its return
 * and rewrite st_ino (offset 8 in arm64 asm-generic struct stat).
 *
 * The statbuf pages were just written by cp_new_stat, so copy_to_user here
 * cannot fault (same reasoning as the uname spoof).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include "susfs_log.h"

static unsigned long param_target_ino;
static unsigned long param_spoofed_ino;
module_param_named(target_ino, param_target_ino, ulong, 0644);
module_param_named(spoofed_ino, param_spoofed_ino, ulong, 0644);

#define ST_INO_OFF 8  /* arm64 asm-generic struct stat: st_dev then st_ino */

struct stat_args {
    unsigned long statbuf;
};

static int kr_newfstatat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct stat_args *a = (struct stat_args *)ri->data;
    struct pt_regs *user = (struct pt_regs *)regs->regs[0];

    /* syscall wrapper does NOT auto-adjust regs on this GKI kernel:
     * regs->regs[0] is the struct pt_regs* argument; user args live in
     * user->regs[0..3] = dfd, filename, statbuf, flag. */
    a->statbuf = user->regs[2];
    return 0;
}

static int kr_newfstatat_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct stat_args *a = (struct stat_args *)ri->data;
    unsigned long ino = 0;
    unsigned long spoofed;

    if (regs_return_value(regs) != 0)
        return 0;
    if (!a->statbuf)
        return 0;

    if (copy_from_user(&ino, (void __user *)(a->statbuf + ST_INO_OFF), sizeof(ino)))
        return 0;
    if (ino != param_target_ino)
        return 0;

    spoofed = param_spoofed_ino;
    if (copy_to_user((void __user *)(a->statbuf + ST_INO_OFF), &spoofed, sizeof(spoofed)))
        return 0;
    pr_info("kstat spoof: ino=%lu -> %lu\n", ino, spoofed);
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = "__arm64_sys_newfstatat",
    .entry_handler = kr_newfstatat_entry,
    .handler = kr_newfstatat_ret,
    .data_size = sizeof(struct stat_args),
    .maxactive = 64,
};

static int __init kstat_spoof_init(void)
{
    int rc = register_kretprobe(&krp);

    if (rc)
        pr_warn("register_kretprobe(newfstatat) failed %d\n", rc);
    else
        pr_info("kstat spoof armed: target=%lu spoof=%lu\n",
                param_target_ino, param_spoofed_ino);
    return 0;
}

static void __exit kstat_spoof_exit(void)
{
    unregister_kretprobe(&krp);
    pr_info("kstat spoof bye\n");
}

module_init(kstat_spoof_init);
module_exit(kstat_spoof_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kstat ino spoof via newfstatat kretprobe");
