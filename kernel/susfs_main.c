// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_main.c - SUSFS LKM entry point.
 *
 * Skeleton only for now.  Feature code (sus_path / sus_kstat / sus_map /
 * open_redirect / avc spoofing / uname spoofing) is added incrementally.
 *
 * Loaded via `ksud insmod` (unexported symbols are relocated via kallsyms).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#define SUSFS_LKM_VERSION "0.1.0-dev"

static int __init susfs_init(void)
{
    pr_info("susfs-lkm: init %s\n", SUSFS_LKM_VERSION);
    return 0;
}

static void __exit susfs_exit(void)
{
    pr_info("susfs-lkm: exit\n");
}

module_init(susfs_init);
module_exit(susfs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SUSFS loadable kernel module (LKM)");
