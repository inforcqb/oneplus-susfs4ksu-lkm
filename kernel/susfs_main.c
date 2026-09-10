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

#include "symbol_resolver.h"
#include "lsm_hook.h"
#include "susfs.h"

#define SUSFS_LKM_VERSION "2.3.0-gki"

static int __init susfs_init(void)
{
    int ret;

    pr_info("susfs_guard_lkm: init v%s\n", SUSFS_LKM_VERSION);
    ksu_init_symbol_resolver();
    ksu_lsm_hook_init();
    susfs_uname_init();
    susfs_kstat_init();
    susfs_sus_map_init();
    sus_path_init();
    susfs_sus_mount_init();
    susfs_spoof_cmdline_init();
    susfs_open_redirect_init();
    susfs_enable_log_init();

    /* Optional: logs its own failure and degrades to "off". */
    susfs_avc_spoof_init();

    /* The supercall kprobe IS the command channel.  With it unregistered no
     * CMD ever reaches the module, so refusing the load is far better than
     * coming up "healthy" and silently ignoring every command. */
    ret = susfs_supercall_init();
    if (ret) {
        pr_err("susfs_guard_lkm: supercall init failed %d, refusing to load\n",
               ret);
        return ret;
    }

    /* Best effort, but a failure must be visible: enabled_features stops
     * advertising HIDE_KSU_SUSFS_SYMBOLS when this fails. */
    if (susfs_hide_syms_init())
        pr_err("susfs_guard_lkm: hide_syms init FAILED - kallsyms NOT hidden\n");

    return 0;
}

static void __exit susfs_exit(void)
{
    susfs_hide_syms_exit();
    susfs_supercall_exit();
    susfs_avc_spoof_exit();
    susfs_enable_log_exit();
    susfs_open_redirect_exit();
    susfs_spoof_cmdline_exit();
    susfs_sus_mount_exit();
    sus_path_exit();
    susfs_sus_map_exit();
    susfs_kstat_exit();
    susfs_uname_exit();
    ksu_lsm_hook_exit();
    pr_info("susfs_guard_lkm: exit\n");
}

module_init(susfs_init);
module_exit(susfs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SUSFS guard LKM (susfs_guard_lkm) v2.3.0-gki");
