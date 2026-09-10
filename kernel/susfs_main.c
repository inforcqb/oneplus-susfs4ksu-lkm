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

/* Our own control nodes.  Hidden from app processes by sus_path below. */
static const char *const susfs_self_hide_paths[] = {
    "/proc/susfs_kstat",
    "/proc/susfs_open_redirect",
    "/proc/susfs_enable_log",
    "/proc/susfs_avc_spoof",
};

/* Register our control nodes in sus_path's hidden set.
 *
 * An app probing /proc/susfs_kstat must see ENOENT, not EACCES: "permission
 * denied" tells the detector the node is there, "no such file or directory"
 * does not.  Using sus_path for this also means the module exercises its own
 * hiding path on every boot, so a broken sus_path shows up immediately.
 *
 * Runs after every feature init, because the nodes must exist for kern_path()
 * to resolve them, and after sus_path_init() so the hooks are already patched. */
static void susfs_self_hide_nodes(void)
{
    int i;

    if (!susfs_expose_proc)
        return;

    for (i = 0; i < ARRAY_SIZE(susfs_self_hide_paths); i++) {
        int rc = sus_path_add_hidden(susfs_self_hide_paths[i]);

        if (rc)
            pr_warn("susfs_guard_lkm: self-hide %s failed %d\n",
                    susfs_self_hide_paths[i], rc);
    }
}

/* The /proc/susfs_* control nodes exist so the module can be configured without
 * depending on a userspace tool whose ABI may not match.
 *
 * They are hidden from app processes with our OWN sus_path feature (see
 * susfs_self_hide_nodes below): an app then gets "No such file or directory",
 * whereas 0600 alone would give "Permission denied" - which advertises that the
 * file exists and is merely off limits.  Root and shell keep full access, the
 * same gate every other sus_path entry uses.
 *
 * Set expose_proc=0 to not create them at all. */
bool susfs_expose_proc = true;
module_param_named(expose_proc, susfs_expose_proc, bool, 0600);

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

    susfs_self_hide_nodes();

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
