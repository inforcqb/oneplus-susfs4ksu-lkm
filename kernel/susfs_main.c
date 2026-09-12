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
/* The directory name the module gets under /sys/module: it has to match what the
 * kernel derives from the module name, because susfs_self_hide_nodes() registers it
 * as a hidden path. */
#define SUSFS_LKM_MODULE_NAME "susfs_guard_lkm"

/* The /proc/susfs_* control nodes are OFF by default.
 *
 * Measured on device: with the nodes present and 0600, an app got
 *   ls -l /proc/susfs_kstat -> No such file or directory   (sus_path inode_getattr fired)
 *   cat  /proc/susfs_kstat -> Permission denied            (it did NOT)
 * and the sus_path perm counter stayed at 0.  Reason: inode_permission() runs
 * the DAC check BEFORE security_inode_permission(), so a 0600 root-owned node
 * fails DAC first and the LSM hook is never reached - the caller sees EACCES,
 * which advertises that the node exists.
 *
 * That is a general property of sus_path's path layer, not specific to these
 * nodes: it can only turn an ENOENT-shaped answer out of files DAC would have
 * ALLOWED (which is why a 0644 file like /data/local/tmp/susfs.ko works, and a
 * 0600 one does not).
 *
 * Therefore the nodes are not created at all by default - absent is the only
 * answer that cannot be distinguished from "no such file".  Set expose_proc=1
 * to create them for hand configuration; they are then also registered in
 * sus_path (see susfs_self_hide_nodes), which still hides stat/open for callers
 * DAC would allow. */
/* Default ON: the nodes are this module's interface, and they are protected by
 * sus_path (every non-root caller sees ENOENT).  They are only created when the
 * LSM layer that does the hiding is installed, so an unprotected node cannot
 * happen; expose_proc=0 removes them entirely for operators who want nothing
 * under /proc at all. */
bool susfs_expose_proc = true;
module_param_named(expose_proc, susfs_expose_proc, bool, 0600);

/* Our own control nodes.  Hidden from app processes by sus_path below. */
static const char *const susfs_self_hide_paths[] = {
    "/proc/susfs_kstat",
    "/proc/susfs_open_redirect",
    "/proc/susfs_enable_log",
    "/proc/susfs_avc_spoof",
    /* And the module's own sysfs directory.
     *
     * A built-in SUSFS has no module entry to hide; a loadable module is listed in
     * /proc/modules and under /sys/module, and BOTH ARE WORLD-READABLE - one
     * `lsmod`, or one readdir of /sys/module, is enough to see that the hiding
     * machinery is loaded, name and all.  Registering the directory makes the
     * listing filter drop it and a direct access answer ENOENT, exactly like any
     * other hidden path; /proc/modules is handled separately (see
     * susfs_hide_syms.c, which already hooks the seq_file show that prints it). */
    "/sys/module/" SUSFS_LKM_MODULE_NAME,
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
        int rc = sus_path_add_self_hidden(susfs_self_hide_paths[i]);

        if (rc)
            pr_warn("susfs_guard_lkm: self-hide %s failed %d\n",
                    susfs_self_hide_paths[i], rc);
    }
}

static int __init susfs_init(void)
{
    int ret;

    pr_info("susfs_guard_lkm: init v%s\n", SUSFS_LKM_VERSION);
    ksu_init_symbol_resolver();
    ksu_lsm_hook_init();

    /* sus_path FIRST: it installs the LSM layer whose state every later feature
     * consults before creating a world-accessible control node (see
     * susfs_expose_proc).  It has no other dependency.
     *
     * Its failure IS fatal: without the LSM slots a registered path is not hidden
     * at all, and coming up "healthy" would have add_sus_path() report success
     * while nothing was hidden. */
    ret = sus_path_init();
    if (ret) {
        pr_err("susfs_guard_lkm: sus_path init failed %d, refusing to load\n", ret);
        return ret;
    }

    susfs_uname_init();
    susfs_kstat_init();
    susfs_sus_map_init();
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
