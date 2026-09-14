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
#include "susfs_log.h"
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

/* ---- layer table: arming order IS the teardown order, reversed --------------
 *
 * Two properties are wanted here and neither is cosmetic:
 *
 *  1. A load that fails half way must leave NOTHING armed.  When module_init()
 *     returns an error the kernel frees this module's memory, so anything still
 *     installed - a patched security_hook_heads slot above all - becomes a
 *     function pointer into freed memory and the next syscall goes through it.
 *     That is why the table calls the exits of the layers it already armed before
 *     failing, instead of just returning the error.
 *
 *  2. Teardown runs in the exact reverse of arming, in one place.  The order has a
 *     visible consequence: sus_path's LSM layer is what answers ENOENT for this
 *     module's own control nodes, and those nodes are world-writable (0777) by
 *     design so that DAC does not answer EACCES first (see the expose_proc note).
 *     Unhooking that layer before the nodes are removed would expose them to every
 *     process for the duration of the unload; with the order in this table the
 *     nodes are gone first, and the LSM layer goes down last.
 *
 * `fatal` marks the two layers whose absence makes the module useless or silent:
 * sus_path (a registered path would not be hidden at all) and the supercall hook
 * (no command would ever reach the module).  Everything else logs its own failure
 * and degrades to "off".
 *
 * The exits are idempotent and safe on a layer whose init never ran (each guards on
 * its own registered/armed flag), which is what lets one path be used for both the
 * failure rollback and the real unload. */
static int layer_lsm_hook_init(void)
{
    ksu_lsm_hook_init();
    return 0;
}

/* Not const: the `armed` flags live here (and the function pointers have to stay
 * valid for the whole module lifetime anyway - see the note on lsm_hook_init/exit
 * about why those two lost their __init/__exit annotations). */
static struct {
    const char *name;
    int (*init)(void);
    void (*exit)(void);
    bool fatal;
    bool armed;			/* exit is run for every layer that was attempted */
} susfs_layers[] = {
    { "lsm_hook",	layer_lsm_hook_init,		ksu_lsm_hook_exit,	false, false },
    { "sus_path",	sus_path_init,			sus_path_exit,		true,  false },
    { "uname",		susfs_uname_init,		susfs_uname_exit,	false, false },
    { "kstat",		susfs_kstat_init,		susfs_kstat_exit,	false, false },
    { "sus_map",	susfs_sus_map_init,		susfs_sus_map_exit,	false, false },
    { "sus_mount",	susfs_sus_mount_init,		susfs_sus_mount_exit,	false, false },
    { "cmdline",	susfs_spoof_cmdline_init,	susfs_spoof_cmdline_exit, false, false },
    { "open_redirect",	susfs_open_redirect_init,	susfs_open_redirect_exit, false, false },
    { "enable_log",	susfs_enable_log_init,		susfs_enable_log_exit,	false, false },
    { "avc_spoof",	susfs_avc_spoof_init,		susfs_avc_spoof_exit,	false, false },
    { "supercall",	susfs_supercall_init,		susfs_supercall_exit,	true,  false },
    { "hide_syms",	susfs_hide_syms_init,		susfs_hide_syms_exit,	false, false },
};

/* Diagnostic: make one layer's init fail, by 1-based index, so the rollback path
 * above can be exercised on the device instead of only being read.  Failing a
 * `fatal` layer must end the load with nothing armed; the check is that the device
 * survives it (a stale LSM slot would be used by the very next syscall) and that a
 * normal load still works afterwards. */
static int fail_layer;
module_param_named(fail_layer, fail_layer, int, 0644);

/* Not __init/__exit on purpose: it is called from both, and calling an __exit
 * function from __init code is what modpost reports as a section mismatch. */
static void susfs_layers_down(int upto)
{
    int i;

    for (i = upto; i >= 0; i--) {
        if (!susfs_layers[i].armed)
            continue;
        susfs_layers[i].armed = false;
        if (susfs_layers[i].exit)
            susfs_layers[i].exit();
    }
}

static int __init susfs_init(void)
{
    int i;

    SUSFS_LOGI("init v%s\n", SUSFS_LKM_VERSION);
    ksu_init_symbol_resolver();

    for (i = 0; i < (int)ARRAY_SIZE(susfs_layers); i++) {
        int ret;

        /* Marked before the call: a layer that half-ran still has to be taken down
         * (sus_path frees its scratch buffer there, for instance). */
        susfs_layers[i].armed = true;

        if (fail_layer == i + 1) {
            pr_warn("susfs_guard_lkm: fail_layer=%d - forcing %s's init to fail (diagnostic)\n",
                    fail_layer, susfs_layers[i].name);
            ret = -EIO;
        } else {
            ret = susfs_layers[i].init ? susfs_layers[i].init() : 0;
        }

        if (!ret)
            continue;

        if (susfs_layers[i].fatal) {
            pr_err("susfs_guard_lkm: %s init failed %d, refusing to load\n",
                   susfs_layers[i].name, ret);
            /* Everything armed so far goes back down: the kernel is about to free
             * this module's memory, and a hook left behind would point into it. */
            susfs_layers_down(i);
            return ret;
        }
        pr_warn("susfs_guard_lkm: %s init failed %d - that feature stays off\n",
                susfs_layers[i].name, ret);
    }

    /* Registered last and undone implicitly: these are entries in sus_path's table,
     * which sus_path_exit() empties - and it runs last, while its LSM layer is still
     * answering ENOENT for the nodes. */
    susfs_self_hide_nodes();

    /* Operator note, because the module hides its own traces from EVERY caller -
     * root included (a built-in SUSFS has no module entry at all, so hiding it
     * only from non-root would leave a trace upstream does not have).  The
     * consequence is that `lsmod | grep susfs` is always empty, and a second
     * `insmod` fails with -EEXIST ("File exists"), which reads like a broken
     * module.  Say where the truth is.
     *
     * THE ONE LINE THAT IGNORES THE LOG SWITCH.  Everything else the module says
     * is informational and follows enable_log (see susfs_log.h); this line is the
     * only evidence that the module came up, and it is the one thing an operator
     * greps for - so it stays unconditional, including for a load that starts
     * silent (`insmod ... enable_log=0`) and for CMD_SUSFS_ENABLE_LOG 0 later.
     * Otherwise "loaded but logging off" is indistinguishable from "not loaded".
     * Note the ordering: susfs_enable_log_init() runs above, so the parameter is
     * already parsed by the time this prints.  The prefix comes from pr_fmt
     * (susfs_log.h), so the message itself must not repeat it - it used to print
     * "susfs_guard_lkm: susfs_guard_lkm: loaded." */
    pr_info("loaded. This module is filtered out of /proc/modules for every caller including root, so `lsmod | grep susfs` stays empty - check /sys/module/%s instead (a second insmod fails with -EEXIST while it is loaded).\n",
            SUSFS_LKM_MODULE_NAME);

    return 0;
}

static void __exit susfs_exit(void)
{
    susfs_layers_down((int)ARRAY_SIZE(susfs_layers) - 1);
    SUSFS_LOGI("susfs_guard_lkm: exit\n");
}

module_init(susfs_init);
module_exit(susfs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SUSFS guard LKM (susfs_guard_lkm) v2.3.0-gki");
