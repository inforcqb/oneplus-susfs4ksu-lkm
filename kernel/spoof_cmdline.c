// SPDX-License-Identifier: GPL-2.0
/*
 * spoof_cmdline.c - spoof /proc/bootconfig (SUSFS SPOOF_CMDLINE_OR_BOOTCONFIG).
 *
 * boot_config_proc_show() (fs/proc/bootconfig.c) simply does
 *   if (saved_boot_config) seq_puts(m, saved_boot_config);
 * so rewriting the static char *saved_boot_config pointer is enough to spoof
 * the whole file.  saved_boot_config is a static BSS variable, resolved at
 * load time by ksud insmod (kallsyms relocation), like selinux_state in kstat.
 * A pointer write is atomic, so this is safe against concurrent seq reads.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include "susfs_log.h"

/* unexported static var; ksud insmod relocates it via kallsyms */
extern char *saved_boot_config;

static char fake_bootconfig[256];
module_param_string(bootconfig, fake_bootconfig, sizeof(fake_bootconfig), 0644);

static char *orig_boot_config;
static bool spoof_active;

int susfs_spoof_cmdline_init(void)
{
    if (!fake_bootconfig[0]) {
        pr_info("spoof_cmdline: no fake bootconfig, not armed\n");
        return 0;
    }

    orig_boot_config = saved_boot_config;
    saved_boot_config = fake_bootconfig;
    spoof_active = true;
    pr_info("spoof_cmdline armed: %s\n", fake_bootconfig);
    return 0;
}

void susfs_spoof_cmdline_exit(void)
{
    if (spoof_active) {
        saved_boot_config = orig_boot_config;
        spoof_active = false;
    }
}
