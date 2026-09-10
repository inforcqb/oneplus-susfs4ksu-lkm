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
 *
 * The fake string is heap-allocated (kstrdup) because the supercall ABI
 * accepts up to 8192 bytes; the insmod param bootconfig= takes precedence and
 * is also copied to the heap so a later supercall can kfree it safely.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "susfs_abi.h"
#include "susfs_log.h"

/* unexported static var; ksud insmod relocates it via kallsyms */
extern char *saved_boot_config;

static char param_bootconfig[256];
module_param_string(bootconfig, param_bootconfig, sizeof(param_bootconfig), 0644);

static char *orig_boot_config;
static char *fake_boot_config;   /* heap-allocated */
static bool spoof_active;

static void spoof_set(const char *fake)
{
	char *dup;

	if (spoof_active)
		kfree(fake_boot_config);
	else
		orig_boot_config = saved_boot_config;

	dup = kstrdup(fake, GFP_KERNEL);
	if (!dup)
		return;
	fake_boot_config = dup;
	saved_boot_config = dup;
	spoof_active = true;
}

int susfs_spoof_cmdline_init(void)
{
	if (!param_bootconfig[0]) {
		pr_info("spoof_cmdline: no fake bootconfig, not armed\n");
		return 0;
	}
	spoof_set(param_bootconfig);
	pr_info("spoof_cmdline armed: %s\n", param_bootconfig);
	return 0;
}

void susfs_spoof_cmdline_exit(void)
{
	if (spoof_active) {
		saved_boot_config = orig_boot_config;
		kfree(fake_boot_config);
		fake_boot_config = NULL;
		spoof_active = false;
	}
}

/* supercall: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG */
void susfs_spoof_cmdline_supercall(void __user **arg)
{
	struct st_susfs_spoof_cmdline_or_bootconfig *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return;

	if (copy_from_user(info, (void __user *)*arg, sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	spoof_set(info->fake_cmdline_or_bootconfig);
	info->err = 0;
	pr_info("spoof_cmdline: set fake bootconfig (supercall)\n");
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*arg)->err,
			 &info->err, sizeof(info->err)))
		pr_warn("cmdline supercall copy_to_user failed\n");
	kfree(info);
}
