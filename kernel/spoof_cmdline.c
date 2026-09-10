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
#include "susfs.h"	/* susfs_abi_path_ok */

/* unexported static var; ksud insmod relocates it via kallsyms */
extern char *saved_boot_config;

static char param_bootconfig[256];
module_param_string(bootconfig, param_bootconfig, sizeof(param_bootconfig), 0644);

static char *orig_boot_config;
static char *fake_boot_config;   /* heap-allocated, currently published */
static bool spoof_active;

/* Strings that saved_boot_config used to point at.
 *
 * A published string must NEVER be freed while saved_boot_config might reach
 * it: /proc/bootconfig is read via seq_puts with no lock of ours, so freeing
 * the old buffer before republishing let a reader touch freed memory.  The old
 * code also returned early when kstrdup failed, leaving saved_boot_config
 * dangling at the buffer it had just freed - and the next set() would free it
 * again.  Retiring instead costs one 8 KB string per update. */
struct retired_str {
	struct list_head list;
	char *s;
};

static LIST_HEAD(retired_strs);

static void spoof_retire(char *s)
{
	struct retired_str *r;

	if (!s)
		return;
	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return;		/* leak rather than free: never free a published string */
	r->s = s;
	list_add_tail(&r->list, &retired_strs);
}

/* Allocate first, publish second.  Returns 0 or a negative errno. */
static int spoof_set(const char *fake)
{
	char *dup;

	dup = kstrdup(fake, GFP_KERNEL);
	if (!dup)
		return -ENOMEM;

	if (!spoof_active)
		orig_boot_config = saved_boot_config;
	else
		spoof_retire(fake_boot_config);

	fake_boot_config = dup;
	saved_boot_config = dup;
	spoof_active = true;
	return 0;
}

int susfs_spoof_cmdline_init(void)
{
	int rc;

	if (!param_bootconfig[0]) {
		pr_info("spoof_cmdline: no fake bootconfig, not armed\n");
		return 0;
	}
	rc = spoof_set(param_bootconfig);
	if (rc) {
		pr_err("spoof_cmdline: set failed %d, not armed\n", rc);
		return rc;
	}
	pr_info("spoof_cmdline armed: %s\n", param_bootconfig);
	return 0;
}

void susfs_spoof_cmdline_exit(void)
{
	struct retired_str *r, *tmp;

	/* Unpublish before freeing anything. */
	if (spoof_active) {
		saved_boot_config = orig_boot_config;
		spoof_active = false;
		orig_boot_config = NULL;
	}
	kfree(fake_boot_config);
	fake_boot_config = NULL;

	list_for_each_entry_safe(r, tmp, &retired_strs, list) {
		list_del(&r->list);
		kfree(r->s);
		kfree(r);
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

	/* Empty string is rejected upstream (-EINVAL); report the real result of
	 * the update instead of always claiming success. */
	if (!info->fake_cmdline_or_bootconfig[0]) {
		info->err = -EINVAL;
		goto out;
	}
	/* spoof_set() kstrdup()s this, i.e. strlen()s it: an unterminated
	 * fixed-size ABI field would be read past the end of the allocation. */
	if (!susfs_abi_path_ok(info->fake_cmdline_or_bootconfig,
			       sizeof(info->fake_cmdline_or_bootconfig))) {
		info->err = -ENAMETOOLONG;
		goto out;
	}

	info->err = spoof_set(info->fake_cmdline_or_bootconfig);
	if (!info->err)
		pr_info("spoof_cmdline: set fake bootconfig (supercall)\n");
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*arg)->err,
			 &info->err, sizeof(info->err)))
		pr_warn("cmdline supercall copy_to_user failed\n");
	kfree(info);
}
