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

/* The supercall's field is SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE (8192) wide, but
 * this insmod parameter cannot be that large: module_param_string()'s value is
 * written through a sysfs attribute, and a sysfs write is capped at one page.  So
 * the parameter tops out at 4095 bytes where the supercall accepts 8191 - a
 * difference worth knowing before setting a long bootconfig at load time. */
static char param_bootconfig[4096];
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
	/* Unpublish - and deliberately free nothing.
	 *
	 * /proc/bootconfig is read through seq_puts() with no lock of ours, so a
	 * reader that already picked up the pointer can still be printing it while
	 * this runs.  The retired list exists for exactly that reason, and unload is
	 * not an exception: the module's own memory is going away anyway, so the
	 * only thing a kfree() here could buy is a use-after-free. */
	if (spoof_active) {
		saved_boot_config = orig_boot_config;
		spoof_active = false;
		orig_boot_config = NULL;
	}
	fake_boot_config = NULL;
}

/* supercall: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG */
void susfs_spoof_cmdline_supercall(void __user **arg)
{
	struct st_susfs_spoof_cmdline_or_bootconfig *info;
	int err;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		/* The kprobe has already claimed the syscall and answered 0, so
		 * returning silently leaves the caller's pre-seeded 126
		 * (ERR_CMD_NOT_SUPPORTED) in place: the C tool then reports "please
		 * enable SUSFS in kernel" for a command this kernel implements, and
		 * ksud's err==126 check turns it into a silent success.  Upstream
		 * writes -ENOMEM here (fs/susfs.c:707-713); this runs in task_work
		 * context, so the writeback is safe. */
		err = -ENOMEM;
		if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user *)*arg)->err,
				 &err, sizeof(err)))
			pr_warn("cmdline supercall copy_to_user failed\n");
		pr_warn_ratelimited("spoof_cmdline: kzalloc failed, reported -ENOMEM\n");
		return;
	}

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
