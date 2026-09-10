// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_enable_log.c - toggle SUSFS debug logging (ENABLE_LOG feature).
 *
 * Upstream SUSFS gates its SUSFS_LOGI() debug output behind a static branch
 * (susfs_is_log_enabled), toggled by CMD_SUSFS_ENABLE_LOG.  An LKM has no
 * static branch, so we expose the same semantics through a global flag and a
 * /proc/susfs_enable_log interface: write "1"/"0" to enable/disable, read to
 * query.  Feature hit-path logs should check susfs_log_enabled() to stay
 * silent by default.
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "susfs_abi.h"
#include "susfs_log.h"

static bool log_enabled;

bool susfs_log_enabled(void)
{
	return READ_ONCE(log_enabled);
}
EXPORT_SYMBOL(susfs_log_enabled);

static int log_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", log_enabled ? 1 : 0);
	return 0;
}

static int log_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, log_proc_show, NULL);
}

static ssize_t log_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	char c;

	if (copy_from_user(&c, buf, 1))
		return -EFAULT;

	if (c == '1')
		WRITE_ONCE(log_enabled, true);
	else if (c == '0')
		WRITE_ONCE(log_enabled, false);

	pr_info("susfs: %s logging to kernel\n", log_enabled ? "enable" : "disable");
	return len;
}

static const struct proc_ops log_proc_ops = {
	.proc_open = log_proc_open,
	.proc_read = seq_read,
	.proc_write = log_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *log_proc_entry;

int susfs_enable_log_init(void)
{
	/* Not created unless asked for: see susfs_expose_proc. */
	if (!susfs_expose_proc) {
		pr_info("susfs_enable_log: /proc node disabled (expose_proc=0)\n");
		return 0;
	}

	/* 0600: an app must not be able to turn logging on/off. */
	log_proc_entry = proc_create("susfs_enable_log", 0600, NULL, &log_proc_ops);
	if (!log_proc_entry)
		pr_warn("proc_create(susfs_enable_log) failed\n");
	else
		pr_info("susfs_enable_log: armed (proc: /proc/susfs_enable_log)\n");
	return 0;
}

void susfs_enable_log_exit(void)
{
	if (log_proc_entry) {
		proc_remove(log_proc_entry);
		log_proc_entry = NULL;
	}
	log_enabled = false;
}

/* supercall: CMD_SUSFS_ENABLE_LOG */
void susfs_enable_log_supercall(void __user **arg)
{
    struct st_susfs_log info = {0};

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }
    WRITE_ONCE(log_enabled, info.enabled);
    info.err = 0;
    pr_info("susfs: %s logging to kernel (supercall)\n",
            log_enabled ? "enable" : "disable");
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_log __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("enable_log supercall copy_to_user failed\n");
}
