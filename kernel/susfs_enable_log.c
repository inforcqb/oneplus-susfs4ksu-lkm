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
#include <linux/cred.h>	/* current_uid(), control-node gate */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc */

static bool log_enabled;

bool susfs_log_enabled(void)
{
	return READ_ONCE(log_enabled);
}
/* Deliberately NOT EXPORT_SYMBOL'd: the only user is this module (susfs_log.h
 * wraps it), and an exported name shows up as a [susfs_guard_lkm]-owned symbol in
 * /proc/kallsyms - part of the module's outward surface that upstream SUSFS does
 * not have. */

static int log_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", log_enabled ? 1 : 0);
	return 0;
}

static int log_proc_open(struct inode *inode, struct file *file)
{
	/* The node is created 0777 on purpose: the ENOENT contract for non-root
	 * callers is delivered by sus_path's hidden set, and a restrictive mode
	 * would answer EACCES instead - which leaks that the node exists.  That
	 * makes sus_path's hook the only thing between an app and this interface,
	 * so the handler refuses non-root callers itself as well.  ENOENT keeps the
	 * same answer the hidden set gives, and costs nothing for the intended
	 * caller (ksu_susfs runs as root). */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, log_proc_show, NULL);
}

static ssize_t log_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	char c;

	/* Same reason as the open check: an fd opened before the process dropped
	 * privileges must not become a way in. */
	if (current_uid().val != 0)
		return -ENOENT;

	if (copy_from_user(&c, buf, 1))
		return -EFAULT;

	/* Only '0' and '1' are the protocol.  The old code accepted every other
	 * byte, still reported len, and toggled nothing - a typo was
	 * indistinguishable from success. */
	if (c != '0' && c != '1')
		return -EINVAL;

	if (c == '1')
		WRITE_ONCE(log_enabled, true);
	else
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
	/* Nothing to register here - logging is toggled over the supercall or by
	 * this node - so the node is the only thing to gate.  See
	 * susfs_control_node_allowed(): 0777 so DAC passes and sus_path's LSM
	 * layer gets to answer ENOENT. */
	if (susfs_control_node_allowed()) {
		log_proc_entry = proc_create("susfs_enable_log", 0777, NULL,
					     &log_proc_ops);
		if (!log_proc_entry)
			pr_warn("proc_create(susfs_enable_log) failed\n");
		else
			pr_info("susfs_enable_log: armed (proc: /proc/susfs_enable_log)\n");
	} else {
		pr_info("susfs_enable_log: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}
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
