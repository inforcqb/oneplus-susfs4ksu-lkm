// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_open_redirect.c - redirect open of a target path to another path
 * (SUSFS OPEN_REDIRECT feature), LKM port.
 *
 * Upstream SUSFS hooks path_openat() and, once the target inode is resolved,
 * swaps the filename for the redirected pathname via getname_kernel() and
 * re-walks the path.  path_openat is static and inlined into do_filp_open on
 * this LTO GKI, so an LKM cannot kprobe it.
 *
 * Instead we kprobe do_filp_open(dfd, pathname, op): pathname->name is a
 * kernel-side writable buffer (struct filename.iname[], EMBEDDED_NAME_MAX
 * ~= 4064 bytes), far larger than the 128-byte path limit.  On a match we
 * strcpy() the redirected pathname over pathname->name in place.  No
 * getname_kernel()/putname() juggling, no kretprobe, no lifetime hazards.
 *
 * Interface mirrors upstream: /proc/susfs_open_redirect
 *   add_open_redirect <target> <redirected> <uid_scheme>
 *   del <target>
 *   clear
 *
 * uid_scheme: 0 = non-app proc (uid % 100000 < 10000).  Schemes 1..4 depend
 * on KernelSU-internal su-domain/umount state that an LKM cannot see; they
 * are rejected with -EOPNOTSUPP for now.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "susfs_log.h"

#define SUS_OR_MAX 64
#define SUSFS_MAX_LEN_PATHNAME 128

enum uid_scheme {
	UID_NON_APP_PROC = 0,
	UID_ROOT_PROC_EXCEPT_SU_PROC,
	UID_NON_SU_PROC,
	UID_UMOUNTED_APP_PROC,
	UID_UMOUNTED_PROC,
};

struct sus_or_entry {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int uid_scheme;
};

static struct sus_or_entry or_entries[SUS_OR_MAX];
static int nor;
static DEFINE_MUTEX(or_lock);

static bool or_uid_matches(int scheme)
{
	switch (scheme) {
	case UID_NON_APP_PROC:
		return current_uid().val % 100000 < 10000;
	default:
		/* 1..4 need su-domain / umount state unavailable to an LKM */
		return false;
	}
}

static struct sus_or_entry *or_find(const char *target)
{
	int i;

	for (i = 0; i < nor; i++)
		if (!strcmp(or_entries[i].target_pathname, target))
			return &or_entries[i];
	return NULL;
}

/* do_filp_open(dfd, pathname, op): pathname is arg #2 (regs->regs[1]) */
static int or_do_filp_open_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct filename *pathname = (struct filename *)regs->regs[1];
	const char *name;
	int i;

	if (!pathname || IS_ERR(pathname) || !pathname->name)
		return 0;
	name = pathname->name;
	if (!*name)
		return 0;

	/* read-mostly: rules are mutated under or_lock, but a torn read here
	 * only affects a single open, never kernel safety. */
	for (i = 0; i < nor; i++) {
		struct sus_or_entry *e = &or_entries[i];

		if (strcmp(name, e->target_pathname))
			continue;
		if (!or_uid_matches(e->uid_scheme))
			continue;
		strcpy((char *)pathname->name, e->redirected_pathname);
		break;
	}
	return 0;
}

static struct kprobe kp_or = {
	.symbol_name = "do_filp_open",
	.pre_handler = or_do_filp_open_pre,
};

static bool or_registered;

static int or_register(void)
{
	int rc;

	if (or_registered)
		return 0;
	rc = register_kprobe(&kp_or);
	if (rc)
		return rc;
	or_registered = true;
	pr_info("susfs_open_redirect: hook installed\n");
	return 0;
}

static void or_unregister(void)
{
	if (!or_registered)
		return;
	unregister_kprobe(&kp_or);
	or_registered = false;
	pr_info("susfs_open_redirect: hook removed\n");
}

/* ---- /proc/susfs_open_redirect ---- */
static int or_proc_show(struct seq_file *m, void *v);
static int or_proc_open(struct inode *inode, struct file *file);
static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off);

static const struct proc_ops or_proc_ops = {
	.proc_open = or_proc_open,
	.proc_read = seq_read,
	.proc_write = or_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *or_proc_entry;

int susfs_open_redirect_init(void)
{
	or_proc_entry = proc_create("susfs_open_redirect", 0666, NULL, &or_proc_ops);
	if (!or_proc_entry)
		pr_warn("proc_create(susfs_open_redirect) failed\n");

	/* hook installed lazily on first rule */
	pr_info("susfs_open_redirect: %d rules (proc: /proc/susfs_open_redirect)\n", nor);
	return 0;
}

void susfs_open_redirect_exit(void)
{
	or_unregister();
	if (or_proc_entry) {
		proc_remove(or_proc_entry);
		or_proc_entry = NULL;
	}
	nor = 0;
}

static int or_proc_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&or_lock);
	if (nor == 0) {
		seq_puts(m, "(empty)\n");
	} else {
		for (i = 0; i < nor; i++)
			seq_printf(m, "%s -> %s uid=%d\n",
				   or_entries[i].target_pathname,
				   or_entries[i].redirected_pathname,
				   or_entries[i].uid_scheme);
	}
	mutex_unlock(&or_lock);
	return 0;
}

static int or_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, or_proc_show, NULL);
}

static int split_ws(char *buf, char **argv, int max)
{
	int argc = 0;
	char *p = buf;

	while (argc < max) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p)
			*p++ = '\0';
	}
	return argc;
}

static int or_add(const char *target, const char *redirected, int scheme)
{
	struct sus_or_entry *e;
	int rc;

	if (scheme < UID_NON_APP_PROC || scheme > UID_UMOUNTED_PROC)
		return -EINVAL;
	if (scheme != UID_NON_APP_PROC)
		return -EOPNOTSUPP;

	e = or_find(target);
	if (!e) {
		if (nor >= SUS_OR_MAX)
			return -ENOSPC;
		e = &or_entries[nor];
		strscpy(e->target_pathname, target, SUSFS_MAX_LEN_PATHNAME);
		nor++;
	}
	strscpy(e->redirected_pathname, redirected, SUSFS_MAX_LEN_PATHNAME);
	e->uid_scheme = scheme;

	/* lazy-register the hook now that we have at least one rule */
	rc = or_register();
	if (rc)
		return rc;
	return 0;
}

static void or_del(const char *target)
{
	struct sus_or_entry *e;
	int i;

	e = or_find(target);
	if (!e)
		return;
	i = (int)(e - or_entries);
	or_entries[i] = or_entries[--nor];
	if (nor == 0)
		or_unregister();
}

static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off)
{
	char cmd[640];
	char *argv[8];
	int argc, err;
	long scheme;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;

	argc = split_ws(cmd, argv, 8);
	if (argc == 0)
		return len;

	mutex_lock(&or_lock);
	err = -EINVAL;

	if (!strcmp(argv[0], "add_open_redirect") && argc == 4) {
		if (kstrtol(argv[3], 10, &scheme)) {
			err = -EINVAL;
		} else {
			err = or_add(argv[1], argv[2], (int)scheme);
		}
	} else if (!strcmp(argv[0], "del") && argc == 2) {
		or_del(argv[1]);
		err = 0;
	} else if (!strcmp(argv[0], "clear")) {
		nor = 0;
		or_unregister();
		err = 0;
	}

	mutex_unlock(&or_lock);

	if (err)
		pr_warn("open_redirect proc write '%s' -> err %d\n", argv[0], err);
	return len;
}
