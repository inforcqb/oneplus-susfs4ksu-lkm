// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kstat.c - spoof kstat fields (SUSFS SUS_KSTAT feature), LKM port.
 *
 * Interface mirrors the original SUSFS userspace commands, exposed through
 * /proc/susfs_kstat (one command per write):
 *
 *   add_sus_kstat <path>
 *       Store the CURRENT stat of <path> as the spoof target (ino/dev/times/
 *       blocks/blksize), flags = KSTAT_AUTO_SPOOF.  Use this BEFORE the path
 *       is bind-mounted / overlayed, then call update_sus_kstat afterwards.
 *
 *   add_sus_kstat_statically <path> <ino> <dev> <nlink> <size> <atime>
 *       <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec> <blocks>
 *       <blksize>
 *       Set each field explicitly; pass "default" to keep the current value
 *       (and NOT spoof that field).  Only non-default fields get their
 *       KSTAT_SPOOF_* flag set.
 *
 *   update_sus_kstat <path>
 *       Re-resolve <path> (after it was bind-mounted / overlayed) and update
 *       target_ino/target_dev only; spoofed values stay as previously added.
 *
 *   update_sus_kstat_full_clone <path>
 *       Same, plus KSTAT_SPOOF_NLINK|KSTAT_SPOOF_SIZE.
 *
 *   del <path>      remove one rule by its target pathname
 *   clear           remove all rules
 *
 * Hook strategy (LTO on this GKI inlines the newfstatat chain
 * vfs_fstatat -> vfs_statx -> vfs_getattr -> cp_new_stat, so VFS-layer
 * kprobes miss): the reliable hook is the return of __arm64_sys_newfstatat,
 * where the user statbuf is fully written.  Rewrite the requested fields
 * there via copy_to_user.  Field offsets are arm64 asm-generic struct stat.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/stat.h>
#include <linux/compat.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc */

/* KSTAT_SPOOF_* bits now live in susfs_abi.h (upstream declares them in
 * susfs.h next to struct st_susfs_sus_kstat).  KSTAT_AUTO_SPOOF* below are
 * local convenience masks for the /proc interface, not part of the supercall
 * ABI. */
#define KSTAT_AUTO_SPOOF (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV | \
	KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC | \
	KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC | \
	KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC | \
	KSTAT_SPOOF_BLKSIZE | KSTAT_SPOOF_BLOCKS)
#define KSTAT_AUTO_SPOOF_FULL_CLONE (KSTAT_AUTO_SPOOF | \
	KSTAT_SPOOF_NLINK | KSTAT_SPOOF_SIZE)

#define SUS_KSTAT_MAX 32
#define KSTAT_PATH_MAX 128

struct sus_kstat_entry {
	char target_pathname[KSTAT_PATH_MAX];
	unsigned long target_ino;
	/* dev stored ENCODED (new_encode_dev) so it matches the user statbuf
	 * st_dev field 1:1 on the tracepoint hot path. */
	dev_t target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	unsigned long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_sec;
	unsigned long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_sec;
	unsigned long spoofed_ctime_tv_nsec;
	long long spoofed_blocks;
	long spoofed_blksize;
	unsigned int flags;
};

static struct sus_kstat_entry kstat_entries[SUS_KSTAT_MAX];
static int nkstat;
static DEFINE_MUTEX(kstat_lock);

/* arm64 asm-generic struct stat offsets (native 64-bit) */
#define ST_DEV_OFF          0
#define ST_INO_OFF          8
#define ST_NLINK_OFF        20
#define ST_SIZE_OFF         48
#define ST_BLKSIZE_OFF      56
#define ST_BLOCKS_OFF       64
#define ST_ATIME_OFF        72
#define ST_ATIME_NSEC_OFF   80
#define ST_MTIME_OFF        88
#define ST_MTIME_NSEC_OFF   96
#define ST_CTIME_OFF        104
#define ST_CTIME_NSEC_OFF   112

/* arm64 compat (AArch32) struct compat_stat offsets (verified on device).
 * st_mode is compat_mode_t (u16) here, hence the tight packing. */
#define COMPAT_ST_DEV_OFF      0
#define COMPAT_ST_INO_OFF      4
#define COMPAT_ST_NLINK_OFF    10
#define COMPAT_ST_SIZE_OFF     20
#define COMPAT_ST_BLKSIZE_OFF  24
#define COMPAT_ST_BLOCKS_OFF   28
#define COMPAT_ST_ATIME_OFF    32
#define COMPAT_ST_ATIME_NSEC_OFF 36
#define COMPAT_ST_MTIME_OFF    40
#define COMPAT_ST_MTIME_NSEC_OFF 44
#define COMPAT_ST_CTIME_OFF    48
#define COMPAT_ST_CTIME_NSEC_OFF 52

/* ARM EABI syscall number for fstatat64, which compat newfstatat maps to.
 * Source: arch/arm64/include/asm/unistd32.h line 667: __NR_fstatat64 327 */
#define COMPAT_FSTATAT64_NR 327

static struct sus_kstat_entry *susfs_kstat_lookup(unsigned long ino, dev_t dev)
{
	int i;

	for (i = 0; i < nkstat; i++)
		if (kstat_entries[i].target_ino == ino &&
		    kstat_entries[i].target_dev == dev)
			return &kstat_entries[i];
	return NULL;
}

static struct sus_kstat_entry *susfs_kstat_find_by_path(const char *path)
{
	int i;

	for (i = 0; i < nkstat; i++)
		if (!strcmp(kstat_entries[i].target_pathname, path))
			return &kstat_entries[i];
	return NULL;
}

/* rewrite the requested fields of the native user statbuf */
static void susfs_kstat_spoof_statbuf(unsigned long statbuf)
{
	struct sus_kstat_entry *e;
	unsigned long ino = 0, dev = 0;
	unsigned long v;
	unsigned int v32;
	long long v64;
	long sl;

	if (copy_from_user(&ino, (void __user *)(statbuf + ST_INO_OFF), sizeof(ino)))
		return;
	if (copy_from_user(&dev, (void __user *)(statbuf + ST_DEV_OFF), sizeof(dev)))
		return;

	e = susfs_kstat_lookup(ino, dev);
	if (!e)
		return;

	if (e->flags & KSTAT_SPOOF_INO) {
		v = e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + ST_INO_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_DEV) {
		v = e->spoofed_dev;
		if (copy_to_user((void __user *)(statbuf + ST_DEV_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_NLINK) {
		v32 = e->spoofed_nlink;
		if (copy_to_user((void __user *)(statbuf + ST_NLINK_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_SIZE) {
		v64 = e->spoofed_size;
		if (copy_to_user((void __user *)(statbuf + ST_SIZE_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		v32 = (unsigned int)e->spoofed_blksize;
		if (copy_to_user((void __user *)(statbuf + ST_BLKSIZE_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLOCKS) {
		v64 = e->spoofed_blocks;
		if (copy_to_user((void __user *)(statbuf + ST_BLOCKS_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC) {
		sl = e->spoofed_atime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_ATIME_OFF), &sl, sizeof(sl)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC) {
		v = e->spoofed_atime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_ATIME_NSEC_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC) {
		sl = e->spoofed_mtime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_MTIME_OFF), &sl, sizeof(sl)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC) {
		v = e->spoofed_mtime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_MTIME_NSEC_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC) {
		sl = e->spoofed_ctime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_CTIME_OFF), &sl, sizeof(sl)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC) {
		v = e->spoofed_ctime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_CTIME_NSEC_OFF), &v, sizeof(v)))
			return;
	}
}

/* compat (32-bit) statbuf: struct compat_stat, st_ino is u32 at offset 4 */
static void susfs_kstat_spoof_compat_statbuf(unsigned long statbuf)
{
	struct sus_kstat_entry *e;
	unsigned int ino = 0, dev = 0;
	unsigned int v32;
	unsigned short v16;
	int v;

	if (copy_from_user(&ino, (void __user *)(statbuf + COMPAT_ST_INO_OFF), sizeof(ino)))
		return;
	if (copy_from_user(&dev, (void __user *)(statbuf + COMPAT_ST_DEV_OFF), sizeof(dev)))
		return;
	e = susfs_kstat_lookup(ino, dev);
	if (!e)
		return;

	if (e->flags & KSTAT_SPOOF_INO) {
		v32 = (unsigned int)e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_INO_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_DEV) {
		v32 = (unsigned int)e->spoofed_dev;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_DEV_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_NLINK) {
		v16 = (unsigned short)e->spoofed_nlink;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_NLINK_OFF), &v16, sizeof(v16)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_SIZE) {
		v = (int)e->spoofed_size;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_SIZE_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		v = (int)e->spoofed_blksize;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_BLKSIZE_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLOCKS) {
		v = (int)e->spoofed_blocks;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_BLOCKS_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC) {
		v = (int)e->spoofed_atime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_ATIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_atime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_ATIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC) {
		v = (int)e->spoofed_mtime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_MTIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_mtime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_MTIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC) {
		v = (int)e->spoofed_ctime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_CTIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_ctime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + COMPAT_ST_CTIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
}

/* sys_exit tracepoint: the user statbuf is fully written by now, and
 * syscall_get_arguments() still returns the original args (verified: args[2]
 * == statbuf), so no per-cpu state is needed. */
static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	unsigned long args[6];
	unsigned long statbuf;

	if (ret != 0)
		return;
	syscall_get_arguments(current, regs, args);
	statbuf = args[2];
	if (!statbuf)
		return;

	if (is_compat_task()) {
		if (syscall_get_nr(current, regs) != COMPAT_FSTATAT64_NR)
			return;
		susfs_kstat_spoof_compat_statbuf(statbuf);
	} else {
		if (syscall_get_nr(current, regs) != __NR_newfstatat)
			return;
		susfs_kstat_spoof_statbuf(statbuf);
	}
}

/* fallback: some paths (vfs_fstat, statx, direct callers) still reach the
 * exported vfs_getattr copy; rewrite the kernel kstat there too. */
struct vfs_getattr_args {
	const struct path *path;
	struct kstat *stat;
};

static int kr_vfs_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_getattr_args *a = (struct vfs_getattr_args *)ri->data;

	a->path = (const struct path *)regs->regs[0];
	a->stat = (struct kstat *)regs->regs[1];
	return 0;
}

static void susfs_kstat_spoof_kstat(struct inode *inode, struct kstat *stat)
{
	struct sus_kstat_entry *e;

	if (!inode || !stat)
		return;
	e = susfs_kstat_lookup(inode->i_ino, new_encode_dev(inode->i_sb->s_dev));
	if (!e)
		return;
	if (e->flags & KSTAT_SPOOF_INO)
		stat->ino = e->spoofed_ino;
	if (e->flags & KSTAT_SPOOF_DEV)
		stat->dev = new_decode_dev(e->spoofed_dev);
	if (e->flags & KSTAT_SPOOF_NLINK)
		stat->nlink = e->spoofed_nlink;
	if (e->flags & KSTAT_SPOOF_SIZE)
		stat->size = e->spoofed_size;
	if (e->flags & KSTAT_SPOOF_BLKSIZE)
		stat->blksize = e->spoofed_blksize;
	if (e->flags & KSTAT_SPOOF_BLOCKS)
		stat->blocks = e->spoofed_blocks;
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC)
		stat->atime.tv_sec = e->spoofed_atime_tv_sec;
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC)
		stat->atime.tv_nsec = e->spoofed_atime_tv_nsec;
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC)
		stat->mtime.tv_sec = e->spoofed_mtime_tv_sec;
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC)
		stat->mtime.tv_nsec = e->spoofed_mtime_tv_nsec;
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC)
		stat->ctime.tv_sec = e->spoofed_ctime_tv_sec;
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC)
		stat->ctime.tv_nsec = e->spoofed_ctime_tv_nsec;
}

static int kr_vfs_getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_getattr_args *a = (struct vfs_getattr_args *)ri->data;

	if (regs_return_value(regs) != 0)
		return 0;
	if (!a->path || !a->path->dentry || !a->stat)
		return 0;
	susfs_kstat_spoof_kstat(a->path->dentry->d_inode, a->stat);
	return 0;
}

static struct kretprobe krp_vfs_getattr = {
	.kp.symbol_name = "vfs_getattr",
	.entry_handler = kr_vfs_getattr_entry,
	.handler = kr_vfs_getattr_ret,
	.data_size = sizeof(struct vfs_getattr_args),
	.maxactive = 64,
};

/* ---- path resolution + rule management (original SUSFS semantics) ---- */

/* resolve <path> and fill the spoofed_* fields with its CURRENT stat
 * (generic_fillattr mapping from the inode fields). */
static int susfs_kstat_fill_from_path(struct sus_kstat_entry *e, const char *path)
{
	struct path p;
	struct inode *inode;
	int err;

	err = kern_path(path, 0, &p);
	if (err)
		return err;
	inode = d_backing_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}

	e->target_ino = inode->i_ino;
	e->target_dev = new_encode_dev(inode->i_sb->s_dev);
	e->spoofed_ino = inode->i_ino;
	e->spoofed_dev = new_encode_dev(inode->i_sb->s_dev);
	e->spoofed_nlink = inode->i_nlink;
	e->spoofed_size = inode->i_size;
	e->spoofed_atime_tv_sec = inode->i_atime.tv_sec;
	e->spoofed_atime_tv_nsec = inode->i_atime.tv_nsec;
	e->spoofed_mtime_tv_sec = inode->i_mtime.tv_sec;
	e->spoofed_mtime_tv_nsec = inode->i_mtime.tv_nsec;
	e->spoofed_ctime_tv_sec = inode->i_ctime.tv_sec;
	e->spoofed_ctime_tv_nsec = inode->i_ctime.tv_nsec;
	e->spoofed_blocks = inode->i_blocks;
	e->spoofed_blksize = 1 << inode->i_blkbits;

	path_put(&p);
	return 0;
}

/* re-resolve only target_ino/target_dev; spoofed values stay untouched */
static int susfs_kstat_reresolve(struct sus_kstat_entry *e)
{
	struct path p;
	struct inode *inode;
	int err;

	err = kern_path(e->target_pathname, 0, &p);
	if (err)
		return err;
	inode = d_backing_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}
	e->target_ino = inode->i_ino;
	e->target_dev = new_encode_dev(inode->i_sb->s_dev);
	path_put(&p);
	return 0;
}

static int susfs_kstat_add(const char *path)
{
	struct sus_kstat_entry *e;
	int err;

	e = susfs_kstat_find_by_path(path);
	if (!e) {
		if (nkstat >= SUS_KSTAT_MAX)
			return -ENOSPC;
		e = &kstat_entries[nkstat];
		strscpy(e->target_pathname, path, KSTAT_PATH_MAX);
		nkstat++;
	}

	err = susfs_kstat_fill_from_path(e, path);
	if (err)
		return err;
	e->flags = KSTAT_AUTO_SPOOF;
	return 0;
}

static int susfs_kstat_update(const char *path, bool full_clone)
{
	struct sus_kstat_entry *e;
	int err;

	e = susfs_kstat_find_by_path(path);
	if (!e)
		return -ENOENT;
	err = susfs_kstat_reresolve(e);
	if (err)
		return err;
	e->flags |= full_clone ? KSTAT_AUTO_SPOOF_FULL_CLONE : KSTAT_AUTO_SPOOF;
	return 0;
}

static void susfs_kstat_del(const char *path)
{
	struct sus_kstat_entry *e;
	int i;

	e = susfs_kstat_find_by_path(path);
	if (!e)
		return;
	i = (int)(e - kstat_entries);
	kstat_entries[i] = kstat_entries[--nkstat];
}

/* parse "default" -> *is_default=true, else parse signed 64-bit int */
static int parse_override(const char *tok, bool *is_default, long long *val)
{
	if (!strcmp(tok, "default")) {
		*is_default = true;
		return 0;
	}
	*is_default = false;
	return kstrtoll(tok, 10, val);
}

/* add_sus_kstat_statically: 12 fields follow the path, each number or
 * "default". */
static int susfs_kstat_add_statically(char **argv, int argc)
{
	struct sus_kstat_entry *e;
	long long val;
	bool dflt;
	int err, i;
	/* field index -> flag and setter, ordered as the CLI:
	 * ino dev nlink size atime atime_nsec mtime mtime_nsec
	 * ctime ctime_nsec blocks blksize */
	static const unsigned int f_flags[12] = {
		KSTAT_SPOOF_INO, KSTAT_SPOOF_DEV, KSTAT_SPOOF_NLINK,
		KSTAT_SPOOF_SIZE, KSTAT_SPOOF_ATIME_TV_SEC,
		KSTAT_SPOOF_ATIME_TV_NSEC, KSTAT_SPOOF_MTIME_TV_SEC,
		KSTAT_SPOOF_MTIME_TV_NSEC, KSTAT_SPOOF_CTIME_TV_SEC,
		KSTAT_SPOOF_CTIME_TV_NSEC, KSTAT_SPOOF_BLOCKS,
		KSTAT_SPOOF_BLKSIZE,
	};
	const char *path = argv[1];

	e = susfs_kstat_find_by_path(path);
	if (!e) {
		if (nkstat >= SUS_KSTAT_MAX)
			return -ENOSPC;
		e = &kstat_entries[nkstat];
		strscpy(e->target_pathname, path, KSTAT_PATH_MAX);
		nkstat++;
	}

	/* start from the CURRENT stat; non-default fields override it */
	err = susfs_kstat_fill_from_path(e, path);
	if (err)
		return err;
	e->flags = 0;

	for (i = 0; i < 12; i++) {
		err = parse_override(argv[2 + i], &dflt, &val);
		if (err)
			return err;
		if (dflt)
			continue;
		e->flags |= f_flags[i];
		switch (i) {
		case 0: e->spoofed_ino = (unsigned long)val; break;
		case 1: e->spoofed_dev = (unsigned long)val; break;
		case 2: e->spoofed_nlink = (unsigned int)val; break;
		case 3: e->spoofed_size = val; break;
		case 4: e->spoofed_atime_tv_sec = (long)val; break;
		case 5: e->spoofed_atime_tv_nsec = (unsigned long)val; break;
		case 6: e->spoofed_mtime_tv_sec = (long)val; break;
		case 7: e->spoofed_mtime_tv_nsec = (unsigned long)val; break;
		case 8: e->spoofed_ctime_tv_sec = (long)val; break;
		case 9: e->spoofed_ctime_tv_nsec = (unsigned long)val; break;
		case 10: e->spoofed_blocks = val; break;
		case 11: e->spoofed_blksize = (long)val; break;
		}
	}
	return 0;
}

/* statically-add from the supercall ABI struct (is_statically=1): copy the
 * caller's 12 spoofed fields + flags verbatim; resolve target ino/dev here. */
static int susfs_kstat_add_statically_abi(struct st_susfs_sus_kstat *info)
{
	struct sus_kstat_entry *e;
	int err;

	e = susfs_kstat_find_by_path(info->target_pathname);
	if (!e) {
		if (nkstat >= SUS_KSTAT_MAX)
			return -ENOSPC;
		e = &kstat_entries[nkstat];
		strscpy(e->target_pathname, info->target_pathname,
			KSTAT_PATH_MAX);
		nkstat++;
	}

	err = susfs_kstat_fill_from_path(e, info->target_pathname);
	if (err)
		return err;

	e->spoofed_ino = info->spoofed_ino;
	e->spoofed_dev = info->spoofed_dev;
	e->spoofed_nlink = info->spoofed_nlink;
	e->spoofed_size = info->spoofed_size;
	e->spoofed_atime_tv_sec = info->spoofed_atime_tv_sec;
	e->spoofed_atime_tv_nsec = info->spoofed_atime_tv_nsec;
	e->spoofed_mtime_tv_sec = info->spoofed_mtime_tv_sec;
	e->spoofed_mtime_tv_nsec = info->spoofed_mtime_tv_nsec;
	e->spoofed_ctime_tv_sec = info->spoofed_ctime_tv_sec;
	e->spoofed_ctime_tv_nsec = info->spoofed_ctime_tv_nsec;
	e->spoofed_blocks = info->spoofed_blocks;
	e->spoofed_blksize = info->spoofed_blksize;
	e->flags = info->flags;
	return 0;
}

/* supercall: CMD_SUSFS_ADD_SUS_KSTAT / UPDATE / STATICALLY */
void susfs_kstat_supercall(unsigned int cmd, void __user **arg)
{
	struct st_susfs_sus_kstat info = {0};
	int err = -EINVAL;

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	mutex_lock(&kstat_lock);
	switch (cmd) {
	case CMD_SUSFS_ADD_SUS_KSTAT:
		err = susfs_kstat_add(info.target_pathname);
		break;
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		err = susfs_kstat_add_statically_abi(&info);
		break;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		err = susfs_kstat_update(info.target_pathname, false);
		break;
	}
	mutex_unlock(&kstat_lock);
	info.err = err;
out:
	/* Upstream (fs/susfs.c susfs_add_sus_kstat) writes back ONLY the err
	 * field for this input-type command, never the whole struct.  Copying
	 * the full struct back would overrun a caller whose own struct is
	 * smaller/differently laid out (the prebuilt ksu_susfs tool), corrupting
	 * its stack — match upstream exactly. */
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("kstat supercall copy_to_user failed\n");
}

/* ---- /proc/susfs_kstat: runtime rule management ---- */
static int kstat_proc_show(struct seq_file *m, void *v);
static int kstat_proc_open(struct inode *inode, struct file *file);
static ssize_t kstat_proc_write(struct file *file, const char __user *buf,
                                size_t len, loff_t *off);

static const struct proc_ops kstat_proc_ops = {
	.proc_open = kstat_proc_open,
	.proc_read = seq_read,
	.proc_write = kstat_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *kstat_proc_entry;

static bool kstat_tp_registered;
static bool kstat_krp_registered;

int susfs_kstat_init(void)
{
	int rc;

	/* Not created unless asked for: see susfs_expose_proc. */
	if (!susfs_expose_proc) {
		pr_info("susfs_kstat: /proc node disabled (expose_proc=0)\n");
		return 0;
	}

	/* 0600, not 0666: the listing exposes configured rules and the switch
	 * turns spoofing off - it must not be readable or writable by an app. */
	kstat_proc_entry = proc_create("susfs_kstat", 0600, NULL, &kstat_proc_ops);
	if (!kstat_proc_entry)
		pr_warn("proc_create(susfs_kstat) failed\n");

	rc = register_trace_sys_exit(kstat_sys_exit, NULL);
	if (rc)
		pr_warn("register_trace_sys_exit failed %d\n", rc);
	else
		kstat_tp_registered = true;

	rc = register_kretprobe(&krp_vfs_getattr);
	if (rc)
		pr_warn("register_kretprobe(vfs_getattr) failed %d\n", rc);
	else
		kstat_krp_registered = true;

	pr_info("kstat armed: %d rules (proc: /proc/susfs_kstat)\n", nkstat);
	return 0;
}

void susfs_kstat_exit(void)
{
	if (kstat_krp_registered) {
		unregister_kretprobe(&krp_vfs_getattr);
		kstat_krp_registered = false;
	}
	if (kstat_tp_registered) {
		unregister_trace_sys_exit(kstat_sys_exit, NULL);
		tracepoint_synchronize_unregister();
		kstat_tp_registered = false;
	}
	if (kstat_proc_entry) {
		proc_remove(kstat_proc_entry);
		kstat_proc_entry = NULL;
	}
	nkstat = 0;
}

static int kstat_proc_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&kstat_lock);
	if (nkstat == 0) {
		seq_puts(m, "(empty)\n");
	} else {
		for (i = 0; i < nkstat; i++) {
			struct sus_kstat_entry *e = &kstat_entries[i];

			seq_printf(m,
				"%s ino=%lu dev=%lu flags=0x%x"
				" [ino=%lu dev=%lu nlink=%u size=%lld"
				" atime=%ld.%lu mtime=%ld.%lu ctime=%ld.%lu"
				" blocks=%lld blksize=%ld]\n",
				e->target_pathname, e->target_ino,
				(unsigned long)e->target_dev, e->flags,
				e->spoofed_ino, e->spoofed_dev, e->spoofed_nlink,
				e->spoofed_size,
				e->spoofed_atime_tv_sec, e->spoofed_atime_tv_nsec,
				e->spoofed_mtime_tv_sec, e->spoofed_mtime_tv_nsec,
				e->spoofed_ctime_tv_sec, e->spoofed_ctime_tv_nsec,
				e->spoofed_blocks, e->spoofed_blksize);
		}
	}
	mutex_unlock(&kstat_lock);
	return 0;
}

static int kstat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kstat_proc_show, NULL);
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

static ssize_t kstat_proc_write(struct file *file, const char __user *buf,
                                size_t len, loff_t *off)
{
	char cmd[768];
	char *argv[16];
	int argc, err;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;

	argc = split_ws(cmd, argv, 16);
	if (argc == 0)
		return len;

	mutex_lock(&kstat_lock);
	err = -EINVAL;

	if (!strcmp(argv[0], "add_sus_kstat") && argc == 2)
		err = susfs_kstat_add(argv[1]);
	else if (!strcmp(argv[0], "add_sus_kstat_statically") && argc == 14)
		err = susfs_kstat_add_statically(argv, argc);
	else if (!strcmp(argv[0], "update_sus_kstat") && argc == 2)
		err = susfs_kstat_update(argv[1], false);
	else if (!strcmp(argv[0], "update_sus_kstat_full_clone") && argc == 2)
		err = susfs_kstat_update(argv[1], true);
	else if (!strcmp(argv[0], "del") && argc == 2) {
		susfs_kstat_del(argv[1]);
		err = 0;
	} else if (!strcmp(argv[0], "clear")) {
		nkstat = 0;
		err = 0;
	}

	mutex_unlock(&kstat_lock);

	if (err)
		pr_warn("kstat proc write '%s' -> err %d\n", argv[0], err);
	return len;
}
