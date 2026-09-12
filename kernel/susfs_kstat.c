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
#include <linux/string.h>
#include <linux/cred.h>
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
/* Upstream's st_susfs_sus_kstat.target_pathname is char[256]; match it, or a
 * legal long path is either truncated (wrong rule) or rejected (fidelity gap). */
#define KSTAT_PATH_MAX 256

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

/* Table locking, in two tiers.
 *
 * kstat_lock (mutex) serialises WRITERS and the /proc read, because writers
 * resolve paths and that sleeps.
 *
 * kstat_table_lock (spinlock) guards the table itself for the READERS, which
 * run on hot paths - the sys_exit tracepoint and the vfs_getattr kretprobe -
 * where sleeping is impossible and kstat_lock therefore cannot be taken.  A
 * reader holds it only long enough to copy the matching entry out; it must
 * never copy_to_user under it.
 *
 * Rule: resolve first (sleeping, outside), then swap (non-sleeping, inside).
 * Publishing a slot before it is fully filled is a bug - an empty slot used to
 * be visible as soon as nkstat was bumped, before kern_path() had even run. */
static DEFINE_SPINLOCK(kstat_table_lock);

/* The part of an entry a reader needs, copied out under kstat_table_lock. */
struct sus_kstat_snapshot {
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

static void kstat_snapshot(const struct sus_kstat_entry *e,
			   struct sus_kstat_snapshot *s)
{
	s->spoofed_ino = e->spoofed_ino;
	s->spoofed_dev = e->spoofed_dev;
	s->spoofed_nlink = e->spoofed_nlink;
	s->spoofed_size = e->spoofed_size;
	s->spoofed_atime_tv_sec = e->spoofed_atime_tv_sec;
	s->spoofed_atime_tv_nsec = e->spoofed_atime_tv_nsec;
	s->spoofed_mtime_tv_sec = e->spoofed_mtime_tv_sec;
	s->spoofed_mtime_tv_nsec = e->spoofed_mtime_tv_nsec;
	s->spoofed_ctime_tv_sec = e->spoofed_ctime_tv_sec;
	s->spoofed_ctime_tv_nsec = e->spoofed_ctime_tv_nsec;
	s->spoofed_blocks = e->spoofed_blocks;
	s->spoofed_blksize = e->spoofed_blksize;
	s->flags = e->flags;
}

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

/* The numbers above are a uapi contract, so they can be checked at build time
 * instead of trusted: arm64 uses the generic layout (__ARCH_WANT_NEW_STAT), and
 * a DDK header change that moved a member would otherwise corrupt the caller's
 * stat buffer instead of failing this build. */
static_assert(offsetof(struct stat, st_dev) == ST_DEV_OFF, "stat.st_dev");
static_assert(offsetof(struct stat, st_ino) == ST_INO_OFF, "stat.st_ino");
static_assert(offsetof(struct stat, st_nlink) == ST_NLINK_OFF, "stat.st_nlink");
static_assert(offsetof(struct stat, st_size) == ST_SIZE_OFF, "stat.st_size");
static_assert(offsetof(struct stat, st_blksize) == ST_BLKSIZE_OFF, "stat.st_blksize");
static_assert(offsetof(struct stat, st_blocks) == ST_BLOCKS_OFF, "stat.st_blocks");
static_assert(offsetof(struct stat, st_atime) == ST_ATIME_OFF, "stat.st_atime");
static_assert(offsetof(struct stat, st_mtime) == ST_MTIME_OFF, "stat.st_mtime");
static_assert(offsetof(struct stat, st_ctime) == ST_CTIME_OFF, "stat.st_ctime");

/* ---- the read gate ----
 *
 * Upstream gates every sus_kstat read on susfs_is_current_proc_umounted_app(),
 * which is exactly (TIF_PROC_UMOUNTED && current_uid().val >= 10000).  The flag
 * is set by KernelSU's setuid_hook only when SUSFS integration is compiled into
 * the kernel; this device's kernel has none (zero susfs symbols in kallsyms), so
 * it never sets and uid >= 10000 is the available proxy - the same one sus_path
 * already uses.
 *
 * Without this gate the spoofing is visible to every process including root,
 * which is a wider behaviour than upstream and a fidelity gap.
 *
 * Writers (the supercall and /proc interface) are configuration and stay
 * ungated. */
static bool susfs_kstat_gate_ok(void)
{
	return current_uid().val >= 10000;
}

/* ---- table access ----
 *
 * The *_table_* helpers below are the ONLY places that modify kstat_entries or
 * nkstat, and each one does it under kstat_table_lock.  Their callers hold
 * kstat_lock, which is what makes the index they pass in stable.
 */

/* Cheapest possible gate for the READ paths: with nothing registered, no lookup
 * can match, so there is no reason to touch user memory at all.  On the sys_exit
 * tracepoint that saves the two copy_from_user() reads the spoofers do before
 * matching; on the show_map_vma kprobe (still armed after a `clear`) and the
 * vfs_getattr kretprobe it saves an uncontended spinlock per VMA / per lookup.
 *
 * READ_ONCE is enough.  nkstat is published only AFTER the entry it counts has
 * been written, under kstat_table_lock (kstat_table_append stores the entry,
 * then bumps the count), so a stale non-zero value only means we do the work we
 * used to do; a stale zero can cost at most the single read that races the very
 * first add.  The authoritative test remains the locked lookup below.
 * sus_path uses the same idiom (READ_ONCE(sus_path_count) in
 * sus_path_match_path) - this is the kstat equivalent. */
static bool susfs_kstat_table_empty(void)
{
	return READ_ONCE(nkstat) == 0;
}

/* Hot-path lookup: match on (ino, dev) and copy the entry out atomically with
 * respect to the writers.  Returns true and fills *out on a match. */
static bool susfs_kstat_lookup(unsigned long ino, dev_t dev,
			       struct sus_kstat_snapshot *out)
{
	unsigned long flags;
	bool found = false;
	int i;

	spin_lock_irqsave(&kstat_table_lock, flags);
	for (i = 0; i < nkstat; i++) {
		if (kstat_entries[i].target_ino == ino &&
		    kstat_entries[i].target_dev == dev) {
			kstat_snapshot(&kstat_entries[i], out);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
	return found;
}

/* Writer-side lookup by path.  Safe without the spinlock: every caller holds
 * kstat_lock, and kstat_lock is what serialises all writers. */
static struct sus_kstat_entry *susfs_kstat_find_by_path(const char *path)
{
	int i;

	for (i = 0; i < nkstat; i++)
		if (!strcmp(kstat_entries[i].target_pathname, path))
			return &kstat_entries[i];
	return NULL;
}

/* Append a fully-prepared entry; -ENOSPC when the table is full. */
static int kstat_table_append(const struct sus_kstat_entry *src)
{
	unsigned long flags;
	int idx = -1;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (nkstat < SUS_KSTAT_MAX) {
		idx = nkstat;
		kstat_entries[idx] = *src;
		nkstat = idx + 1;
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
	return idx;
}

/* Replace a live entry wholesale (update: the reader sees old or new, never a
 * mix of the two). */
static void kstat_table_put(int idx, const struct sus_kstat_entry *src)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat)
		kstat_entries[idx] = *src;
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* Re-target an entry, and optionally raise its flags. */
static void kstat_table_retarget(int idx, unsigned long ino, dev_t dev,
				 unsigned int add_flags)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat) {
		kstat_entries[idx].target_ino = ino;
		kstat_entries[idx].target_dev = dev;
		kstat_entries[idx].flags |= add_flags;
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* Remove by index: move the last entry into the hole.  The reader must not be
 * able to observe that move half-done, hence the lock. */
static void kstat_table_del(int idx)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat) {
		nkstat--;
		if (idx != nkstat)
			kstat_entries[idx] = kstat_entries[nkstat];
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

static void kstat_table_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	nkstat = 0;
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* ---- /proc/<pid>/maps coverage ----
 *
 * Upstream's susfs_sus_kstat_spoof_show_map_vma() rewrites the dev/ino on the
 * line from inside show_map_vma(), where dev and ino are still local variables.
 * An LKM cannot reach those locals.  Re-printing the line ourselves would mean
 * reproducing the kernel's column padding exactly (show_vma_header_prefix uses
 * seq_setwidth()/seq_pad(), neither exported, and m->pad_until is private
 * state); a line that is padded differently from its neighbours is itself a
 * tell.  So the line is dropped instead.
 *
 * That still closes the detection this exists for: a stat() that reports one
 * ino while /proc/<pid>/maps reports the real one is a direct contradiction,
 * and it is the cheapest cross-check there is.  A mapped file that must stay
 * listed is what sus_map is for.
 *
 * Armed on the first rule that spoofs ino or dev, not before. */
static int kstat_show_map_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
	struct sus_kstat_snapshot snap;
	struct inode *inode;

	if (susfs_kstat_table_empty())
		return 0;
	if (!vma || !vma->vm_file)
		return 0;
	inode = file_inode(vma->vm_file);
	if (!inode)
		return 0;
	if (!susfs_kstat_gate_ok())
		return 0;
	if (!susfs_kstat_lookup(inode->i_ino,
				new_encode_dev(inode->i_sb->s_dev), &snap))
		return 0;
	if (!(snap.flags & (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV)))
		return 0;

	/* Skip the line by returning straight to the caller (x0 is irrelevant:
	 * show_map_vma returns void). */
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe kp_kstat_map_vma = {
	.symbol_name = "show_map_vma",
	.pre_handler = kstat_show_map_vma_pre,
};

static bool kstat_maps_registered;

/* Registering sleeps, so this runs from the rule-management paths (kstat_lock
 * held, process context), never from the hot paths. */
static void kstat_maps_arm(void)
{
	int rc;

	if (kstat_maps_registered)
		return;
	rc = register_kprobe(&kp_kstat_map_vma);
	if (rc)
		pr_warn("susfs_kstat: register_kprobe(show_map_vma) failed %d\n", rc);
	else {
		kstat_maps_registered = true;
		pr_info("susfs_kstat: maps hook armed (show_map_vma)\n");
	}
}

static void kstat_maps_disarm(void)
{
	if (!kstat_maps_registered)
		return;
	unregister_kprobe(&kp_kstat_map_vma);
	kstat_maps_registered = false;
}

/* rewrite the requested fields of the native user statbuf */
static void susfs_kstat_spoof_statbuf(unsigned long statbuf)
{
	/* Snapshot, not a pointer into the table: the lookup hands out a private
	 * copy so a concurrent writer cannot retarget the entry between the match
	 * and the copy_to_user below (which must not run under a spinlock). */
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;
	unsigned long ino = 0, dev = 0;
	unsigned long v;
	unsigned int v32;
	long long v64;
	long sl;

	if (susfs_kstat_table_empty())
		return;
	if (!susfs_kstat_gate_ok())
		return;

	if (copy_from_user(&ino, (void __user *)(statbuf + ST_INO_OFF), sizeof(ino)))
		return;
	if (copy_from_user(&dev, (void __user *)(statbuf + ST_DEV_OFF), sizeof(dev)))
		return;

	if (!susfs_kstat_lookup(ino, dev, &snap))
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

/* AArch32 (compat) statbuf layouts.
 *
 * There are TWO of them, and which one a syscall fills is decided by its number,
 * not by the fact that the caller is 32-bit:
 *
 *   __NR_fstatat64 327, __NR_fstat64 197
 *       -> struct stat64, arch/arm64/include/asm/stat.h:19-48, filled by
 *          cp_new_stat64() (fs/stat.c:486) through SYSCALL_DEFINE4(fstatat64,...)
 *          (fs/stat.c:556, enabled by __ARCH_WANT_COMPAT_STAT64).  This struct is
 *          NOT struct compat_stat, and it is not laid out the way the 4-byte
 *          INT_MAX... see the alignment note below.
 *
 *   __NR_stat 106, __NR_lstat 107, __NR_fstat 108
 *       -> struct compat_stat (arch/arm64/include/asm/compat.h:38-67), filled by
 *          cp_compat_stat().  This kernel tree's unistd32.h has no mapping for
 *          those numbers, so nothing reaches them here; they are listed so the
 *          next reader does not conclude that "compat = compat_stat" and wire the
 *          wrong offsets (which is exactly what this code used to do: it read
 *          st_ino at +4, i.e. the HIGH half of st_dev in stat64 - always 0 - so
 *          the lookup could never match and 32-bit callers got no spoofing at
 *          all, while a match would have written into st_dev/st_rdev).
 *
 * ALIGNMENT, and how these numbers were established (twice corrected):
 *   compat_u64/compat_s64 are `__attribute__((aligned(4)))` only when
 *   CONFIG_COMPAT_FOR_U64_ALIGNMENT is set (include/asm-generic/compat.h).  That
 *   option is selected by the 32-bit arm architecture only, so on this arm64
 *   kernel the plain `typedef s64 compat_s64;` applies and the u64 members keep
 *   their natural 8-byte alignment: st_size is at +48, not +44, and st_ino at
 *   +96, not +88.  Reading a 4-byte-aligned layout is not a silent near-miss - it
 *   was measured on device with tools/susfs_compat_stat: a 6-byte file reported
 *   size=25769803776 = 6 << 32, i.e. the low half of the field came from the
 *   padding and the high half from the value.  The offsets below are the ones
 *   that client and the kernel agree on. */
#define STAT64_ST_DEV_OFF       0	/* compat_u64 */
#define STAT64_ST_BROKEN_INO_OFF 12	/* compat_ulong_t __st_ino (what is filled) */
#define STAT64_ST_NLINK_OFF     20	/* compat_uint_t */
#define STAT64_ST_SIZE_OFF      48	/* compat_s64 */
#define STAT64_ST_BLKSIZE_OFF   56	/* compat_ulong_t */
#define STAT64_ST_BLOCKS_OFF    64	/* compat_u64 */
#define STAT64_ST_ATIME_OFF     72
#define STAT64_ST_ATIME_NSEC_OFF 76
#define STAT64_ST_MTIME_OFF     80
#define STAT64_ST_MTIME_NSEC_OFF 84
#define STAT64_ST_CTIME_OFF     88
#define STAT64_ST_CTIME_NSEC_OFF 92
#define STAT64_ST_INO_OFF       96	/* compat_u64 (unfilled: STAT64_HAS_BROKEN_ST_INO) */
#define STAT64_ST_SIZE          104

/* ARM EABI syscall numbers that fill struct stat64. */
#define COMPAT_FSTATAT64_NR	327	/* fstatat64(dfd, path, statbuf, flag) */
#define COMPAT_FSTAT64_NR	197	/* fstat64(fd, statbuf) */

/* compat (32-bit) statbuf: struct stat64 (see above) - one of the two layouts,
 * and the one both handled syscalls actually use. */
static void susfs_kstat_spoof_compat_statbuf(unsigned long statbuf)
{
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;
	unsigned long long v64;
	unsigned int ino = 0, dev = 0;
	unsigned int v32;
	int v;

	if (susfs_kstat_table_empty())
		return;
	if (!susfs_kstat_gate_ok())
		return;

	/* Key lookup on what the kernel ACTUALLY filled: __st_ino at +12.
	 *
	 * stat64 carries the STAT64_HAS_BROKEN_ST_INO marker (arch/arm64/include/asm/
	 * stat.h), so cp_new_stat64() writes __st_ino and leaves st_ino (+96) alone -
	 * reading the key from +96 would therefore compare against whatever the
	 * caller's buffer happened to contain and never match.  Both fields are
	 * written when spoofing, so a libc that synthesises st_ino from __st_ino and
	 * one that reads st_ino directly both see the spoofed value. */
	if (copy_from_user(&ino, (void __user *)(statbuf + STAT64_ST_BROKEN_INO_OFF), sizeof(ino)))
		return;
	if (copy_from_user(&dev, (void __user *)(statbuf + STAT64_ST_DEV_OFF), sizeof(dev)))
		return;
	if (!susfs_kstat_lookup(ino, dev, &snap))
		return;

	if (e->flags & KSTAT_SPOOF_INO) {
		v32 = (unsigned int)e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BROKEN_INO_OFF), &v32, sizeof(v32)))
			return;
		v64 = (unsigned long long)e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_INO_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_DEV) {
		v64 = (unsigned long long)e->spoofed_dev;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_DEV_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_NLINK) {
		v32 = (unsigned int)e->spoofed_nlink;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_NLINK_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_SIZE) {
		v64 = (unsigned long long)e->spoofed_size;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_SIZE_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		v32 = (unsigned int)e->spoofed_blksize;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BLKSIZE_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_BLOCKS) {
		v64 = (unsigned long long)e->spoofed_blocks;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BLOCKS_OFF), &v64, sizeof(v64)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC) {
		v = (int)e->spoofed_atime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_ATIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_atime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_ATIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC) {
		v = (int)e->spoofed_mtime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_MTIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_mtime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_MTIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC) {
		v = (int)e->spoofed_ctime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_CTIME_OFF), &v, sizeof(v)))
			return;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_ctime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_CTIME_NSEC_OFF), &v32, sizeof(v32)))
			return;
	}
}

/* sys_exit tracepoint: the user statbuf is fully written by now, and
 * syscall_get_arguments() still returns the original args (verified: args[2]
 * == statbuf), so no per-cpu state is needed. */
static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	unsigned long args[6];
	long nr;

	if (ret != 0)
		return;
	syscall_get_arguments(current, regs, args);
	nr = syscall_get_nr(current, regs);

	/* The statbuf argument is NOT the same one for every syscall, so the NULL
	 * check has to live inside each branch: fstat64(fd, statbuf) keeps it in
	 * args[1], and checking args[2] first (as this did) made every 32-bit
	 * fstat64() return early - the rule was applied to fstatat64 and silently
	 * not to fstat64. */
	if (is_compat_task()) {
		/* Both of these fill struct stat64. */
		if (nr == COMPAT_FSTATAT64_NR)
			susfs_kstat_spoof_compat_statbuf((unsigned long)compat_ptr((u32)args[2]));
		else if (nr == COMPAT_FSTAT64_NR)
			susfs_kstat_spoof_compat_statbuf((unsigned long)compat_ptr((u32)args[1]));
	} else {
		if (nr != __NR_newfstatat)
			return;
		if (!args[2])
			return;
		susfs_kstat_spoof_statbuf(args[2]);
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
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;

	if (susfs_kstat_table_empty())
		return;
	if (!inode || !stat)
		return;
	if (!susfs_kstat_gate_ok())
		return;
	if (!susfs_kstat_lookup(inode->i_ino, new_encode_dev(inode->i_sb->s_dev),
				&snap))
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

/* resolve <path> to its CURRENT (ino, encoded dev).  Sleeps - never call this
 * with kstat_table_lock held (writers hold only kstat_lock here). */
static int susfs_kstat_resolve(const char *path, unsigned long *ino, dev_t *dev)
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
	*ino = inode->i_ino;
	*dev = new_encode_dev(inode->i_sb->s_dev);
	path_put(&p);
	return 0;
}

/* resolve <path> and fill the spoofed_* fields with its CURRENT stat
 * (generic_fillattr mapping from the inode fields).
 *
 * Fills a DETACHED entry only.  Callers build here, then commit through one of
 * the kstat_table_* helpers; nothing half-built is ever visible to a reader. */
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

/* re-resolve only target_ino/target_dev; spoofed values stay untouched.
 * Resolves first (sleeping), then re-targets under the lock: a reader sees the
 * old pair or the new pair, never ino-of-B with dev-of-A. */
static int susfs_kstat_update(const char *path, bool full_clone)
{
	struct sus_kstat_entry *e;
	unsigned long ino;
	dev_t dev;
	int err;

	e = susfs_kstat_find_by_path(path);
	if (!e)
		return -ENOENT;
	err = susfs_kstat_resolve(path, &ino, &dev);
	if (err)
		return err;
	kstat_table_retarget((int)(e - kstat_entries), ino, dev,
			     full_clone ? KSTAT_AUTO_SPOOF_FULL_CLONE
					: KSTAT_AUTO_SPOOF);
	return 0;
}

/* add/update a rule from its pathname; kstat_lock held */
static int susfs_kstat_add(const char *path)
{
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	int err, idx;

	if (strlen(path) >= KSTAT_PATH_MAX)
		return -ENAMETOOLONG;

	e = susfs_kstat_find_by_path(path);

	memset(&tmp, 0, sizeof(tmp));
	err = susfs_kstat_fill_from_path(&tmp, path);
	if (err)
		return err;
	strscpy(tmp.target_pathname, path, KSTAT_PATH_MAX);
	tmp.flags = KSTAT_AUTO_SPOOF;

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
}

static void susfs_kstat_del(const char *path)
{
	struct sus_kstat_entry *e = susfs_kstat_find_by_path(path);

	if (!e)
		return;
	kstat_table_del((int)(e - kstat_entries));
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
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	long long val;
	bool dflt;
	int err, i, idx;
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

	if (strlen(path) >= KSTAT_PATH_MAX)
		return -ENAMETOOLONG;

	e = susfs_kstat_find_by_path(path);

	memset(&tmp, 0, sizeof(tmp));
	/* start from the CURRENT stat; non-default fields override it */
	err = susfs_kstat_fill_from_path(&tmp, path);
	if (err)
		return err;
	strscpy(tmp.target_pathname, path, KSTAT_PATH_MAX);
	tmp.flags = 0;

	for (i = 0; i < 12; i++) {
		err = parse_override(argv[2 + i], &dflt, &val);
		if (err)
			return err;
		if (dflt)
			continue;
		tmp.flags |= f_flags[i];
		switch (i) {
		case 0: tmp.spoofed_ino = (unsigned long)val; break;
		case 1: tmp.spoofed_dev = (unsigned long)val; break;
		case 2: tmp.spoofed_nlink = (unsigned int)val; break;
		case 3: tmp.spoofed_size = val; break;
		case 4: tmp.spoofed_atime_tv_sec = (long)val; break;
		case 5: tmp.spoofed_atime_tv_nsec = (unsigned long)val; break;
		case 6: tmp.spoofed_mtime_tv_sec = (long)val; break;
		case 7: tmp.spoofed_mtime_tv_nsec = (unsigned long)val; break;
		case 8: tmp.spoofed_ctime_tv_sec = (long)val; break;
		case 9: tmp.spoofed_ctime_tv_nsec = (unsigned long)val; break;
		case 10: tmp.spoofed_blocks = val; break;
		case 11: tmp.spoofed_blksize = (long)val; break;
		}
	}

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
}

/* statically-add from the supercall ABI struct (is_statically=1): copy the
 * caller's 12 spoofed fields + flags verbatim; resolve target ino/dev here. */
static int susfs_kstat_add_statically_abi(struct st_susfs_sus_kstat *info)
{
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	int err, idx;

	e = susfs_kstat_find_by_path(info->target_pathname);

	memset(&tmp, 0, sizeof(tmp));
	err = susfs_kstat_fill_from_path(&tmp, info->target_pathname);
	if (err)
		return err;
	strscpy(tmp.target_pathname, info->target_pathname, KSTAT_PATH_MAX);

	tmp.spoofed_ino = info->spoofed_ino;
	tmp.spoofed_dev = info->spoofed_dev;
	tmp.spoofed_nlink = info->spoofed_nlink;
	tmp.spoofed_size = info->spoofed_size;
	tmp.spoofed_atime_tv_sec = info->spoofed_atime_tv_sec;
	tmp.spoofed_atime_tv_nsec = info->spoofed_atime_tv_nsec;
	tmp.spoofed_mtime_tv_sec = info->spoofed_mtime_tv_sec;
	tmp.spoofed_mtime_tv_nsec = info->spoofed_mtime_tv_nsec;
	tmp.spoofed_ctime_tv_sec = info->spoofed_ctime_tv_sec;
	tmp.spoofed_ctime_tv_nsec = info->spoofed_ctime_tv_nsec;
	tmp.spoofed_blocks = info->spoofed_blocks;
	tmp.spoofed_blksize = info->spoofed_blksize;
	tmp.flags = info->flags;

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
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

	/* All three commands key on target_pathname, and a caller may fill all 256
	 * bytes of that field - reject an unterminated one before any strlen() or
	 * kern_path() can walk off our stack copy of the struct. */
	if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {
		info.err = -ENAMETOOLONG;
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
	/* Armed outside the lock and only after a rule actually landed: a hook
	 * that can never fire is worse than no hook. */
	if (!err)
		kstat_maps_arm();
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

	/* The hooks are armed UNCONDITIONALLY, and that is not cosmetic: the
	 * supercall interface (CMD_SUSFS_ADD_SUS_KSTAT) can install rules with no
	 * /proc node at all, so skipping registration when expose_proc=0 silently
	 * turned the whole feature into a no-op - rules accepted, never applied.
	 * expose_proc decides whether the node exists, nothing else. */
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

	/* 0777 is deliberate, not an oversight.  inode_permission() runs the DAC
	 * check BEFORE security_inode_permission(), so a node the app cannot open
	 * hands it EACCES - "this exists, you may not read it" - instead of the
	 * ENOENT sus_path is supposed to produce.  0777 lets DAC pass and leaves
	 * the answer to sus_path's LSM layer.
	 *
	 * That makes the LSM layer the ONLY thing between an app and a
	 * world-writable control node, so without it we do not create the node -
	 * see susfs_control_node_allowed(). */
	if (susfs_control_node_allowed()) {
		kstat_proc_entry = proc_create("susfs_kstat", 0777, NULL,
					       &kstat_proc_ops);
		if (!kstat_proc_entry)
			pr_warn("proc_create(susfs_kstat) failed\n");
	} else {
		pr_info("susfs_kstat: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	pr_info("kstat armed: %d rules (tp=%d krp=%d proc=%d)\n", nkstat,
		kstat_tp_registered, kstat_krp_registered,
		kstat_proc_entry != NULL);
	return 0;
}

void susfs_kstat_exit(void)
{
	kstat_maps_disarm();
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
	kstat_table_clear();
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
	/* 0777 is deliberate (the ENOENT contract comes from sus_path's hidden set,
	 * not from the mode), so refuse non-root callers here too - see the note in
	 * susfs_enable_log.c's log_proc_open().  This node enumerates every hidden
	 * path and spoofed value, which is exactly what a detector would want. */
	if (current_uid().val != 0)
		return -ENOENT;
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
		kstat_table_clear();
		err = 0;
	}

	mutex_unlock(&kstat_lock);

	if (!err)
		kstat_maps_arm();

	if (err)
		pr_warn("kstat proc write '%s' -> err %d\n", argv[0], err);
	return len;
}
