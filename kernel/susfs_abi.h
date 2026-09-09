// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_abi.h - SUSFS kernel<->userspace ABI (supercall via reboot(2)).
 *
 * Mirrors upstream susfs_def.h + susfs.h struct layouts exactly, so the
 * prebuilt ksu_susfs tool (and SukiSU's ksud susfs bindings) can drive this
 * LKM unmodified.  Field order / types / sizes MUST match the userspace side.
 *
 * Wire protocol:
 *   syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id, &mut payload)
 * The kernel writes payload.err back (0 = ok, else errno-style).
 */
#ifndef __SUSFS_ABI_H
#define __SUSFS_ABI_H

#include <linux/types.h>

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC        0xFAFAFAFA

/* command IDs (shared with ksu_susfs / ksud) */
#define CMD_SUSFS_ADD_SUS_PATH                 0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP            0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_ADD_SUS_KSTAT                0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT             0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY     0x55572
#define CMD_SUSFS_SET_UNAME                    0x55590
#define CMD_SUSFS_ENABLE_LOG                   0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG    0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT            0x555c0
#define CMD_SUSFS_SHOW_VERSION                 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES        0x555e2
#define CMD_SUSFS_SHOW_VARIANT                 0x555e3
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING      0x60010
#define CMD_SUSFS_ADD_SUS_MAP                  0x60020

#define ERR_CMD_NOT_SUPPORTED 126

#define SUSFS_MAX_LEN_PATHNAME                  256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE   8192
#define SUSFS_ENABLED_FEATURES_SIZE             8192
#define SUSFS_MAX_VERSION_BUFSIZE               16
#define SUSFS_MAX_VARIANT_BUFSIZE               16

#define SUSFS_VERSION_STR "v1.5.2"
#define SUSFS_VARIANT_STR "gki"

/* ---- payload structs (must match userspace #[repr(C)] layouts) ---- */

struct st_susfs_sus_path {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int err;
};

struct st_susfs_sus_map {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int err;
};

struct st_susfs_sus_kstat {
	int is_statically;
	unsigned long target_ino;
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
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
	int flags;
	int err;
};

struct st_susfs_uname {
	char release[65];
	char version[65];
	int err;
};

struct st_susfs_log {
	bool enabled;
	int err;
};

struct st_susfs_avc_log_spoofing {
	bool enabled;
	int err;
};

struct st_susfs_hide_sus_mnts {
	bool enabled;
	int err;
};

struct st_susfs_open_redirect {
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int uid_scheme;
	int err;
};

struct st_susfs_spoof_cmdline_or_bootconfig {
	char fake_cmdline_or_bootconfig[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
	int err;
};

struct st_susfs_version {
	char susfs_version[SUSFS_MAX_VERSION_BUFSIZE];
	int err;
};

struct st_susfs_variant {
	char susfs_variant[SUSFS_MAX_VARIANT_BUFSIZE];
	int err;
};

struct st_susfs_enabled_features {
	char enabled_features[SUSFS_ENABLED_FEATURES_SIZE];
	int err;
};

#endif
