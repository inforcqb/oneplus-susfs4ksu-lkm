/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_H
#define __SUSFS_H

/* feature init/exit (each feature is its own translation unit) */
int susfs_uname_init(void);
void susfs_uname_exit(void);

int susfs_kstat_init(void);
void susfs_kstat_exit(void);

int susfs_sus_map_init(void);
void susfs_sus_map_exit(void);

int sus_path_init(void);
void sus_path_exit(void);

int susfs_sus_mount_init(void);
void susfs_sus_mount_exit(void);

int susfs_spoof_cmdline_init(void);
void susfs_spoof_cmdline_exit(void);

int susfs_open_redirect_init(void);
void susfs_open_redirect_exit(void);

int susfs_enable_log_init(void);
void susfs_enable_log_exit(void);
bool susfs_log_enabled(void);

int susfs_avc_spoof_init(void);
void susfs_avc_spoof_exit(void);

int susfs_supercall_init(void);
void susfs_supercall_exit(void);

#endif
