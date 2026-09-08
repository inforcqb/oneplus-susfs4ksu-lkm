/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_H
#define __SUSFS_H

/* feature init/exit (each feature is its own translation unit) */
int susfs_uname_init(void);
void susfs_uname_exit(void);

int susfs_kstat_init(void);
void susfs_kstat_exit(void);

#endif
