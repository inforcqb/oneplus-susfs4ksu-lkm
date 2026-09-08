/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_LOG_H
#define __SUSFS_LOG_H

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "susfs: " fmt
#endif

#endif
