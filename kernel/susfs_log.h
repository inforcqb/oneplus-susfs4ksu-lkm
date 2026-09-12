/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_LOG_H
#define __SUSFS_LOG_H

#include <linux/types.h>
#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "susfs_guard_lkm: " fmt
#endif

/* ENABLE_LOG, the way upstream has it: SUSFS_LOGI() is the informational channel
 * (rule add/remove, hook arming, hit paths) and it sits behind the switch that
 * CMD_SUSFS_ENABLE_LOG / /proc/susfs_enable_log toggles - default ON, matching
 * upstream's DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled).  pr_warn/pr_err stay
 * unconditional: a failure has to be visible whether or not logging is on
 * (upstream's SUSFS_LOGE is unconditional for the same reason).
 *
 * This used to be an interface with no consumers - the flag existed, nothing read
 * it, and every informational line printed regardless.  That is a root-side
 * fingerprint: turn logging off, do something SUSFS-related, and see whether the
 * kernel still talks about it.  Measured before the fix: `enable_log 0` plus a
 * rule add still produced "susfs_guard_lkm: sus_path: ..." in dmesg. */
bool susfs_log_enabled(void);

#define SUSFS_LOGI(fmt, ...)						\
	do {								\
		if (susfs_log_enabled())				\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

#endif
