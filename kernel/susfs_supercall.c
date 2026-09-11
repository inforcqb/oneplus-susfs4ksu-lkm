// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_supercall.c - SUSFS supercall dispatcher (reboot(2) ABI).
 *
 * The ksu_susfs tool (and SukiSU ksud) reach SUSFS through:
 *   syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id, &mut payload)
 * The kernel handler writes payload.err back (0 = ok, errno-style otherwise).
 *
 * Upstream SUSFS patches kernel/reboot.c SYSCALL_DEFINE4 to branch into
 * ksu_handle_sys_reboot().  An LKM cannot patch that, so we kprobe
 * __arm64_sys_reboot and match the magic values ourselves.
 *
 * Two hard constraints:
 *  - arm64 syscall-wrapper quirk: __arm64_sys_reboot's kprobe sees
 *    regs->regs[0] == struct pt_regs * (the wrapper's __regs argument); the
 *    real user args live in real_regs->regs[0..3].  See SukiSU's
 *    PT_REAL_REGS() / arch.h.
 *  - kprobe pre_handler runs in interrupt context and must not copy_from_user.
 *    We defer the actual command to task_work (TWA_RESUME), which runs in
 *    process context before returning to userspace — same trick SukiSU uses.
 *
 * The handler functions have upstream's signature `void xxx(void __user **arg)`
 * where *arg points at the userspace payload struct; each reads it, acts, and
 * writes back payload.err.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/task_work.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"

/* per-command deferred work */
struct susfs_tw {
	struct callback_head cb;
	unsigned int cmd;
	void __user *payload;   /* points at the userspace payload struct */
};

/* ---- feature handlers (upstream signature) ---- */
static void susfs_show_version(void __user **arg)
{
	struct st_susfs_version info = {0};

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	strscpy(info.susfs_version, SUSFS_VERSION_STR, SUSFS_MAX_VERSION_BUFSIZE);
	info.err = 0;
out:
	if (copy_to_user((void __user *)*arg, &info, sizeof(info)))
		pr_warn("susfs show_version copy_to_user failed\n");
}

static void susfs_show_variant(void __user **arg)
{
	struct st_susfs_variant info = {0};

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	strscpy(info.susfs_variant, SUSFS_VARIANT_STR, SUSFS_MAX_VARIANT_BUFSIZE);
	info.err = 0;
out:
	if (copy_to_user((void __user *)*arg, &info, sizeof(info)))
		pr_warn("susfs show_variant copy_to_user failed\n");
}

/* List every feature this LKM implements, using upstream CONFIG macro names.
 *
 * Entries with an `active` callback are only reported while the feature is
 * really installed.  Advertising a feature whose registration failed produces
 * the exact inconsistency a detector probes for, so failing ones are omitted
 * (and logged by their init). */
struct feature_entry {
	const char *name;
	bool (*active)(void);	/* NULL = always present */
};

static const struct feature_entry enabled_features[] = {
	{ "CONFIG_KSU_SUSFS_SUS_PATH\n",	sus_path_lsm_active },
	{ "CONFIG_KSU_SUSFS_SUS_MOUNT\n",	NULL },
	{ "CONFIG_KSU_SUSFS_SUS_KSTAT\n",	NULL },
	{ "CONFIG_KSU_SUSFS_SPOOF_UNAME\n",	NULL },
	{ "CONFIG_KSU_SUSFS_ENABLE_LOG\n",	NULL },
	{ "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS\n",	susfs_hide_syms_active },
	{ "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n", NULL },
	{ "CONFIG_KSU_SUSFS_OPEN_REDIRECT\n",	NULL },
	{ "CONFIG_KSU_SUSFS_SUS_MAP\n",		NULL },
};

static void susfs_show_enabled_features(void __user **arg)
{
	struct st_susfs_enabled_features *info;
	size_t off = 0;
	int i;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return;

	for (i = 0; i < ARRAY_SIZE(enabled_features); i++) {
		const char *name = enabled_features[i].name;
		size_t len = strlen(name);

		if (enabled_features[i].active && !enabled_features[i].active())
			continue;
		if (off + len >= SUSFS_ENABLED_FEATURES_SIZE)
			break;
		memcpy(info->enabled_features + off, name, len);
		off += len;
	}
	info->err = 0;

	if (copy_to_user((void __user *)*arg, info, sizeof(*info)))
		pr_warn("susfs show_enabled_features copy_to_user failed\n");
	kfree(info);
}

/* ---- dispatcher ---- */
static void susfs_tw_func(struct callback_head *cb)
{
	struct susfs_tw *tw = container_of(cb, struct susfs_tw, cb);
	void __user *arg = tw->payload;

	switch (tw->cmd) {
	case CMD_SUSFS_SHOW_VERSION:
		susfs_show_version(&arg);
		break;
	case CMD_SUSFS_SHOW_VARIANT:
		susfs_show_variant(&arg);
		break;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
		susfs_show_enabled_features(&arg);
		break;
	case CMD_SUSFS_ADD_SUS_PATH:
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
		sus_path_supercall(&arg);
		break;
	case CMD_SUSFS_ADD_SUS_MAP:
		susfs_sus_map_supercall(&arg);
		break;
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		susfs_kstat_supercall(tw->cmd, &arg);
		break;
	case CMD_SUSFS_SET_UNAME:
		susfs_uname_supercall(&arg);
		break;
	case CMD_SUSFS_ENABLE_LOG:
		susfs_enable_log_supercall(&arg);
		break;
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
		susfs_avc_spoof_supercall(&arg);
		break;
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		susfs_spoof_cmdline_supercall(&arg);
		break;
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		susfs_open_redirect_supercall(&arg);
		break;
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
		susfs_sus_mount_supercall(&arg);
		break;
	default:
		/* Unreachable: reboot_pre() only defers a command that
		 * susfs_cmd_handled() accepted.  Kept as a net in case the two
		 * lists ever drift apart. */
		pr_info("susfs supercall: unsupported cmd 0x%x\n", tw->cmd);
		break;
	}
	kfree(tw);
}

/* Commands susfs_tw_func() above actually dispatches - keep the two in sync.
 *
 * The kprobe consults this BEFORE it commits to swallowing the syscall, because
 * upstream answers an unrecognised command with `return -EINVAL` from
 * ksu_handle_sys_reboot() (KernelSU/10_enable_susfs_for_ksu.patch:2925-2926);
 * reboot.c's `if (ret) goto orig_flow;` then falls through to the real reboot
 * path, whose magic check rejects 0xDEADBEEF/0xFAFAFAFA with -EINVAL - i.e.
 * userspace gets -EINVAL out of reboot(2).  Upstream writes NOTHING to
 * payload.err in that case, and that is the whole kernel-side contract: 126
 * (ERR_CMD_NOT_SUPPORTED) is a USERSPACE sentinel - the ksu_susfs C tool
 * pre-seeds err with it and treats "still 126 after the syscall" as "the kernel
 * never handled this command" (ksu_susfs/jni/features/sus_map.c:51-53,
 * ksu_susfs/jni/includes/susfs_defs.h:16-18).
 *
 * So an unknown command must NOT be hijacked: leave the regs alone, let
 * reboot(2) return -EINVAL, leave err untouched.  Every command listed here
 * still short-circuits to 0 exactly as before, which is what the already
 * verified command paths depend on. */
static bool susfs_cmd_handled(unsigned int cmd)
{
	switch (cmd) {
	case CMD_SUSFS_SHOW_VERSION:
	case CMD_SUSFS_SHOW_VARIANT:
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
	case CMD_SUSFS_ADD_SUS_PATH:
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
	case CMD_SUSFS_ADD_SUS_MAP:
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
	case CMD_SUSFS_SET_UNAME:
	case CMD_SUSFS_ENABLE_LOG:
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
		return true;
	default:
		return false;
	}
}

static int reboot_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct pt_regs *real_regs = (struct pt_regs *)regs->regs[0];
	int magic1, magic2;
	unsigned int cmd;
	void __user *payload;
	struct susfs_tw *tw;

	/* A prober runs before the callee, so an argument the callee would have
	 * checked is still raw here - see the filename_lookup lesson in
	 * sus_path.c.  The syscall ABI does guarantee this one, but a NULL check
	 * costs nothing and this is the path that accepts commands. */
	if (!real_regs)
		return 0;

	magic1 = (int)real_regs->regs[0];
	magic2 = (int)real_regs->regs[1];
	cmd = (unsigned int)real_regs->regs[2];
	payload = (void __user *)real_regs->regs[3];

	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;
	if (magic2 != SUSFS_MAGIC)
		return 0;
	if (current_uid().val != 0)
		return 0;

	/* Not ours to answer: leave the syscall alone so reboot(2) reports the
	 * -EINVAL upstream reports, and payload.err keeps whatever the caller put
	 * there (that is how the C tool detects "command not supported").  See
	 * susfs_cmd_handled(). */
	if (!susfs_cmd_handled(cmd)) {
		pr_info("susfs supercall: unsupported cmd 0x%x\n", cmd);
		return 0;
	}

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;
	tw->cmd = cmd;
	tw->payload = payload;
	tw->cb.func = susfs_tw_func;

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("susfs supercall: task_work_add failed\n");
		return 0;
	}

	/* Upstream SUSFS patches kernel/reboot.c so that a handled supercall does
	 * `return ret` (0) instead of falling through to the real reboot path:
	 *
	 *     ret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	 *     if (ret) goto orig_flow;
	 *     return ret;            <- syscall returns 0 on success
	 *
	 * We cannot patch reboot.c, so mirror it from the kprobe: skip the rest of
	 * __arm64_sys_reboot and return 0.  Callers (the prebuilt ksu_susfs tool)
	 * check the syscall result, and with the magic values being invalid
	 * otherwise reboot would return -EINVAL.  The command itself still runs
	 * from task_work before we return to userspace. */
	regs->pc = regs->regs[30];
	regs->regs[0] = 0;
	return 1;
}

static struct kprobe reboot_kp = {
	.symbol_name = "__arm64_sys_reboot",
	.pre_handler = reboot_pre,
};

static bool sc_registered;

int susfs_supercall_init(void)
{
	int rc;

	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_warn("susfs supercall: register_kprobe(reboot) failed %d\n", rc);
		return rc;
	}
	sc_registered = true;
	pr_info("susfs supercall: armed (reboot ABI, version " SUSFS_VERSION_STR ")\n");
	return 0;
}

void susfs_supercall_exit(void)
{
	if (sc_registered) {
		unregister_kprobe(&reboot_kp);
		sc_registered = false;
	}
}
