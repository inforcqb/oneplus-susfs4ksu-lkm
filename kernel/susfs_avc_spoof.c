// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_avc_spoof.c - hide the KernelSU su domain from SELinux AVC audit logs
 * (SUSFS AVC_LOG_SPOOFING feature), LKM port.
 *
 * Upstream SUSFS hooks avc_audit_post_callback() and, when the audit target
 * sid is the su domain, prints a priv_app context instead (static branch
 * gated).  This hides "denied { ... } tcontext=u:r:su:s0" lines from dmesg,
 * which root-hiding detectors grep for.
 *
 * avc_audit_post_callback is static, but its address is taken and passed to
 * the EXPORT_SYMBOL common_lsm_audit(), so LTO cannot inline it: there is a
 * real out-of-line copy to kprobe.
 *
 * Our pre_handler runs in interrupt context (no sleep), so it only rewrites
 * sad->tsid in place: su sid -> priv_app sid.  The function body then calls
 * security_sid_to_context() with the rewritten sid and naturally emits the
 * priv_app context.  Equivalent to upstream's string swap, but cleaner.
 *
 * The su/priv_app sids are resolved at init time (process context) via the
 * EXPORT_SYMBOL security_secctx_to_secid(), with module_param overrides.
 *
 * Interface: /proc/susfs_avc_spoof   write "1"/"0", read to query.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/security.h>
#include <linux/lsm_audit.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "susfs_log.h"

/* module_param overrides for the two domains */
static char avc_su_ctx[128] = "u:r:su:s0";
static char avc_priv_app_ctx[128] = "u:r:priv_app:s0:c512,c768";
module_param_string(avc_su_ctx, avc_su_ctx, sizeof(avc_su_ctx), 0644);
module_param_string(avc_priv_app_ctx, avc_priv_app_ctx, sizeof(avc_priv_app_ctx), 0644);

static u32 avc_su_sid;
static u32 avc_priv_app_sid;
static bool avc_spoof_enabled;
static bool avc_registered;

/* local definition matching security/selinux/include/avc.h (avoids the
 * private header; only the layout up to tsid matters, which is stable) */
struct selinux_state;
struct selinux_audit_data {
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 requested;
	u32 audited;
	u32 denied;
	int result;
	struct selinux_state *state;
};

/* avc_audit_post_callback(ab, a): ab=regs[0], a=regs[1] */
static atomic_t avc_hit_count = ATOMIC_INIT(0);
static atomic_t avc_enter_count = ATOMIC_INIT(0);

static int avc_audit_post_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct common_audit_data *ad = (struct common_audit_data *)regs->regs[1];
	struct selinux_audit_data *sad;

	atomic_inc(&avc_enter_count);
	if (!ad)
		return 0;
	sad = ad->selinux_audit_data;
	if (!sad)
		return 0;

	if (sad->tsid == avc_su_sid) {
		atomic_inc(&avc_hit_count);
		sad->tsid = avc_priv_app_sid;
	}
	return 0;
}

static struct kprobe kp_avc = {
	.symbol_name = "avc_audit_post_callback",
	.pre_handler = avc_audit_post_pre,
};

static int avc_register(void)
{
	int rc;

	if (avc_registered)
		return 0;
	rc = register_kprobe(&kp_avc);
	if (rc)
		return rc;
	avc_registered = true;
	pr_info("susfs_avc_spoof: hook installed (avc_audit_post_callback)\n");
	return 0;
}

static void avc_unregister(void)
{
	if (!avc_registered)
		return;
	unregister_kprobe(&kp_avc);
	avc_registered = false;
	pr_info("susfs_avc_spoof: hook removed\n");
}

/* ---- /proc/susfs_avc_spoof ---- */
static int avc_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d (su_sid=%u priv_app_sid=%u enter=%d hits=%d)\n",
		   avc_spoof_enabled ? 1 : 0, avc_su_sid, avc_priv_app_sid,
		   atomic_read(&avc_enter_count), atomic_read(&avc_hit_count));
	return 0;
}

static int avc_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, avc_proc_show, NULL);
}

static ssize_t avc_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	char c;
	int rc = 0;

	if (copy_from_user(&c, buf, 1))
		return -EFAULT;

	if (c == '1') {
		if (!avc_spoof_enabled) {
			rc = avc_register();
			if (!rc)
				avc_spoof_enabled = true;
		}
	} else if (c == '0') {
		avc_unregister();
		avc_spoof_enabled = false;
	}

	if (rc)
		pr_warn("avc_spoof: enable failed %d\n", rc);
	return len;
}

static const struct proc_ops avc_proc_ops = {
	.proc_open = avc_proc_open,
	.proc_read = seq_read,
	.proc_write = avc_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *avc_proc_entry;

int susfs_avc_spoof_init(void)
{
	int err;

	err = security_secctx_to_secid(avc_su_ctx, strlen(avc_su_ctx), &avc_su_sid);
	if (err) {
		pr_warn("avc_spoof: secctx_to_secid(%s) failed %d\n", avc_su_ctx, err);
		avc_su_sid = 0;
	}
	err = security_secctx_to_secid(avc_priv_app_ctx, strlen(avc_priv_app_ctx),
				       &avc_priv_app_sid);
	if (err) {
		pr_warn("avc_spoof: secctx_to_secid(%s) failed %d\n",
			avc_priv_app_ctx, err);
		avc_priv_app_sid = 0;
	}
	pr_info("avc_spoof: su_sid=%u (%s), priv_app_sid=%u (%s)\n",
		avc_su_sid, avc_su_ctx, avc_priv_app_sid, avc_priv_app_ctx);

	avc_proc_entry = proc_create("susfs_avc_spoof", 0666, NULL, &avc_proc_ops);
	if (!avc_proc_entry)
		pr_warn("proc_create(susfs_avc_spoof) failed\n");
	else
		pr_info("susfs_avc_spoof: proc ready (/proc/susfs_avc_spoof)\n");
	return 0;
}

void susfs_avc_spoof_exit(void)
{
	avc_unregister();
	avc_spoof_enabled = false;
	if (avc_proc_entry) {
		proc_remove(avc_proc_entry);
		avc_proc_entry = NULL;
	}
}
