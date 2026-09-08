/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_LSM_HOOK_H
#define __SUSFS_LSM_HOOK_H

#include <linux/lsm_hooks.h>
#include <linux/stddef.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define KSU_LSM_HOOK_HEADS_TYPE struct lsm_static_calls_table
#else
#define KSU_LSM_HOOK_HEADS_TYPE struct security_hook_heads
#endif

struct ksu_lsm_hook {
    const char *head_name;
    const char *target_name;
    size_t head_offset;
    size_t hook_offset;
    void *replacement;
    void *original;
    struct security_hook_list *entry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    struct lsm_static_call *scall;
#else
    struct security_hook_list list;
#endif
    /* the offset from target_name to the real hook target */
    int offset;
};

#define KSU_LSM_HOOK_INIT(member, target_symbol, replacement_fn, off)                                                  \
    {                                                                                                                  \
        .head_name = #member, .target_name = target_symbol, .head_offset = offsetof(KSU_LSM_HOOK_HEADS_TYPE, member),  \
        .hook_offset = offsetof(struct security_hook_list, hook.member), .replacement = (void *)(replacement_fn),      \
        .offset = off,                                                                                                 \
    }

/* Runtime patching of existing LSM hook slots (workaround for out-of-tree
 * modules; the normal path is security_add_hooks()).  Coherent via
 * text patching + RCU synchronization. */

int ksu_lsm_hook(struct ksu_lsm_hook *hook);
void ksu_lsm_unhook(struct ksu_lsm_hook *hook);

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook);
void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook);

void ksu_lsm_hook_init(void);
void ksu_lsm_hook_exit(void);

#endif
