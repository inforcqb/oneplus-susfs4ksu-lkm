/* SPDX-License-Identifier: GPL-2.0 */
/*
 * lsm_hook.c - runtime LSM hook installation (ported from KernelSU/SukiSU
 * hook/lsm_hook.c).
 *
 * Two mechanisms, both writing through ksu_patch_text() because every word they touch
 * lives in read-only-after-init memory:
 *
 *   replace  - find the struct security_hook_list whose function slot equals a symbol
 *              resolved by name and overwrite that slot; the old pointer is kept in
 *              hook->original and the replacement has to call it for pass-through.  The
 *              slot sits in someone else's (SELinux's) entry, so the hook runs at
 *              SELinux's position and a caller LSM that returns non-zero first masks it.
 *   insert   - add our OWN struct security_hook_list node at the HEAD of the same hlist
 *              (hook->insert, see KSU_LSM_HOOK_INSERT).  No symbol is resolved, no
 *              original exists to call, and the node runs before every registered LSM,
 *              so it can only add a denial - never suppress one.
 *
 * The 6.12+ static-call dispatch is a different mechanism and only the replace path is
 * implemented for it: an insertion implementation would have to be mirrored there (the
 * node list is not walked at all, so inserting into security_hook_heads would have no
 * effect).  hook->insert is rejected with -ENOSYS on that branch.
 */
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

#include "symbol_resolver.h"
#include "lsm_hook.h"
#include "patch_memory.h"
#include "susfs_log.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/static_call.h>
#endif

struct ksu_lsm_hook_entry {
    struct ksu_lsm_hook *hook;
};

/* Defined below, called from ksu_unregister_lsm_hook() - see its comment for why
 * synchronize_rcu() alone is not enough. */
static void ksu_lsm_hook_drain(void);

static DEFINE_MUTEX(ksu_lsm_hook_lock);
static struct ksu_lsm_hook_entry ksu_lsm_hook_entries[16];
static int ksu_lsm_hook_count;

static bool ksu_lsm_hook_is_tracked(struct ksu_lsm_hook *hook)
{
    int i;

    for (i = 0; i < ksu_lsm_hook_count; i++) {
        if (ksu_lsm_hook_entries[i].hook == hook)
            return true;
    }

    return false;
}

static int ksu_lsm_hook_track(struct ksu_lsm_hook *hook)
{
    if (ksu_lsm_hook_is_tracked(hook))
        return 0;

    if (ksu_lsm_hook_count >= ARRAY_SIZE(ksu_lsm_hook_entries)) {
        pr_err("lsm_hook: tracking table full, cannot record %s\n", hook->head_name ?: "unknown");
        return -ENOSPC;
    }

    ksu_lsm_hook_entries[ksu_lsm_hook_count++].hook = hook;
    return 0;
}

static void ksu_lsm_hook_untrack(struct ksu_lsm_hook *hook)
{
    int i;

    for (i = 0; i < ksu_lsm_hook_count; i++) {
        if (ksu_lsm_hook_entries[i].hook != hook)
            continue;

        ksu_lsm_hook_entries[i] = ksu_lsm_hook_entries[--ksu_lsm_hook_count];
        return;
    }
}

static int ksu_lsm_hook_patch_slot(void **slot, void *value)
{
    void *patched = value;
    int ret;

    ret = ksu_patch_text(slot, &patched, sizeof(patched), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (!ret)
        smp_wmb();

    return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
/* ---- insertion into a hook list (hook->insert) -------------------------------
 *
 * security_hook_heads.member is a struct hlist_head and every LSM that implements the
 * hook owns a node in it (SELinux's live in selinux_hooks[] __lsm_ro_after_init, so
 * every write below goes through ksu_patch_text()).  Our node is one member of
 * struct ksu_lsm_hook in module memory and is writable directly - but note that it is
 * only reachable from the kernel's list after the patched write of head->first, so the
 * walk can never observe a half-initialised node.
 */

/* Locate the list head for hook->head_name and cross-check it against the kernel's own
 * registration.
 *
 * The address is computed from offsetof(struct security_hook_heads, member), and
 * security_hook_heads is __randomize_layout.  RANDSTRUCT is off in every GKI build this
 * module targets (the CI log prints the struct), so the offset is correct today - but
 * rather than depend on that, the computed value is validated against the entries the
 * kernel itself registered: LSM_HOOK_INIT sets entry->head to the address of the member
 * it was added to, so the first entry found at that address must point back at it.
 *
 * That check is what makes a wrong offset harmless: patching an hlist_head that no LSM
 * call site ever walks would install a hook that is silently never called, which reads
 * exactly like a working layer in every counter.  A mismatch fails the load instead.
 *
 * The heads this module inserts into are non-empty at load time (SELinux registers its
 * table at boot), and the replace path treated "target not found" as a hard error too,
 * so an empty head is -ENOENT rather than a second, unvalidatable code path. */
static int ksu_lsm_hook_head_at(unsigned long heads_addr, struct ksu_lsm_hook *hook,
                                struct hlist_head **out)
{
    struct hlist_head *head;
    struct security_hook_list *first;

    /* The offset must land on a whole word inside the array, or the computed address is
     * not even a head and reading it would be out of bounds. */
    if (hook->head_offset + sizeof(struct hlist_head) > sizeof(struct security_hook_heads)) {
        pr_err("lsm_hook: %s: head offset %#lx is outside security_hook_heads\n",
                hook->head_name ?: "unknown", (unsigned long)hook->head_offset);
        return -EINVAL;
    }

    head = (struct hlist_head *)(heads_addr + hook->head_offset);
    first = hlist_entry_safe(READ_ONCE(head->first), struct security_hook_list, list);

    if (!first) {
        pr_err("lsm_hook: %s: hook list is empty - refusing to insert (nothing to cross-check the head offset against)\n",
                hook->head_name ?: "unknown");
        return -ENOENT;
    }
    if (first->head != head) {
        pr_err("lsm_hook: %s: entry at %px reports head %px, computed %px - struct security_hook_heads layout mismatch, refusing to patch\n",
                hook->head_name ?: "unknown", first, first->head, head);
        return -EINVAL;
    }

    *out = head;
    return 0;
}

/* Insert our node at the head of the (non-empty) list.  Called with the lock held and
 * only after ksu_lsm_hook_head_at() validated the head. */
static int ksu_lsm_hook_insert_head(struct ksu_lsm_hook *hook, struct hlist_head *head)
{
    struct security_hook_list *node = &hook->list;
    struct hlist_node *first = READ_ONCE(head->first);
    struct security_hook_list *first_entry;
    int ret;

    first_entry = hlist_entry_safe(first, struct security_hook_list, list);
    if (!first_entry || first_entry->head != head) {
        pr_err("lsm_hook: %s: head %px changed under us, refusing to insert\n",
                hook->head_name ?: "unknown", head);
        return -EAGAIN;
    }

    /* Our node: set the hook word through the same offset the slot path uses, so the
     * per-hook initialiser never has to name the union member itself.  `lsm` is char *
     * on 5.10/5.15 and const char * on 6.1/6.6 - a plain literal assignment compiles on
     * both (CI prints the field per variant). */
    memset(node, 0, sizeof(*node));
    *(void **)((char *)node + hook->hook_offset) = hook->replacement;
    node->head = head;
    node->lsm = "susfs";
    node->list.next = first;
    node->list.pprev = &head->first;

    /* 1. head->first, in __lsm_ro_after_init memory.  This is the write that publishes
     *    the node: everything else it needs is already in place above. */
    ret = ksu_lsm_hook_patch_slot((void **)&head->first, node);
    if (ret)
        return ret;

    /* 2. the displaced node's back pointer, inside selinux_hooks[] (also RO after init).
     *    The dispatcher's walk only reads ->next, so the chain works without this - it is
     *    needed so that whoever removes THAT node later (another LSM unloading, or the
     *    kernel's own hlist_del) does not unlink from a stale pointer into our node. */
    ret = ksu_lsm_hook_patch_slot((void **)&first->pprev, &node->list.next);
    if (ret) {
        /* Roll the publication back: a node that is linked but whose neighbour points at
         * it the wrong way would corrupt the list on the next removal. */
        if (ksu_lsm_hook_patch_slot((void **)&head->first, first))
            pr_err("lsm_hook: %s: failed to roll back head->first after a failed insert\n",
                    hook->head_name ?: "unknown");
        node->list.next = NULL;
        node->list.pprev = NULL;
        return ret;
    }

    hook->entry = node;
    SUSFS_LOGI("lsm_hook: inserted %s as the first node of its list (head %px, before %px, replacement %px)\n",
            hook->head_name ?: "unknown", head, first, hook->replacement);
    return 0;
}

/* Unlink our node from the head of the list.  hook->list.pprev points either at
 * &head->first or - if something inserted in front of us after we were installed - at the
 * previous node's ->next; both live in memory that only ksu_patch_text() may write. */
static int ksu_lsm_hook_remove_head(struct ksu_lsm_hook *hook)
{
    struct hlist_node **pprev = hook->list.list.pprev;
    struct hlist_node *next = READ_ONCE(hook->list.list.next);
    int ret;

    if (!pprev || READ_ONCE(*pprev) != &hook->list.list) {
        pr_err("lsm_hook: %s: back pointer %px does not point at our node - refusing to unlink\n",
                hook->head_name ?: "unknown", pprev);
        return -EINVAL;
    }

    /* 1. whatever points at us must point at our successor. */
    ret = ksu_lsm_hook_patch_slot((void **)pprev, next);
    if (ret)
        return ret;

    /* 2. the successor must point back at that same slot.  Not needed for the walk (it
     *    never reads ->pprev), needed so that the removal of THAT node later - by any
     *    LSM, or by the kernel's own hlist_del - does not write through a pointer into
     *    this module's memory after the module is gone. */
    if (next) {
        ret = ksu_lsm_hook_patch_slot((void **)&next->pprev, pprev);
        if (ret) {
            /* Our node is already out of the chain; only the successor's back pointer is
             * stale.  Put the chain back the way it was rather than leave the list in a
             * state where a later removal writes through our node. */
            if (ksu_lsm_hook_patch_slot((void **)pprev, &hook->list.list))
                pr_err("lsm_hook: %s: failed to re-link our node after a failed unlink\n",
                        hook->head_name ?: "unknown");
            return ret;
        }
    }

    hook->list.list.next = NULL;
    hook->list.list.pprev = NULL;
    hook->entry = NULL;
    SUSFS_LOGI("lsm_hook: removed %s node from its list\n", hook->head_name ?: "unknown");
    return 0;
}
#endif /* < 6.12 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef void (*ksu_static_call_update_t)(struct static_call_key *key, void *tramp, void *func);

static int ksu_lsm_hook_update_scall(struct lsm_static_call *scall, void *value)
{
    __static_call_update(scall->key, scall->trampoline, value);
    smp_wmb();
    return 0;
}
#endif

int ksu_lsm_hook(struct ksu_lsm_hook *hook)
{
    int ret = 0;
    struct security_hook_list *entry;
    void *target;
    const char *target_name;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    static unsigned long scalls_addr = 0;
    struct lsm_static_call *scalls = NULL;
    static size_t scalls_count = 0;
    static u32 lsm_max_cnt = 5;
    struct security_hook_list *selected_entry = NULL;
    struct lsm_static_call *selected_scall = NULL;
    void **selected_slot = NULL;
    void *selected_origin = NULL;
    size_t i;
#else
    unsigned long heads_addr;
    struct hlist_head *head;
    struct security_hook_list *selected_entry = NULL;
    void **selected_slot = NULL;
    void *selected_origin = NULL;
#endif

    if (!hook || !hook->replacement)
        return -EINVAL;

    mutex_lock(&ksu_lsm_hook_lock);

    if (hook->entry) {
        ret = -EALREADY;
        goto out_unlock;
    }

    if (hook->insert) {
        /* Insertion needs no symbol: there is no original to find and no slot to match.
         * Everything it does is validated in ksu_lsm_hook_head_at() before the first
         * patched write. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
        /* Out of scope on this branch: 6.12+ does not walk security_hook_heads at all
         * (the call sites go through the static calls in lsm_static_calls_table), so
         * inserting a node into a list nobody walks would install a hook that is never
         * called - it has to be mirrored in the static-call world instead.  Fail closed
         * rather than silently no-op. */
        pr_err("lsm_hook: %s: insertion is not implemented for the 6.12+ static-call dispatch\n",
                hook->head_name ?: "unknown");
        ret = -ENOSYS;
        goto out_unlock;
#else
        heads_addr = find_kernel_symbol_exact("security_hook_heads");
        if (!heads_addr) {
            pr_err("lsm_hook: failed to resolve security_hook_heads\n");
            ret = -ENOENT;
            goto out_unlock;
        }

        ret = ksu_lsm_hook_head_at(heads_addr, hook, &head);
        if (ret)
            goto out_unlock;

        ret = ksu_lsm_hook_track(hook);
        if (ret) {
            pr_err("lsm_hook: too many hooks to track: %d\n", ret);
            goto out_unlock;
        }

        ret = ksu_lsm_hook_insert_head(hook, head);
        if (ret) {
            pr_err("lsm_hook: failed to insert %s at the head of its list: %d\n",
                    hook->head_name ?: "unknown", ret);
            ksu_lsm_hook_untrack(hook);
            goto out_unlock;
        }
        goto out_unlock;
#endif
    }

    /* ---- replace path: find the entry whose function slot holds the resolved symbol.
     * Everything below is the pre-insertion mechanism, kept for hooks that do not set
     * hook->insert (and for the 6.12+ static-call dispatch). ---- */
    target_name = hook->target_name;
    if (!target_name) {
        pr_err("lsm_hook: hook %s: target_name is required\n", hook->head_name ?: "unknown");
        ret = -EINVAL;
        goto out_unlock;
    }

    target = hook->original;
    if (!target)
        target = ksu_resolve_symbol_for_functable_hook(target_name);
    if (!target) {
        pr_err("lsm_hook: failed to resolve target for %s\n", hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }
    SUSFS_LOGI("target: 0x%lx %pSb\n", (unsigned long)target, target);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!scalls_addr) {
        scalls_addr = find_kernel_symbol_exact("static_calls_table");
    }
    if (!scalls_addr) {
        pr_err("lsm_hook: failed to resolve static_calls_table\n");
        ret = -ENOSYS;
        goto out_unlock;
    }

    if (scalls_count == 0) {
        unsigned long sym_size = sizeof(struct lsm_static_calls_table);
        u32 lsm_active_cnt = 5;
        if (!kallsyms_lookup_size_offset(scalls_addr, &sym_size, NULL)) {
            pr_err("failed to get size\n");
        }
        unsigned long addr = find_kernel_symbol_exact("lsm_active_cnt");
        if (!addr) {
            pr_err("failed to get lsm_active_cnt\n");
        } else {
            lsm_active_cnt = *(u32 *)addr;
        }
        SUSFS_LOGI("lsm_active_cnt = %d\n", lsm_active_cnt);
        if (lsm_active_cnt == 0 || lsm_active_cnt > 20) {
            pr_err("invalid lsm_active_cnt\n");
        } else {
            lsm_max_cnt = lsm_active_cnt;
            if (sym_size % (lsm_active_cnt * sizeof(struct lsm_static_call)) != 0) {
                pr_warn("invalid struct size\n");
            }
            scalls_count = sym_size / sizeof(struct lsm_static_call);
            SUSFS_LOGI("scalls_count = %zu\n", scalls_count);
        }
    }

    if (scalls_count == 0) {
        pr_err("no scalls_count found!\n");
        ret = -ENOSYS;
        goto out_unlock;
    }

    scalls = (struct lsm_static_call *)scalls_addr;
    for (i = 0; i < scalls_count; i++) {
        struct lsm_static_call *scall = &scalls[i];
        void **slot;
        void *current_origin;

        entry = READ_ONCE(scall->hl);
        if (!entry)
            continue;

        slot = (void **)((char *)entry + hook->hook_offset);
        current_origin = READ_ONCE(*slot);

        int j;
        for (j = 0; j < ksu_lsm_hook_count; j++) {
            if (ksu_lsm_hook_entries[j].hook->replacement == current_origin) {
                current_origin = ksu_lsm_hook_entries[j].hook->original;
                break;
            }
        }

        if (current_origin == hook->replacement) {
            ret = -EALREADY;
            goto out_unlock;
        }

        if (current_origin != target) {
            continue;
        }

        SUSFS_LOGI("found slot %ld orig %pSb\n", i, current_origin);

        if (!hook->offset) {
            selected_entry = entry;
            selected_scall = scall;
            selected_slot = slot;
            selected_origin = current_origin;
        } else {
            size_t hook_idx = (i / lsm_max_cnt + hook->offset) * lsm_max_cnt;
            if (hook_idx >= scalls_count) {
                pr_err("last lsm hook reached\n");
                ret = -EINVAL;
                goto out_unlock;
            }
            scall = &scalls[hook_idx];
            entry = READ_ONCE(scall->hl);
            if (entry) {
                slot = (void **)((char *)entry + hook->hook_offset);
                current_origin = READ_ONCE(*slot);
            } else {
                current_origin = NULL;
            }
            SUSFS_LOGI("found real slot %ld orig %pSb\n", i, current_origin);

            if (current_origin == hook->replacement) {
                ret = -EALREADY;
                goto out_unlock;
            }
            selected_entry = entry;
            selected_scall = scall;
            selected_slot = slot;
            selected_origin = current_origin;
        }
        break;
    }

    if (!selected_scall) {
        pr_err("lsm_hook: target %s not found in head %s\n", target_name, hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }

    ret = ksu_lsm_hook_track(hook);
    if (ret) {
        pr_err("lsm_hook: too many hooks to track: %d\n", ret);
        goto out_unlock;
    }

    if (ksu_lsm_hook_patch_slot(selected_slot, hook->replacement)) {
        pr_err("lsm_hook: failed to patch %s\n", hook->head_name ?: "unknown");
        ret = -EFAULT;
        goto out_untrack;
    }

    if (ksu_lsm_hook_update_scall(selected_scall, hook->replacement)) {
        if (ksu_lsm_hook_patch_slot(selected_slot, selected_origin)) {
            pr_err("lsm_hook: failed to roll back %s after static call update failure\n", hook->head_name ?: "unknown");
        }
        ret = -EFAULT;
        goto out_untrack;
    }

    if (!selected_origin)
        static_branch_enable(selected_scall->active);

    hook->entry = selected_entry;
    hook->scall = selected_scall;
    hook->original = selected_origin;
    SUSFS_LOGI("lsm_hook: patched %s hook slot %px from %px to %px\n", hook->head_name ?: "unknown", selected_slot,
            selected_origin, hook->replacement);
#else
    heads_addr = find_kernel_symbol_exact("security_hook_heads");
    if (!heads_addr) {
        pr_err("lsm_hook: failed to resolve security_hook_heads\n");
        ret = -ENOENT;
        goto out_unlock;
    }
    unsigned long heads_size = sizeof(struct security_hook_heads);
    /* heads_size is deliberately just sizeof() and not kallsyms_lookup_size_offset():
     * that symbol is UNEXPORTED in every GKI tree this module targets, so calling it
     * makes the module unloadable by a plain `insmod` (unknown symbol) on all six
     * variants - and the lookup only ever produced this same number, since the fallback
     * was already the struct size.  Deleting the call is behaviour-neutral. */

    head = (struct hlist_head *)heads_addr;
    struct hlist_head *head_end = (struct hlist_head *)(heads_addr + heads_size);
    SUSFS_LOGI("heads_addr 0x%lx head_offset 0x%lx heads_size %ld hook_offset 0x%lx\n", (unsigned long)heads_addr,
            hook->head_offset, heads_size, hook->hook_offset);

    for (; head < head_end; head++) {
        hlist_for_each_entry (entry, head, list) {
            void **slot = (void **)((char *)entry + hook->hook_offset);
            void *current_origin = READ_ONCE(*slot);
            int j;
            for (j = 0; j < ksu_lsm_hook_count; j++) {
                if (ksu_lsm_hook_entries[j].hook->replacement == current_origin) {
                    current_origin = ksu_lsm_hook_entries[j].hook->original;
                    break;
                }
            }
            if (current_origin == hook->replacement) {
                ret = -EALREADY;
                goto out_unlock;
            }
            if (current_origin == target) {
                SUSFS_LOGI("found %s (target %s) at head offset %ld (provided %ld)\n", hook->head_name, hook->target_name,
                        (unsigned long)head - heads_addr, hook->head_offset);
                selected_entry = entry;
                selected_slot = slot;
                selected_origin = current_origin;
                break;
            }
        }
        if (selected_entry) {
            if (hook->offset) {
                head += hook->offset;
                if (head < (struct hlist_head *)heads_addr || head >= head_end) {
                    pr_err("invalid offset\n");
                    ret = -EINVAL;
                    goto out_unlock;
                }
                /* just check if already hooked */
                hlist_for_each_entry (entry, head, list) {
                    void **slot = (void **)((char *)entry + hook->hook_offset);
                    void *current_origin = READ_ONCE(*slot);
                    if (current_origin == hook->replacement) {
                        ret = -EALREADY;
                        goto out_unlock;
                    }
                }
                if (head->first) {
                    selected_entry = hlist_entry(head->first, struct security_hook_list, list);
                    selected_slot = (void **)((char *)selected_entry + hook->hook_offset);
                    selected_origin = *selected_slot;
                } else {
                    selected_entry = &hook->list;
                    hook->list.head = head;
                    hook->list.list.next = NULL;
                    hook->list.list.pprev = &head->first;
                    hook->list.lsm = "ksu";
                    *(void **)((char *)selected_entry + hook->hook_offset) = hook->replacement;
                    selected_slot = (void **)&head->first;
                    selected_origin = NULL;
                }
            }
            break;
        }
    }

    if (!selected_entry) {
        pr_err("lsm_hook: target %s not found in head %s\n", target_name, hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }

    ret = ksu_lsm_hook_track(hook);
    if (ret) {
        pr_err("lsm_hook: too many hooks to track: %d\n", ret);
        goto out_unlock;
    }

    if (selected_origin) {
        SUSFS_LOGI("patch func addr\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, hook->replacement);
    } else {
        SUSFS_LOGI("patch head->first\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, &hook->list);
    }

    if (ret) {
        pr_err("lsm_hook: failed to patch %s\n", hook->head_name ?: "unknown");
        ret = -EFAULT;
        goto out_untrack;
    }

    hook->entry = selected_entry;
    hook->original = selected_origin;
    SUSFS_LOGI("lsm_hook: patched %s hook slot %px from %px to %px\n", hook->head_name ?: "unknown", selected_slot,
            selected_origin, hook->replacement);
#endif
    goto out_unlock;
out_untrack:
    ksu_lsm_hook_untrack(hook);

out_unlock:
    mutex_unlock(&ksu_lsm_hook_lock);
    return ret;
}

void ksu_lsm_unhook(struct ksu_lsm_hook *hook)
{
    void **slot;
    mutex_lock(&ksu_lsm_hook_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!hook->entry || !hook->scall) {
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }
    slot = (void **)((char *)hook->entry + hook->hook_offset);
    if (ksu_lsm_hook_patch_slot(slot, hook->original)) {
        pr_err("lsm_hook: failed to restore %s\n", hook->head_name ?: "unknown");
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }
    if (ksu_lsm_hook_update_scall(hook->scall, hook->original)) {
        if (ksu_lsm_hook_patch_slot(slot, hook->replacement))
            pr_err("lsm_hook: failed to reapply %s after static call restore failure\n", hook->head_name ?: "unknown");
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }
    SUSFS_LOGI("lsm_hook: restored %s hook slot %px to %px\n", hook->head_name ?: "unknown", slot, hook->original);
#else
    if (!hook->entry) {
        mutex_unlock(&ksu_lsm_hook_lock);
        return;
    }

    if (hook->entry == &hook->list) {
        /* Our own struct security_hook_list node is in the list: either a hook->insert
         * node, or (legacy) a replace-mode hook that found its head empty.  Both are
         * unlinked the same way - the general hlist removal through hook->list.pprev,
         * which is &head->first for a node at the head, so the old code's
         * "head->first = NULL" falls out of it. */
        if (ksu_lsm_hook_remove_head(hook)) {
            mutex_unlock(&ksu_lsm_hook_lock);
            return;
        }
    } else {
        slot = (void **)((char *)hook->entry + hook->hook_offset);
        SUSFS_LOGI("unhook patch slot\n");
        if (ksu_lsm_hook_patch_slot(slot, hook->original)) {
            pr_err("lsm_hook: failed to restore %s\n", hook->head_name ?: "unknown");
            mutex_unlock(&ksu_lsm_hook_lock);
            return;
        }
        SUSFS_LOGI("lsm_hook: restored %s hook slot %px to %px\n", hook->head_name ?: "unknown", slot, hook->original);
    }
#endif

    ksu_lsm_hook_untrack(hook);
    hook->entry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    hook->scall = NULL;
#endif
    mutex_unlock(&ksu_lsm_hook_lock);

    /* Drained AFTER the lock is released.  The wait is unbounded by nature
     * (synchronize_rcu_tasks() waits for every task to reach a quiescent state, and
     * the fallback is a 50 ms sleep), and holding ksu_lsm_hook_lock across it
     * serialised every other hook operation behind this one - including the rollback
     * of a failed load.  The node/slot is already unlinked above, so nothing can newly
     * enter the replacement function while we wait.  It stays on the removal path for
     * the insert case as much as for the slot case: the dispatcher's walk is not an
     * RCU read-side section (see ksu_lsm_hook_drain()), and a task can be inside our
     * replacement - reached through the very node that was just unlinked - when the
     * module text goes away. */
    ksu_lsm_hook_drain();
}

/* Wait until nothing can still be inside a replacement function.
 *
 * synchronize_rcu() is not enough here: the LSM call sites walk their hook list
 * with a plain hlist_for_each_entry (security/security.c), so they are not RCU
 * read-side sections and a task that is already executing our replacement is
 * invisible to that barrier.  It can still be there when the module text is
 * unmapped, which is a use-after-free on the next instruction.
 *
 * synchronize_rcu_tasks() waits for every task to pass through a context switch,
 * which does cover it.  The symbol is resolved at runtime and called through a
 * __nocfi wrapper (kCFI checks the type hash at such a call sites); if it cannot
 * be resolved, a delay is the fallback, and synchronize_rcu() still runs. */
static void (*ksu_lsm_sync_rcu_tasks_fn)(void);
static bool ksu_lsm_sync_looked_up;

static __nocfi void ksu_lsm_call_drain(void (*fn)(void))
{
    fn();
}

static void ksu_lsm_hook_drain(void)
{
    if (!ksu_lsm_sync_looked_up) {
        ksu_lsm_sync_rcu_tasks_fn =
            (void *)find_kernel_symbol_exact("synchronize_rcu_tasks");
        if (ksu_lsm_sync_rcu_tasks_fn) {
            /* Cache SUCCESS only: caching a failure keeps the 50 ms fallback forever,
             * even on a kernel where the symbol would have been found later. */
            ksu_lsm_sync_looked_up = true;
        } else {
            pr_warn("lsm_hook: synchronize_rcu_tasks not found, using a delay\n");
        }
    }

    synchronize_rcu();
    if (ksu_lsm_sync_rcu_tasks_fn)
        ksu_lsm_call_drain(ksu_lsm_sync_rcu_tasks_fn);
    else
        msleep(50);
}

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
    return ksu_lsm_hook(hook);
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
    ksu_lsm_unhook(hook);
}

/* No __init/__exit annotation on these two, on purpose: the module's layer table
 * (susfs_main.c) holds their addresses and calls the exit from the rollback path of
 * a FAILED load, i.e. from plain .text.  Keeping them in the init/exit sections
 * would make the table hold a pointer into a section modpost reports as a mismatch
 * and the kernel frees after a successful load.  They are a few dozen bytes. */
void ksu_lsm_hook_init(void)
{
    SUSFS_LOGI("lsm_hook: init, tracked hooks=%d\n", READ_ONCE(ksu_lsm_hook_count));
}

void ksu_lsm_hook_exit(void)
{
    struct ksu_lsm_hook *hooks[ARRAY_SIZE(ksu_lsm_hook_entries)];
    int count;
    int i;

    mutex_lock(&ksu_lsm_hook_lock);
    count = ksu_lsm_hook_count;
    for (i = 0; i < count; i++)
        hooks[i] = ksu_lsm_hook_entries[i].hook;
    mutex_unlock(&ksu_lsm_hook_lock);

    for (i = count - 1; i >= 0; i--)
        ksu_lsm_unhook(hooks[i]);
}
