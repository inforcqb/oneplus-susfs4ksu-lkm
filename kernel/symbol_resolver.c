/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symbol_resolver.c - kernel symbol lookup (ported from KernelSU/SukiSU
 * infra/symbol_resolver.c).
 *
 * NO kallsyms_* ENTRY POINT IS AN ELF IMPORT HERE
 * ----------------------------------------------
 * A module that imports a symbol provided by ANOTHER MODULE cannot load until that module
 * is loaded first.  On a 6.1 device with KernelSU built as a module, kallsyms_lookup_name,
 * kallsyms_lookup, kallsyms_lookup_size_offset, kallsyms_on_each_symbol and
 * kallsyms_on_each_match_symbol are all provided by kernelsu.ko - so an `extern` reference
 * to any of them silently makes this module depend on KernelSU, which is the exact
 * opposite of the point of shipping our own loader.
 *
 * They are bootstrapped at runtime instead: register_kprobe() resolves a symbol NAME
 * through the kernel's own kallsyms and never consults the export table, so it needs no
 * link-time reference of its own.  The .github/workflows/build-ddk.yml step
 * "Verify sections" fails the build if any of those five names comes back into the .ko's
 * undefined-symbol list.
 *
 * GKI disables kallsyms_lookup_name export, so resolution walks kallsyms via
 * kallsyms_on_each_symbol.  For function-table hooks under LLVM CFI (< 6.1),
 * the slot stores the ".cfi_jt" jump-table variant rather than the function
 * itself; ksu_resolve_symbol_for_functable_hook() prefers that variant.
 */
#include "symbol_resolver.h"
#include "susfs_log.h"
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

/* https://github.com/torvalds/linux/commit/89245600941e4e0f87d77f60ee269b5e61ef4e49 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define USE_KCFI 1
#else
#define USE_KCFI 0
#endif

#if !USE_KCFI
static const char cfi_suffix[] = ".cfi_jt";
static const size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;
#endif

/* It's not guaranteed kallsyms_on_each_symbol exists in 5.x. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define ALWAYS_HAVE_ON_EACH_SYMBOL 1
#else
#define ALWAYS_HAVE_ON_EACH_SYMBOL 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_ON_EACH_MATCH_SYMBOL 1
#else
#define HAVE_ON_EACH_MATCH_SYMBOL 0
#endif

/* ---- the four entry points, all of them runtime-bootstrapped --------------------
 *
 * File-scope pointers, NULL until ksu_init_symbol_resolver() runs.  Every call through one
 * of them sits in a __nocfi function: a pointer is called indirectly and CFI checks
 * indirect call sites, so on a kCFI kernel (6.1+) a wrong type is a panic at that call,
 * not a compile-time complaint.
 */
static unsigned long (*kallsyms_lookup_name_fn)(const char *name) = NULL;
static const char *(*kallsyms_lookup_fn)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset,
                                         char **modname, char *namebuf) = NULL;

/*
 * The walker's callback signature lost its `struct module *` argument in 6.6, so the
 * POINTER's type is version-gated exactly like the callbacks below (that argument is also
 * what carries the module-ownership information before 6.6 - see ksu_exact_name_cb()).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
typedef int (*ksu_on_each_symbol_fn_t)(int (*fn)(void *, const char *, unsigned long), void *data);
#else
typedef int (*ksu_on_each_symbol_fn_t)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
#endif

static ksu_on_each_symbol_fn_t kallsyms_on_each_symbol_fn = NULL;

#if HAVE_ON_EACH_MATCH_SYMBOL
static int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long), const char *name, void *data) = NULL;
static int find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 0;
}
#endif

/*
 * Resolve a symbol NAME at runtime.  This is why nothing in this file imports a
 * kallsyms_* symbol: register_kprobe() looks the name up in the kernel's own kallsyms
 * (that is what .symbol_name is for) and never touches the export table.  The only
 * link-time dependencies it adds are register_kprobe/unregister_kprobe, which this module
 * already imports for its other kprobes.
 *
 * __nocfi: the address it returns is stored in a function pointer and called indirectly,
 * and an indirect call is what CFI checks - so the calling side is __nocfi too (see
 * find_kernel_symbol_exact() and resolve_symbol_variant()).
 *
 * Failure is normal, not fatal: NULL only leaves that pointer NULL, which turns off the
 * features that need it (find_kernel_symbol_exact() then returns 0).  It must never be
 * turned into a load failure.
 */
static __nocfi void *ksu_bootstrap_symbol(const char *name)
{
    struct kprobe kp;
    void *addr = NULL;

    memset(&kp, 0, sizeof(kp));
    /* The cast keeps this warning-free whichever const-ness this tree declares for
     * symbol_name. */
    kp.symbol_name = (void *)name;

    if (!register_kprobe(&kp)) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    }

    if (!addr)
        pr_warn("symbol_resolver: cannot bootstrap %s (kprobe could not resolve it)\n", name);

    return addr;
}

struct ksu_lookup_symbol_ctx {
    const char *symbol_name;
    size_t symbol_len;
    void *match;
};

/* Exact-name lookup through the walker.  Only reachable when kallsyms_lookup() itself did
 * not bootstrap (see find_kernel_symbol_exact()); before 6.6 this callback is also the
 * module-ownership check, because `mod` is the only owner information the kernel hands out
 * once kallsyms_lookup() is gone. */
struct ksu_exact_name_ctx {
    const char *symbol_name;
    unsigned long addr;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int ksu_exact_name_cb(void *data, const char *name, unsigned long addr)
#else
static int ksu_exact_name_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_exact_name_ctx *ctx = data;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    /* OWNERSHIP, before 6.6: a non-NULL `mod` means another module provides this symbol -
     * the same fact kallsyms_lookup()'s modname reports - and it is refused here. */
    if (mod)
        return 0;
#endif

    if (!name || strcmp(name, ctx->symbol_name) != 0)
        return 0;

    ctx->addr = addr;
    return 1;	/* stop the walk */
}

unsigned long __nocfi find_kernel_symbol_exact(const char *symbol_name)
{
    unsigned long addr = 0;

    if (!symbol_name || !symbol_name[0])
        return 0;

#if HAVE_ON_EACH_MATCH_SYMBOL
    /* 6.1+ can match the exact name in the kernel.  It carries no ownership check, which
     * is why it is only tried first and not the only path - the same order as before this
     * file stopped importing kallsyms_lookup_name. */
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(find_kernel_symbol_exact_cb, symbol_name, &addr);
        return addr;
    }
#endif

    /* Graceful degradation, and the one place it is decided: with no bootstrapped
     * kallsyms_lookup_name there is no name lookup at all, so every feature that needs a
     * resolved symbol stays off and says so at its own init.  The module still loads. */
    if (unlikely(!kallsyms_lookup_name_fn))
        return 0;

    addr = kallsyms_lookup_name_fn(symbol_name);
    if (!addr)
        return 0;	/* walking kallsyms for address 0 answers nothing */

    if (likely(kallsyms_lookup_fn)) {
        /* PATH IN USE on every kernel this module builds against: name -> address with the
         * bootstrapped kallsyms_lookup_name(), then the ownership check with the
         * bootstrapped kallsyms_lookup() - the same two calls as before this change, only
         * reached through pointers now.  modname is non-NULL for a symbol a module owns,
         * and such a symbol is refused because that module may not be loaded at all. */
        char *module_name = NULL;
        char buf[KSYM_SYMBOL_LEN];

        kallsyms_lookup_fn(addr, NULL, NULL, &module_name, buf);
        if (unlikely(module_name)) {
            pr_warn("ignore symbol %s of module %s\n", symbol_name, module_name);
            return 0;
        }
        return addr;
    }

    /* kallsyms_lookup() is unavailable, so the owner has to come from the walker instead:
     * before 6.6 its callback is handed the owning `struct module *`, and
     * ksu_exact_name_cb() refuses a symbol whose mod is non-NULL - the rule "never take a
     * symbol another MODULE provides" is enforced by the walk.  The walk must also confirm
     * the address, otherwise we would be trusting a symbol we could not check. */
    if (kallsyms_on_each_symbol_fn) {
        struct ksu_exact_name_ctx ctx = { .symbol_name = symbol_name };

        kallsyms_on_each_symbol_fn(ksu_exact_name_cb, &ctx);
        if (ctx.addr != addr) {
            pr_warn("ignore symbol %s: the kallsyms walk did not confirm it as vmlinux's\n", symbol_name);
            return 0;
        }
        return addr;
    }

    /* Neither kallsyms_lookup() nor the walker bootstrapped, and from 6.6 the walker does
     * not carry the owner either - so nothing is left to check the owner with.  Fail
     * closed rather than take a symbol whose owner cannot be verified.  This is not a path
     * any supported kernel takes: they bootstrap from the same kernel and succeed or fail
     * together, and on 6.1+ the match-symbol walk above answers first. */
    pr_warn("ignore symbol %s: its owner cannot be checked on this kernel\n", symbol_name);
    return 0;
}

static inline bool ksu_symbol_has_suffix(const char *name, size_t name_len, const char *suffix, size_t suffix_len)
{
    return name_len >= suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int lookup_symbol_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int lookup_symbol_variant_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;
    size_t name_len;

    if (!name || !addr)
        return 0;

    name_len = strlen(name);

    if (strcmp(name, ctx->symbol_name) != 0) {
        if (name_len <= ctx->symbol_len || strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0 ||
            name[ctx->symbol_len] != '.')
            return 0;
    }

#if !USE_KCFI
    if (ksu_symbol_has_suffix(name, name_len, cfi_suffix, cfi_suffix_len)) {
        ctx->match = (void *)addr;
        SUSFS_LOGI("use .cfi_jt variant: %s\n", name);
        return 1;
    }
#endif

    if (!ctx->match) {
        ctx->match = (void *)addr;
        SUSFS_LOGI("found variant: %s\n", name);
#if USE_KCFI
        return 1;
#endif
    }

    return 0;
}

static __nocfi void *resolve_symbol_variant(const char *symbol_name, size_t symbol_len)
{
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
    };

    /* Indirect call: __nocfi above, like every other call through these pointers. */
    if (unlikely(!kallsyms_on_each_symbol_fn))
        return NULL;

    kallsyms_on_each_symbol_fn(lookup_symbol_variant_cb, &ctx);

    return ctx.match;
}

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name)
{
    void *addr;
    size_t symbol_len;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);

#if !USE_KCFI
    /* Try .cfi_jt suffix first */
    char cfi_name[KSYM_NAME_LEN];
    snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", symbol_name);
    addr = (void *)find_kernel_symbol_exact(cfi_name);
    if (addr)
        return addr;

    addr = resolve_symbol_variant(symbol_name, symbol_len);
    if (addr)
        return addr;

    return (void *)find_kernel_symbol_exact(symbol_name);
#else
    addr = (void *)find_kernel_symbol_exact(symbol_name);
    if (addr)
        return addr;

    return resolve_symbol_variant(symbol_name, symbol_len);
#endif
}

void __init ksu_init_symbol_resolver(void)
{
    int match_ok = 0;

    /* Every one of these is bootstrapped by NAME through a kprobe - never linked against.
     * A NULL result is a degradation, not an error: it only turns off the features that
     * need that entry point. */
    kallsyms_lookup_name_fn = ksu_bootstrap_symbol("kallsyms_lookup_name");
    kallsyms_lookup_fn = ksu_bootstrap_symbol("kallsyms_lookup");
    kallsyms_on_each_symbol_fn = ksu_bootstrap_symbol("kallsyms_on_each_symbol");
#if ALWAYS_HAVE_ON_EACH_SYMBOL
    /* From 5.19 the walker is always there, so its absence is a real loss of coverage;
     * before 5.19 it may simply not exist and ksu_bootstrap_symbol()'s warning is the
     * whole story. */
    if (!kallsyms_on_each_symbol_fn)
        pr_warn("kallsyms_on_each_symbol exists in every 5.19+ kernel but did not resolve!\n");
#endif
#if HAVE_ON_EACH_MATCH_SYMBOL
    kallsyms_on_each_match_symbol_fn = ksu_bootstrap_symbol("kallsyms_on_each_match_symbol");
    match_ok = !!kallsyms_on_each_match_symbol_fn;
#endif

    /* One line for the record: whether these came up decides which mechanism resolves
     * symbols, which is what makes "feature X stays off" readable in a log. */
    SUSFS_LOGI("symbol_resolver: kprobe bootstrap (1 = usable): lookup_name=%d lookup=%d walker=%d match=%d\n",
               !!kallsyms_lookup_name_fn, !!kallsyms_lookup_fn, !!kallsyms_on_each_symbol_fn, match_ok);
}
