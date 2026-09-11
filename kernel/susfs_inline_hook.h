/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_INLINE_HOOK_H
#define __SUSFS_INLINE_HOOK_H

#include <linux/types.h>

/* One patched entry point.
 *
 * entry      the function we patch (its real entry, not a .cfi_jt thunk)
 * orig       the two instructions the patch overwrites
 * tramp      module_alloc page holding: bti c ; orig[0] ; orig[1] ;
 *            ldr x16,#8 ; ret x16 ; entry+8
 * tramp_var  the .S variable the matching stub loads that address from
 * installed  whether the entry currently holds the patch
 */
struct susfs_ih_hook {
	unsigned long entry;
	u32 orig[2];
	void *tramp;
	u64 *tramp_var;
	bool installed;
};

/* Resolve module_alloc / set_memory_* (needed once, before any install). */
int susfs_ih_init(void);
bool susfs_ih_ready(void);

/* Patch `sym` to jump into `stub`, which must load its trampoline from
 * `tramp_var`.  Returns 0 or a negative errno; on failure nothing is patched. */
int susfs_ih_install(struct susfs_ih_hook *h, const char *sym, void *stub,
		     u64 *tramp_var);

/* Restore the original instructions.  The trampoline page is retired, never
 * freed: a CPU may still be running it. */
void susfs_ih_uninstall(struct susfs_ih_hook *h);

#endif
