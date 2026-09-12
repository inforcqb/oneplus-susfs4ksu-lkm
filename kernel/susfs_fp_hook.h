/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * susfs_fp_hook.h - syscall interception by replacing a sys_call_table entry
 */

#ifndef __SUSFS_FP_HOOK_H
#define __SUSFS_FP_HOOK_H

#include <linux/types.h>

struct pt_regs;

/* The kernel's own syscall entry type: on arm64 a table entry is a function that
 * takes the caller's registers.  Kept as our own typedef so this file does not
 * depend on <asm/syscall.h> being reachable. */
typedef long (*susfs_syscall_fn_t)(const struct pt_regs *regs);

struct susfs_fp_hook {
	int nr;					/* __NR_* */
	const char *name;			/* our wrapper, for logs */
	const char *sym;			/* the kernel's wrapper symbol, for logs */
	susfs_syscall_fn_t wrapper;		/* what we put into the table */
	susfs_syscall_fn_t *orig_slot;		/* where the wrapper reads the original */
	susfs_syscall_fn_t orig;		/* the entry we replaced */
	bool installed;
};

/* Resolves and caches sys_call_table; 0 on the first success. */
int susfs_fp_init(void);

unsigned long susfs_fp_syscall_table(void);

int susfs_fp_install(struct susfs_fp_hook *h);
void susfs_fp_remove(struct susfs_fp_hook *h);

/* Blocks until no CPU can still be inside a wrapper; call before the module text
 * may go away (i.e. once, after all entries are restored). */
void susfs_fp_drain(void);

/* Prints table[nr] next to the plain and the .cfi_jt symbol for one entry. */
void susfs_fp_dump_entry(int nr, const char *sym);

/* Prints the first instruction of a wrapper - 'bti c' or nothing. */
void susfs_fp_dump_wrapper(const char *name, const void *fn);

#endif /* __SUSFS_FP_HOOK_H */
