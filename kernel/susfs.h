/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_H
#define __SUSFS_H

#include <linux/string.h>
#include <linux/err.h>	/* IS_ERR */
#include <linux/mm.h>	/* PAGE_SIZE */

/* A kernel pointer taken out of a kprobe register, checked before it is
 * dereferenced.
 *
 * single_open()s fake inode is (void *)1, and a kretprobe on a function the kernel
 * calls with such a sentinel hands that value over as "the argument": this module
 * once panicked on exactly that (the sus_map vma probe, fault address 0xa1, fixed
 * with a "< PAGE_SIZE" test that only that one probe had).  Every kernel object
 * lives above the first page, so that one test covers the sentinel as well as a
 * garbage register, and IS_ERR() covers the error-pointer convention.  User
 * pointers must NOT go through it - they are legitimately small. */
static inline bool susfs_ptr_plausible(const void *p)
{
	return (unsigned long)p >= PAGE_SIZE && !IS_ERR(p);
}

/* Bind a fixed-size ABI pathname field to a C string safely.
 *
 * The st_susfs_* structs carry char[N] pathname fields that a caller need not
 * NUL-terminate.  Handing such a field to strlen()/strcmp()/kern_path() walks
 * off the end of the struct - and the struct lives on OUR kernel stack, so it
 * reads (and then resolves) whatever follows it.  Every consumer of an ABI
 * pathname must pass it through this check first. */
static inline bool susfs_abi_path_ok(const char *field, size_t size)
{
	return strnlen(field, size) < size;
}

/* Add a path to sus_path's hidden set from kernel code (no supercall needed).
 * Used to self-hide the /proc control nodes.  Returns 0 or a negative errno. */
int sus_path_add_hidden(const char *path);

/* Same, for one of this module's own control nodes: the rule is flagged so the
 * gate hides it from EVERY non-root caller, not merely from apps (uid>=10000).
 * Without that, a probe running as system (1000) or shell (2000) reads the node
 * name straight out of /proc - see sus_path_entry_gate_any(). */
int sus_path_add_self_hidden(const char *path);

/* Undo sus_path_add_self_hidden(): drop the rule for @path and restore whatever it
 * changed (the relaxed mode, the inode reference).  Returns the number of rules
 * removed, so 0 means "it was not registered".  Process context only (iput). */
int sus_path_del_path(const char *path);

/* The module's own name, in the two spellings the kernel derives from it: the
 * /sys/module directory and the "modinfo name" are both the module file name, and
 * the self-hide rules and the /proc/modules filter have to agree with it. */
#define SUSFS_LKM_MODULE_NAME "susfs_guard_lkm"
#define SUSFS_LKM_SYSFS_DIR   "/sys/module/" SUSFS_LKM_MODULE_NAME

/* hide_modules (susfs_hide_syms.c): filters a list of module NAMES out of
 * /proc/modules (and out of /sys/module for non-root callers, and their
 * /proc/kallsyms lines).  Control surface: this node, plus the parameter of the same
 * name.  Both are root-only; the node answers ENOENT for everyone else because it is
 * registered in sus_path's self-protected set. */
#define SUSFS_HIDE_MODULES_NODE "/proc/susfs_hide_modules"
bool susfs_hide_modules_active(void);

/* The sus_mount control node: it decides WHICH mounts count as ours (the on/off
 * switch stays the hide_sus_mnts_for_non_su_procs supercall).  Root-only commands,
 * ENOENT for everyone else through sus_path - the same contract as the other nodes. */
#define SUSFS_HIDE_MOUNTS_NODE "/proc/susfs_hide_mounts"
bool susfs_hide_modules_node_ready(void);

/* sus_path's own control node.  `cat` is the rule listing - the same view the hide_list
 * parameter prints - and writing takes the commands (add/del/clear).  It exists because
 * the listing used to be reachable only through a sysfs parameter while every other
 * control surface of this module has a /proc front end, and a rule table an operator
 * cannot see is how "the rule is registered but nothing is hidden" stays invisible.
 * Root-only, and registered in the self-protected set: everyone else gets ENOENT. */
#define SUSFS_PATH_NODE "/proc/susfs_path"

/* Whether the /proc/susfs_* control nodes are created at all.  Defaults to TRUE:
 * the nodes are the module's own interface, and sus_path hides them from every
 * non-root caller (ENOENT, not EACCES).  They are only created when the LSM
 * layer that does the hiding is actually installed, so nobody can end up with an
 * unprotected control node; expose_proc=0 removes them entirely.
 * Defined in susfs_main.c. */
extern bool susfs_expose_proc;

/* feature init/exit (each feature is its own translation unit) */
int susfs_uname_init(void);
void susfs_uname_exit(void);

int susfs_kstat_init(void);
void susfs_kstat_exit(void);

int susfs_sus_map_init(void);
void susfs_sus_map_exit(void);

int sus_path_init(void);
void sus_path_exit(void);

int susfs_sus_mount_init(void);
void susfs_sus_mount_exit(void);

int susfs_spoof_cmdline_init(void);
void susfs_spoof_cmdline_exit(void);

int susfs_open_redirect_init(void);
void susfs_open_redirect_exit(void);

int susfs_enable_log_init(void);
void susfs_enable_log_exit(void);
bool susfs_log_enabled(void);

int susfs_avc_spoof_init(void);
void susfs_avc_spoof_exit(void);

int susfs_supercall_init(void);
void susfs_supercall_exit(void);

/* feature supercall handlers (upstream signature: void xxx(void __user **arg)) */
void susfs_uname_supercall(void __user **arg);
void susfs_enable_log_supercall(void __user **arg);
void susfs_avc_spoof_supercall(void __user **arg);
void susfs_spoof_cmdline_supercall(void __user **arg);
void susfs_sus_map_supercall(void __user **arg);
void sus_path_supercall(unsigned int cmd, void __user **arg);
void susfs_kstat_supercall(unsigned int cmd, void __user **arg);
void susfs_open_redirect_supercall(void __user **arg);
void susfs_sus_mount_supercall(void __user **arg);

int susfs_hide_syms_init(void);
void susfs_hide_syms_exit(void);

/* Actual install state.  enabled_features must not advertise a feature whose
 * registration failed - hide_syms used to fail silently and still be reported
 * as active, which is exactly the kind of inconsistency a detector looks for. */
bool susfs_hide_syms_active(void);
bool sus_path_lsm_active(void);

/* Whether a 0777 /proc/susfs_* control node may be created.
 *
 * Two independent conditions, neither optional:
 *   - susfs_expose_proc: the operator opted in to having the nodes at all;
 *   - sus_path_lsm_active(): with 0777 DAC lets every caller through, so the
 *     LSM layer is the only thing that can still answer ENOENT for an app.
 *
 * This gates node CREATION ONLY.  It must never gate hook registration: an
 * earlier revision returned early from the feature inits on !susfs_expose_proc,
 * which silently disabled sus_kstat's tracepoint and kretprobe entirely (rules
 * were still accepted over the supercall and never applied). */
static inline bool susfs_control_node_allowed(void)
{
	return susfs_expose_proc && sus_path_lsm_active();
}

/* open_redirect, reverse direction, for callers that only have an inode NUMBER:
 * fdinfo prints "ino:\t<i>" with no device, so this is a lookup by ino alone and
 * returns false when the number is ambiguous (two rules, same redirected ino) or when the caller is not one the reverse disguise applies to.  On success *out_ino is the target inode the caller should be shown and *out_mnt_id the target mount id (0 when unknown). */
bool susfs_open_redirect_spoof_ids(unsigned long ino, unsigned long *out_ino, unsigned long *out_mnt_id);

#endif
