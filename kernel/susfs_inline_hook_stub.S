/* SPDX-License-Identifier: GPL-2.0
 *
 * susfs_inline_hook_stub.S - the landing code for every inline-hooked entry.
 *
 * A patched entry is `bti c ; b <stub>`, so a stub is entered with the target's
 * argument registers untouched, LR still the caller's return address, and SP
 * exactly as it was on entry to the real function.
 *
 * The C decision function may clobber x0-x18 (AAPCS caller-saved), and the allow
 * path hands control to the trampoline, whose first replayed instruction is the
 * target's own prologue - it expects the original arguments.  Hence the full
 * save/restore, which is the first of the four faults recorded in
 * INLINE_HOOK.md.
 *
 * Both exits use `ret x16`, exempt from the BTI check where `br` is not.
 */

#define IH_SAVE()						\
	sub	sp, sp, #160;					\
	stp	x0,  x1,  [sp, #0];				\
	stp	x2,  x3,  [sp, #16];				\
	stp	x4,  x5,  [sp, #32];				\
	stp	x6,  x7,  [sp, #48];				\
	stp	x8,  x9,  [sp, #64];				\
	stp	x10, x11, [sp, #80];				\
	stp	x12, x13, [sp, #96];				\
	stp	x14, x15, [sp, #112];				\
	stp	x16, x17, [sp, #128];				\
	stp	x18, x30, [sp, #144]

#define IH_RESTORE()						\
	ldp	x0,  x1,  [sp, #0];				\
	ldp	x2,  x3,  [sp, #16];				\
	ldp	x4,  x5,  [sp, #32];				\
	ldp	x6,  x7,  [sp, #48];				\
	ldp	x8,  x9,  [sp, #64];				\
	ldp	x10, x11, [sp, #80];				\
	ldp	x12, x13, [sp, #96];				\
	ldp	x14, x15, [sp, #112];				\
	ldp	x16, x17, [sp, #128];				\
	ldp	x18, x30, [sp, #144];				\
	add	sp, sp, #160

#define IH_TAIL(n)						\
	IH_RESTORE();						\
	adrp	x16, susfs_ih_tramp_##n;			
	add	x16, x16, :lo12:susfs_ih_tramp_##n;			\
	ldr	x16, [x16];					\
	br	x16

#define IH_HIDE()						\
	IH_RESTORE();						\
	mov	x0, #-2;	/* -ENOENT */			\
	ret

	.text

/* syscall wrappers: x0 is the pt_regs to read the user pointer from, argno the
 * x-register holding the pathname in the 64-bit ABI. */
#define SUSFS_IH_SYS_STUB(n, argno)				\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	mov	w1, #argno;					\
	bl	susfs_ih_decide;				\
	cbz	x0, 9f;						\
	IH_HIDE();						\
9:;								\
	IH_TAIL(n);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* name-taking entries (filename_lookup, do_filp_open, user_path_at_empty): the
 * name is in x1, and w1 carries the mode (0 = struct filename, 1 = user ptr). */
#define SUSFS_IH_NAME_STUB(n, mode)				\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	mov	x0, x1;						\
	mov	w1, #mode;					\
	bl	susfs_ih_decide_name;				\
	cbz	x0, 9f;						\
	IH_HIDE();						\
9:;								\
	IH_TAIL(n);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* onLeave hook: the same patch, but the stub hands the frame back to itself.
 *
 * It stores the caller's real LR in a spare slot, points the target's LR at the
 * label after the trampoline jump, and enters the original function.  The
 * target's own prologue (paciasp and friends) then signs THAT LR, so its
 * epilogue restores and authenticates it happily - and control lands back here
 * with x0 holding the target's return value.  We then call the C after-handler
 * and leave with the real LR, so this can rewrite a return value.
 *
 * Layout: [0..144] x0-x18, [152] LR for the target, [160] real LR,
 *         [168] the target's return value. */
#define SUSFS_IH_LEAVE_STUB(n, after_fn)			\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	sub	sp, sp, #192;					\
	stp	x0,  x1,  [sp, #0];				\
	stp	x2,  x3,  [sp, #16];				\
	stp	x4,  x5,  [sp, #32];				\
	stp	x6,  x7,  [sp, #48];				\
	stp	x8,  x9,  [sp, #64];				\
	stp	x10, x11, [sp, #80];				\
	stp	x12, x13, [sp, #96];				\
	stp	x14, x15, [sp, #112];				\
	stp	x16, x17, [sp, #128];				\
	str	x18, [sp, #144];				\
	str	x30, [sp, #160];	/* real LR */		\
	adr	x9, 9f;						\
	str	x9,  [sp, #152];	/* LR for target */	\
	mov	x30, x9;					\
	ldp	x0,  x1,  [sp, #0];				\
	ldp	x2,  x3,  [sp, #16];				\
	ldp	x4,  x5,  [sp, #32];				\
	ldp	x6,  x7,  [sp, #48];				\
	ldp	x8,  x9,  [sp, #64];				\
	ldp	x10, x11, [sp, #80];				\
	ldp	x12, x13, [sp, #96];				\
	ldp	x14, x15, [sp, #112];				\
	ldr	x18, [sp, #144];				\
	adrp	x16, susfs_ih_tramp_##n;			
	add	x16, x16, :lo12:susfs_ih_tramp_##n;			\
	ldr	x16, [x16];					\
	br	x16;						\
9:;	/* x0 = target's return value */			\
	str	x0, [sp, #168];					\
	ldp	x0,  x1,  [sp, #0];	/* original args */	\
	ldr	x2,  [sp, #168];	/* return value */	\
	bl	after_fn;					\
	ldr	x30, [sp, #160];				\
	add	sp, sp, #192;					\
	ret

	SUSFS_IH_SYS_STUB(openat, 1)
	SUSFS_IH_SYS_STUB(openat2, 1)
	SUSFS_IH_SYS_STUB(newfstatat, 1)
	SUSFS_IH_SYS_STUB(statx, 1)
	SUSFS_IH_SYS_STUB(faccessat, 1)
	SUSFS_IH_SYS_STUB(faccessat2, 1)
	SUSFS_IH_SYS_STUB(readlinkat, 1)
	SUSFS_IH_SYS_STUB(execve, 0)

	SUSFS_IH_NAME_STUB(filename_lookup, 0)
	SUSFS_IH_NAME_STUB(do_filp_open, 0)
	SUSFS_IH_NAME_STUB(user_path_at_empty, 1)

	/* onLeave: needs the result of the original call */
	SUSFS_IH_LEAVE_STUB(getname, susfs_ih_after_getname)

	.bss
	.align	3
#define SUSFS_IH_TRAMP(n)					\
	.globl	susfs_ih_tramp_##n;				\
susfs_ih_tramp_##n:;						\
	.quad	0

	SUSFS_IH_TRAMP(openat)
	SUSFS_IH_TRAMP(openat2)
	SUSFS_IH_TRAMP(newfstatat)
	SUSFS_IH_TRAMP(statx)
	SUSFS_IH_TRAMP(faccessat)
	SUSFS_IH_TRAMP(faccessat2)
	SUSFS_IH_TRAMP(readlinkat)
	SUSFS_IH_TRAMP(execve)
	SUSFS_IH_TRAMP(filename_lookup)
	SUSFS_IH_TRAMP(do_filp_open)
	SUSFS_IH_TRAMP(user_path_at_empty)
	SUSFS_IH_TRAMP(getname)
