/* SPDX-License-Identifier: GPL-2.0
 *
 * susfs_inline_hook_stub.S - the landing code for every inline-hooked entry.
 *
 * A patched entry is `bti c ; b <stub>`, so a stub is entered with the target's
 * argument registers untouched, LR still the caller's return address, and SP
 * exactly as it was on entry to the real function.
 *
 * Rules learned the hard way (see INLINE_HOOK.md):
 *
 *  - x0-x18 must survive the C calls: the allow path hands the original
 *    arguments to the trampoline, which replays the target's prologue;
 *  - immediates inside a macro body must NOT be written as hash-param: cpp reads
 *    that as the stringise operator, and the assembler then sees a quoted
 *    string where an immediate belongs;
 *  - each stub loads its trampoline address from a .bss variable that C fills in
 *    at install time.  This is the shape verified end to end in the standalone
 *    test module.
 *
 * Entering the trampoline uses `br`, which does not touch the return-address
 * stack; a `ret` there would pop it and cost a return misprediction on every
 * hooked call.  Resuming the target at entry+8 still has to use `ret`: it is
 * mid-function, so BTI rejects br/blr there and only ret is exempt.
 */

.hidden susfs_ih_decide
.hidden susfs_ih_decide_name
.hidden susfs_ih_after_getname

#define IH_SAVE()						\
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
	str	x30, [sp, #160];					\
	mrs	x9, nzcv;					\
	str	x9, [sp, #168]

#define IH_RESTORE_ARGS()					\
	ldp	x0,  x1,  [sp, #0];				\
	ldp	x2,  x3,  [sp, #16];				\
	ldp	x4,  x5,  [sp, #32];				\
	ldp	x6,  x7,  [sp, #48];				\
	ldp	x8,  x9,  [sp, #64];				\
	ldp	x10, x11, [sp, #80];				\
	ldp	x12, x13, [sp, #96];				\
	ldp	x14, x15, [sp, #112];				\
	ldr	x18, [sp, #144];					\
	ldr	x17, [sp, #168];				\
	msr	nzcv, x17

#define IH_TRAMP_ADDR(n)					\
	adrp	x16, susfs_ih_tramp_##n;			\
	add	x16, x16, :lo12:susfs_ih_tramp_##n;		\
	ldr	x16, [x16]

/* allow path: pick up this entry's trampoline and leave for it */
#define IH_TAIL(n)						\
	IH_RESTORE_ARGS();					\
	ldr	x30, [sp, #160];				\
	IH_TRAMP_ADDR(n);					\
	add	sp, sp, #192;\
	br	x16

/* hit path: leave with ENOENT instead of running the original */
#define IH_HIDE()						\
	IH_RESTORE_ARGS();					\
	ldr	x30, [sp, #160];				\
	add	sp, sp, #192;					\
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
	mov	w1, argno;					\
	bl	susfs_ih_decide;				\
	cbz	w0, 8f;						\
	IH_HIDE();						\
8:;								\
	IH_TAIL(n);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* name-taking entries (filename_lookup, do_filp_open, user_path_at_empty): the
 * name is in x1, w1 carries the mode (0 = struct filename, already in kernel
 * memory, 1 = user pointer). */
#define SUSFS_IH_NAME_STUB(n, mode)				\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	mov	x0, x1;						\
	mov	w1, mode;					\
	bl	susfs_ih_decide_name;				\
	cbz	w0, 8f;						\
	IH_HIDE();						\
8:;								\
	IH_TAIL(n);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* onLeave: the stub hands the frame back to itself.
 *
 * The caller's real LR goes in a spare slot, the target's LR is pointed at the
 * label after the trampoline jump, and the original runs.  Its own prologue
 * (paciasp and friends) then signs THAT LR, so its epilogue restores and
 * authenticates it happily - control lands back here with x0 holding the result,
 * which the C after-handler may replace.
 *
 * Frame layout: [0..144] x0-x18, [152] LR handed to the target, [160] the real
 * LR, [168] NZCV, [176] the target's return value.  The target runs with SP
 * still at the stub's frame base - 192 bytes deeper than its callers expect - so
 * its own frame lives at [sp-192-N, sp-192) and cannot touch any slot above it.
 * That is what makes reading the original arguments back at 9f safe.
 *
 * Precondition: the target must be reachable with registers alone (<= 8
 * arguments): a target taking arguments on the stack would read them out of this
 * frame instead of its caller's.
 *
 * Contract: after_fn(u64 a0, u64 a1, u64 ret) returns the value the target's
 * caller should see; the stub returns exactly that. */
#define SUSFS_IH_LEAVE_STUB(n, after_fn)			\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	adr	x9, 9f;						\
	str	x9, [sp, #152];					\
	mov	x30, x9;					\
	IH_RESTORE_ARGS();					\
	IH_TRAMP_ADDR(n);					\
	br	x16;						\
9:;								\
	str	x0, [sp, #176];					\
	ldp	x0, x1, [sp, #0];				\
	ldr	x2, [sp, #176];					\
	bl	after_fn;					\
	ldr	x30, [sp, #160];				\
	add	sp, sp, #192;					\
	ret;							\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

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
