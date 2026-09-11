/* SPDX-License-Identifier: GPL-2.0
 *
 * susfs_inline_hook_stub.S - the landing code for every inline-hooked entry.
 *
 * A patched entry is `bti c ; b <stub>`, so a stub is entered with the target's
 * argument registers untouched, LR still the caller's return address, and SP
 * exactly as it was on entry to the real function.
 *
 * Two rules learned the hard way (see INLINE_HOOK.md):
 *
 *  - x0-x18 must survive the C calls: the allow path hands the original
 *    arguments to the trampoline, which replays the target's prologue.
 *
 *  - a stub must NOT take a module symbol's address itself.  `ldr x16, =sym`
 *    becomes movz/movk, and even adrp/add or adrp/:got: get folded into the same
 *    thing by the assembler - a module address is not known until load time.  So
 *    the trampoline pointer is fetched by CALLING C (susfs_ih_get_tramp), where
 *    the compiler emits the addressing it knows is correct.
 *
 * Entering the trampoline uses `br`, which does not touch the return-address
 * stack; a `ret` there would pop it and guarantee a return misprediction for
 * every hooked call.  Resuming the target at entry+8 still has to use `ret`: it
 * is mid-function, so BTI rejects br/blr there and only ret is exempt.
 */

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
	str	x30, [sp, #160]

#define IH_RESTORE_ARGS()					\
	ldp	x0,  x1,  [sp, #0];				\
	ldp	x2,  x3,  [sp, #16];				\
	ldp	x4,  x5,  [sp, #32];				\
	ldp	x6,  x7,  [sp, #48];				\
	ldp	x8,  x9,  [sp, #64];				\
	ldp	x10, x11, [sp, #80];				\
	ldp	x12, x13, [sp, #96];				\
	ldp	x14, x15, [sp, #112];				\
	ldr	x18, [sp, #144]

/* allow path: ask C for this entry's trampoline, then leave for it */
#define IH_TAIL(idx)						\
	mov	w0, #idx;					\
	bl	susfs_ih_get_tramp;				\
	mov	x16, x0;					\
	IH_RESTORE_ARGS();					\
	br	x16

/* hit path: leave with ENOENT instead of running the original */
#define IH_HIDE()						\
	IH_RESTORE_ARGS();					\
	ldr	x30, [sp, #160];				\
	add	sp, sp, #192;					\
	mov	x0, #-2;	/* -ENOENT */			\
	ret

.hidden susfs_ih_decide
.hidden susfs_ih_decide_name
.hidden susfs_ih_after_getname
.hidden susfs_ih_get_tramp

	.text

/* syscall wrappers: x0 is the pt_regs to read the user pointer from, argno the
 * x-register holding the pathname in the 64-bit ABI. */
#define SUSFS_IH_SYS_STUB(n, idx, argno)			\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	mov	w1, #argno;					\
	bl	susfs_ih_decide;				\
	cbz	x0, 8f;						\
	IH_HIDE();						\
8:;								\
	IH_TAIL(idx);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* name-taking entries (filename_lookup, do_filp_open, user_path_at_empty): the
 * name is in x1, w1 carries the mode (0 = struct filename, already in kernel
 * memory, 1 = user pointer). */
#define SUSFS_IH_NAME_STUB(n, idx, mode)			\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	mov	x0, x1;						\
	mov	w1, #mode;					\
	bl	susfs_ih_decide_name;				\
	cbz	x0, 8f;						\
	IH_HIDE();						\
8:;								\
	IH_TAIL(idx);						\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* onLeave: the stub hands the frame back to itself.
 *
 * The caller's real LR goes in a spare slot, the target's LR is pointed at the
 * label after the trampoline jump, and the original runs.  Its own prologue
 * (paciasp and friends) then signs THAT LR, so its epilogue restores and
 * authenticates it happily - control lands back here with x0 holding the result,
 * which the C after-handler may replace.
 *
 * Layout: [0..144] x0-x18, [152] LR for the target, [160] real LR,
 *         [168] the target's return value. */
#define SUSFS_IH_LEAVE_STUB(n, idx, after_fn)			\
	.globl	susfs_ih_stub_##n;				\
	.type	susfs_ih_stub_##n, %function;			\
susfs_ih_stub_##n:;						\
	IH_SAVE();						\
	adr	x9, 9f;						\
	str	x9, [sp, #152];					\
	mov	w0, #idx;					\
	bl	susfs_ih_get_tramp;				\
	mov	x16, x0;					\
	ldr	x30, [sp, #152];				\
	IH_RESTORE_ARGS();					\
	br	x16;						\
9:;								\
	str	x0, [sp, #168];					\
	ldp	x0, x1, [sp, #0];				\
	ldr	x2, [sp, #168];					\
	bl	after_fn;					\
	ldr	x30, [sp, #160];				\
	add	sp, sp, #192;					\
	ret;							\
	.size	susfs_ih_stub_##n, . - susfs_ih_stub_##n

/* Index into ih_table[] in sus_path.c - the order must match. */
	SUSFS_IH_SYS_STUB(openat, 0, 1)
	SUSFS_IH_SYS_STUB(openat2, 1, 1)
	SUSFS_IH_SYS_STUB(newfstatat, 2, 1)
	SUSFS_IH_SYS_STUB(statx, 3, 1)
	SUSFS_IH_SYS_STUB(faccessat, 4, 1)
	SUSFS_IH_SYS_STUB(faccessat2, 5, 1)
	SUSFS_IH_SYS_STUB(readlinkat, 6, 1)
	SUSFS_IH_SYS_STUB(execve, 7, 0)

	SUSFS_IH_NAME_STUB(filename_lookup, 8, 0)
	SUSFS_IH_NAME_STUB(do_filp_open, 9, 0)
	SUSFS_IH_NAME_STUB(user_path_at_empty, 10, 1)

	SUSFS_IH_LEAVE_STUB(getname, 11, susfs_ih_after_getname)
