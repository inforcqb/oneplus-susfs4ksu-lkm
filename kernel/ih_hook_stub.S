/* SPDX-License-Identifier: GPL-2.0
 *
 * ih_hook_stub.S - inline-hook landing code.
 *
 * A patched entry looks like
 *
 *     bti c            <- landing pad kept, the syscall table calls this
 *     b   <stub>
 *
 * so a stub is entered with the target's argument registers untouched, LR still
 * holding the caller's return address, and SP exactly as it was on entry to the
 * real function.  Nothing here has run the target's paciasp, so LR is unsigned
 * and a plain `ret` is correct.
 *
 * CRITICAL: the C decision function may clobber x0-x18 (AAPCS: they are
 * caller-saved).  The allow path hands control back to the trampoline, which
 * replays the overwritten prologue and then falls into the REST of the original
 * function - and that code expects its arguments, x0 first.  So every argument
 * register is saved across the call and restored before either exit.  Missing
 * that is exactly how the first attempt panicked.
 *
 * The allow path leaves with `ret x16`, exempt from the BTI check, the same
 * reasoning as frida-gum's put_jmp_reg().
 */
#define IH_SAVE_REGS()						\
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

#define IH_RESTORE_REGS()					\
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

	.text

/* Self-test target, written in assembly on purpose:
 *  - a C function in a module gets a stack-protector canary loaded with adrp
 *    (PC-relative), which the patch sanity check must refuse;
 *  - worse, in a kCFI kernel the ADDRESS of a C function taken in C code is the
 *    .cfi_jt entry ("bti c ; b func"), so patching it would patch the thunk.
 *    This pair avoids both: ih_test_target has a replayable prologue, and
 *    ih_test_target_addr computes the real entry with adrp/add, which no
 *    compiler rewrites - the same problem kCFI posed for the first attempt. */
	.globl	ih_test_target
	.type	ih_test_target, %function
ih_test_target:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	w1, #3
	mul	x0, x0, x1
	add	x0, x0, #7
	ldp	x29, x30, [sp], #16
	ret
	.size	ih_test_target, . - ih_test_target

	.globl	ih_test_target_addr
	.type	ih_test_target_addr, %function
ih_test_target_addr:
	adrp	x0, ih_test_target
	add	x0, x0, :lo12:ih_test_target
	ret
	.size	ih_test_target_addr, . - ih_test_target_addr

	.globl	ih_openat_stub
	.type	ih_openat_stub, %function
ih_openat_stub:
	IH_SAVE_REGS()
	bl	ih_openat_decide
	cbz	x0, ih_openat_allow
	IH_RESTORE_REGS()
	mov	x0, #-2			/* -ENOENT */
	ret
ih_openat_allow:
	IH_RESTORE_REGS()
	ldr	x16, =ih_openat_tramp
	ldr	x16, [x16]
	br	x16
	.size	ih_openat_stub, . - ih_openat_stub

/* Same shape, for the self-test target: the decision function decides purely on
 * the argument value, so the stub just forwards x0. */
	.globl	ih_selftest_stub
	.type	ih_selftest_stub, %function
ih_selftest_stub:
	IH_SAVE_REGS()
	bl	ih_selftest_decide
	cbz	x0, ih_selftest_allow
	IH_RESTORE_REGS()
	mov	x0, #-2
	ret
ih_selftest_allow:
	IH_RESTORE_REGS()
	ldr	x16, =ih_selftest_tramp
	ldr	x16, [x16]
	br	x16
	.size	ih_selftest_stub, . - ih_selftest_stub

	.bss
	.align	3
	.globl	ih_openat_tramp
ih_openat_tramp:
	.quad	0
	.globl	ih_selftest_tramp
ih_selftest_tramp:
	.quad	0
