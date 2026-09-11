/* SPDX-License-Identifier: GPL-2.0
 *
 * ih_hook_stub.S - the inline-hook landing code for __arm64_sys_openat.
 *
 * The patched entry is
 *
 *     bti c            <- landing pad kept: the syscall table calls this
 *     b   ih_openat_stub
 *
 * so this stub is entered with the wrapper's argument still in x0, LR still
 * holding the caller's return address, and SP exactly as it was on entry to the
 * real function.  Nothing here has run paciasp, so the LR is unsigned and a
 * plain `ret` is correct.
 *
 *   hide  -> x0 = -ENOENT and return to the caller.
 *   allow -> jump into the trampoline WITHOUT building a frame, because the
 *            trampoline replays the two instructions we overwrote
 *            (paciasp ; sub sp, ...) and those have to see the original SP.
 *            That exit uses `ret x16`, which is exempt from the BTI check -
 *            the same reasoning as frida-gum's put_jmp_reg().
 */
	.text

	.globl	ih_openat_stub
	.type	ih_openat_stub, %function
ih_openat_stub:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	ih_openat_decide
	cbz	x0, ih_openat_allow
	ldp	x29, x30, [sp], #16
	mov	x0, #-2			/* -ENOENT */
	ret
ih_openat_allow:
	ldp	x29, x30, [sp], #16
	ldr	x16, =ih_openat_tramp
	ldr	x16, [x16]
	br	x16
	.size	ih_openat_stub, . - ih_openat_stub

	.bss
	.align	3
	.globl	ih_openat_tramp
ih_openat_tramp:
	.quad	0
