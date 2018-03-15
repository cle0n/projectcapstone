	.file	"nestedloop.c"
	.section	.rodata
.LC0:
	.string	"Welcome to the nest."
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movl	$0, -12(%rbp)
	jmp	.L2
.L7:
	movl	$0, -8(%rbp)
	jmp	.L3
.L6:
	movl	$0, -4(%rbp)
	jmp	.L4
.L5:
	movl	$.LC0, %edi
	call	puts
	addl	$1, -4(%rbp)
.L4:
	cmpl	$1, -4(%rbp)
	jle	.L5
	addl	$1, -8(%rbp)
.L3:
	cmpl	$1, -8(%rbp)
	jle	.L6
	addl	$1, -12(%rbp)
.L2:
	cmpl	$1, -12(%rbp)
	jle	.L7
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4"
	.section	.note.GNU-stack,"",@progbits
