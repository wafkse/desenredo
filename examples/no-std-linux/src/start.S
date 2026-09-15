	.section	.text._start,"ax",@progbits
	.globl	_start
	.type	_start,@function
_start:
	.cfi_startproc
	.cfi_def_cfa %rsp, 8
	.cfi_undefined %rip
	movq	%rsp, %rdi
	andq	$-16, %rsp
	callq	desenredo_entry
	ud2
	.cfi_endproc
.Lstart_end:
	.size	_start, .Lstart_end-_start


	.section	".note.GNU-stack","",@progbits
