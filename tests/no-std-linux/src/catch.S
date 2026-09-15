	.section	.text._start,"ax",@progbits
	.globl	_start
	.type	_start,@function
_start:
	.cfi_startproc
	.cfi_def_cfa %rsp, 8
	.cfi_undefined %rip
	andq	$-16, %rsp
	callq	desenredo_entry
	ud2
	.cfi_endproc
.Ltmp0:
	.size	_start, .Ltmp0-_start

	.section	.text.desenredo_trace_probe,"ax",@progbits
	.globl	desenredo_trace_probe
	.type	desenredo_trace_probe,@function
desenredo_trace_probe:
	.cfi_startproc
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset %rbp, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset %r12, -32
	pushq	%r13
	.cfi_def_cfa_offset 40
	.cfi_offset %r13, -40
	pushq	%r14
	.cfi_def_cfa_offset 48
	.cfi_offset %r14, -48
	pushq	%r15
	.cfi_def_cfa_offset 56
	.cfi_offset %r15, -56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	movq	%rdi, (%rsp)

	movq	$1360072977, %rbx               # imm = 0x51111111
	movq	$1377968674, %rbp               # imm = 0x52222222
	movq	$1395864371, %r12               # imm = 0x53333333
	movq	$1413760068, %r13               # imm = 0x54444444
	movq	$1431655765, %r14               # imm = 0x55555555
	movq	$1449551462, %r15               # imm = 0x56666666

	movq	(%rsp), %rsi
	leaq	desenredo_trace_visit(%rip), %rdi
	callq	_Unwind_Backtrace
	.globl	desenredo_trace_return
desenredo_trace_return:
	movq	%rax, 8(%rsp)
	movq	$1, 16(%rsp)
	cmpq	$1360072977, %rbx               # imm = 0x51111111
	jne	.Ltrace_clobbered
	cmpq	$1377968674, %rbp               # imm = 0x52222222
	jne	.Ltrace_clobbered
	cmpq	$1395864371, %r12               # imm = 0x53333333
	jne	.Ltrace_clobbered
	cmpq	$1413760068, %r13               # imm = 0x54444444
	jne	.Ltrace_clobbered
	cmpq	$1431655765, %r14               # imm = 0x55555555
	jne	.Ltrace_clobbered
	cmpq	$1449551462, %r15               # imm = 0x56666666
	jne	.Ltrace_clobbered
	jmp	.Ltrace_restore
.Ltrace_clobbered:
	movq	$0, 16(%rsp)
.Ltrace_restore:
	movq	8(%rsp), %rax
	cmpq	$1, 16(%rsp)
	je	.Ltrace_done
	movl	$2, %eax
.Ltrace_done:
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%r15
	.cfi_def_cfa_offset 48
	popq	%r14
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%rbp
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
.Ltmp1:
	.size	desenredo_trace_probe, .Ltmp1-desenredo_trace_probe

	.section	.text.desenredo_force_probe,"ax",@progbits
	.globl	desenredo_force_probe
	.type	desenredo_force_probe,@function
desenredo_force_probe:
	.cfi_startproc
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	movq	%rsi, %rdx
	leaq	desenredo_force_stop(%rip), %rsi
	callq	_Unwind_ForcedUnwind
	.globl	desenredo_force_return
desenredo_force_return:
	addq	$8, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
.Ltmp2:
	.size	desenredo_force_probe, .Ltmp2-desenredo_force_probe

	.section	.text.desenredo_register_inner,"ax",@progbits
	.type	desenredo_register_inner,@function
desenredo_register_inner:
	.cfi_startproc
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset %rbp, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset %r12, -32
	pushq	%r13
	.cfi_def_cfa_offset 40
	.cfi_offset %r13, -40
	pushq	%r14
	.cfi_def_cfa_offset 48
	.cfi_offset %r14, -48
	pushq	%r15
	.cfi_def_cfa_offset 56
	.cfi_offset %r15, -56
	subq	$8, %rsp
	.cfi_def_cfa_offset 64

	movq	$1896943889, %rbx               # imm = 0x71111111
	movq	$1914839586, %rbp               # imm = 0x72222222
	movq	$1932735283, %r12               # imm = 0x73333333
	movq	$1950630980, %r13               # imm = 0x74444444
	movq	$1968526677, %r14               # imm = 0x75555555
	movq	$1986422374, %r15               # imm = 0x76666666
	callq	*%rdi

	addq	$8, %rsp
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	retq
	.cfi_endproc
.Ltmp3:
	.size	desenredo_register_inner, .Ltmp3-desenredo_register_inner

	.section	.text.desenredo_register_probe,"ax",@progbits
	.globl	desenredo_register_probe
	.type	desenredo_register_probe,@function
desenredo_register_probe:
.Lregister_func:
	.cfi_startproc
	.cfi_personality 27, rust_eh_personality
	.cfi_lsda 27, .Lregister_lsda
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset %rbp, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset %r12, -32
	pushq	%r13
	.cfi_def_cfa_offset 40
	.cfi_offset %r13, -40
	pushq	%r14
	.cfi_def_cfa_offset 48
	.cfi_offset %r14, -48
	pushq	%r15
	.cfi_def_cfa_offset 56
	.cfi_offset %r15, -56
	subq	$8, %rsp
	.cfi_def_cfa_offset 64

	movq	$1628508433, %rbx               # imm = 0x61111111
	movq	$1646404130, %rbp               # imm = 0x62222222
	movq	$1664299827, %r12               # imm = 0x63333333
	movq	$1682195524, %r13               # imm = 0x64444444
	movq	$1700091221, %r14               # imm = 0x65555555
	movq	$1717986918, %r15               # imm = 0x66666666
.Lregister_begin:
	callq	desenredo_register_inner
.Lregister_end:
	xorl	%eax, %eax
	jmp	.Lregister_done

.Lregister_landing:
	movq	%rax, %rdi
	movl	$1, %esi
	cmpq	$1628508433, %rbx               # imm = 0x61111111
	jne	.Lregister_bad
	cmpq	$1646404130, %rbp               # imm = 0x62222222
	jne	.Lregister_bad
	cmpq	$1664299827, %r12               # imm = 0x63333333
	jne	.Lregister_bad
	cmpq	$1682195524, %r13               # imm = 0x64444444
	jne	.Lregister_bad
	cmpq	$1700091221, %r14               # imm = 0x65555555
	jne	.Lregister_bad
	cmpq	$1717986918, %r15               # imm = 0x66666666
	jne	.Lregister_bad
	jmp	.Lregister_finish
.Lregister_bad:
	xorl	%esi, %esi
.Lregister_finish:
	callq	desenredo_register_landing

.Lregister_done:
	addq	$8, %rsp
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	retq
	.cfi_endproc
.Ltmp4:
	.size	desenredo_register_probe, .Ltmp4-desenredo_register_probe

	.section	.gcc_except_table.desenredo_register_probe,"a",@progbits
	.p2align	2, 0x0
.Lregister_lsda:
	.byte	255
	.byte	255
	.byte	1
	.uleb128 .Lregister_actions-.Lregister_sites
.Lregister_sites:
	.uleb128 .Lregister_begin-.Lregister_func
	.uleb128 .Lregister_end-.Lregister_begin
	.uleb128 .Lregister_landing-.Lregister_func
	.byte	1
.Lregister_actions:
	.byte	1
	.byte	0

	.section	.text.desenredo_outer_catch,"ax",@progbits
	.globl	desenredo_outer_catch
	.type	desenredo_outer_catch,@function
desenredo_outer_catch:
.Louter_func:
	.cfi_startproc
	.cfi_personality 27, rust_eh_personality
	.cfi_lsda 27, .Louter_lsda
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
.Louter_begin:
	callq	*%rdi
.Louter_end:
	xorl	%eax, %eax
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Louter_landing:
	movq	%rax, %rdi
	callq	unexpected_non_unwind_landing
	ud2
	.cfi_endproc
.Ltmp5:
	.size	desenredo_outer_catch, .Ltmp5-desenredo_outer_catch

	.section	.gcc_except_table.desenredo_outer_catch,"a",@progbits
	.p2align	2, 0x0
.Louter_lsda:
	.byte	255
	.byte	255
	.byte	1
	.uleb128 .Louter_actions-.Louter_sites
.Louter_sites:
	.uleb128 .Louter_begin-.Louter_func
	.uleb128 .Louter_end-.Louter_begin
	.uleb128 .Louter_landing-.Louter_func
	.byte	1
.Louter_actions:
	.byte	1
	.byte	0

	.section	.text.memcpy,"ax",@progbits
	.globl	memcpy
	.type	memcpy,@function
memcpy:
	movq	%rdi, %rax
	testq	%rdx, %rdx
	je	.Lmemcpy_done
.Lmemcpy_loop:
	movb	(%rsi), %cl
	movb	%cl, (%rdi)
	incq	%rsi
	incq	%rdi
	decq	%rdx
	jne	.Lmemcpy_loop
.Lmemcpy_done:
	retq
.Ltmp6:
	.size	memcpy, .Ltmp6-memcpy

	.section	.text.memset,"ax",@progbits
	.globl	memset
	.type	memset,@function
memset:
	movq	%rdi, %rax
	testq	%rdx, %rdx
	je	.Lmemset_done
.Lmemset_loop:
	movb	%sil, (%rdi)
	incq	%rdi
	decq	%rdx
	jne	.Lmemset_loop
.Lmemset_done:
	retq
.Ltmp7:
	.size	memset, .Ltmp7-memset

	.section	.text.memmove,"ax",@progbits
	.globl	memmove
	.type	memmove,@function
memmove:
	movq	%rdi, %rax
	testq	%rdx, %rdx
	je	.Lmemmove_done
	cmpq	%rsi, %rdi
	jbe	.Lmemmove_forward
	leaq	(%rsi,%rdx), %rcx
	cmpq	%rcx, %rdi
	jae	.Lmemmove_forward
	addq	%rdx, %rsi
	addq	%rdx, %rdi
.Lmemmove_back:
	decq	%rsi
	decq	%rdi
	movb	(%rsi), %cl
	movb	%cl, (%rdi)
	decq	%rdx
	jne	.Lmemmove_back
	retq
.Lmemmove_forward:
	movb	(%rsi), %cl
	movb	%cl, (%rdi)
	incq	%rsi
	incq	%rdi
	decq	%rdx
	jne	.Lmemmove_forward
.Lmemmove_done:
	retq
.Ltmp8:
	.size	memmove, .Ltmp8-memmove

	.section	".note.GNU-stack","",@progbits
