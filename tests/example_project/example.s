	.file	"example.c"
	.text
.Ltext0:
	.file 0 "/home/mahaloz/github/decbench/tests/example_project" "example.c"
	.globl	EXTRA_RUN
	.data
	.align 4
	.type	EXTRA_RUN, @object
	.size	EXTRA_RUN, 4
EXTRA_RUN:
	.long	3
	.globl	EARLY_EXIT
	.align 4
	.type	EARLY_EXIT, @object
	.size	EARLY_EXIT, 4
EARLY_EXIT:
	.long	4
	.section	.rodata
.LC0:
	.string	"next_job"
	.text
	.globl	next_job
	.type	next_job, @function
next_job:
.LFB0:
	.file 1 "example.c"
	.loc 1 14 20
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 15 5
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 16 12
	movl	$1, %eax
	.loc 1 17 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	next_job, .-next_job
	.section	.rodata
.LC1:
	.string	"refresh_jobs"
	.text
	.globl	refresh_jobs
	.type	refresh_jobs, @function
refresh_jobs:
.LFB1:
	.loc 1 19 24
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 20 5
	leaq	.LC1(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 21 12
	movl	$2, %eax
	.loc 1 22 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	refresh_jobs, .-refresh_jobs
	.section	.rodata
.LC2:
	.string	"fast_unlock"
	.text
	.globl	fast_unlock
	.type	fast_unlock, @function
fast_unlock:
.LFB2:
	.loc 1 24 23
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 25 5
	leaq	.LC2(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 26 12
	movl	$4, %eax
	.loc 1 27 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	fast_unlock, .-fast_unlock
	.section	.rodata
.LC3:
	.string	"checking..."
	.text
	.globl	complete_job
	.type	complete_job, @function
complete_job:
.LFB3:
	.loc 1 29 24
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 30 5
	leaq	.LC3(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 31 12
	movl	$0, %eax
	.loc 1 32 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	complete_job, .-complete_job
	.section	.rodata
.LC4:
	.string	"log_workers"
	.text
	.globl	log_workers
	.type	log_workers, @function
log_workers:
.LFB4:
	.loc 1 34 24
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 35 5
	leaq	.LC4(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 36 1
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	log_workers, .-log_workers
	.section	.rodata
.LC5:
	.string	"job_status"
	.text
	.globl	job_status
	.type	job_status, @function
job_status:
.LFB5:
	.loc 1 38 27
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	.loc 1 39 5
	leaq	.LC5(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 40 12
	movl	-4(%rbp), %eax
	.loc 1 41 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	job_status, .-job_status
	.globl	schedule_job
	.type	schedule_job, @function
schedule_job:
.LFB6:
	.loc 1 45 1
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movl	%edx, -12(%rbp)
	.loc 1 46 8
	cmpl	$0, -4(%rbp)
	je	.L13
	.loc 1 46 20 discriminator 1
	cmpl	$0, -8(%rbp)
	je	.L13
	.loc 1 47 9
	call	complete_job
	.loc 1 48 18
	movl	EARLY_EXIT(%rip), %eax
	.loc 1 48 12
	cmpl	%eax, -12(%rbp)
	je	.L17
	.loc 1 51 9
	call	next_job
.L13:
	.loc 1 54 5
	call	refresh_jobs
	.loc 1 55 8
	cmpl	$0, -8(%rbp)
	je	.L18
	.loc 1 56 9
	call	fast_unlock
	jmp	.L15
.L17:
	.loc 1 49 13
	nop
	jmp	.L15
.L18:
	.loc 1 58 1
	nop
.L15:
	.loc 1 59 5
	call	complete_job
	.loc 1 60 5
	call	log_workers
	.loc 1 61 12
	movl	-8(%rbp), %eax
	movl	%eax, %edi
	call	job_status
	.loc 1 62 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	schedule_job, .-schedule_job
	.globl	count_to_n
	.type	count_to_n, @function
count_to_n:
.LFB7:
	.loc 1 65 23
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -20(%rbp)
	.loc 1 66 9
	movl	$0, -8(%rbp)
.LBB2:
	.loc 1 67 14
	movl	$0, -4(%rbp)
	.loc 1 67 5
	jmp	.L20
.L21:
	.loc 1 68 13
	movl	-4(%rbp), %eax
	addl	%eax, -8(%rbp)
	.loc 1 67 29 discriminator 3
	addl	$1, -4(%rbp)
.L20:
	.loc 1 67 23 discriminator 1
	movl	-4(%rbp), %eax
	cmpl	-20(%rbp), %eax
	jl	.L21
.LBE2:
	.loc 1 70 12
	movl	-8(%rbp), %eax
	.loc 1 71 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	count_to_n, .-count_to_n
	.globl	classify_number
	.type	classify_number, @function
classify_number:
.LFB8:
	.loc 1 74 28
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	.loc 1 75 8
	cmpl	$0, -4(%rbp)
	jns	.L24
	.loc 1 76 16
	movl	$-1, %eax
	jmp	.L25
.L24:
	.loc 1 77 15
	cmpl	$0, -4(%rbp)
	jne	.L26
	.loc 1 78 16
	movl	$0, %eax
	jmp	.L25
.L26:
	.loc 1 79 15
	cmpl	$9, -4(%rbp)
	jg	.L27
	.loc 1 80 16
	movl	$1, %eax
	jmp	.L25
.L27:
	.loc 1 81 15
	cmpl	$99, -4(%rbp)
	jg	.L28
	.loc 1 82 16
	movl	$2, %eax
	jmp	.L25
.L28:
	.loc 1 84 16
	movl	$3, %eax
.L25:
	.loc 1 86 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE8:
	.size	classify_number, .-classify_number
	.globl	main
	.type	main, @function
main:
.LFB9:
	.loc 1 89 1
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movq	%rsi, -16(%rbp)
	.loc 1 90 8
	cmpl	$3, -4(%rbp)
	jg	.L30
	.loc 1 91 16
	movl	$1, %eax
	jmp	.L31
.L30:
	.loc 1 92 53
	movq	-16(%rbp), %rax
	addq	$24, %rax
	movq	(%rax), %rax
	.loc 1 92 56
	movzbl	(%rax), %eax
	.loc 1 92 12
	movsbl	%al, %edx
	.loc 1 92 41
	movq	-16(%rbp), %rax
	addq	$16, %rax
	movq	(%rax), %rax
	.loc 1 92 44
	movzbl	(%rax), %eax
	.loc 1 92 12
	movsbl	%al, %ecx
	.loc 1 92 29
	movq	-16(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rax
	.loc 1 92 32
	movzbl	(%rax), %eax
	.loc 1 92 12
	movsbl	%al, %eax
	movl	%ecx, %esi
	movl	%eax, %edi
	call	schedule_job
.L31:
	.loc 1 93 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x294
	.value	0x5
	.byte	0x1
	.byte	0x8
	.long	.Ldebug_abbrev0
	.uleb128 0xa
	.long	.LASF27
	.byte	0x1d
	.long	.LASF0
	.long	.LASF1
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x1
	.byte	0x8
	.byte	0x7
	.long	.LASF2
	.uleb128 0x1
	.byte	0x4
	.byte	0x7
	.long	.LASF3
	.uleb128 0x1
	.byte	0x1
	.byte	0x8
	.long	.LASF4
	.uleb128 0x1
	.byte	0x2
	.byte	0x7
	.long	.LASF5
	.uleb128 0x1
	.byte	0x1
	.byte	0x6
	.long	.LASF6
	.uleb128 0x1
	.byte	0x2
	.byte	0x5
	.long	.LASF7
	.uleb128 0xb
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x1
	.byte	0x8
	.byte	0x5
	.long	.LASF8
	.uleb128 0x4
	.long	0x6b
	.uleb128 0x1
	.byte	0x1
	.byte	0x6
	.long	.LASF9
	.uleb128 0xc
	.long	0x6b
	.uleb128 0x4
	.long	0x72
	.uleb128 0x6
	.long	.LASF10
	.byte	0xb
	.long	0x58
	.uleb128 0x9
	.byte	0x3
	.quad	EXTRA_RUN
	.uleb128 0x6
	.long	.LASF11
	.byte	0xc
	.long	0x58
	.uleb128 0x9
	.byte	0x3
	.quad	EARLY_EXIT
	.uleb128 0xd
	.long	.LASF28
	.byte	0x2
	.value	0x2d4
	.byte	0xc
	.long	0x58
	.long	0xbb
	.uleb128 0xe
	.long	0x77
	.byte	0
	.uleb128 0x5
	.long	.LASF14
	.byte	0x58
	.long	0x58
	.quad	.LFB9
	.quad	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0xf8
	.uleb128 0x2
	.long	.LASF12
	.byte	0x58
	.byte	0xe
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x2
	.long	.LASF13
	.byte	0x58
	.byte	0x1b
	.long	0xf8
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.uleb128 0x4
	.long	0x66
	.uleb128 0x7
	.long	.LASF15
	.byte	0x4a
	.long	0x58
	.quad	.LFB8
	.quad	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x12a
	.uleb128 0x8
	.string	"x"
	.byte	0x4a
	.byte	0x19
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.byte	0
	.uleb128 0x7
	.long	.LASF16
	.byte	0x41
	.long	0x58
	.quad	.LFB7
	.quad	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x183
	.uleb128 0x8
	.string	"n"
	.byte	0x41
	.byte	0x14
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -36
	.uleb128 0x9
	.string	"sum"
	.byte	0x42
	.byte	0x9
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xf
	.quad	.LBB2
	.quad	.LBE2-.LBB2
	.uleb128 0x9
	.string	"i"
	.byte	0x43
	.byte	0xe
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.byte	0
	.byte	0
	.uleb128 0x5
	.long	.LASF17
	.byte	0x2c
	.long	0x58
	.quad	.LFB6
	.quad	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x1de
	.uleb128 0x2
	.long	.LASF18
	.byte	0x2c
	.byte	0x16
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x2
	.long	.LASF19
	.byte	0x2c
	.byte	0x26
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0x2
	.long	.LASF20
	.byte	0x2c
	.byte	0x34
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -28
	.uleb128 0x10
	.long	.LASF29
	.byte	0x1
	.byte	0x3a
	.byte	0x1
	.quad	.L15
	.byte	0
	.uleb128 0x5
	.long	.LASF21
	.byte	0x26
	.long	0x58
	.quad	.LFB5
	.quad	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x20d
	.uleb128 0x2
	.long	.LASF22
	.byte	0x26
	.byte	0x14
	.long	0x58
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.byte	0
	.uleb128 0x11
	.long	.LASF30
	.byte	0x1
	.byte	0x22
	.byte	0x6
	.quad	.LFB4
	.quad	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x3
	.long	.LASF23
	.byte	0x1d
	.long	0x58
	.quad	.LFB3
	.quad	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x3
	.long	.LASF24
	.byte	0x18
	.long	0x58
	.quad	.LFB2
	.quad	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x3
	.long	.LASF25
	.byte	0x13
	.long	0x58
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x3
	.long	.LASF26
	.byte	0xe
	.long	0x58
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 5
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0x21
	.sleb128 8
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 5
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 5
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 5
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7a
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x1f
	.uleb128 0x1b
	.uleb128 0x1f
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0xa
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x11
	.uleb128 0x1
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF26:
	.string	"next_job"
.LASF15:
	.string	"classify_number"
.LASF24:
	.string	"fast_unlock"
.LASF7:
	.string	"short int"
.LASF19:
	.string	"fast_job"
.LASF22:
	.string	"stats"
.LASF14:
	.string	"main"
.LASF20:
	.string	"mode"
.LASF27:
	.string	"GNU C17 13.3.0 -mtune=generic -march=x86-64 -g -fno-inline -fno-builtin -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"
.LASF18:
	.string	"needs_next"
.LASF8:
	.string	"long int"
.LASF16:
	.string	"count_to_n"
.LASF11:
	.string	"EARLY_EXIT"
.LASF17:
	.string	"schedule_job"
.LASF4:
	.string	"unsigned char"
.LASF29:
	.string	"cleanup"
.LASF12:
	.string	"argc"
.LASF6:
	.string	"signed char"
.LASF3:
	.string	"unsigned int"
.LASF28:
	.string	"puts"
.LASF13:
	.string	"argv"
.LASF5:
	.string	"short unsigned int"
.LASF9:
	.string	"char"
.LASF23:
	.string	"complete_job"
.LASF25:
	.string	"refresh_jobs"
.LASF2:
	.string	"long unsigned int"
.LASF10:
	.string	"EXTRA_RUN"
.LASF21:
	.string	"job_status"
.LASF30:
	.string	"log_workers"
	.section	.debug_line_str,"MS",@progbits,1
.LASF0:
	.string	"example.c"
.LASF1:
	.string	"/home/mahaloz/github/decbench/tests/example_project"
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
