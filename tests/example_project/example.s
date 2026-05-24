	.file	"example.c"
	.text
.Ltext0:
	.file 0 "/home/mahaloz/github/decbench/tests/example_project" "example.c"
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"next_job"
	.text
	.p2align 4
	.globl	next_job
	.type	next_job, @function
next_job:
.LFB13:
	.file 1 "example.c"
	.loc 1 14 20 view -0
	.cfi_startproc
	endbr64
	.loc 1 15 5 view .LVU1
	.loc 1 14 20 is_stmt 0 view .LVU2
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	.loc 1 15 5 view .LVU3
	leaq	.LC0(%rip), %rdi
	call	puts@PLT
.LVL0:
	.loc 1 16 5 is_stmt 1 view .LVU4
	.loc 1 17 1 is_stmt 0 view .LVU5
	movl	$1, %eax
	addq	$8, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE13:
	.size	next_job, .-next_job
	.section	.rodata.str1.1
.LC1:
	.string	"refresh_jobs"
	.text
	.p2align 4
	.globl	refresh_jobs
	.type	refresh_jobs, @function
refresh_jobs:
.LFB14:
	.loc 1 19 24 is_stmt 1 view -0
	.cfi_startproc
	endbr64
	.loc 1 20 5 view .LVU7
	.loc 1 19 24 is_stmt 0 view .LVU8
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	.loc 1 20 5 view .LVU9
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
.LVL1:
	.loc 1 21 5 is_stmt 1 view .LVU10
	.loc 1 22 1 is_stmt 0 view .LVU11
	movl	$2, %eax
	addq	$8, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE14:
	.size	refresh_jobs, .-refresh_jobs
	.section	.rodata.str1.1
.LC2:
	.string	"fast_unlock"
	.text
	.p2align 4
	.globl	fast_unlock
	.type	fast_unlock, @function
fast_unlock:
.LFB15:
	.loc 1 24 23 is_stmt 1 view -0
	.cfi_startproc
	endbr64
	.loc 1 25 5 view .LVU13
	.loc 1 24 23 is_stmt 0 view .LVU14
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	.loc 1 25 5 view .LVU15
	leaq	.LC2(%rip), %rdi
	call	puts@PLT
.LVL2:
	.loc 1 26 5 is_stmt 1 view .LVU16
	.loc 1 27 1 is_stmt 0 view .LVU17
	movl	$4, %eax
	addq	$8, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE15:
	.size	fast_unlock, .-fast_unlock
	.section	.rodata.str1.1
.LC3:
	.string	"checking..."
	.text
	.p2align 4
	.globl	complete_job
	.type	complete_job, @function
complete_job:
.LFB16:
	.loc 1 29 24 is_stmt 1 view -0
	.cfi_startproc
	endbr64
	.loc 1 30 5 view .LVU19
	.loc 1 29 24 is_stmt 0 view .LVU20
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	.loc 1 30 5 view .LVU21
	leaq	.LC3(%rip), %rdi
	call	puts@PLT
.LVL3:
	.loc 1 31 5 is_stmt 1 view .LVU22
	.loc 1 32 1 is_stmt 0 view .LVU23
	xorl	%eax, %eax
	addq	$8, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE16:
	.size	complete_job, .-complete_job
	.section	.rodata.str1.1
.LC4:
	.string	"log_workers"
	.text
	.p2align 4
	.globl	log_workers
	.type	log_workers, @function
log_workers:
.LFB17:
	.loc 1 34 24 is_stmt 1 view -0
	.cfi_startproc
	endbr64
	.loc 1 35 5 view .LVU25
	leaq	.LC4(%rip), %rdi
	jmp	puts@PLT
.LVL4:
	.cfi_endproc
.LFE17:
	.size	log_workers, .-log_workers
	.section	.rodata.str1.1
.LC5:
	.string	"job_status"
	.text
	.p2align 4
	.globl	job_status
	.type	job_status, @function
job_status:
.LVL5:
.LFB18:
	.loc 1 38 27 view -0
	.cfi_startproc
	.loc 1 38 27 is_stmt 0 view .LVU27
	endbr64
	.loc 1 39 5 is_stmt 1 view .LVU28
	.loc 1 38 27 is_stmt 0 view .LVU29
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	.loc 1 38 27 view .LVU30
	movl	%edi, %ebx
	.loc 1 39 5 view .LVU31
	leaq	.LC5(%rip), %rdi
.LVL6:
	.loc 1 39 5 view .LVU32
	call	puts@PLT
.LVL7:
	.loc 1 40 5 is_stmt 1 view .LVU33
	.loc 1 41 1 is_stmt 0 view .LVU34
	movl	%ebx, %eax
	popq	%rbx
	.cfi_def_cfa_offset 8
.LVL8:
	.loc 1 41 1 view .LVU35
	ret
	.cfi_endproc
.LFE18:
	.size	job_status, .-job_status
	.p2align 4
	.globl	schedule_job
	.type	schedule_job, @function
schedule_job:
.LVL9:
.LFB19:
	.loc 1 45 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 45 1 is_stmt 0 view .LVU37
	endbr64
	.loc 1 46 5 is_stmt 1 view .LVU38
	.loc 1 45 1 is_stmt 0 view .LVU39
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movl	%esi, %ebx
	subq	$8, %rsp
	.cfi_def_cfa_offset 32
	.loc 1 46 8 view .LVU40
	testl	%edi, %edi
	je	.L14
	testl	%esi, %esi
	je	.L14
	movl	%edx, %ebp
	.loc 1 47 9 is_stmt 1 view .LVU41
	call	complete_job
.LVL10:
	.loc 1 48 9 view .LVU42
	.loc 1 48 12 is_stmt 0 view .LVU43
	cmpl	%ebp, EARLY_EXIT(%rip)
	je	.L16
	.loc 1 51 9 is_stmt 1 view .LVU44
	call	next_job
.LVL11:
	.loc 1 54 5 view .LVU45
	call	refresh_jobs
.LVL12:
	.loc 1 55 5 view .LVU46
.L17:
	.loc 1 56 9 view .LVU47
	call	fast_unlock
.LVL13:
.L16:
	.loc 1 59 5 view .LVU48
	call	complete_job
.LVL14:
	.loc 1 60 5 view .LVU49
	call	log_workers
.LVL15:
	.loc 1 61 5 view .LVU50
	.loc 1 62 1 is_stmt 0 view .LVU51
	addq	$8, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 24
	.loc 1 61 12 view .LVU52
	movl	%ebx, %edi
	.loc 1 62 1 view .LVU53
	popq	%rbx
	.cfi_def_cfa_offset 16
.LVL16:
	.loc 1 62 1 view .LVU54
	popq	%rbp
	.cfi_def_cfa_offset 8
	.loc 1 61 12 view .LVU55
	jmp	job_status
.LVL17:
	.p2align 4,,10
	.p2align 3
.L14:
	.cfi_restore_state
	.loc 1 54 5 is_stmt 1 view .LVU56
	call	refresh_jobs
.LVL18:
	.loc 1 55 5 view .LVU57
	.loc 1 55 8 is_stmt 0 view .LVU58
	testl	%ebx, %ebx
	je	.L16
	jmp	.L17
	.cfi_endproc
.LFE19:
	.size	schedule_job, .-schedule_job
	.p2align 4
	.globl	count_to_n
	.type	count_to_n, @function
count_to_n:
.LVL19:
.LFB20:
	.loc 1 65 23 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 65 23 is_stmt 0 view .LVU60
	endbr64
	.loc 1 66 5 is_stmt 1 view .LVU61
.LVL20:
	.loc 1 67 5 view .LVU62
.LBB2:
	.loc 1 67 10 view .LVU63
	.loc 1 67 23 discriminator 1 view .LVU64
	testl	%edi, %edi
	jle	.L32
	.loc 1 67 14 is_stmt 0 view .LVU65
	xorl	%eax, %eax
.LBE2:
	.loc 1 66 9 view .LVU66
	xorl	%edx, %edx
	testb	$1, %dil
	je	.L31
.LVL21:
.LBB3:
	.loc 1 68 9 is_stmt 1 view .LVU67
	.loc 1 67 29 discriminator 3 view .LVU68
	movl	$1, %eax
.LVL22:
	.loc 1 67 23 discriminator 1 view .LVU69
	cmpl	$1, %edi
	je	.L29
.LVL23:
	.p2align 4,,10
	.p2align 3
.L31:
	.loc 1 68 9 view .LVU70
	.loc 1 67 29 discriminator 3 view .LVU71
	.loc 1 67 23 discriminator 1 view .LVU72
	.loc 1 68 9 view .LVU73
	.loc 1 68 13 is_stmt 0 view .LVU74
	leal	1(%rdx,%rax,2), %edx
.LVL24:
	.loc 1 67 29 is_stmt 1 discriminator 3 view .LVU75
	addl	$2, %eax
.LVL25:
	.loc 1 67 23 discriminator 1 view .LVU76
	cmpl	%eax, %edi
	jne	.L31
.L29:
	.loc 1 67 23 is_stmt 0 discriminator 1 view .LVU77
.LBE3:
	.loc 1 71 1 view .LVU78
	movl	%edx, %eax
.LVL26:
	.loc 1 71 1 view .LVU79
	ret
.LVL27:
	.p2align 4,,10
	.p2align 3
.L32:
	.loc 1 66 9 view .LVU80
	xorl	%edx, %edx
	.loc 1 70 5 is_stmt 1 view .LVU81
	.loc 1 71 1 is_stmt 0 view .LVU82
	movl	%edx, %eax
	ret
	.cfi_endproc
.LFE20:
	.size	count_to_n, .-count_to_n
	.p2align 4
	.globl	classify_number
	.type	classify_number, @function
classify_number:
.LVL28:
.LFB21:
	.loc 1 74 28 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 74 28 is_stmt 0 view .LVU84
	endbr64
	.loc 1 75 5 is_stmt 1 view .LVU85
	.loc 1 75 8 is_stmt 0 view .LVU86
	testl	%edi, %edi
	js	.L41
	.loc 1 77 12 is_stmt 1 view .LVU87
	.loc 1 78 16 is_stmt 0 view .LVU88
	movl	$0, %eax
	.loc 1 77 15 view .LVU89
	je	.L39
	.loc 1 79 12 is_stmt 1 view .LVU90
	.loc 1 80 16 is_stmt 0 view .LVU91
	movl	$1, %eax
	.loc 1 79 15 view .LVU92
	cmpl	$9, %edi
	jle	.L39
	.loc 1 81 12 is_stmt 1 view .LVU93
	.loc 1 82 16 is_stmt 0 view .LVU94
	xorl	%eax, %eax
	cmpl	$99, %edi
	setg	%al
	addl	$2, %eax
	ret
.L41:
	.loc 1 76 16 view .LVU95
	movl	$-1, %eax
.L39:
	.loc 1 86 1 view .LVU96
	ret
	.cfi_endproc
.LFE21:
	.size	classify_number, .-classify_number
	.section	.text.startup,"ax",@progbits
	.p2align 4
	.globl	main
	.type	main, @function
main:
.LVL29:
.LFB22:
	.loc 1 89 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 89 1 is_stmt 0 view .LVU98
	endbr64
	.loc 1 90 5 is_stmt 1 view .LVU99
	.loc 1 90 8 is_stmt 0 view .LVU100
	cmpl	$3, %edi
	jg	.L48
	.loc 1 93 1 view .LVU101
	movl	$1, %eax
	ret
.L48:
	.loc 1 92 5 is_stmt 1 view .LVU102
	.loc 1 92 56 is_stmt 0 view .LVU103
	movq	24(%rsi), %rax
	.loc 1 92 32 view .LVU104
	movq	8(%rsi), %rcx
	.loc 1 92 12 view .LVU105
	movsbl	(%rax), %edx
	.loc 1 92 44 view .LVU106
	movq	16(%rsi), %rax
	.loc 1 92 12 view .LVU107
	movsbl	(%rcx), %edi
.LVL30:
	.loc 1 92 12 view .LVU108
	movsbl	(%rax), %eax
	movl	%eax, %esi
.LVL31:
	.loc 1 92 12 view .LVU109
	jmp	schedule_job
.LVL32:
	.cfi_endproc
.LFE22:
	.size	main, .-main
	.globl	EARLY_EXIT
	.data
	.align 4
	.type	EARLY_EXIT, @object
	.size	EARLY_EXIT, 4
EARLY_EXIT:
	.long	4
	.globl	EXTRA_RUN
	.align 4
	.type	EXTRA_RUN, @object
	.size	EXTRA_RUN, 4
EXTRA_RUN:
	.long	3
	.text
.Letext0:
	.file 2 "/usr/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x3e4
	.value	0x5
	.byte	0x1
	.byte	0x8
	.long	.Ldebug_abbrev0
	.uleb128 0xb
	.long	.LASF28
	.byte	0x1d
	.long	.LASF0
	.long	.LASF1
	.long	.LLRL9
	.quad	0
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
	.uleb128 0xc
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x1
	.byte	0x8
	.byte	0x5
	.long	.LASF8
	.uleb128 0x7
	.long	0x67
	.uleb128 0x1
	.byte	0x1
	.byte	0x6
	.long	.LASF9
	.uleb128 0xd
	.long	0x67
	.uleb128 0x7
	.long	0x6e
	.uleb128 0x8
	.long	.LASF10
	.byte	0xb
	.long	0x54
	.uleb128 0x9
	.byte	0x3
	.quad	EXTRA_RUN
	.uleb128 0x8
	.long	.LASF11
	.byte	0xc
	.long	0x54
	.uleb128 0x9
	.byte	0x3
	.quad	EARLY_EXIT
	.uleb128 0xe
	.long	.LASF29
	.byte	0x2
	.value	0x2d4
	.byte	0xc
	.long	0x54
	.long	0xb7
	.uleb128 0xf
	.long	0x73
	.byte	0
	.uleb128 0x2
	.long	.LASF14
	.byte	0x58
	.long	0x54
	.quad	.LFB22
	.quad	.LFE22-.LFB22
	.uleb128 0x1
	.byte	0x9c
	.long	0x10b
	.uleb128 0x5
	.long	.LASF12
	.byte	0x58
	.byte	0xe
	.long	0x54
	.long	.LLST7
	.long	.LVUS7
	.uleb128 0x5
	.long	.LASF13
	.byte	0x58
	.byte	0x1b
	.long	0x10b
	.long	.LLST8
	.long	.LVUS8
	.uleb128 0x10
	.quad	.LVL32
	.long	0x192
	.byte	0
	.uleb128 0x7
	.long	0x62
	.uleb128 0x2
	.long	.LASF15
	.byte	0x4a
	.long	0x54
	.quad	.LFB21
	.quad	.LFE21-.LFB21
	.uleb128 0x1
	.byte	0x9c
	.long	0x13c
	.uleb128 0x9
	.string	"x"
	.byte	0x4a
	.byte	0x19
	.long	0x54
	.uleb128 0x1
	.byte	0x55
	.byte	0
	.uleb128 0x2
	.long	.LASF16
	.byte	0x41
	.long	0x54
	.quad	.LFB20
	.quad	.LFE20-.LFB20
	.uleb128 0x1
	.byte	0x9c
	.long	0x192
	.uleb128 0x9
	.string	"n"
	.byte	0x41
	.byte	0x14
	.long	0x54
	.uleb128 0x1
	.byte	0x55
	.uleb128 0xa
	.string	"sum"
	.byte	0x42
	.byte	0x9
	.long	0x54
	.long	.LLST4
	.long	.LVUS4
	.uleb128 0x11
	.long	.LLRL5
	.uleb128 0xa
	.string	"i"
	.byte	0x43
	.byte	0xe
	.long	0x54
	.long	.LLST6
	.long	.LVUS6
	.byte	0
	.byte	0
	.uleb128 0x2
	.long	.LASF17
	.byte	0x2c
	.long	0x54
	.quad	.LFB19
	.quad	.LFE19-.LFB19
	.uleb128 0x1
	.byte	0x9c
	.long	0x270
	.uleb128 0x5
	.long	.LASF18
	.byte	0x2c
	.byte	0x16
	.long	0x54
	.long	.LLST1
	.long	.LVUS1
	.uleb128 0x5
	.long	.LASF19
	.byte	0x2c
	.byte	0x26
	.long	0x54
	.long	.LLST2
	.long	.LVUS2
	.uleb128 0x5
	.long	.LASF20
	.byte	0x2c
	.byte	0x34
	.long	0x54
	.long	.LLST3
	.long	.LVUS3
	.uleb128 0x12
	.long	.LASF30
	.byte	0x1
	.byte	0x3a
	.byte	0x1
	.quad	.L16
	.uleb128 0x3
	.quad	.LVL10
	.long	0x2f9
	.uleb128 0x3
	.quad	.LVL11
	.long	0x3ad
	.uleb128 0x3
	.quad	.LVL12
	.long	0x371
	.uleb128 0x3
	.quad	.LVL13
	.long	0x335
	.uleb128 0x3
	.quad	.LVL14
	.long	0x2f9
	.uleb128 0x3
	.quad	.LVL15
	.long	0x2bf
	.uleb128 0x13
	.quad	.LVL17
	.long	0x270
	.long	0x262
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xa3
	.uleb128 0x1
	.byte	0x54
	.byte	0
	.uleb128 0x3
	.quad	.LVL18
	.long	0x371
	.byte	0
	.uleb128 0x2
	.long	.LASF21
	.byte	0x26
	.long	0x54
	.quad	.LFB18
	.quad	.LFE18-.LFB18
	.uleb128 0x1
	.byte	0x9c
	.long	0x2bf
	.uleb128 0x5
	.long	.LASF22
	.byte	0x26
	.byte	0x14
	.long	0x54
	.long	.LLST0
	.long	.LVUS0
	.uleb128 0x6
	.quad	.LVL7
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC5
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	.LASF26
	.byte	0x1
	.byte	0x22
	.byte	0x6
	.quad	.LFB17
	.quad	.LFE17-.LFB17
	.uleb128 0x1
	.byte	0x9c
	.long	0x2f9
	.uleb128 0x15
	.quad	.LVL4
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC4
	.byte	0
	.byte	0
	.uleb128 0x2
	.long	.LASF23
	.byte	0x1d
	.long	0x54
	.quad	.LFB16
	.quad	.LFE16-.LFB16
	.uleb128 0x1
	.byte	0x9c
	.long	0x335
	.uleb128 0x6
	.quad	.LVL3
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC3
	.byte	0
	.byte	0
	.uleb128 0x2
	.long	.LASF24
	.byte	0x18
	.long	0x54
	.quad	.LFB15
	.quad	.LFE15-.LFB15
	.uleb128 0x1
	.byte	0x9c
	.long	0x371
	.uleb128 0x6
	.quad	.LVL2
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC2
	.byte	0
	.byte	0
	.uleb128 0x2
	.long	.LASF25
	.byte	0x13
	.long	0x54
	.quad	.LFB14
	.quad	.LFE14-.LFB14
	.uleb128 0x1
	.byte	0x9c
	.long	0x3ad
	.uleb128 0x6
	.quad	.LVL1
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC1
	.byte	0
	.byte	0
	.uleb128 0x16
	.long	.LASF27
	.byte	0x1
	.byte	0xe
	.byte	0x5
	.long	0x54
	.quad	.LFB13
	.quad	.LFE13-.LFB13
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x6
	.quad	.LVL0
	.long	0xa0
	.uleb128 0x4
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x9
	.byte	0x3
	.quad	.LC0
	.byte	0
	.byte	0
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
	.uleb128 0x3
	.uleb128 0x48
	.byte	0
	.uleb128 0x7d
	.uleb128 0x1
	.uleb128 0x7f
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x49
	.byte	0
	.uleb128 0x2
	.uleb128 0x18
	.uleb128 0x7e
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x5
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x48
	.byte	0x1
	.uleb128 0x7d
	.uleb128 0x1
	.uleb128 0x7f
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0x21
	.sleb128 8
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
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
	.uleb128 0x9
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
	.uleb128 0xa
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0xb
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
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0xc
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
	.uleb128 0xd
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xe
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
	.uleb128 0xf
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x48
	.byte	0
	.uleb128 0x7d
	.uleb128 0x1
	.uleb128 0x82
	.uleb128 0x19
	.uleb128 0x7f
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
	.uleb128 0x48
	.byte	0x1
	.uleb128 0x7d
	.uleb128 0x1
	.uleb128 0x82
	.uleb128 0x19
	.uleb128 0x7f
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x2e
	.byte	0x1
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
	.uleb128 0x7a
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x48
	.byte	0x1
	.uleb128 0x7d
	.uleb128 0x1
	.uleb128 0x82
	.uleb128 0x19
	.uleb128 0x7f
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x2e
	.byte	0x1
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
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loclists,"",@progbits
	.long	.Ldebug_loc3-.Ldebug_loc2
.Ldebug_loc2:
	.value	0x5
	.byte	0x8
	.byte	0
	.long	0
.Ldebug_loc0:
.LVUS7:
	.uleb128 0
	.uleb128 .LVU108
	.uleb128 .LVU108
	.uleb128 0
.LLST7:
	.byte	0x6
	.quad	.LVL29
	.byte	0x4
	.uleb128 .LVL29-.LVL29
	.uleb128 .LVL30-.LVL29
	.uleb128 0x1
	.byte	0x55
	.byte	0x4
	.uleb128 .LVL30-.LVL29
	.uleb128 .LFE22-.LVL29
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.byte	0
.LVUS8:
	.uleb128 0
	.uleb128 .LVU109
	.uleb128 .LVU109
	.uleb128 0
.LLST8:
	.byte	0x6
	.quad	.LVL29
	.byte	0x4
	.uleb128 .LVL29-.LVL29
	.uleb128 .LVL31-.LVL29
	.uleb128 0x1
	.byte	0x54
	.byte	0x4
	.uleb128 .LVL31-.LVL29
	.uleb128 .LFE22-.LVL29
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.byte	0
.LVUS4:
	.uleb128 .LVU62
	.uleb128 .LVU67
	.uleb128 .LVU69
	.uleb128 .LVU71
	.uleb128 .LVU71
	.uleb128 .LVU75
	.uleb128 .LVU75
	.uleb128 .LVU80
	.uleb128 .LVU80
	.uleb128 0
.LLST4:
	.byte	0x6
	.quad	.LVL20
	.byte	0x4
	.uleb128 .LVL20-.LVL20
	.uleb128 .LVL21-.LVL20
	.uleb128 0x2
	.byte	0x30
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL22-.LVL20
	.uleb128 .LVL23-.LVL20
	.uleb128 0x1
	.byte	0x51
	.byte	0x4
	.uleb128 .LVL23-.LVL20
	.uleb128 .LVL24-.LVL20
	.uleb128 0x6
	.byte	0x71
	.sleb128 0
	.byte	0x70
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL24-.LVL20
	.uleb128 .LVL27-.LVL20
	.uleb128 0x1
	.byte	0x51
	.byte	0x4
	.uleb128 .LVL27-.LVL20
	.uleb128 .LFE20-.LVL20
	.uleb128 0x2
	.byte	0x30
	.byte	0x9f
	.byte	0
.LVUS6:
	.uleb128 .LVU64
	.uleb128 .LVU67
	.uleb128 .LVU69
	.uleb128 .LVU72
	.uleb128 .LVU72
	.uleb128 .LVU76
	.uleb128 .LVU76
	.uleb128 .LVU79
	.uleb128 .LVU80
	.uleb128 0
.LLST6:
	.byte	0x6
	.quad	.LVL20
	.byte	0x4
	.uleb128 .LVL20-.LVL20
	.uleb128 .LVL21-.LVL20
	.uleb128 0x2
	.byte	0x30
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL22-.LVL20
	.uleb128 .LVL23-.LVL20
	.uleb128 0x1
	.byte	0x50
	.byte	0x4
	.uleb128 .LVL23-.LVL20
	.uleb128 .LVL25-.LVL20
	.uleb128 0x3
	.byte	0x70
	.sleb128 1
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL25-.LVL20
	.uleb128 .LVL26-.LVL20
	.uleb128 0x1
	.byte	0x50
	.byte	0x4
	.uleb128 .LVL27-.LVL20
	.uleb128 .LFE20-.LVL20
	.uleb128 0x2
	.byte	0x30
	.byte	0x9f
	.byte	0
.LVUS1:
	.uleb128 0
	.uleb128 .LVU42
	.uleb128 .LVU42
	.uleb128 .LVU56
	.uleb128 .LVU56
	.uleb128 .LVU57
	.uleb128 .LVU57
	.uleb128 0
.LLST1:
	.byte	0x6
	.quad	.LVL9
	.byte	0x4
	.uleb128 .LVL9-.LVL9
	.uleb128 .LVL10-1-.LVL9
	.uleb128 0x1
	.byte	0x55
	.byte	0x4
	.uleb128 .LVL10-1-.LVL9
	.uleb128 .LVL17-.LVL9
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL17-.LVL9
	.uleb128 .LVL18-1-.LVL9
	.uleb128 0x1
	.byte	0x55
	.byte	0x4
	.uleb128 .LVL18-1-.LVL9
	.uleb128 .LFE19-.LVL9
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.byte	0
.LVUS2:
	.uleb128 0
	.uleb128 .LVU42
	.uleb128 .LVU42
	.uleb128 .LVU54
	.uleb128 .LVU54
	.uleb128 .LVU56
	.uleb128 .LVU56
	.uleb128 .LVU56
	.uleb128 .LVU56
	.uleb128 0
.LLST2:
	.byte	0x6
	.quad	.LVL9
	.byte	0x4
	.uleb128 .LVL9-.LVL9
	.uleb128 .LVL10-1-.LVL9
	.uleb128 0x1
	.byte	0x54
	.byte	0x4
	.uleb128 .LVL10-1-.LVL9
	.uleb128 .LVL16-.LVL9
	.uleb128 0x1
	.byte	0x53
	.byte	0x4
	.uleb128 .LVL16-.LVL9
	.uleb128 .LVL17-1-.LVL9
	.uleb128 0x1
	.byte	0x55
	.byte	0x4
	.uleb128 .LVL17-1-.LVL9
	.uleb128 .LVL17-.LVL9
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL17-.LVL9
	.uleb128 .LFE19-.LVL9
	.uleb128 0x1
	.byte	0x53
	.byte	0
.LVUS3:
	.uleb128 0
	.uleb128 .LVU42
	.uleb128 .LVU42
	.uleb128 .LVU47
	.uleb128 .LVU47
	.uleb128 .LVU56
	.uleb128 .LVU56
	.uleb128 .LVU57
	.uleb128 .LVU57
	.uleb128 0
.LLST3:
	.byte	0x6
	.quad	.LVL9
	.byte	0x4
	.uleb128 .LVL9-.LVL9
	.uleb128 .LVL10-1-.LVL9
	.uleb128 0x1
	.byte	0x51
	.byte	0x4
	.uleb128 .LVL10-1-.LVL9
	.uleb128 .LVL12-.LVL9
	.uleb128 0x1
	.byte	0x56
	.byte	0x4
	.uleb128 .LVL12-.LVL9
	.uleb128 .LVL17-.LVL9
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x51
	.byte	0x9f
	.byte	0x4
	.uleb128 .LVL17-.LVL9
	.uleb128 .LVL18-1-.LVL9
	.uleb128 0x1
	.byte	0x51
	.byte	0x4
	.uleb128 .LVL18-1-.LVL9
	.uleb128 .LFE19-.LVL9
	.uleb128 0x4
	.byte	0xa3
	.uleb128 0x1
	.byte	0x51
	.byte	0x9f
	.byte	0
.LVUS0:
	.uleb128 0
	.uleb128 .LVU32
	.uleb128 .LVU32
	.uleb128 .LVU35
	.uleb128 .LVU35
	.uleb128 0
.LLST0:
	.byte	0x6
	.quad	.LVL5
	.byte	0x4
	.uleb128 .LVL5-.LVL5
	.uleb128 .LVL6-.LVL5
	.uleb128 0x1
	.byte	0x55
	.byte	0x4
	.uleb128 .LVL6-.LVL5
	.uleb128 .LVL8-.LVL5
	.uleb128 0x1
	.byte	0x53
	.byte	0x4
	.uleb128 .LVL8-.LVL5
	.uleb128 .LFE18-.LVL5
	.uleb128 0x1
	.byte	0x50
	.byte	0
.Ldebug_loc3:
	.section	.debug_aranges,"",@progbits
	.long	0x3c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	.LFB22
	.quad	.LFE22-.LFB22
	.quad	0
	.quad	0
	.section	.debug_rnglists,"",@progbits
.Ldebug_ranges0:
	.long	.Ldebug_ranges3-.Ldebug_ranges2
.Ldebug_ranges2:
	.value	0x5
	.byte	0x8
	.byte	0
	.long	0
.LLRL5:
	.byte	0x5
	.quad	.LBB2
	.byte	0x4
	.uleb128 .LBB2-.LBB2
	.uleb128 .LBE2-.LBB2
	.byte	0x4
	.uleb128 .LBB3-.LBB2
	.uleb128 .LBE3-.LBB2
	.byte	0
.LLRL9:
	.byte	0x7
	.quad	.Ltext0
	.uleb128 .Letext0-.Ltext0
	.byte	0x7
	.quad	.LFB22
	.uleb128 .LFE22-.LFB22
	.byte	0
.Ldebug_ranges3:
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF28:
	.string	"GNU C17 13.3.0 -mtune=generic -march=x86-64 -g -O2 -fno-inline -fno-builtin -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"
.LASF27:
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
.LASF30:
	.string	"cleanup"
.LASF12:
	.string	"argc"
.LASF6:
	.string	"signed char"
.LASF3:
	.string	"unsigned int"
.LASF29:
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
.LASF26:
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
