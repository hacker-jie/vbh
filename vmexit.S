#include <linux/linkage.h>
//#include <asm/dwarf2.h>
//#include <asm/asm.h>
//#include <asm/percpu.h>
#include "regs.h"

#define VCPU_REGS_RAX	(__VCPU_REGS_RAX * 8)
#define VCPU_REGS_RCX	(__VCPU_REGS_RCX * 8)
#define VCPU_REGS_RDX	(__VCPU_REGS_RDX * 8)
#define VCPU_REGS_RBX	(__VCPU_REGS_RBX * 8)
#define VCPU_REGS_RSP	(__VCPU_REGS_RSP * 8)
#define VCPU_REGS_RBP	(__VCPU_REGS_RBP * 8)
#define VCPU_REGS_RSI	(__VCPU_REGS_RSI * 8)
#define VCPU_REGS_RDI	(__VCPU_REGS_RDI * 8)

#ifdef CONFIG_X86_64
#define VCPU_REGS_R8	(__VCPU_REGS_R8 * 8)
#define VCPU_REGS_R9	(__VCPU_REGS_R9 * 8)
#define VCPU_REGS_R10	(__VCPU_REGS_R10 * 8)
#define VCPU_REGS_R11	(__VCPU_REGS_R11 * 8)
#define VCPU_REGS_R12	(__VCPU_REGS_R12 * 8)
#define VCPU_REGS_R13	(__VCPU_REGS_R13 * 8)
#define VCPU_REGS_R14	(__VCPU_REGS_R14 * 8)
#define VCPU_REGS_R15	(__VCPU_REGS_R15 * 8)
#endif
#define VCPU_REGS_CR2	(__VCPU_REGS_CR2 * 8)

ENTRY(vmx_switch_and_exit_handle_vmexit)
//push rcx
	push %rcx
//move reg scratch to rcx
	mov 8(%rsp), %rcx
//copy rax thru rbp thru r11 to offsets within rcx
//use enum*8 as offset
	mov %rax, VCPU_REGS_RAX(%rcx)
	mov %rbx, VCPU_REGS_RBX(%rcx)
	mov %rdx, VCPU_REGS_RDX(%rcx)
	mov %rsi, VCPU_REGS_RSI(%rcx)
	mov %rdi, VCPU_REGS_RDI(%rcx)
	mov %rbp, VCPU_REGS_RBP(%rcx)
	popq VCPU_REGS_RCX(%rcx)
	mov %r8 , VCPU_REGS_R8(%rcx)
	mov %r9 , VCPU_REGS_R9(%rcx)
	mov %r10, VCPU_REGS_R10(%rcx)
	mov %r11, VCPU_REGS_R11(%rcx)
	mov %r12, VCPU_REGS_R12(%rcx)
	mov %r13, VCPU_REGS_R13(%rcx)
	mov %r14, VCPU_REGS_R14(%rcx)
	mov %r15, VCPU_REGS_R15(%rcx)
	mov %cr2, %rax
	mov %rax, VCPU_REGS_CR2(%rcx)
//call the C part of handler
	mov %rsp, %rbp
	mov 8(%rsp), %rdi
	mov 16(%rsp), %rsi
	call vmx_switch_and_exit_handler
	// set scratch reg to rcx
	mov (%rsp), %rcx
	cmp $1, %rax
	je do_vmxoff
//copy values from memory into registers
	mov VCPU_REGS_CR2(%rcx), %rax
	mov %rax, %cr2
	mov VCPU_REGS_RAX(%rcx), %rax
	mov VCPU_REGS_RBX(%rcx), %rbx
	mov VCPU_REGS_RDX(%rcx), %rdx
	mov VCPU_REGS_RSI(%rcx), %rsi
	mov VCPU_REGS_RDI(%rcx), %rdi
	mov VCPU_REGS_RBP(%rcx), %rbp
	mov VCPU_REGS_R8(%rcx),  %r8
	mov VCPU_REGS_R9(%rcx), %r9
	mov VCPU_REGS_R10(%rcx), %r10
	mov VCPU_REGS_R11(%rcx), %r11
	mov VCPU_REGS_R12(%rcx), %r12
	mov VCPU_REGS_R13(%rcx), %r13
	mov VCPU_REGS_R14(%rcx), %r14
	mov VCPU_REGS_R15(%rcx), %r15
	mov VCPU_REGS_RCX(%rcx), %rcx
//vmresume
	.byte 0x0f, 0x01, 0xc3
	ret
do_vmxoff:
	mov 8(%rsp), %rdi
	mov 16(%rsp), %rsi

	mov $0x6802, %ebx // read guest cr3
	vmread %rbx, %rax
	mov %rax, %cr3

	mov $0x681e, %ebx // read guest rip
	vmread %rbx, %rax
	mov %rax, %r11

	mov $0x440c, %ebx // read guest rip length
	vmread %rbx, %rax
	add %rax, %r11

	mov    $0x681c, %ebx  //read guest rsp
	vmread %rbx, %rax
	mov    %rax, %r10
	mov %r10, %rsp

	mov    $0x6820, %ebx  //read guest rflags
	vmread %rbx, %rax

	push $0x18 //push the guest state on stack for iretq
	push %r10
	push %rax
	push $0x10
	push %r11
	push %rcx
	push %rdi

	call vbh_vmcs_clear
	vmxoff

	pop %rax // pass vbh_data to rax so it can return with it
	pop %rcx
	mov VCPU_REGS_CR2(%rcx), %rbx
	mov %rbx, %cr2
	mov VCPU_REGS_RBX(%rcx), %rbx
	mov VCPU_REGS_RDX(%rcx), %rdx
	mov VCPU_REGS_RSI(%rcx), %rsi
	mov VCPU_REGS_RDI(%rcx), %rdi
	mov VCPU_REGS_RBP(%rcx), %rbp
	mov VCPU_REGS_R8(%rcx),  %r8
	mov VCPU_REGS_R9(%rcx), %r9
	mov VCPU_REGS_R10(%rcx), %r10
	mov VCPU_REGS_R11(%rcx), %r11
	mov VCPU_REGS_R12(%rcx), %r12
	mov VCPU_REGS_R13(%rcx), %r13
	mov VCPU_REGS_R14(%rcx), %r14
	mov VCPU_REGS_R15(%rcx), %r15
	mov VCPU_REGS_RCX(%rcx), %rcx

	iretq
END(vmx_switch_and_exit_handle_vmexit)

/**
 * __vmenter - VM-Enter the current loaded VMCS
 *
 * %RFLAGS.ZF:	!VMCS.LAUNCHED, i.e. controls VMLAUNCH vs. VMRESUME
 *
 * Returns:
 *	%RFLAGS.CF is set on VM-Fail Invalid
 *	%RFLAGS.ZF is set on VM-Fail Valid
 *	%RFLAGS.{CF,ZF} are cleared on VM-Success, i.e. VM-Exit
 *
 * Note that VMRESUME/VMLAUNCH fall-through and return directly if
 * they VM-Fail, whereas a successful VM-Enter + VM-Exit will jump
 * to vmx_vmexit.
 */
ENTRY(__vmenter)
	/* EFLAGS.ZF is set if VMCS.LAUNCHED == 0 */
	je 2f

1:	vmresume
	ret

2:	vmlaunch
	ret
ENDPROC(__vmenter)

/**
 * __vmexit - Handle a VMX VM-Exit
 *
 * Returns:
 *	%RFLAGS.{CF,ZF} are cleared on VM-Success, i.e. VM-Exit
 *
 * This is __vmenter's partner in crime.  On a VM-Exit, control will jump
 * here after hardware loads the host's state, i.e. this is the destination
 * referred to by VMCS.HOST_RIP.
 */
ENTRY(__vmexit)
	ret
ENDPROC(__vmexit)

/**
 * __vmx_root_vcpu_run - Run a vCPU via a transition to VMX guest mode
 * @vmx:	struct vcpu_vmx * (forwarded to vmx_update_host_rsp)
 * @regs:	unsigned long * (to guest registers)
 * @launched:	%true if the VMCS has been launched
 *
 * Returns:
 *	0 on VM-Exit, 1 on VM-Fail
 */
ENTRY(__nested_vcpu_run)
	push %rbp
	push %rdx
	push %rcx
	push %rbx
#ifdef CONFIG_X86_64
	push %r15
	push %r14
	push %r13
	push %r12
#else
	push %edi
	push %esi
#endif
	push %rdi

	mov $0x6c14, %ebx
	lea -8(%rsp), %rcx
	vmwrite %rcx, %rbx

	mov %rdi, %rcx
	cmp $1, %rsi

	mov VCPU_REGS_CR2(%rcx), %rax
	mov %rax, %cr2
	mov VCPU_REGS_RAX(%rcx), %rax
	mov VCPU_REGS_RBX(%rcx), %rbx
	mov VCPU_REGS_RDX(%rcx), %rdx
	mov VCPU_REGS_RSI(%rcx), %rsi
	mov VCPU_REGS_RDI(%rcx), %rdi
	mov VCPU_REGS_RBP(%rcx), %rbp
#ifdef CONFIG_X86_64
	mov VCPU_REGS_R8(%rcx),  %r8
	mov VCPU_REGS_R9(%rcx), %r9
	mov VCPU_REGS_R10(%rcx), %r10
	mov VCPU_REGS_R11(%rcx), %r11
	mov VCPU_REGS_R12(%rcx), %r12
	mov VCPU_REGS_R13(%rcx), %r13
	mov VCPU_REGS_R14(%rcx), %r14
	mov VCPU_REGS_R15(%rcx), %r15
#endif
	mov (VCPU_REGS_RCX)(%rcx), %rcx

	call __vmenter

	/* Jump on VM-Fail. */
	jbe 2f

	push %rcx
	mov 8(%rsp), %rcx

	mov %rax, VCPU_REGS_RAX(%rcx)
	mov %rbx, VCPU_REGS_RBX(%rcx)
	mov %rdx, VCPU_REGS_RDX(%rcx)
	mov %rsi, VCPU_REGS_RSI(%rcx)
	mov %rdi, VCPU_REGS_RDI(%rcx)
	mov %rbp, VCPU_REGS_RBP(%rcx)
	popq VCPU_REGS_RCX(%rcx)
#ifdef CONFIG_X86_64
	mov %r8 , VCPU_REGS_R8(%rcx)
	mov %r9 , VCPU_REGS_R9(%rcx)
	mov %r10, VCPU_REGS_R10(%rcx)
	mov %r11, VCPU_REGS_R11(%rcx)
	mov %r12, VCPU_REGS_R12(%rcx)
	mov %r13, VCPU_REGS_R13(%rcx)
	mov %r14, VCPU_REGS_R14(%rcx)
	mov %r15, VCPU_REGS_R15(%rcx)
#endif
	mov %cr2, %rax
	mov %rax, VCPU_REGS_CR2(%rcx)

	/* Clear RAX to indicate VM-Exit (as opposed to VM-Fail). */
	xor %eax, %eax

	/*
	 * Clear all general purpose registers except RSP and RAX to prevent
	 * speculative use of the guest's values, even those that are reloaded
	 * via the stack.  In theory, an L1 cache miss when restoring registers
	 * could lead to speculative execution with the guest's values.
	 * Zeroing XORs are dirt cheap, i.e. the extra paranoia is essentially
	 * free.  RSP and RAX are exempt as RSP is restored by hardware during
	 * VM-Exit and RAX is explicitly loaded with 0 or 1 to return VM-Fail.
	 */
1:	xor %ebx, %ebx
	xor %ecx, %ecx
	xor %edx, %edx
	xor %esi, %esi
	xor %edi, %edi
	xor %ebp, %ebp
#ifdef CONFIG_X86_64
	xor %r8d,  %r8d
	xor %r9d,  %r9d
	xor %r10d, %r10d
	xor %r11d, %r11d
	xor %r12d, %r12d
	xor %r13d, %r13d
	xor %r14d, %r14d
	xor %r15d, %r15d
#endif

	pop %rdi
#ifdef CONFIG_X86_64
	pop %r12
	pop %r13
	pop %r14
	pop %r15
#else
	pop %esi
	pop %edi
#endif
	pop %rbx
	pop %rcx
	pop %rdx
	pop %rbp
	ret
	/* VM-Fail.  Out-of-line to avoid a taken Jcc after VM-Exit. */
2:	mov $1, %eax
	jmp 1b
ENDPROC(__nested_vcpu_run)
