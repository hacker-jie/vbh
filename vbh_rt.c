// SPDX-License-Identifier: GPL-2.0

#include "vbh.h"
#include "cpu.h"
#include "nested.h"
#include "mem_ops.h"
#include "tee_root.h"
#include "tee_nonroot.h"
#include "pt.h"

#define CR0	0
#define CR3	3
#define CR4	4

#define VMX_EPTP_MT_WB		0x6ull
#define VMX_EPTP_PWL_4		0x18ull

#define	NR_LOAD_MSRS		8
#define NR_STORE_MSRS		8

#define MOV_TO_CR		0

#define EXIT_REASON_INIT        3

typedef struct _exception_details
{
    char    *name;
    u8      is_available;
    u8      has_error_code;
    u8      has_specific_info;
}exception_details;

#if 0
static int inject_pending_vcpu_exceptions(struct vbh_vcpu_vmx *vcpu);
static int inject_exception(struct vbh_vcpu_vmx *vcpu, u32 exception, u32 error_code);

static const exception_details exception_info[NUMBER_OF_RESERVED_EXCEPTIONS] = 
{
    [X86_TRAP_DE] =     {.name = "Divide Error",                        .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_DB] =     {.name = "Debug Exception",                     .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_NMI] =    {.name = "NMI Interrupt",                       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_BP] =     {.name = "Breakpoint",                          .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_OF] =     {.name = "Overflow",                            .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_BR] =     {.name = "Bound Range Exceeded",                .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_UD] =     {.name = "Invalid Opcode",                      .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_NM] =     {.name = "Device Not Available",                .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_DF] =     {.name = "Double Fault",                        .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_TS] =     {.name = "Invalid TSS",                         .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_NP] =     {.name = "Segment Not Present",                 .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_SS] =     {.name = "Stack-Segment Fault",                 .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_GP] =     {.name = "General Protection",                  .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_PF] =     {.name = "Page Fault",                          .is_available = 1, .has_error_code = 1, .has_specific_info = 1},
    [X86_TRAP_MF] =     {.name = "Math Fault",                          .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_AC] =     {.name = "Alignment Check",                     .is_available = 1, .has_error_code = 1, .has_specific_info = 0},
    [X86_TRAP_MC] =     {.name = "Machine Check",                       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
    [X86_TRAP_XF] =     {.name = "SIMD Floating-Point Exception",       .is_available = 1, .has_error_code = 0, .has_specific_info = 0},
};
#endif

static void skip_emulated_instruction(struct vbh_vcpu_vmx *vcpu)
{
	unsigned long rip;

	if (!vcpu->skip_instruction_not_used) {
		rip = vcpu->regs[VCPU_REGS_RIP];
		rip += exec_vmread32(VM_EXIT_INSTRUCTION_LEN);
		vcpu->regs[VCPU_REGS_RIP] = rip;
		vcpu->instruction_skipped = true;
	}
}

static void vmx_switch_skip_instruction(struct vbh_vcpu_vmx *vcpu)
{
	skip_emulated_instruction(vcpu);
}

void handle_cpuid(struct vbh_vcpu_vmx *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];
	vbh_read_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
	//skip_emulated_instruction(vcpu);
}

//Description:	A method for handling guest software exceptions
int handle_exception_exit(struct vbh_vcpu_vmx *vcpu)
{
	int error = 0;
	//TODO: leave for later to see if needed

	// In this case we want to skip the instruction that generated the exception that was handled
	//vmx_switch_skip_instruction(vcpu);

	return error;
}
void handle_ept_violation(struct vbh_vcpu_vmx *vcpu)
{
	unsigned long exit_qual = exec_vmreadl(EXIT_QUALIFICATION);
	unsigned long long gpa = exec_vmread64(GUEST_PHYSICAL_ADDRESS);
	unsigned long gla = exec_vmreadl(GUEST_LINEAR_ADDRESS);
	unsigned long g_rsp, g_rip;

	g_rsp = exec_vmreadl(GUEST_RSP);
	g_rip = exec_vmreadl(GUEST_RIP);

	pr_err("EPT_VIOLATION at GPA -> 0x%llx GVA -> 0x%lx, exit_qulification = 0x%lx, G_RSP = 0x%lx, G_RIP=0x%lx\n",
		gpa, gla, exit_qual, g_rsp, g_rip);

	// Skip the instruction regardless the value of allow.
	// TODO: skip only if allow is false.
	//vmx_switch_skip_instruction(vcpu);
}

static int handle_vmcall(struct vbh_data *vbh, struct vbh_vcpu_vmx *vcpu,
			 int *do_vmxoff)
{
	u64 nr, a0, a1, a2, a3;
	int ret = 0;

	nr = vcpu->regs[VCPU_REGS_RAX];
	a0 = vcpu->regs[VCPU_REGS_RBX];
	a1 = vcpu->regs[VCPU_REGS_RCX];
	a2 = vcpu->regs[VCPU_REGS_RDX];
	a3 = vcpu->regs[VCPU_REGS_RSI];

	if (nr == KVM_HC_ROOT_VMXOFF) {
		// Don't need to update GUEST_RIP for this case
		vcpu->skip_instruction_not_used = true;
		if (do_vmxoff)
			*do_vmxoff = 1;
		return 0;
	}

	if (nr == 1)
		vbh_mem_status(vbh);

	if ((nr == VBH_NESTED_FLUSH_TLB_RANGE) && vbh->enable_shadow_ept)
		nested_flush_tlb_with_range(vcpu, a0, a1, a2);
	else if ((nr == VBH_NESTED_FLUSH_TLB_ALL) && vbh->enable_shadow_ept)
		nested_flush_tlb(vcpu, a0);
	else if (nr == TEE_HYPERCALL_CREATE) {
		ret = handle_tee_create(vbh, a0, a1, a2, a3);
		exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));
	} else if (nr == TEE_HYPERCALL_RUN) {
		struct vmcs *host_vmcs = vcpu->pcpu_vmcs;

		ret = handle_te_run(vbh, host_vmcs);
	}

	//skip_emulated_instruction(vcpu);

	return ret;
}

void handle_read_msr(struct vbh_vcpu_vmx *vcpu)
{
	u32 low, high;
	unsigned long msr = vcpu->regs[VCPU_REGS_RCX];

	// msr should be in rcx
	vbh_rdmsr(msr, low, high);

	// Debug only
	pr_err("<1> %s: Value of msr 0x%lx: low=0x%x, high=0x%x\n",
		__func__, msr, low, high);

	// save msr value into rax and rdx
	vcpu->regs[VCPU_REGS_RAX] = low;
	vcpu->regs[VCPU_REGS_RDX] = high;

	//vmx_switch_skip_instruction(vcpu);
}

void handle_write_msr(struct vbh_vcpu_vmx *vcpu)
{
	u32 new_low, new_high;
	unsigned long old_value, new_value;
	unsigned long msr = vcpu->regs[VCPU_REGS_RCX];

	// msr should be in rcx
	new_low = vcpu->regs[VCPU_REGS_RAX];
	new_high = vcpu->regs[VCPU_REGS_RDX];

	new_value = (unsigned long)new_high << 32 | new_low;

	// Get old value
	old_value = msr_read((u32)msr);

	pr_info("%s: write MSR 0x%lx not permitted\n", __func__, msr);

	//vmx_switch_skip_instruction(vcpu);
}

void handle_mtf(struct vbh_vcpu_vmx *vcpu)
{
	// TODO: report event.  What format?
}

void handle_cr(struct vbh_vcpu_vmx *vcpu)
{
	unsigned long exit_qual, val;
	int cr;
	int type;
	int reg;
	unsigned long old_value;

	exit_qual = exec_vmreadl(EXIT_QUALIFICATION);
	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;

	switch (type) {
	case MOV_TO_CR:
		switch (cr) {
		case CR0:
			old_value = exec_vmreadl(GUEST_CR0);
			val = vcpu->regs[reg];
			// skip next instruction
			//vmx_switch_skip_instruction(vcpu);
			break; // CR0
		case CR4:
			old_value = exec_vmreadl(GUEST_CR4);
			val = vcpu->regs[reg];
			// VMXE bit is owned by host, others are owned by guest
			// So only when guest is trying to modify VMXE bit it
			// can cause vmexit and get here.
			exec_vmwritel(CR4_READ_SHADOW, val);
			// skip next instruction
			//vmx_switch_skip_instruction(vcpu);
			break;	// CR4
		default:
			break;
		} //MOV_TO_CR
	default:
		break;
	}
}

static void handle_xsetbv(struct vbh_vcpu_vmx *vcpu)
{
	u32 eax = (u32)(vcpu->regs[VCPU_REGS_RAX] & -1u);
	u32 edx = (u32)(vcpu->regs[VCPU_REGS_RDX] & -1u);
	u32 ecx = (u32)(vcpu->regs[VCPU_REGS_RCX] & -1u);

	//TODO: currently it is directly use xsetbv, any
	// audit needed?
	asm volatile(".byte 0x0f,0x01,0xd1" /* xsetbv */
			: : "a" (eax), "d" (edx), "c" (ecx));
}

int vmx_switch_and_exit_handler(struct vbh_data *vbh, int cpu)
{
	//int error = 0;
	unsigned long *reg_area;
	struct vbh_vcpu_vmx *vcpu_ptr;
	u32 vmexit_reason;
	u64 gpa;
	int do_vmxoff = 0;
	int ret = 0;

	BUG_ON(vbh->magic_code != VBH_DATA_MAGIC_CODE);

	vcpu_ptr = &vbh->vcpus[cpu]->vcpu_vmx;

	reg_area = vbh->vcpus[cpu]->reg_scratch;
	reg_area[VCPU_REGS_RIP] = exec_vmreadl(GUEST_RIP);
	reg_area[VCPU_REGS_RSP] = exec_vmreadl(GUEST_RSP);

	vmexit_reason = exec_vmread32(VM_EXIT_REASON);
	vcpu_ptr->instruction_skipped = false;
	vcpu_ptr->skip_instruction_not_used = false;

	vcpu_ptr->instr_info = exec_vmread32(VMX_INSTRUCTION_INFO);
	vcpu_ptr->exit_qualification = exec_vmreadl(EXIT_QUALIFICATION);

	switch (vmexit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		pr_err("<1> vmexit_reason: EXIT_REASON_EXCEPTION_NMI or EXCEPTION_EXIT\n");
		handle_exception_exit(vcpu_ptr);
		break;
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu_ptr);
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		gpa = exec_vmread64(GUEST_PHYSICAL_ADDRESS);
		pr_err("<1> vmexit_reason: guest physical address 0x%llx resulted in EPT_MISCONFIG\n",
			gpa);
		//dump_entries(vbh->vmx_eptp_pml4, gpa);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		pr_err("<1> vmexit_reason: EPT_VIOLATION\n");
		handle_ept_violation(vcpu_ptr);
		break;
	case EXIT_REASON_VMCALL:
		reg_area[VCPU_REGS_RAX] = handle_vmcall(vbh, vcpu_ptr, &do_vmxoff);
		break;
	case EXIT_REASON_CR_ACCESS:
		pr_err("<1> vmexit_reason: CR_ACCESS.\n");
		handle_cr(vcpu_ptr);
		break;
	case EXIT_REASON_MSR_READ:
		pr_err("<1> vmexit_reason: MSR_READ.\n");
		handle_read_msr(vcpu_ptr);
		break;
	case EXIT_REASON_MSR_WRITE:
		handle_write_msr(vcpu_ptr);
		break;
	case EXIT_REASON_INIT:
		pr_err("<1> vmexit reason: INIT on cpu-[%d].\n", cpu);
		break;
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		pr_err("<1> vmexit_reason: MONITOR_TRAP_FLAG.\n");
		handle_mtf(vcpu_ptr);
		break;
	case EXIT_REASON_INVEPT:
		ret = invept_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMCLEAR:
		ret = vmclear_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMPTRLD:
		ret = vmptrld_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMREAD:
		ret = vmread_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMWRITE:
		ret = vmwrite_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMLAUNCH:
		ret = vmlaunch_vmexit_handler(vcpu_ptr);
		if (!ret)
			vcpu_ptr->skip_instruction_not_used = true;
		break;
	case EXIT_REASON_VMRESUME:
		ret = vmresume_vmexit_handler(vcpu_ptr);
		if (!ret)
			vcpu_ptr->skip_instruction_not_used = true;
		break;
	case EXIT_REASON_INVVPID:
		ret = invvpid_vmexit_handler(vcpu_ptr);
		break;
	case EXIT_REASON_VMOFF:
		break;
	case EXIT_REASON_VMON:
		ret = vmxon_handler(vcpu_ptr);
		break;
	case EXIT_REASON_XSETBV:
		handle_xsetbv(vcpu_ptr);
		break;
	default:
		pr_err("<1> CPU-%d: Unhandled vmexit reason 0x%x.\n",
			cpu, vmexit_reason);
		break;
	}

	if (ret)
		pr_err("%s: vmexit reason %d invalid result %d\n", __func__, vmexit_reason, ret);
#if 0
    // At the end of every vmexit, inject pending interrupts/exceptions
    error = inject_pending_vcpu_exceptions(vcpu_ptr);
    if (error)
    {
        pr_err("inject_pending_vcpu_exceptions failed with error = 0x%016X !\n", error);
    }
#endif

	vmx_switch_skip_instruction(vcpu_ptr);

	if (vcpu_ptr->instruction_skipped == true)
		exec_vmwritel(GUEST_RIP, reg_area[VCPU_REGS_RIP]);

	return do_vmxoff;
}

#if 0
static int inject_pending_vcpu_exceptions(struct vbh_vcpu_vmx *vcpu)
{
    // The order is the following, based on Intel System Programming Manual:
    // Chapter 6.9: Priority Among Simultaneous Exceptions and Interrupts
    //   INIT / SIPI
    //   Breakpoint
    //   NMI
    //   Hardware interrupts (PIC, LAPIC)
    //   Low priority exceptions (GP etc)

    //
    //  1. Hardware resets / MC
    //  2. Trap on TSS
    //  3. External hardware interventions (flush, stopclk, SMI, INIT)
    //  4. Traps on the previous instruction (breakpoints, debug trap exceptions)
    //  5. NMI
    //  6. Maskable hardware interrupts
    //  7. Code breakpoint fault
    //  8. Faults from fetching next instruction (code-segment limit violation, code page fault)
    //  9. Faults from decoding next instruction (instruction length > 15, invalid opcode, coprocessor not available)
    // 10. Fault on executing an instruction (overflow, bound error, invalid TSS, segment not present, stack fault, GP, data page fault,
    //     alignment check, x87 FPU FP exception, SIMD FP exception)
    //
	int error = 0;
    exception_additional_info additional_info;

    if (vcpu == NULL)
    {
        return -EINVAL;
    }

    // If there's nothing in pending
    if (vcpu->vcpu_exception.exception_injection_mask == 0x0)
    {
        return 0;
    }

    if (vcpu->vcpu_exception.exception_injection_mask & VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_PF))
    {
        additional_info = vcpu->vcpu_exception.additional_info[X86_TRAP_PF];
        
        // Reset the injection flag.
        vcpu->vcpu_exception.exception_injection_mask &= ~(VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_PF));

        // Effectively inject a PF
        error = inject_exception(vcpu, X86_TRAP_PF, additional_info.exception_error_code);
        if (error)
        {
            pr_err("inject_exception failed with error = 0x%016X !\n", error);
			return error;
        }

        // Handle specific info, if exist and valid
        if(!(exception_info[X86_TRAP_PF].has_specific_info))
        {
            return 0;
        }

        //
        // If inject_exception succeeded, then we can handle exception custom informations
        //
        // Is virtual_address field from additional_info valid?
        if(test_bit(virtual_address, additional_info.specific_additional_info.page_fault_specific.field_is_ok))
        {
            //vcpu->regs[VCPU_REGS_CR2] = additional_info.specific_additional_info.page_fault_specific.virtual_address;
            vcpu->cr2 = additional_info.specific_additional_info.page_fault_specific.virtual_address;
        }

        return 0;
    }

    // Debug exception
    if (vcpu->vcpu_exception.exception_injection_mask & VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_BP))
    {
        // Reset the injection flag.
        vcpu->vcpu_exception.exception_injection_mask &= ~(VCPU_INJECT_EXCEPTION_MASK(X86_TRAP_BP));

        // Effectively inject
        error = inject_exception(vcpu, X86_TRAP_BP, 0);
        if (error)
        {
            pr_err("inject_exception failed with error = 0x%016X !\n", error);
			return error;
        }
        
        return 0;
    }

	// Command is not implemened
	return -EOPNOTSUPP;
}

static int inject_exception(struct vbh_vcpu_vmx *vcpu, u32 exception, u32 error_code)
{
    u64 guest_cr0;
    u32 entry_interruption_information_raw = 0;
    vm_entry_int_info entry_interruption_information;

    printk(KERN_INFO "inject_exception exception = 0x%016X, name = %s\n", exception, exception_info[exception].name);
    
    entry_interruption_information.value = 0;

    // Read guest cr0
    guest_cr0 = exec_vmreadl(GUEST_CR0);

    // Populate interruption information fields
    entry_interruption_information.fields.valid = 1;
    entry_interruption_information.fields.vector = exception;

    // If ProtectedMode bit is set in CR0 (bit0) and the vector is at most 31,
    // the event should be injected as a HardwareException
    if ((guest_cr0 & PE) == 0)
    {
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_EXTERNAL_INTERRUPT;
        entry_interruption_information.fields.deliver_error_code = 0;
        
        goto inject;
    }

    if(exception == X86_TRAP_BP)
    {
        // Software exception
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_SOFTWARE_EXCEPTION;

        // If VM entry successfully injects (with no nested exception) an event with interruption type software
        // interrupt, privileged software exception, or software exception, the current guest RIP is incremented by the
        // VM-entry instruction length before being pushed on the stack.
        exec_vmwrite32(VM_ENTRY_INSTRUCTION_LEN, 0);

        goto inject;
    }
    else
    {
        entry_interruption_information.fields.interruption_type = INTERRUPTION_TYPE_HARDWARE_EXCEPTION;
    }
    
    if (exception_info[exception].has_error_code)
    {
        entry_interruption_information.fields.deliver_error_code = 1;
        exec_vmwrite32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
    }

inject:
    entry_interruption_information_raw = vm_entry_info_pack(entry_interruption_information);
    exec_vmwrite32(VM_ENTRY_INTR_INFO_FIELD, entry_interruption_information_raw);

    return 0;
}
#endif
