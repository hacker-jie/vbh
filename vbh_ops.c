#include <linux/processor.h>
#include <asm/msr.h>
#include "vbh.h"
#include "vmx_ops.h"
#include "pt.h"
#include "cpu.h"

void vbh_vmcs_clear(struct vbh_data *vbh, int cpu)
{
	struct vbh_vcpu_vmx *vcpu;

	vcpu = &vbh->vcpus[cpu]->vcpu_vmx;
	exec_vmclear(vbh_pa(vcpu->pcpu_vmcs));
}

unsigned long segment_base(struct vbh_desc_ptr *gdt, u16 selector)
{
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = vbh_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;
		table_base = segment_base(gdt, ldt_selector);
	}

	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = (unsigned)(d->base0 | ((d->base1) << 16) | ((d->base2) << 24));

#ifdef CONFIG_X86_64
	if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
		v |= ((unsigned long)((tss_desc *)d)->base3) << 32;
#endif
	return v;
}

unsigned int segment_limit(struct vbh_desc_ptr *gdt, u16 selector)
{
	struct desc_struct *d;
	unsigned long table_base;
	unsigned int l;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {
		/* from ldt */
		u16 ldt_selector = vbh_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;
		table_base = segment_base(gdt, ldt_selector);
	}

	d = (struct desc_struct *)(table_base + (selector & ~7));
	l = d->limit0 | (d->limit1 << 16);
	return l;
}

void load_host_state_area(u64 cr3_pa)
{
	struct vbh_desc_ptr dt;
	u16 selector;
	u32 high, low;
	unsigned long a;
	u16 tr;

	vbh_store_gdt(&dt);

	exec_vmwritel(HOST_CR0, vbh_read_cr0() & ~X86_CR0_TS);
	exec_vmwritel(HOST_CR3, cr3_pa);
	exec_vmwritel(HOST_CR4, vbh_read_cr4());

	asm ("mov %%cs, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_CS_SELECTOR, selector);

	asm ("mov %%ss, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_SS_SELECTOR, selector);

	asm ("mov %%ds, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_DS_SELECTOR, selector);

	asm ("mov %%es, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_ES_SELECTOR, selector);

	asm ("mov %%fs, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_FS_SELECTOR, selector);
	exec_vmwritel(HOST_FS_BASE, msr_read(MSR_FS_BASE));


	asm ("mov %%gs, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(HOST_GS_SELECTOR, selector);
	exec_vmwritel(HOST_GS_BASE, msr_read(MSR_GS_BASE));


	asm volatile ("str %0" : "=r" (tr));
	exec_vmwrite16(HOST_TR_SELECTOR, tr);
	exec_vmwritel(HOST_TR_BASE, segment_base(&dt, tr));

	exec_vmwritel(HOST_GDTR_BASE, dt.address);

	vbh_store_idt(&dt);
	exec_vmwritel(HOST_IDTR_BASE, dt.address);

	//MSR area
	vbh_rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	exec_vmwrite32(HOST_IA32_SYSENTER_CS, low);

	vbh_rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	exec_vmwritel(HOST_IA32_SYSENTER_ESP, a);

	vbh_rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	exec_vmwritel(HOST_IA32_SYSENTER_EIP, a);

	vbh_rdmsrl(MSR_EFER, a);
	exec_vmwrite64(HOST_IA32_EFER, a);

	vbh_rdmsrl(MSR_IA32_CR_PAT, a);
	exec_vmwrite64(HOST_IA32_PAT, a);
}

//TODO: see if any optimization can be done here?
void save_host_state_area(struct host_state *state)
{
	state->rsp = exec_vmreadl(HOST_RSP);
	state->rip = exec_vmreadl(HOST_RIP);

	state->cr0 = exec_vmreadl(HOST_CR0);
	state->cr3 = exec_vmreadl(HOST_CR3);
	state->cr4 = exec_vmreadl(HOST_CR4);
	state->cs_selector = exec_vmread16(HOST_CS_SELECTOR);
	state->ss_selector = exec_vmread16(HOST_SS_SELECTOR);
	state->ds_selector = exec_vmread16(HOST_DS_SELECTOR);
	state->es_selector = exec_vmread16(HOST_ES_SELECTOR);
	state->fs_selector = exec_vmread16(HOST_FS_SELECTOR);
	state->fs_base = exec_vmreadl(HOST_FS_BASE);
	state->gs_selector = exec_vmread16(HOST_GS_SELECTOR);
	state->gs_base = exec_vmreadl(HOST_GS_BASE);
	state->tr_selector = exec_vmread16(HOST_TR_SELECTOR);
	state->tr_base = exec_vmreadl(HOST_TR_BASE);
	state->gdtr_base = exec_vmreadl(HOST_GDTR_BASE);
	state->idtr_base = exec_vmreadl(HOST_IDTR_BASE);
	state->ia32_sysenter_cs = exec_vmread32(HOST_IA32_SYSENTER_CS);
	state->ia32_sysenter_esp = exec_vmreadl(HOST_IA32_SYSENTER_ESP);
	state->ia32_sysenter_eip = exec_vmreadl(HOST_IA32_SYSENTER_EIP);
	state->ia32_efer = exec_vmread64(HOST_IA32_EFER);
	state->ia32_pat = exec_vmread64(HOST_IA32_PAT);
}

//TODO: see if any optimization can be done here?
void restore_host_state_area(struct host_state *state)
{
	exec_vmwritel(HOST_RSP, state->rsp);
	exec_vmwritel(HOST_RIP, state->rip);

	exec_vmwritel(HOST_CR0, state->cr0);
	exec_vmwritel(HOST_CR3, state->cr3);
	exec_vmwritel(HOST_CR4, state->cr4);
	exec_vmwrite16(HOST_CS_SELECTOR, state->cs_selector);
	exec_vmwrite16(HOST_SS_SELECTOR, state->ss_selector);
	exec_vmwrite16(HOST_DS_SELECTOR, state->ds_selector);
	exec_vmwrite16(HOST_ES_SELECTOR, state->es_selector);
	exec_vmwrite16(HOST_FS_SELECTOR, state->fs_selector);
	exec_vmwritel(HOST_FS_BASE, state->fs_base);
	exec_vmwrite16(HOST_GS_SELECTOR, state->gs_selector);
	exec_vmwritel(HOST_GS_BASE, state->gs_base);
	exec_vmwrite16(HOST_TR_SELECTOR, state->tr_selector);
	exec_vmwritel(HOST_TR_BASE, state->tr_base);
	exec_vmwritel(HOST_GDTR_BASE, state->gdtr_base);
	exec_vmwritel(HOST_IDTR_BASE, state->idtr_base);
	exec_vmwrite32(HOST_IA32_SYSENTER_CS, state->ia32_sysenter_cs);
	exec_vmwritel(HOST_IA32_SYSENTER_ESP, state->ia32_sysenter_esp);
	exec_vmwritel(HOST_IA32_SYSENTER_EIP, state->ia32_sysenter_eip);
	exec_vmwrite64(HOST_IA32_EFER, state->ia32_efer);
	exec_vmwrite64(HOST_IA32_PAT, state->ia32_pat);
}

u64 construct_eptp(unsigned long root_hpa, struct vmx_capability *vmx_cap)
{
	u64 eptp = 0;

	if (vmx_cap->ept & VMX_EPT_PAGE_WALK_4_BIT)
		eptp = VMX_EPTP_PWL_4;

	if (vmx_cap->ept & VMX_EPTP_WB_BIT)
		eptp |= VMX_EPTP_MT_WB;

	eptp |= (root_hpa & PAGE_MASK);

	pr_err("<1> vmx_capability.ept=0x%x, vmx_capability.vpid=0x%x eptp 0x%llx\n",
		vmx_cap->ept, vmx_cap->vpid, eptp);

	return eptp;
}

void load_execution_control(struct vbh_data *vbh,
			    struct vmcs_config *vmcs_config_ptr,
			    u64 eptp, bool is_primary)
{
//	u32 high, low;
//	u32 value;

//	rdmsr(MSR_IA32_VMX_PINBASED_CTLS, low, high);
//	value = 0x16;
//	value = value | low;
//	value = value & high;
	exec_vmwrite32(PIN_BASED_VM_EXEC_CONTROL,
				vmcs_config_ptr->pin_based_exec_ctrl);

//	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, low, high);
//	value = 0x94006172;
//	value = value | low;
//	value = value & high;
	//enable seconday controls
	exec_vmwrite32(CPU_BASED_VM_EXEC_CONTROL,
				vmcs_config_ptr->cpu_based_exec_ctrl);

//	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, low, high);
//	value = 0x0;
//	value = value | low;
//	value = value & high;
	//enable seconday controls
	exec_vmwrite32(SECONDARY_VM_EXEC_CONTROL,
				vmcs_config_ptr->cpu_based_2nd_exec_ctrl);
	pr_info("%s: cpu_based_2nd_exec_ctrl 0x%x\n",
		__func__, vmcs_config_ptr->cpu_based_2nd_exec_ctrl);

	exec_vmwrite64(EPT_POINTER, eptp);
	exec_vmwrite32(CR3_TARGET_COUNT, 0);
	if (!is_primary) {
		exec_vmwrite32(EXCEPTION_BITMAP, 0x60042);
		return;
	}

	exec_vmwrite32(EXCEPTION_BITMAP, 0);

	exec_vmwrite64(IO_BITMAP_A, vbh_pa(vbh->vmx_io_bitmap_a_switch));

	exec_vmwrite64(IO_BITMAP_B, vbh_pa(vbh->vmx_io_bitmap_b_switch));

	exec_vmwrite64(MSR_BITMAP, vbh_pa(vbh->vmx_msr_bitmap_switch));


	exec_vmwritel(CR0_GUEST_HOST_MASK, 0); //guest owns the bits

	exec_vmwritel(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);

	//TODO: MSR bitmap addresses - all bits shud be set to 0
}

void load_vmentry_control(struct vmcs_config *vmcs_config_ptr)
{
//	u32 low, high;
//	u32 value;

//	rdmsr(MSR_IA32_VMX_ENTRY_CTLS, low, high);
//	value = 0x93ff;
//	value = value | low;
//	value = value & high;

	exec_vmwrite32(VM_ENTRY_CONTROLS, vmcs_config_ptr->vmentry_ctrl);
	exec_vmwrite32(VM_ENTRY_INTR_INFO_FIELD, 0);
	exec_vmwrite32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	exec_vmwrite32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

void load_vmexit_control(struct vmcs_config *vmcs_config_ptr)
{
//	u32 low, high;
//	u32 value;

//	rdmsr(MSR_IA32_VMX_EXIT_CTLS, low, high);
//	value = 0x336fff;
//	value = value | low;
//	value = value & high;

	exec_vmwrite32(VM_EXIT_CONTROLS, vmcs_config_ptr->vmexit_ctrl);
	exec_vmwrite32(VM_EXIT_MSR_STORE_COUNT, 0);
}

static bool vbh_has_vmx_invept_context(struct vbh_data *vbh)
{
	return vbh->vmx_cap.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

void vbh_invept(struct vbh_data *vbh, u64 eptp)
{
	if (vbh_has_vmx_invept_context(vbh))
		exec_invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
	else
		exec_invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static bool is_invpcid_supported(void)
{
	int eax = 0x07, ebx = 0, ecx = 0, edx = 0;

	__cpuid(&eax, &ebx, &ecx, &edx);

	if ((ebx >> 10) & 1)
		return true;

	pr_info("<1> invpcid is not supported.\n");
	return false;
}

static bool is_rdtscp_supported(void)
{
	int eax = 0x80000001, ebx = 0, ecx = 0, edx = 0;

	__cpuid(&eax, &ebx, &ecx, &edx);

	if ((edx >> 27) & 1)
		return true;

	pr_info("<1> rdtscp is not supported.\n");
	return false;
}

static int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, int *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	pr_err("<1> adjust_vmx_control: msr=0x%x, value=0x%llx.\n",
				msr, (u64)vmx_msr_high << 32 | vmx_msr_low);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

bool is_xsaves_supported(void)
{
	int eax = 0xD, ebx = 0, ecx = 1, edx = 0;

	__cpuid(&eax, &ebx, &ecx, &edx);

	if ((eax >> 3) & 1)
		return true;

	pr_info("<1> xsaves is not supported.\n");
	return false;
}

void build_vmcs_config(struct vmcs_config *vmcs_config_p, bool is_primary_os)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	int _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;
	u64 basic_msr_value;

	// if INVPCID is disabled, return error
	if (!is_invpcid_supported()) {
		pr_err("<1> INVPCID is disabled.\n");
		return;
	}

	if (is_primary_os) {
		min = CPU_BASED_USE_MSR_BITMAPS |
		      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
		opt = 0;
	} else {
		min = CPU_BASED_HLT_EXITING |
		      CPU_BASED_CR8_LOAD_EXITING |
		      CPU_BASED_CR8_STORE_EXITING |
		      CPU_BASED_UNCOND_IO_EXITING |
		      CPU_BASED_MOV_DR_EXITING |
		      CPU_BASED_USE_TSC_OFFSETING |
		      CPU_BASED_MWAIT_EXITING |
		      CPU_BASED_MONITOR_EXITING |
		      CPU_BASED_RDPMC_EXITING;

		opt = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	}
	if (adjust_vmx_controls(min, opt,
		MSR_IA32_VMX_PROCBASED_CTLS, &_cpu_based_exec_control) < 0)
		return;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = SECONDARY_EXEC_ENABLE_EPT;

		if (is_invpcid_supported())
			min2 |= SECONDARY_EXEC_ENABLE_INVPCID;

		if (is_xsaves_supported())
			min2 |= SECONDARY_EXEC_XSAVES;

		if (is_rdtscp_supported())
			min2 |= SECONDARY_EXEC_RDTSCP;

		opt2 = 0;
		if (!is_primary_os) {
			min2 &= ~(SECONDARY_EXEC_RDTSCP | SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_XSAVES);
			opt2 |=	SECONDARY_EXEC_WBINVD_EXITING |
				SECONDARY_EXEC_RDRAND_EXITING |
				SECONDARY_EXEC_RDSEED_EXITING;
		}

		if (adjust_vmx_controls(min2, opt2,
			MSR_IA32_VMX_PROCBASED_CTLS2,
			&_cpu_based_2nd_exec_control) < 0)
			return;
	}

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
				CPU_BASED_CR3_STORE_EXITING);
	}

	min = 0;
	opt = 0;

#ifdef CONFIG_X86_64
	min = VM_EXIT_HOST_ADDR_SPACE_SIZE  | VM_EXIT_LOAD_IA32_EFER |
		VM_EXIT_SAVE_IA32_EFER;
#endif

	if (!is_primary_os) {
		min &= ~VM_EXIT_SAVE_IA32_EFER;
		min |= VM_EXIT_ACK_INTR_ON_EXIT;
		opt |= VM_EXIT_LOAD_IA32_PAT;
	}

	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
					&_vmexit_control) < 0)
		return;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	min = 0;
	opt = 0;
	if (!is_primary_os) {
		min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
		//opt = PIN_BASED_VIRTUAL_NMIS;
	}

	basic_msr_value = (u64)vmx_msr_high << 32 | vmx_msr_low;
	if (basic_msr_value & VMX_BASIC_TRUE_CTLS) {
		pr_err("basic_msr_value=0x%llx, bit 55 is set.\n", basic_msr_value);
		if (adjust_vmx_controls(min, opt,
			MSR_IA32_VMX_TRUE_PINBASED_CTLS,
			&_pin_based_exec_control) < 0) {
			pr_err("Failed to set pinbased control.\n");
			return;
		}
	} else {
		pr_err("basic_msr_value=0x%llx, bit 55 is NOT set.\n", basic_msr_value);
		if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
						&_pin_based_exec_control) < 0) {
			pr_err("Failed to set pinbased control.\n");
			return;
		}
	}

	if (is_primary_os) {
		min = VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE;
		opt = VM_ENTRY_LOAD_IA32_EFER;
	} else {
		min = VM_ENTRY_LOAD_DEBUG_CONTROLS;
		opt = VM_ENTRY_IA32E_MODE |
		      VM_ENTRY_LOAD_IA32_PAT |
		      VM_ENTRY_LOAD_IA32_EFER;
	}
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
					&_vmentry_control) < 0)
		return;

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return;

	vmcs_config_p->size = vmx_msr_high & 0x1fff;
	vmcs_config_p->order = get_order(vmcs_config_p->size);
	vmcs_config_p->basic_cap = vmx_msr_high & ~0x1fff;
	vmcs_config_p->revision_id = vmx_msr_low;

	vmcs_config_p->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_config_p->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_config_p->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_config_p->vmexit_ctrl         = _vmexit_control;
	vmcs_config_p->vmentry_ctrl        = _vmentry_control;
}


