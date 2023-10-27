#include <linux/kernel.h>
#include <asm/vmx.h>
#include "vmx_root.h"
#include "vmx_common.h"
#include "../ops.h"
#include "../vmx.h"
#include "page_tracker.h"

const struct nonroot_vmcs_field vmcs_field_to_nonroot_vmcs[] = {
	/* 64 bit rw */
	NONROOT_VMCS_FIELD(GUEST_RIP, guest_rip,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(GUEST_RSP, guest_rsp,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC),
	NONROOT_VMCS_FIELD(GUEST_RFLAGS, guest_rflags,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC),
	NONROOT_VMCS_FIELD(HOST_IA32_PAT, host_ia32_pat,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_IA32_EFER, host_ia32_efer,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_CR0, host_cr0,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_CR3, host_cr3,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_CR4, host_cr4,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_IA32_SYSENTER_ESP, host_ia32_sysenter_esp,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_IA32_SYSENTER_EIP, host_ia32_sysenter_eip,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_RIP, host_rip,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(IO_BITMAP_A, io_bitmap_a,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP),
	NONROOT_VMCS_FIELD(IO_BITMAP_B, io_bitmap_b,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP),
	NONROOT_VMCS_FIELD(MSR_BITMAP, msr_bitmap,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP),
	NONROOT_VMCS_FIELD(GUEST_ES_BASE, guest_es_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_CS_BASE, guest_cs_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_SS_BASE, guest_ss_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_DS_BASE, guest_ds_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_FS_BASE, guest_fs_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GS_BASE, guest_gs_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_LDTR_BASE, guest_ldtr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_TR_BASE, guest_tr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GDTR_BASE, guest_gdtr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_IDTR_BASE, guest_idtr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(TSC_OFFSET, tsc_offset,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2),
	NONROOT_VMCS_FIELD(VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2),
	NONROOT_VMCS_FIELD(VMCS_LINK_POINTER, vmcs_link_pointer,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_IA32_DEBUGCTL, guest_ia32_debugctl,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_IA32_PAT, guest_ia32_pat,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_IA32_EFER, guest_ia32_efer,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_PDPTR0, guest_pdptr0,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_PDPTR1, guest_pdptr1,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_PDPTR2, guest_pdptr2,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_PDPTR3, guest_pdptr3,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_SYSENTER_ESP, guest_sysenter_esp,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_SYSENTER_EIP, guest_sysenter_eip,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(CR0_GUEST_HOST_MASK, cr0_guest_host_mask,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(CR4_GUEST_HOST_MASK, cr4_guest_host_mask,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(CR0_READ_SHADOW, cr0_read_shadow,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(CR4_READ_SHADOW, cr4_read_shadow,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(GUEST_CR0, guest_cr0,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(GUEST_CR3, guest_cr3,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(GUEST_CR4, guest_cr4,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(GUEST_DR7, guest_dr7,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR),
	NONROOT_VMCS_FIELD(HOST_FS_BASE, host_fs_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(HOST_GS_BASE, host_gs_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(HOST_TR_BASE, host_tr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(HOST_GDTR_BASE, host_gdtr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(HOST_IDTR_BASE, host_idtr_base,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(HOST_RSP, host_rsp,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER),
	NONROOT_VMCS_FIELD(EPT_POINTER, ept_pointer,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT),
	NONROOT_VMCS_FIELD(GUEST_BNDCFGS, guest_bndcfgs,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(XSS_EXIT_BITMAP, xss_exit_bitmap,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2),

	/* 64 bit read only */
	NONROOT_VMCS_FIELD(GUEST_PHYSICAL_ADDRESS, guest_physical_address,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(EXIT_QUALIFICATION, exit_qualification,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	/*
	 * Not defined in KVM:
	 *
	 * NONROOT_VMCS_FIELD(0x00006402, exit_io_instruction_ecx,
	 *		HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	 * NONROOT_VMCS_FIELD(0x00006404, exit_io_instruction_esi,
	 *		HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	 * NONROOT_VMCS_FIELD(0x00006406, exit_io_instruction_esi,
	 *		HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	 * NONROOT_VMCS_FIELD(0x00006408, exit_io_instruction_eip,
	 *		HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	 */
	NONROOT_VMCS_FIELD(GUEST_LINEAR_ADDRESS, guest_linear_address,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),

	/*
	 * No mask defined in the spec as Hyper-V doesn't currently support
	 * these. Future proof by resetting the whole clean field mask on
	 * access.
	 */
	NONROOT_VMCS_FIELD(VM_EXIT_MSR_STORE_ADDR, vm_exit_msr_store_addr,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(VM_EXIT_MSR_LOAD_ADDR, vm_exit_msr_load_addr,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(VM_ENTRY_MSR_LOAD_ADDR, vm_entry_msr_load_addr,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(CR3_TARGET_VALUE0, cr3_target_value0,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(CR3_TARGET_VALUE1, cr3_target_value1,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(CR3_TARGET_VALUE2, cr3_target_value2,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(CR3_TARGET_VALUE3, cr3_target_value3,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),

	/* 32 bit rw */
	NONROOT_VMCS_FIELD(TPR_THRESHOLD, tpr_threshold,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC),
	NONROOT_VMCS_FIELD(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC),
	NONROOT_VMCS_FIELD(EXCEPTION_BITMAP, exception_bitmap,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN),
	NONROOT_VMCS_FIELD(VM_ENTRY_CONTROLS, vm_entry_controls,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY),
	NONROOT_VMCS_FIELD(VM_ENTRY_INTR_INFO_FIELD, vm_entry_intr_info_field,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT),
	NONROOT_VMCS_FIELD(VM_ENTRY_EXCEPTION_ERROR_CODE,
		     vm_entry_exception_error_code,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT),
	NONROOT_VMCS_FIELD(VM_ENTRY_INSTRUCTION_LEN, vm_entry_instruction_len,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT),
	NONROOT_VMCS_FIELD(HOST_IA32_SYSENTER_CS, host_ia32_sysenter_cs,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1),
	NONROOT_VMCS_FIELD(VM_EXIT_CONTROLS, vm_exit_controls,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1),
	NONROOT_VMCS_FIELD(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1),
	NONROOT_VMCS_FIELD(GUEST_ES_LIMIT, guest_es_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_CS_LIMIT, guest_cs_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_SS_LIMIT, guest_ss_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_DS_LIMIT, guest_ds_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_FS_LIMIT, guest_fs_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GS_LIMIT, guest_gs_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_LDTR_LIMIT, guest_ldtr_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_TR_LIMIT, guest_tr_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GDTR_LIMIT, guest_gdtr_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_IDTR_LIMIT, guest_idtr_limit,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_ES_AR_BYTES, guest_es_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_CS_AR_BYTES, guest_cs_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_SS_AR_BYTES, guest_ss_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_DS_AR_BYTES, guest_ds_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_FS_AR_BYTES, guest_fs_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GS_AR_BYTES, guest_gs_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_LDTR_AR_BYTES, guest_ldtr_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_TR_AR_BYTES, guest_tr_ar_bytes,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_ACTIVITY_STATE, guest_activity_state,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_SYSENTER_CS, guest_sysenter_cs,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),

	/* 32 bit read only */
	NONROOT_VMCS_FIELD(VM_INSTRUCTION_ERROR, vm_instruction_error,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(VM_EXIT_REASON, vm_exit_reason,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(VM_EXIT_INTR_INFO, vm_exit_intr_info,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(VM_EXIT_INTR_ERROR_CODE, vm_exit_intr_error_code,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(IDT_VECTORING_INFO_FIELD, idt_vectoring_info_field,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(IDT_VECTORING_ERROR_CODE, idt_vectoring_error_code,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(VM_EXIT_INSTRUCTION_LEN, vm_exit_instruction_len,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),
	NONROOT_VMCS_FIELD(VMX_INSTRUCTION_INFO, vmx_instruction_info,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE),

	/* No mask defined in the spec (not used) */
	NONROOT_VMCS_FIELD(PAGE_FAULT_ERROR_CODE_MASK, page_fault_error_code_mask,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(PAGE_FAULT_ERROR_CODE_MATCH, page_fault_error_code_match,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(CR3_TARGET_COUNT, cr3_target_count,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(VM_EXIT_MSR_STORE_COUNT, vm_exit_msr_store_count,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_load_count,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),
	NONROOT_VMCS_FIELD(VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL),

	/* 16 bit rw */
	NONROOT_VMCS_FIELD(HOST_ES_SELECTOR, host_es_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_CS_SELECTOR, host_cs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_SS_SELECTOR, host_ss_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_DS_SELECTOR, host_ds_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_FS_SELECTOR, host_fs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_GS_SELECTOR, host_gs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(HOST_TR_SELECTOR, host_tr_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
	NONROOT_VMCS_FIELD(GUEST_ES_SELECTOR, guest_es_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_CS_SELECTOR, guest_cs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_SS_SELECTOR, guest_ss_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_DS_SELECTOR, guest_ds_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_FS_SELECTOR, guest_fs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_GS_SELECTOR, guest_gs_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_LDTR_SELECTOR, guest_ldtr_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(GUEST_TR_SELECTOR, guest_tr_selector,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2),
	NONROOT_VMCS_FIELD(VIRTUAL_PROCESSOR_ID, virtual_processor_id,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT),

	/* New added */
	NONROOT_VMCS_FIELD(VM_FUNCTION_CONTROL, vm_function_control,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1),
	NONROOT_VMCS_FIELD(APIC_ACCESS_ADDR, apic_access_addr,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1),
	NONROOT_VMCS_FIELD(GUEST_IA32_PERF_GLOBAL_CTRL, guest_ia32_perf_global_ctrl,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1),
	NONROOT_VMCS_FIELD(HOST_IA32_PERF_GLOBAL_CTRL, host_ia32_perf_global_ctrl,
		     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1),
};
const unsigned int nr_nonroot_vmcs_fields = ARRAY_SIZE(vmcs_field_to_nonroot_vmcs);

static inline void vmx_root_do_vmload(u64 phys_addr)
{
	vmx_asm1(vmptrld, "m"(phys_addr), __va(phys_addr), phys_addr);
}

static void vmx_root_do_vmclear(u64 phys_addr)
{
	vmx_asm1(vmclear, "m"(phys_addr), vbh_va(phys_addr), phys_addr);
}

static struct root_kvm_ept *get_saved_root_kvm_ept(struct root_kvm *root_kvm,
						   u64 ept_gpa)
{
	struct root_kvm_ept *p;

	if (list_empty(&root_kvm->ept_list))
		return NULL;

	list_for_each_entry(p, &root_kvm->ept_list, list) {
		if (p->ept_gpa == ept_gpa) {
			list_del(&p->list);
			return p;
		}
	}

	return NULL;
}

/*
 * The assumption is that each VM only has one EPT root page
 * for all vCPUs. If this is not true, the implementation needs
 * to be changed.
 */
static int vmx_root_update_eptp(struct vbh_data *vbh,
				struct root_kvm *root_kvm,
				u64 ept_pointer)
{
	u64 ept_gpa = ept_pointer & PAGE_MASK;
	struct root_kvm_ept *p = NULL;
	u64 pre_ept_gpa = 0;
	int ret = 0;
	bool update = false;

	BUG_ON(!ept_gpa);

	sspinlock_obtain(&root_kvm->lock);

	pre_ept_gpa = root_kvm->ept_gpa;
	if (pre_ept_gpa != ept_gpa) {
		p = get_saved_root_kvm_ept(root_kvm, ept_gpa);
		if (p) {
			/* already marked. Let's use it */
			root_kvm->ept_gpa = ept_gpa;
			p->ept_gpa = pre_ept_gpa;
			list_add(&p->list, &root_kvm->ept_list);
		} else {
			/* a new ept pointer */
			if (pre_ept_gpa) {
				/* save previous ept gpa */
				p = vbh_malloc(vbh, sizeof(struct root_kvm_ept));
				if (!p) {
					ret = -ENOMEM;
					goto out;
				}
				p->ept_gpa = pre_ept_gpa;
				list_add(&p->list, &root_kvm->ept_list);
			}
			/* update the new one */
			root_kvm->ept_gpa = ept_gpa;
			update = true;
			memset(vbh_va(ept_gpa), 0, PAGE_SIZE);
#if 0
			if (vbh_update_pfn_status(vbh, ept_gpa >> PAGE_SHIFT, true, false)) {
				//FIXME: need to do this on all pcpu.
				vbh_invept(vbh);
			} else
				BUG_ON(printk("This should be the 1st time to WP\n"));
#endif

		}
	}

	sspinlock_release(&root_kvm->lock);

#if 0
	BUG_ON(update && vbh_set_ram_metadata_in_range(vbh, ept_gpa,
						PAGE_SIZE, &update, NULL,
						root_kvm->data.vm_id));
#endif

	vmcs_write64(EPT_POINTER, ept_pointer);
	return 0;
out:
	sspinlock_release(&root_kvm->lock);
	return ret;
}

static bool vmx_root_verify_root_page(struct vbh_data *vbh, u64 root_page)
{
	struct root_kvm *p;

	if (list_empty(&vbh->kvm_head))
		return false;

	list_for_each_entry(p, &vbh->kvm_head, list) {
		if (p->pa == root_page) {
			//TODO? need to check page permission?
			return true;
		}
	}

	return false;
}

static int update_vmcs_from_nonroot_to_root(struct vbh_data *vbh,
					    struct root_kvm *root_kvm)
{
	struct nonroot_vmcs *vmcs = __current_nonroot_vmcs;
	int ret = 0;

	vmcs_write32(TPR_THRESHOLD, vmcs->tpr_threshold);
	vmcs_writel(GUEST_RIP, vmcs->guest_rip);

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC))) {
		vmcs_writel(GUEST_RSP, vmcs->guest_rsp);
		vmcs_writel(GUEST_RFLAGS, vmcs->guest_rflags);
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
				vmcs->guest_interruptibility_info);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC))) {
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
				vmcs->cpu_based_vm_exec_control);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN))) {
		vmcs_write32(EXCEPTION_BITMAP, vmcs->exception_bitmap);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY))) {
		vmcs_write32(VM_ENTRY_CONTROLS, vmcs->vm_entry_controls);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT))) {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
				vmcs->vm_entry_intr_info_field);
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
				vmcs->vm_entry_exception_error_code);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
				vmcs->vm_entry_instruction_len);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1))) {
		vmcs_write64(HOST_IA32_PAT, vmcs->host_ia32_pat);
		vmcs_write64(HOST_IA32_EFER, vmcs->host_ia32_efer);
		vmcs_write64(HOST_IA32_PERF_GLOBAL_CTRL, vmcs->host_ia32_perf_global_ctrl);
		vmcs_writel(HOST_CR0, vmcs->host_cr0);
		vmcs_writel(HOST_CR3, vmcs->host_cr3);
		vmcs_writel(HOST_CR4, vmcs->host_cr4);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, vmcs->host_ia32_sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_EIP, vmcs->host_ia32_sysenter_eip);
		vmcs_writel(HOST_RIP, vmcs->host_rip);
		vmcs_write32(HOST_IA32_SYSENTER_CS, vmcs->host_ia32_sysenter_cs);
		vmcs_write16(HOST_ES_SELECTOR, vmcs->host_es_selector);
		vmcs_write16(HOST_CS_SELECTOR, vmcs->host_cs_selector);
		vmcs_write16(HOST_SS_SELECTOR, vmcs->host_ss_selector);
		vmcs_write16(HOST_DS_SELECTOR, vmcs->host_ds_selector);
		vmcs_write16(HOST_FS_SELECTOR, vmcs->host_fs_selector);
		vmcs_write16(HOST_GS_SELECTOR, vmcs->host_gs_selector);
		vmcs_write16(HOST_TR_SELECTOR, vmcs->host_tr_selector);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1))) {
		vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmcs->pin_based_vm_exec_control);
		vmcs_write32(VM_EXIT_CONTROLS, vmcs->vm_exit_controls);
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vmcs->secondary_vm_exec_control);
		vmcs_write64(VM_FUNCTION_CONTROL, vmcs->vm_function_control);
		vmcs_write64(APIC_ACCESS_ADDR, vmcs->apic_access_addr);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP))) {
		vmcs_write64(IO_BITMAP_A, vmcs->io_bitmap_a);
		vmcs_write64(IO_BITMAP_B, vmcs->io_bitmap_b);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP))) {
		vmcs_write64(MSR_BITMAP, vmcs->msr_bitmap);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2))) {
		vmcs_writel(GUEST_ES_BASE, vmcs->guest_es_base);
		vmcs_writel(GUEST_CS_BASE, vmcs->guest_cs_base);
		vmcs_writel(GUEST_SS_BASE, vmcs->guest_ss_base);
		vmcs_writel(GUEST_DS_BASE, vmcs->guest_ds_base);
		vmcs_writel(GUEST_FS_BASE, vmcs->guest_fs_base);
		vmcs_writel(GUEST_GS_BASE, vmcs->guest_gs_base);
		vmcs_writel(GUEST_LDTR_BASE, vmcs->guest_ldtr_base);
		vmcs_writel(GUEST_TR_BASE, vmcs->guest_tr_base);
		vmcs_writel(GUEST_GDTR_BASE, vmcs->guest_gdtr_base);
		vmcs_writel(GUEST_IDTR_BASE, vmcs->guest_idtr_base);
		vmcs_write32(GUEST_ES_LIMIT, vmcs->guest_es_limit);
		vmcs_write32(GUEST_CS_LIMIT, vmcs->guest_cs_limit);
		vmcs_write32(GUEST_SS_LIMIT, vmcs->guest_ss_limit);
		vmcs_write32(GUEST_DS_LIMIT, vmcs->guest_ds_limit);
		vmcs_write32(GUEST_FS_LIMIT, vmcs->guest_fs_limit);
		vmcs_write32(GUEST_GS_LIMIT, vmcs->guest_gs_limit);
		vmcs_write32(GUEST_LDTR_LIMIT, vmcs->guest_ldtr_limit);
		vmcs_write32(GUEST_TR_LIMIT, vmcs->guest_tr_limit);
		vmcs_write32(GUEST_GDTR_LIMIT, vmcs->guest_gdtr_limit);
		vmcs_write32(GUEST_IDTR_LIMIT, vmcs->guest_idtr_limit);
		vmcs_write32(GUEST_ES_AR_BYTES, vmcs->guest_es_ar_bytes);
		vmcs_write32(GUEST_CS_AR_BYTES, vmcs->guest_cs_ar_bytes);
		vmcs_write32(GUEST_SS_AR_BYTES, vmcs->guest_ss_ar_bytes);
		vmcs_write32(GUEST_DS_AR_BYTES, vmcs->guest_ds_ar_bytes);
		vmcs_write32(GUEST_FS_AR_BYTES, vmcs->guest_fs_ar_bytes);
		vmcs_write32(GUEST_GS_AR_BYTES, vmcs->guest_gs_ar_bytes);
		vmcs_write32(GUEST_LDTR_AR_BYTES, vmcs->guest_ldtr_ar_bytes);
		vmcs_write32(GUEST_TR_AR_BYTES, vmcs->guest_tr_ar_bytes);
		vmcs_write16(GUEST_ES_SELECTOR, vmcs->guest_es_selector);
		vmcs_write16(GUEST_CS_SELECTOR, vmcs->guest_cs_selector);
		vmcs_write16(GUEST_SS_SELECTOR, vmcs->guest_ss_selector);
		vmcs_write16(GUEST_DS_SELECTOR, vmcs->guest_ds_selector);
		vmcs_write16(GUEST_FS_SELECTOR, vmcs->guest_fs_selector);
		vmcs_write16(GUEST_GS_SELECTOR, vmcs->guest_gs_selector);
		vmcs_write16(GUEST_LDTR_SELECTOR, vmcs->guest_ldtr_selector);
		vmcs_write16(GUEST_TR_SELECTOR, vmcs->guest_tr_selector);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2))) {
		vmcs_write64(TSC_OFFSET, vmcs->tsc_offset);
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, vmcs->virtual_apic_page_addr);
		if (vbh->xsaves_supported)
			vmcs_write64(XSS_EXIT_BITMAP, vmcs->xss_exit_bitmap);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR))) {
		vmcs_writel(CR0_GUEST_HOST_MASK, vmcs->cr0_guest_host_mask);
		vmcs_writel(CR4_GUEST_HOST_MASK, vmcs->cr4_guest_host_mask);
		vmcs_writel(CR0_READ_SHADOW, vmcs->cr0_read_shadow);
		vmcs_writel(CR4_READ_SHADOW, vmcs->cr4_read_shadow);
		vmcs_writel(GUEST_CR0, vmcs->guest_cr0);
		vmcs_writel(GUEST_CR3, vmcs->guest_cr3);
		vmcs_writel(GUEST_CR4, vmcs->guest_cr4);
		vmcs_writel(GUEST_DR7, vmcs->guest_dr7);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER))) {
		vmcs_writel(HOST_FS_BASE, vmcs->host_fs_base);
		vmcs_writel(HOST_GS_BASE, vmcs->host_gs_base);
		vmcs_writel(HOST_TR_BASE, vmcs->host_tr_base);
		vmcs_writel(HOST_GDTR_BASE, vmcs->host_gdtr_base);
		vmcs_writel(HOST_IDTR_BASE, vmcs->host_idtr_base);
		//vmcs_writel(HOST_RSP, vmcs->host_rsp); // updated before vmenter
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT))) {
		ret = vmx_root_update_eptp(vbh, root_kvm, vmcs->ept_pointer);
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmcs->virtual_processor_id);
	}

	if (unlikely(!(vmcs->hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1))) {
		vmcs_write64(VMCS_LINK_POINTER, vmcs->vmcs_link_pointer);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs->guest_ia32_debugctl);
		vmcs_write64(GUEST_IA32_PAT, vmcs->guest_ia32_pat);
		vmcs_write64(GUEST_IA32_EFER, vmcs->guest_ia32_efer);
		vmcs_write64(GUEST_IA32_PERF_GLOBAL_CTRL, vmcs->guest_ia32_perf_global_ctrl);
		vmcs_write64(GUEST_PDPTR0, vmcs->guest_pdptr0);
		vmcs_write64(GUEST_PDPTR1, vmcs->guest_pdptr1);
		vmcs_write64(GUEST_PDPTR2, vmcs->guest_pdptr2);
		vmcs_write64(GUEST_PDPTR3, vmcs->guest_pdptr3);
		vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
				vmcs->guest_pending_dbg_exceptions);
		vmcs_writel(GUEST_SYSENTER_ESP, vmcs->guest_sysenter_esp);
		vmcs_writel(GUEST_SYSENTER_EIP, vmcs->guest_sysenter_eip);
		if (vbh->mpx_supported)
			vmcs_write64(GUEST_BNDCFGS, vmcs->guest_bndcfgs);
		vmcs_write32(GUEST_ACTIVITY_STATE, vmcs->guest_activity_state);
		vmcs_write32(GUEST_SYSENTER_CS, vmcs->guest_sysenter_cs);
	}

	/*
	 * Not used?
	 * vmcs12->vm_exit_msr_store_addr = evmcs->vm_exit_msr_store_addr;
	 * vmcs12->vm_exit_msr_load_addr = evmcs->vm_exit_msr_load_addr;
	 * vmcs12->vm_entry_msr_load_addr = evmcs->vm_entry_msr_load_addr;
	 * vmcs12->cr3_target_value0 = evmcs->cr3_target_value0;
	 * vmcs12->cr3_target_value1 = evmcs->cr3_target_value1;
	 * vmcs12->cr3_target_value2 = evmcs->cr3_target_value2;
	 * vmcs12->cr3_target_value3 = evmcs->cr3_target_value3;
	 * vmcs12->page_fault_error_code_mask =
	 *		evmcs->page_fault_error_code_mask;
	 * vmcs12->page_fault_error_code_match =
	 *		evmcs->page_fault_error_code_match;
	 * vmcs12->cr3_target_count = evmcs->cr3_target_count;
	 * vmcs12->vm_exit_msr_store_count = evmcs->vm_exit_msr_store_count;
	 * vmcs12->vm_exit_msr_load_count = evmcs->vm_exit_msr_load_count;
	 * vmcs12->vm_entry_msr_load_count = evmcs->vm_entry_msr_load_count;
	 */

	/*
	 * Read only fields:
	 * vmcs12->guest_physical_address = evmcs->guest_physical_address;
	 * vmcs12->vm_instruction_error = evmcs->vm_instruction_error;
	 * vmcs12->vm_exit_reason = evmcs->vm_exit_reason;
	 * vmcs12->vm_exit_intr_info = evmcs->vm_exit_intr_info;
	 * vmcs12->vm_exit_intr_error_code = evmcs->vm_exit_intr_error_code;
	 * vmcs12->idt_vectoring_info_field = evmcs->idt_vectoring_info_field;
	 * vmcs12->idt_vectoring_error_code = evmcs->idt_vectoring_error_code;
	 * vmcs12->vm_exit_instruction_len = evmcs->vm_exit_instruction_len;
	 * vmcs12->vmx_instruction_info = evmcs->vmx_instruction_info;
	 * vmcs12->exit_qualification = evmcs->exit_qualification;
	 * vmcs12->guest_linear_address = evmcs->guest_linear_address;
	 *
	 * Not present in struct vmcs12:
	 * vmcs12->exit_io_instruction_ecx = evmcs->exit_io_instruction_ecx;
	 * vmcs12->exit_io_instruction_esi = evmcs->exit_io_instruction_esi;
	 * vmcs12->exit_io_instruction_edi = evmcs->exit_io_instruction_edi;
	 * vmcs12->exit_io_instruction_eip = evmcs->exit_io_instruction_eip;
	 */

	vmcs->hv_clean_fields |= HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;

	return ret;
}

static void update_vmcs_from_root_to_nonroot(struct vbh_data *vbh)
{
	struct nonroot_vmcs *vmcs = __current_nonroot_vmcs;

	/*
	 * Should not be changed by KVM:
	 *
	 * evmcs->host_es_selector = vmcs12->host_es_selector;
	 * evmcs->host_cs_selector = vmcs12->host_cs_selector;
	 * evmcs->host_ss_selector = vmcs12->host_ss_selector;
	 * evmcs->host_ds_selector = vmcs12->host_ds_selector;
	 * evmcs->host_fs_selector = vmcs12->host_fs_selector;
	 * evmcs->host_gs_selector = vmcs12->host_gs_selector;
	 * evmcs->host_tr_selector = vmcs12->host_tr_selector;
	 * evmcs->host_ia32_pat = vmcs12->host_ia32_pat;
	 * evmcs->host_ia32_efer = vmcs12->host_ia32_efer;
	 * evmcs->host_cr0 = vmcs12->host_cr0;
	 * evmcs->host_cr3 = vmcs12->host_cr3;
	 * evmcs->host_cr4 = vmcs12->host_cr4;
	 * evmcs->host_ia32_sysenter_esp = vmcs12->host_ia32_sysenter_esp;
	 * evmcs->host_ia32_sysenter_eip = vmcs12->host_ia32_sysenter_eip;
	 * evmcs->host_rip = vmcs12->host_rip;
	 * evmcs->host_ia32_sysenter_cs = vmcs12->host_ia32_sysenter_cs;
	 * evmcs->host_fs_base = vmcs12->host_fs_base;
	 * evmcs->host_gs_base = vmcs12->host_gs_base;
	 * evmcs->host_tr_base = vmcs12->host_tr_base;
	 * evmcs->host_gdtr_base = vmcs12->host_gdtr_base;
	 * evmcs->host_idtr_base = vmcs12->host_idtr_base;
	 * evmcs->host_rsp = vmcs12->host_rsp;
	 * sync_vmcs02_to_vmcs12() doesn't read these:
	 * evmcs->io_bitmap_a = vmcs12->io_bitmap_a;
	 * evmcs->io_bitmap_b = vmcs12->io_bitmap_b;
	 * evmcs->msr_bitmap = vmcs12->msr_bitmap;
	 * evmcs->ept_pointer = vmcs12->ept_pointer;
	 * evmcs->xss_exit_bitmap = vmcs12->xss_exit_bitmap;
	 * evmcs->vm_exit_msr_store_addr = vmcs12->vm_exit_msr_store_addr;
	 * evmcs->vm_exit_msr_load_addr = vmcs12->vm_exit_msr_load_addr;
	 * evmcs->vm_entry_msr_load_addr = vmcs12->vm_entry_msr_load_addr;
	 * evmcs->cr3_target_value0 = vmcs12->cr3_target_value0;
	 * evmcs->cr3_target_value1 = vmcs12->cr3_target_value1;
	 * evmcs->cr3_target_value2 = vmcs12->cr3_target_value2;
	 * evmcs->cr3_target_value3 = vmcs12->cr3_target_value3;
	 * evmcs->tpr_threshold = vmcs12->tpr_threshold;
	 * evmcs->virtual_processor_id = vmcs12->virtual_processor_id;
	 * evmcs->exception_bitmap = vmcs12->exception_bitmap;
	 * evmcs->vmcs_link_pointer = vmcs12->vmcs_link_pointer;
	 * evmcs->pin_based_vm_exec_control = vmcs12->pin_based_vm_exec_control;
	 * evmcs->vm_exit_controls = vmcs12->vm_exit_controls;
	 * evmcs->secondary_vm_exec_control = vmcs12->secondary_vm_exec_control;
	 * evmcs->page_fault_error_code_mask =
	 *		vmcs12->page_fault_error_code_mask;
	 * evmcs->page_fault_error_code_match =
	 *		vmcs12->page_fault_error_code_match;
	 * evmcs->cr3_target_count = vmcs12->cr3_target_count;
	 * evmcs->virtual_apic_page_addr = vmcs12->virtual_apic_page_addr;
	 * evmcs->tsc_offset = vmcs12->tsc_offset;
	 * evmcs->guest_ia32_debugctl = vmcs12->guest_ia32_debugctl;
	 * evmcs->cr0_guest_host_mask = vmcs12->cr0_guest_host_mask;
	 * evmcs->cr4_guest_host_mask = vmcs12->cr4_guest_host_mask;
	 * evmcs->cr0_read_shadow = vmcs12->cr0_read_shadow;
	 * evmcs->cr4_read_shadow = vmcs12->cr4_read_shadow;
	 * evmcs->vm_exit_msr_store_count = vmcs12->vm_exit_msr_store_count;
	 * evmcs->vm_exit_msr_load_count = vmcs12->vm_exit_msr_load_count;
	 * evmcs->vm_entry_msr_load_count = vmcs12->vm_entry_msr_load_count;
	 *
	 * Not present in struct vmcs12:
	 * evmcs->exit_io_instruction_ecx = vmcs12->exit_io_instruction_ecx;
	 * evmcs->exit_io_instruction_esi = vmcs12->exit_io_instruction_esi;
	 * evmcs->exit_io_instruction_edi = vmcs12->exit_io_instruction_edi;
	 * evmcs->exit_io_instruction_eip = vmcs12->exit_io_instruction_eip;
	 */
	//vmcs->host_ia32_perf_global_ctrl = vmcs_read64(HOST_IA32_PERF_GLOBAL_CTRL); // might not needed

	vmcs->guest_es_selector = vmcs_read16(GUEST_ES_SELECTOR);
	vmcs->guest_cs_selector = vmcs_read16(GUEST_CS_SELECTOR);
	vmcs->guest_ss_selector = vmcs_read16(GUEST_SS_SELECTOR);
	vmcs->guest_ds_selector = vmcs_read16(GUEST_DS_SELECTOR);
	vmcs->guest_fs_selector = vmcs_read16(GUEST_FS_SELECTOR);
	vmcs->guest_gs_selector = vmcs_read16(GUEST_GS_SELECTOR);
	vmcs->guest_ldtr_selector = vmcs_read16(GUEST_LDTR_SELECTOR);
	vmcs->guest_tr_selector = vmcs_read16(GUEST_TR_SELECTOR);

	vmcs->guest_es_limit = vmcs_read32(GUEST_ES_LIMIT);
	vmcs->guest_cs_limit = vmcs_read32(GUEST_CS_LIMIT);
	vmcs->guest_ss_limit = vmcs_read32(GUEST_SS_LIMIT);
	vmcs->guest_ds_limit = vmcs_read32(GUEST_DS_LIMIT);
	vmcs->guest_fs_limit = vmcs_read32(GUEST_FS_LIMIT);
	vmcs->guest_gs_limit = vmcs_read32(GUEST_GS_LIMIT);
	vmcs->guest_ldtr_limit = vmcs_read32(GUEST_LDTR_LIMIT);
	vmcs->guest_tr_limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs->guest_gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	vmcs->guest_idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);

	vmcs->guest_es_ar_bytes = vmcs_read32(GUEST_ES_AR_BYTES);
	vmcs->guest_cs_ar_bytes = vmcs_read32(GUEST_CS_AR_BYTES);
	vmcs->guest_ss_ar_bytes = vmcs_read32(GUEST_SS_AR_BYTES);
	vmcs->guest_ds_ar_bytes = vmcs_read32(GUEST_DS_AR_BYTES);
	vmcs->guest_fs_ar_bytes = vmcs_read32(GUEST_FS_AR_BYTES);
	vmcs->guest_gs_ar_bytes = vmcs_read32(GUEST_GS_AR_BYTES);
	vmcs->guest_ldtr_ar_bytes = vmcs_read32(GUEST_LDTR_AR_BYTES);
	vmcs->guest_tr_ar_bytes = vmcs_read32(GUEST_TR_AR_BYTES);

	vmcs->guest_es_base = vmcs_readl(GUEST_ES_BASE);
	vmcs->guest_cs_base = vmcs_readl(GUEST_CS_BASE);
	vmcs->guest_ss_base = vmcs_readl(GUEST_SS_BASE);
	vmcs->guest_ds_base = vmcs_readl(GUEST_DS_BASE);
	vmcs->guest_fs_base = vmcs_readl(GUEST_FS_BASE);
	vmcs->guest_gs_base = vmcs_readl(GUEST_GS_BASE);
	vmcs->guest_ldtr_base = vmcs_readl(GUEST_LDTR_BASE);
	vmcs->guest_tr_base = vmcs_readl(GUEST_TR_BASE);
	vmcs->guest_gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	vmcs->guest_idtr_base = vmcs_readl(GUEST_IDTR_BASE);

	vmcs->guest_ia32_pat = vmcs_read64(GUEST_IA32_PAT);
	vmcs->guest_ia32_efer = vmcs_read64(GUEST_IA32_EFER);
	//vmcs->guest_ia32_perf_global_ctrl = vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL); // might not needed

	vmcs->guest_pdptr0= vmcs_read64(GUEST_PDPTR0);
	vmcs->guest_pdptr1= vmcs_read64(GUEST_PDPTR1);
	vmcs->guest_pdptr2= vmcs_read64(GUEST_PDPTR2);
	vmcs->guest_pdptr3= vmcs_read64(GUEST_PDPTR3);

	vmcs->guest_pending_dbg_exceptions =
		vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);
	vmcs->guest_sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	vmcs->guest_sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);

	vmcs->guest_activity_state = vmcs_read32(GUEST_ACTIVITY_STATE);
	vmcs->guest_sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);

	vmcs->guest_cr0 = vmcs_readl(GUEST_CR0);
	vmcs->guest_cr3 = vmcs_readl(GUEST_CR3);
	vmcs->guest_cr4 = vmcs_readl(GUEST_CR4);
	vmcs->guest_dr7 = vmcs_readl(GUEST_DR7);

	vmcs->guest_physical_address = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	vmcs->vm_instruction_error = vmcs_read32(VM_INSTRUCTION_ERROR);
	vmcs->vm_exit_reason = vmcs_read32(VM_EXIT_REASON);
	vmcs->vm_exit_intr_info= vmcs_read32(VM_EXIT_INTR_INFO);
	vmcs->vm_exit_intr_error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	vmcs->idt_vectoring_info_field = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	vmcs->idt_vectoring_error_code = vmcs_read32(IDT_VECTORING_ERROR_CODE);
	vmcs->vm_exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs->vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);

	vmcs->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	vmcs->guest_linear_address = vmcs_readl(GUEST_LINEAR_ADDRESS);
	vmcs->guest_rsp = vmcs_readl(GUEST_RSP);
	vmcs->guest_rflags = vmcs_readl(GUEST_RFLAGS);

	vmcs->guest_interruptibility_info =
		vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	vmcs->cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	vmcs->vm_entry_controls = vmcs_read32(VM_ENTRY_CONTROLS);
	vmcs->vm_entry_intr_info_field = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);
	vmcs->vm_entry_exception_error_code = vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE);
	vmcs->vm_entry_instruction_len = vmcs_read32(VM_ENTRY_INSTRUCTION_LEN);

	vmcs->guest_rip = vmcs_readl(GUEST_RIP);
	if (vbh->mpx_supported)
		vmcs->guest_bndcfgs = vmcs_read64(GUEST_BNDCFGS);

	// for debug
	vmcs->host_rsp = vmcs_readl(HOST_RSP);
	vmcs->host_rip = vmcs_readl(HOST_RIP);
}


extern int switch_to_nonroot(struct vbh_data *vbh);
bool __vmx_vcpu_run(struct vcpu_vmx *vmx, unsigned long *regs, bool launched);
static int vmx_enter(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int fail;

	if (vcpu->arch.cr2 != read_cr2())
		write_cr2(vcpu->arch.cr2);

	fail = __vmx_vcpu_run(vmx, (unsigned long *)&vcpu->arch.regs,
			      vmx->loaded_vmcs->launched);

	vcpu->arch.cr2 = read_cr2();

	return fail;
}

int vmx_root_vmenter(struct vbh_data *vbh, u64 arg, u64 root_page)
{
	struct root_param *p = vbh_va(arg);
	struct root_kvm *root_kvm = vbh_va(root_page);
	struct kvm_vcpu *vcpu = p->vcpu;
	int ret;

	// Verify if the root_page is a valid page
	if (!vmx_root_verify_root_page(vbh, root_page))
		BUG_ON(printk("%s: Root page 0x%llx not valid. Implementation bug? Malicious host?\n", __func__, root_page));

	// load vmcs
	vmx_root_do_vmload(p->vmenter.vmcs_pa);
	// write vmcs
	ret = update_vmcs_from_nonroot_to_root(vbh, root_kvm);
	if (ret)
		goto out;
	// handle invept
	if (p->invept.execute) {
		if (p->invept.global)
			vmx_root_do_invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
		else
			vmx_root_do_invept(p->invept.ext, p->invept.eptp, p->invept.gpa);
		memset(&p->invept, 0, sizeof(struct invept_data));
	}

	// TODO: handle invvpid

	ret = vmx_enter(vcpu);

	// read vmcs
	update_vmcs_from_root_to_nonroot(vbh);

out:
	// Before back to nonroot needs to load nonroot VMCS
	// as the current VMCS belongs to a VM.
	switch_to_nonroot(vbh);

	return ret;
}

int vmx_root_vmclear(u64 vmcs_pa, u64 shadow_vmcs_pa, bool launched)
{
	vmx_root_do_vmclear(vmcs_pa);

	if (shadow_vmcs_pa && launched)
		vmx_root_do_vmclear(shadow_vmcs_pa);

	return 0;
}

int vmx_root_vminit(struct vbh_data *vbh, u64 root_page_pa)
{
	struct root_kvm *root_kvm = vbh_va(root_page_pa), *p;
	unsigned long vm_type = root_kvm->data.vm_type;
	int vm_id = root_kvm->data.vm_id;
	int ret = 0;

	if (vm_id <= VBH_ID)
		return -EINVAL;

	sspinlock_obtain(&vbh->kvm_lock);
	if (!list_empty(&vbh->kvm_head)) {
		list_for_each_entry(p, &vbh->kvm_head, list) {
			if (p->pa == root_page_pa) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (!ret) {
		root_kvm->pa = root_page_pa;
		list_add(&root_kvm->list, &vbh->kvm_head);
	}
	sspinlock_release(&vbh->kvm_lock);

	if (ret)
		return ret;

	if (vbh_set_ram_metadata_in_range(vbh, root_page_pa, PAGE_SIZE, NULL, NULL, VBH_ID))
		BUG_ON(printk("set invalid pa 0x%llx. Buggy code?\n", root_page_pa));

	if (vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4,
				root_page_pa, PAGE_SIZE,
				false, false, false)) {
		//FIXME: need to do this on all pcpu.
		vmx_root_do_invept(VMX_EPT_EXTENT_CONTEXT, vbh->eptp, 0);
	}

	root_kvm->data.vm_type = vm_type;
	root_kvm->data.vm_id = vm_id;
	sspinlock_init(&root_kvm->lock);
	INIT_LIST_HEAD(&root_kvm->ept_list);
	return 0;
}

static void __vmx_root_vmfree(struct vbh_data *vbh, u64 pa)
{
	struct root_kvm *root_kvm = vbh_va(pa);

	if (!list_empty(&root_kvm->ept_list)) {
		struct root_kvm_ept *p, *n;
		list_for_each_entry_safe(p, n, &root_kvm->ept_list, list) {
			list_del(&p->list);
			vbh_free(vbh, p);
		}
	}

	if (vbh_unset_ram_metadata_in_range(vbh, pa, PAGE_SIZE, NULL, NULL, VBH_ID))
		BUG_ON(printk("unset invalid pa 0x%llx. Buggy code?\n", pa));

	memset((void *)root_kvm + sizeof(struct root_page_base_data), 0,
		PAGE_SIZE - sizeof(struct root_page_base_data));

	vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4,
				pa, PAGE_SIZE,
				true, true, true);

	//FIXME: need to do this on all pcpu.
	vmx_root_do_invept(VMX_EPT_EXTENT_CONTEXT, vbh->eptp, 0);
}

void vmx_root_vmfree(struct vbh_data *vbh, u64 pa)
{
	struct root_kvm *p;

	sspinlock_obtain(&vbh->kvm_lock);
	if (!list_empty(&vbh->kvm_head)) {
		list_for_each_entry(p, &vbh->kvm_head, list) {
			if (p->pa == pa) {
				list_del(&p->list);
				break;
			}
		}
	}
	sspinlock_release(&vbh->kvm_lock);
	__vmx_root_vmfree(vbh, p->pa);
}

#ifdef CONFIG_X86_64
static void __set_spte(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}
#else
static void __set_spte(u64 *sptep, u64 spte)
{
	//Not supported.
	BUG_ON(1);
}
#endif

static bool vmx_root_set_pte(struct vbh_data *vbh, struct root_kvm *root_kvm,
			     u64 base_gfn, int level, u64 pte)
{
	bool invept = false;
	u64 *sptep, pa;
	size_t size;
	//bool ept_map= true;

	if (!pte || level > vbh->ept_walks)
		return false;

	pa = pte_to_pa(pte);

	if (!is_last_spte(pte, level)) {
		/* link spte */
#if 0
		if (vbh_set_ram_metadata_in_range(vbh, pa, PAGE_SIZE,
						&ept_map, NULL, root_kvm->data.vm_id)) {
			BUG_ON(printk("buggy code or malicious host?\n"));
		}
		invept = vbh_update_pfn_status(vbh, pa >> PAGE_SHIFT, true, false);
#endif
		if (invept)
			memset(vbh_va(pa), 0, PAGE_SIZE);
	} else if (pte & 1) {
		//u8 ret;
		/*
		 * last level spte. it might be IO.
		 * As pte present, it will not causing EPT misconfig IO
		 * vmexit, so it should be ram, or the real pass through
		 * IO
		 */
		if (is_large_pte(pte))
			size = KVM_HPAGE_SIZE(level);
		else
			size = PAGE_SIZE;
#if 0
		ret = vbh_set_ram_metadata_in_range(vbh, pa, size, &ept_map,
						    NULL, root_kvm->data.vm_id);
		if (ret == RET_SUCCESS) {
			/* TODO: For secure VM needs to:
			 * 1. isolate memory.
			 * 2. if IOMMU is identity mapping, remove mappings
			 * from table.
			 * 3. if IOMMU is dynamic mapping, check if already
			 * mapped.(future work)
			 */
			;
		} else if (ret == RET_NOT_FOUND) {
			/* TODO: for pass through IO, it cannot set the ram metadata
			 * so needs to set the IO metadata at here.
			 */
			;
		} else
			BUG_ON(printk("%s: buggy code?\n", __func__));
#endif
	}

	sptep = sptep_for_gfn(vbh_va(root_kvm->ept_gpa),
			base_gfn, vbh->ept_walks, level);
	BUG_ON(!sptep);

	//trace_printk("%s: write protect: root_ept 0x%llx sptep 0x%llx level %d base_gfn 0x%llx pa 0x%llx pte 0x%llx\n",
	//	__func__, (u64)vbh_va(root_kvm->ept_gpa), (u64)sptep, level, base_gfn, pa, pte);

	__set_spte(sptep, pte);

	return invept;
}

int vmx_root_build_ept(struct vbh_data *vbh, u64 root_page, u64 param)
{
	struct root_kvm *root_kvm = vbh_va(root_page);
	struct root_param *p = vbh_va(param);
	struct ept_data *ept = &p->ept;
	bool invept = false;
	int i;

	BUG_ON(root_kvm->data.vm_id <= VBH_ID);

	for (i = PT64_ROOT_MAX_LEVEL; i > 0; i--) {
		struct mmu_data *mmu = &ept->mmu[i - 1];
		invept |= vmx_root_set_pte(vbh, root_kvm, mmu->base_gfn,
					   i, mmu->pte);
	}

	if (invept)
		//FIXME: need to do this on all pcpu.
		vbh_invept(vbh);

	memset(ept, 0, sizeof(struct ept_data));

	return 0;
}
