#ifndef __KVM_X86_VMX_ROOT_H
#define __KVM_X86_VMX_ROOT_H

#include <linux/smp.h>
#include <linux/jump_label.h>
#include <linux/errno.h>
#include <linux/percpu-defs.h>

#include "../vmcs.h"

//#define VBH_DEBUG
#undef VBH_DEBUG

#ifdef VBH_DEBUG
#define VBH_WARN_ONCE(condition, format...) WARN_ONCE(condition, format...)
#define vbh_tp(format...) trace_printk(format)
#else
#define VBH_WARN_ONCE(condition, format...)
#define vbh_tp(format...)
#endif

DECLARE_PER_CPU(struct vmcs *, current_nonroot_vmcs);

struct nonroot_vmcs {
	u32 revision_id;
	u32 abort;

	u16 host_es_selector;
	u16 host_cs_selector;
	u16 host_ss_selector;
	u16 host_ds_selector;
	u16 host_fs_selector;
	u16 host_gs_selector;
	u16 host_tr_selector;

	u16 padding16_1;

	u64 host_ia32_pat;
	u64 host_ia32_efer;

	u64 host_cr0;
	u64 host_cr3;
	u64 host_cr4;

	u64 host_ia32_sysenter_esp;
	u64 host_ia32_sysenter_eip;
	u64 host_rip;
	u32 host_ia32_sysenter_cs;

	u32 pin_based_vm_exec_control;
	u32 vm_exit_controls;
	u32 secondary_vm_exec_control;

	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;

	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;

	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;

	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;

	u64 guest_es_base;
	u64 guest_cs_base;
	u64 guest_ss_base;
	u64 guest_ds_base;
	u64 guest_fs_base;
	u64 guest_gs_base;
	u64 guest_ldtr_base;
	u64 guest_tr_base;
	u64 guest_gdtr_base;
	u64 guest_idtr_base;

	u64 padding64_1[3];

	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;

	u64 cr3_target_value0;
	u64 cr3_target_value1;
	u64 cr3_target_value2;
	u64 cr3_target_value3;

	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;

	u32 cr3_target_count;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_msr_load_count;

	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 vmcs_link_pointer;

	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;

	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;

	u64 guest_pending_dbg_exceptions;
	u64 guest_sysenter_esp;
	u64 guest_sysenter_eip;

	u32 guest_activity_state;
	u32 guest_sysenter_cs;

	u64 cr0_guest_host_mask;
	u64 cr4_guest_host_mask;
	u64 cr0_read_shadow;
	u64 cr4_read_shadow;
	u64 guest_cr0;
	u64 guest_cr3;
	u64 guest_cr4;
	u64 guest_dr7;

	u64 host_fs_base;
	u64 host_gs_base;
	u64 host_tr_base;
	u64 host_gdtr_base;
	u64 host_idtr_base;
	u64 host_rsp;

	u64 ept_pointer;

	u16 virtual_processor_id;
	u16 padding16_2[3];

	u64 padding64_2[5];
	u64 guest_physical_address;

	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;

	u64 exit_qualification;
	u64 exit_io_instruction_ecx;
	u64 exit_io_instruction_esi;
	u64 exit_io_instruction_edi;
	u64 exit_io_instruction_eip;

	u64 guest_linear_address;
	u64 guest_rsp;
	u64 guest_rflags;

	u32 guest_interruptibility_info;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 vm_entry_controls;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;

	u64 guest_rip;

	/* new added */
	u64 vm_function_control;
	u64 apic_access_addr;
	u64 guest_ia32_perf_global_ctrl;
	u64 host_ia32_perf_global_ctrl;

	u32 hv_clean_fields;
	u32 hv_padding_32;
	u32 hv_synthetic_controls;
	struct {
		u32 nested_flush_hypercall:1;
		u32 msr_bitmap:1;
		u32 reserved:30;
	}  __packed hv_enlightenments_control;
	u32 hv_vp_id;

	u64 hv_vm_id;
	u64 partition_assist_page;
	u64 padding64_4[4];
	u64 guest_bndcfgs;
	u64 padding64_5[7];
	u64 xss_exit_bitmap;
	u64 padding64_6[7];
} __packed;

#define __current_nonroot_vmcs ((struct nonroot_vmcs *)this_cpu_read(current_nonroot_vmcs))

#define NONROOT_ROL16(val, n) ((u16)(((u16)(val) << (n)) | ((u16)(val) >> (16 - (n)))))
#define NONROOT_VMCS_OFFSET(x) offsetof(struct nonroot_vmcs, x)
#define NONROOT_VMCS_FIELD(number, name, clean_field) [NONROOT_ROL16(number, 6)] = \
		{NONROOT_VMCS_OFFSET(name), clean_field}

#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE			0
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP		BIT(0)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP		BIT(1)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2		BIT(2)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1		BIT(3)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC		BIT(4)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT		BIT(5)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY		BIT(6)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN		BIT(7)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR			BIT(8)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT		BIT(9)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC		BIT(10)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1		BIT(11)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2		BIT(12)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER		BIT(13)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1		BIT(14)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ENLIGHTENMENTSCONTROL	BIT(15)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL			0xFFFF

struct nonroot_vmcs_field {
	u16 offset;
	u16 clean_field;
};

extern const struct nonroot_vmcs_field vmcs_field_to_nonroot_vmcs[];
extern const unsigned int nr_nonroot_vmcs_fields;

static __always_inline int get_nonroot_vmcs_offset(unsigned long field, u16 *clean_field)
{
	unsigned int index = NONROOT_ROL16(field, 6);
	const struct nonroot_vmcs_field *vmcs_field;

	vbh_tp("%s: index 0x%x field 0x%lx nr_nonroot_vmcs_fields 0x%x\n",
		__func__, index, field, nr_nonroot_vmcs_fields);

	if (unlikely(index >= nr_nonroot_vmcs_fields)) {
		WARN_ONCE(1, "KVM: accessing unsupported EVMCS field %lx\n",
			  field);
		return -ENOENT;
	}

	vmcs_field = &vmcs_field_to_nonroot_vmcs[index];

	if (clean_field)
		*clean_field = vmcs_field->clean_field;

	if (vmcs_field->offset < 0)
		WARN_ONCE(1, "KVM: invalid offset for field %lx\n", field);

	if (vmcs_field->offset == 0 && field != 0) {
		WARN(1, "KVM: accessing invalid nonroot_vmcs field 0x%lx, should be fixed!\n", field);
	}

	return vmcs_field->offset;
}

static inline void nonroot_vmcs_write64(unsigned long field, u64 value)
{
	u16 clean_field;
	int offset = get_nonroot_vmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	vbh_tp("%s: field 0x%lx value 0x%llx offset 0x%x\n", __func__, field, value, offset);
	*(u64 *)((char *)__current_nonroot_vmcs + offset) = value;

	__current_nonroot_vmcs->hv_clean_fields &= ~clean_field;
}

static inline void nonroot_vmcs_write32(unsigned long field, u32 value)
{
	u16 clean_field;
	int offset = get_nonroot_vmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	vbh_tp("%s: field 0x%lx value 0x%x offset 0x%x\n", __func__, field, value, offset);
	*(u32 *)((char *)__current_nonroot_vmcs + offset) = value;
	__current_nonroot_vmcs->hv_clean_fields &= ~clean_field;
}

static inline void nonroot_vmcs_write16(unsigned long field, u16 value)
{
	u16 clean_field;
	int offset = get_nonroot_vmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	vbh_tp("%s: field 0x%lx value 0x%x offset 0x%x\n", __func__, field, value, offset);
	*(u16 *)((char *)__current_nonroot_vmcs + offset) = value;
	__current_nonroot_vmcs->hv_clean_fields &= ~clean_field;
}

static inline u64 nonroot_vmcs_read64(unsigned long field)
{
	int offset = get_nonroot_vmcs_offset(field, NULL);
	u64 value;

	if (offset < 0)
		return 0;

	value = *(u64 *)((char *)__current_nonroot_vmcs + offset);
	vbh_tp("%s: field 0x%lx value 0x%llx offset 0x%x\n", __func__, field, value, offset);
	return value;
}

static inline u32 nonroot_vmcs_read32(unsigned long field)
{
	int offset = get_nonroot_vmcs_offset(field, NULL);
	u32 value;

	if (offset < 0)
		return 0;

	value = *(u32 *)((char *)__current_nonroot_vmcs + offset);
	vbh_tp("%s: field 0x%lx value 0x%x offset 0x%x\n", __func__, field, value, offset);
	return value;
}

static inline u16 nonroot_vmcs_read16(unsigned long field)
{
	int offset = get_nonroot_vmcs_offset(field, NULL);
	u16 value;

	if (offset < 0)
		return 0;

	value = *(u16 *)((char *)__current_nonroot_vmcs + offset);
	vbh_tp("%s: field 0x%lx value 0x%x offset 0x%x\n", __func__, field, value, offset);
	return value;
}

static inline void nonroot_vmcs_touch_msr_bitmap(void)
{
	if (unlikely(!__current_nonroot_vmcs))
		return;

	if (__current_nonroot_vmcs->hv_enlightenments_control.msr_bitmap)
		__current_nonroot_vmcs->hv_clean_fields &=
			~HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP;
}

#endif
