#ifndef __VBH_VMCS_H
#define __VBH_VMCS_H

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};

struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[0];
};

struct vmcs12 {
	u8 vmcs_hdr[4];
	u32 abort;

	/*
	 * Rest of the memory is used for "VMCS Data"
	 * Layout of VMCS Data is non-architectural and processor
	 * implemetation specific.
	 */

	u32 launch_state; /* Possible that this member is not needed */
	/*
	 * 16-bit Control Fields
	 */
	u16 vpid;
	u16 posted_intr_nv;
	u16 eptp_index;
	/*
	 * 16-bit Read-only Fields
	 */
	u16 padding;
	/*
	 * 16-bit Guest-State Fields
	 */
	u16 guest_es;
	u16 guest_cs;
	u16 guest_ss;
	u16 guest_ds;
	u16 guest_fs;
	u16 guest_gs;
	u16 guest_ldtr;
	u16 guest_tr;
	u16 guest_intr_status;
	u16 pml_index;
	/*
	 * 16-bit Host-State Fields
	 */
	u16 host_es;
	u16 host_cs;
	u16 host_ss;
	u16 host_ds;
	u16 host_fs;
	u16 host_gs;
	u16 host_tr;
	/*
	 * 64-bit Control Fields
	 */
	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_load_addr;
	u64 executive_vmcs_ptr;
	u64 pml_addr;
	u64 tsc_offset;
	u64 virtual_apic_addr;
	u64 apic_access_addr;
	u64 posted_interrupt_desc_addr;
	u64 vm_func_controls;
	u64 eptp_pointer;
	u64 eoi_exit_bitmap0;
	u64 eoi_exit_bitmap1;
	u64 eoi_exit_bitmap2;
	u64 eoi_exit_bitmap3;
	u64 eptp_list_addr;
	u64 vmread_bitmap_addr;
	u64 vmwrite_bitmap_addr;
	u64 virt_exception_info_addr;
	u64 xss_exiting_bitmap;
	u64 encls_exiting_bitmap;
	u64 sub_page_permission_ptr;
	u64 tsc_multiplier;
	/*
	 * 64-bit Read-Only Data Fields
	 */
	u64 guest_phys_addr;
	/*
	 * 64-bit Guest-State Fields
	 */
	u64 vmcs_link_ptr;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;
	u64 ia32_perf_global_ctrl;
	u64 guest_pdpte0;
	u64 guest_pdpte1;
	u64 guest_pdpte2;
	u64 guest_pdpte3;
	u64 guest_ia32_bndcfgs;
	u64 guest_ia32_rtit_ctl;
	/*
	 * 64-bit Host-State Fields
	 */
	u64 host_ia32_pat;
	u64 host_ia32_efer;
	u64 host_ia32_perf_global_ctrl;
	/*
	 * 32-bit Control Fields
	 */
	u32 pin_based_exec_ctrl;
	u32 proc_based_exec_ctrl;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_err_code;
	u32 vm_entry_instr_len;
	u32 tpr_threshold;
	u32 proc_based_exec_ctrl2;
	u32 ple_gap;
	u32 ple_window;
	/*
	 * 32-bit Read-Only Data Fields
	 */
	u32 vm_instr_error;
	u32 exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instr_len;
	u32 vm_exit_instr_info;
	/*
	 * 32-bit Guest-State Fields
	 */
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
	u32 guest_es_ar;
	u32 guest_cs_ar;
	u32 guest_ss_ar;
	u32 guest_ds_ar;
	u32 guest_fs_ar;
	u32 guest_gs_ar;
	u32 guest_ldtr_ar;
	u32 guest_tr_ar;
	u32 guest_intr_state;
	u32 guest_activity_state;
	u32 guest_smbase;
	u32 guest_ia32_sysenter_cs;
	u32 vmx_preempt_timer_val;
	/*
	 * 32-bit Host-State Fields
	 */
	u32 host_ia32_sysenter_cs;
	/*
	 * Natural-width Control Fields
	 */
	u64 cr0_guest_host_mask;
	u64 cr4_guest_host_mask;
	u64 cr0_read_shadow;
	u64 cr4_read_shadow;
	u64 cr3_target_val0;
	u64 cr3_target_val1;
	u64 cr3_target_val2;
	u64 cr3_target_val3;
	/*
	 * Natural-width Read-Only Data Fields
	 */
	u64 exit_qual;
	u64 io_rcx;
	u64 io_rsi;
	u64 io_rdi;
	u64 io_rip;
	u64 guest_linear_addr;
	/*
	 * Natural-width Guest-State Fields
	 */
	u64 guest_cr0;
	u64 guest_cr3;
	u64 guest_cr4;
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
	u64 guest_dr7;
	u64 guest_rsp;
	u64 guest_rip;
	u64 guest_rflags;
	u64 guest_pending_debug_excp;
	u64 guest_ia32_sysenter_esp;
	u64 guest_ia32_sysenter_eip;
	/*
	 * Natural-width Host-State Fields
	 */
	u64 host_cr0;
	u64 host_cr3;
	u64 host_cr4;
	u64 host_fs_base;
	u64 host_gs_base;
	u64 host_tr_base;
	u64 host_gdtr_base;
	u64 host_idtr_base;
	u64 host_ia32_sysenter_esp;
	u64 host_ia32_sysenter_eip;
	u64 host_rsp;
	u64 host_rip;
} __aligned(PAGE_SIZE);

#endif
