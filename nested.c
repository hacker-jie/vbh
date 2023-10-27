#include "vbh.h"
#include "pt.h"
#include "nested_debug.h"
#include "cpu.h"
#include "vbh_ops.h"
#include "nested.h"
#include "mem_ops.h"
#include "lock.h"

/*
 * This is an array of offsets into a structure of type "struct vmcs12"
 * 16 offsets for a total of 16 GROUPs. 4 "field widths" by 4 "field types".
 * "Field type" is either Control, Read-Only Data, Guest State or Host State.
 * Refer to the definition of "struct vmcs12" on how the fields are
 * grouped together for these offsets to work in tandem.
 * Refer to Intel SDM Appendix B Field Encoding in VMCS for info on how
 * fields are grouped and indexed within a group.
 */
static const u16 vmcs12_group_offset_table[16] = {
	offsetof(struct vmcs12, vpid),	/* 16-bit Control Fields */
	offsetof(struct vmcs12, padding),	/* 16-bit Read-Only Fields */
	offsetof(struct vmcs12, guest_es), /* 16-bit Guest-State Fields */
	offsetof(struct vmcs12, host_es),	/* 16-bit Host-State Fields */
	offsetof(struct vmcs12, io_bitmap_a),	/* 64-bit Control Fields */
	offsetof(struct vmcs12, guest_phys_addr),	/* 64-bit Read-Only Data Fields */
	offsetof(struct vmcs12, vmcs_link_ptr),	/* 64-bit Guest-State Fields */
	offsetof(struct vmcs12, host_ia32_pat),	/* 64-bit Host-State Fields */
	offsetof(struct vmcs12, pin_based_exec_ctrl),	/* 32-bit Control Fields */
	offsetof(struct vmcs12, vm_instr_error),	/* 32-bit Read-Only Data Fields */
	offsetof(struct vmcs12, guest_es_limit),	/* 32-bit Guest-State Fields */
	offsetof(struct vmcs12, host_ia32_sysenter_cs),	/* 32-bit Host-State Fields */
	offsetof(struct vmcs12, cr0_guest_host_mask),	/* Natural-width Control Fields */
	offsetof(struct vmcs12, exit_qual),		/* Natural-width Read-Only Data Fields */
	offsetof(struct vmcs12, guest_cr0),		/* Natural-width Guest-State Fields */
	offsetof(struct vmcs12, host_cr0),			/* Natural-width Host-State Fields */
};

/*
 * field_idx is the index of field with in the group.
 *
 * Access-type is 0 for all widths except for 64-bit
 * For 64-bit if Access-type is 1, offset is moved to
 * high 4 bytes of the field.
 */
#define OFFSET_INTO_VMCS12(group_idx, field_idx, width_in_bytes, access_type)	 (vmcs12_group_offset_table[group_idx] + \
											field_idx*width_in_bytes + \
											access_type*sizeof(uint32_t))
/*
 * VMCS fields included in the dual-purpose VMCS: as shadow for L1 and
 * as hardware VMCS for (nested) L2.
 * No need to put high field here.
 * TODO: more fileds can be put
 */
const u32 vmcs_shadow_fields[] = {
	/* 16-bits */
	VIRTUAL_PROCESSOR_ID,

	GUEST_ES_SELECTOR,
	GUEST_CS_SELECTOR,
	GUEST_SS_SELECTOR,
	GUEST_DS_SELECTOR,
	GUEST_FS_SELECTOR,
	GUEST_GS_SELECTOR,
	GUEST_LDTR_SELECTOR,
	GUEST_TR_SELECTOR,
	GUEST_INTR_STATUS,
	GUEST_PML_INDEX,

	/* 64-bits */
	IO_BITMAP_A,
	IO_BITMAP_B,
	MSR_BITMAP,
	VM_EXIT_MSR_STORE_ADDR,
	VM_EXIT_MSR_LOAD_ADDR,
	VM_ENTRY_MSR_LOAD_ADDR,
	PML_ADDRESS, //audit?
	TSC_OFFSET,
	VIRTUAL_APIC_PAGE_ADDR,
	APIC_ACCESS_ADDR,
	VM_FUNCTION_CONTROL,
	EPT_POINTER, //audit
	VMREAD_BITMAP, //audit
	VMWRITE_BITMAP, //audit
	XSS_EXIT_BITMAP,
	TSC_MULTIPLIER,
	GUEST_PHYSICAL_ADDRESS,
	VMCS_LINK_POINTER, //audit
	GUEST_IA32_DEBUGCTL,
	GUEST_IA32_PAT,
	GUEST_IA32_EFER,
	GUEST_IA32_PERF_GLOBAL_CTRL,
	GUEST_PDPTR0, //audit
	GUEST_PDPTR1, //audit
	GUEST_PDPTR2, //audit
	GUEST_PDPTR3, //audit
	GUEST_BNDCFGS,

	/* 32-bits */
	PIN_BASED_VM_EXEC_CONTROL,
	CPU_BASED_VM_EXEC_CONTROL,
	EXCEPTION_BITMAP,
	PAGE_FAULT_ERROR_CODE_MASK,
	PAGE_FAULT_ERROR_CODE_MATCH,
	CR3_TARGET_COUNT,
	VM_EXIT_CONTROLS,
	VM_EXIT_MSR_STORE_COUNT,
	VM_EXIT_MSR_LOAD_COUNT,
	VM_ENTRY_CONTROLS,
	VM_ENTRY_MSR_LOAD_COUNT,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INSTRUCTION_LEN,
	TPR_THRESHOLD,
	SECONDARY_VM_EXEC_CONTROL,
	PLE_GAP,
	PLE_WINDOW,
	VM_INSTRUCTION_ERROR,
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INTR_ERROR_CODE,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INSTRUCTION_LEN,
	VMX_INSTRUCTION_INFO,
	GUEST_ES_LIMIT,
	GUEST_CS_LIMIT,
	GUEST_SS_LIMIT,
	GUEST_DS_LIMIT,
	GUEST_FS_LIMIT,
	GUEST_GS_LIMIT,
	GUEST_LDTR_LIMIT,
	GUEST_TR_LIMIT,
	GUEST_GDTR_LIMIT,
	GUEST_IDTR_LIMIT,
	GUEST_ES_AR_BYTES,
	GUEST_CS_AR_BYTES,
	GUEST_SS_AR_BYTES,
	GUEST_DS_AR_BYTES,
	GUEST_FS_AR_BYTES,
	GUEST_GS_AR_BYTES,
	GUEST_LDTR_AR_BYTES,
	GUEST_TR_AR_BYTES,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_SYSENTER_CS,
	//VMX_GUEST_SMBASE,
	VMX_PREEMPTION_TIMER_VALUE,
	CR0_GUEST_HOST_MASK,
	CR4_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	CR3_TARGET_VALUE0,
	CR3_TARGET_VALUE1,
	CR3_TARGET_VALUE2,
	CR3_TARGET_VALUE3,
	EXIT_QUALIFICATION,
	GUEST_LINEAR_ADDRESS,
	//VMX_IO_RCX,
	//VMX_IO_RSI,
	//VMX_IO_RDI,
	//VMX_IO_RIP,
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_ES_BASE,
	GUEST_CS_BASE,
	GUEST_SS_BASE,
	GUEST_DS_BASE,
	GUEST_FS_BASE,
	GUEST_GS_BASE,
	GUEST_LDTR_BASE,
	GUEST_TR_BASE,
	GUEST_GDTR_BASE,
	GUEST_IDTR_BASE,
	GUEST_DR7,
	GUEST_RSP,
	GUEST_RIP,
	GUEST_RFLAGS,
	GUEST_PENDING_DBG_EXCEPTIONS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
	~0U
};

#define VMXERR_UNSUPPORTED_COMPONENT            (12)
#define VMX_SUCCEED		0
#define VMX_FAIL_VALID		1
#define VMX_FAIL_INVALID	2
static void nested_vmx_result(int result, int error_number)
{
	unsigned long rflags = exec_vmreadl(GUEST_RFLAGS);

	/* ISDM: section 30.2 CONVENTIONS */
	rflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
		X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);

	if (result == VMX_FAIL_VALID) {
		rflags |= X86_EFLAGS_ZF;
		exec_vmwrite32(VM_INSTRUCTION_ERROR, error_number);
	} else if (result == VMX_FAIL_INVALID) {
		rflags |= X86_EFLAGS_CF;
	}

	if (result != VMX_SUCCEED) {
		vmx_err("VMX failed: %d/%d\n", result, error_number);
	}

	exec_vmwritel(GUEST_RFLAGS, rflags);
}

static u64 get_gva_from_memory_operand(struct vbh_vcpu_vmx *vcpu)
{
	u32 instr_info = vcpu->instr_info;
	int  scaling = instr_info & 3;
	int  index_reg = (instr_info >> 18) & 0xf;
	bool index_is_valid = !(instr_info & (1u << 22));
	int  base_reg       = (instr_info >> 23) & 0xf;
	bool base_is_valid  = !(instr_info & (1u << 27));
	u64 gva;

	/*
	 * SDM Table 27-13 Format of the VM-Exit Instruction-Information Field as Used for
	 * VMCLEAR, VMPTRLD, VMPTRST, VMXON, XRSTORS, and XSAVES
	 *
	 * address size: assume 64 bits
	 */

	/* Addr = segment_base + offset */
	/* offset = base + [index * scale] + displacement */
	gva = vcpu->exit_qualification; /* displacement */

	if (base_is_valid)
		gva += vcpu->regs[base_reg];
	if (index_is_valid)
		gva += vcpu->regs[index_reg] << scaling;

	//TODO: should also check the segment and address size

	return gva;
}

static u64 read_from_memory_operand(struct vbh_vcpu_vmx *vcpu)
{
	u64 gva, vmptr_gpa, value;
	u64 err_code = 0U;
	u64 *hva;

	gva = get_gva_from_memory_operand(vcpu);

	(void)gva2gpa(vcpu, gva, &vmptr_gpa, &err_code);

	/* get vmptr GPA from the guest pointer than content it */
	hva = hpa2hva(gpa2hpa(vmptr_gpa));

	//TODO: read length check?

	//vbh_stac();
	value = *hva;
	//vbh_clac();

	//vmx_log("value: %llx ptr_gva: %llx\n", value, gva);
	return value;
}

static void write_to_memory_operand(struct vbh_vcpu_vmx *vcpu, u64 value)
{
	u64 gva, vmptr_gpa;
	u64 err_code = 0U;
	u64 *hva;

	gva = get_gva_from_memory_operand(vcpu);

	(void)gva2gpa(vcpu, gva, &vmptr_gpa, &err_code);

	/* get vmptr GPA from the guest pointer than content it */
	hva = hpa2hva(gpa2hpa(vmptr_gpa));

	//TODO: write length check?

	//vbh_stac();
	*hva = value;
	//vbh_clac();

	//vmx_log("value: %llx ptr_gva: %llx\n", value, gva);
}

static u64 get_vmptr_gpa(struct vbh_vcpu_vmx *vcpu)
{
	return read_from_memory_operand(vcpu);
}

static int get_invvpid_ept_operand(struct vbh_vcpu_vmx *vcpu, void *operand, size_t size, u64 *type)
{
	int ret = 0;

	u32 instr_info = vcpu->instr_info;
	u64 gva, gpa;
	u64 err_code = 0U;
	u32 reg2 = (instr_info >> 28) & 0xf;

	*type = vcpu->regs[reg2];

	gva = get_gva_from_memory_operand(vcpu);
	gva2gpa(vcpu, gva, &gpa, &err_code);
	vbh_memcpy(operand, size, hpa2hva(gpa2hpa(gpa)), size);

	//TODO: get error ret from the above code?
	return ret;
}

/*
 * Given a vmcs field, this API returns the offset into a structure of
 * type "struct acrn_vmcs12"
 */
static u16 vmcs_field_to_vmcs12_offset(u32 vmcs_field)
{
	/*
	 * A value of group index 0001b is not valid because
	 * there are no 16-bit Read-Only fields.
	 * Refer to Appendix B Field Encoding in VMCS in SDM
	 * We do not check for the invalid value here and trust
	 * L1 KVM does not get creative in passing an incorrect
	 * vmcs_field.
	 */
	u16 group_idx = (VMX_VMCS_FIELD_WIDTH(vmcs_field) << 2U) | VMX_VMCS_FIELD_TYPE(vmcs_field);
	u8 width_in_bytes;
	u8 field_width = VMX_VMCS_FIELD_WIDTH(vmcs_field);

	if (field_width == VMX_VMCS_FIELD_WIDTH_16) {
		width_in_bytes = 2U;
	} else if (field_width == VMX_VMCS_FIELD_WIDTH_32) {
		width_in_bytes = 4U;
	} else {
		/*
		 * Natural-width or 64-bit
		 */
		width_in_bytes = 8U;
	}

	return OFFSET_INTO_VMCS12(group_idx,
			VMX_VMCS_FIELD_INDEX(vmcs_field), width_in_bytes, /* field index within the group */
			VMX_VMCS_FIELD_ACCESS_HIGH(vmcs_field));
}

static u64 vmcs12_read_field(u64 vmcs_hva, u32 field)
{
	u64 *ptr = (u64 *)(vmcs_hva + vmcs_field_to_vmcs12_offset(field));
	u64 val64 = 0UL;

	switch (VMX_VMCS_FIELD_WIDTH(field)) {
		case VMX_VMCS_FIELD_WIDTH_16:
			val64 = *(u16 *)ptr;
			break;
		case VMX_VMCS_FIELD_WIDTH_32:
			val64 = *(u32 *)ptr;
			break;
		case VMX_VMCS_FIELD_WIDTH_64:
			if (!!VMX_VMCS_FIELD_ACCESS_HIGH(field)) {
				val64 = *(u64 *)ptr;
			} else {
				val64 = *ptr;
			}
			break;
		default:	/* 64bits fields */
			val64 = *ptr;
			break;
	}

	return val64;
}

static void vmcs12_write_field(u64 vmcs_hva, u32 field, u64 val64)
{
	u64 *ptr = (u64 *)(vmcs_hva + vmcs_field_to_vmcs12_offset(field));

	switch (VMX_VMCS_FIELD_WIDTH(field)) {
		case VMX_VMCS_FIELD_WIDTH_16:
			*(u16 *)ptr = (u16)val64;
			break;
		case VMX_VMCS_FIELD_WIDTH_32:
			*(u32 *)ptr = (u32)val64;
			break;
		case VMX_VMCS_FIELD_WIDTH_64:
			if (!!VMX_VMCS_FIELD_ACCESS_HIGH(field)) {
				*(u32 *)ptr = (u32)val64;
			} else {
				*ptr = val64;
			}
			break;
		default:	/* 64bits fields */
			*ptr = val64;
			break;
	}
}

/*
 * Copy shadow fields from vmcs02 to vmcs12
 * At entry, the active VMCS is vmcs01
 */
static void copy_vmcs02_to_vmcs12(struct vbh_vcpu_vmx *vcpu)
{
	u64 vmcs12 = (u64)&vcpu->nested.vmcs12;
	u64 val64;
	u32 idx;

	/* load shadow VMCS */
	exec_vmptrld(vbh_pa(vcpu->nested.vmcs02));

	for (idx = 0; vmcs_shadow_fields[idx] != ~0U; idx++) {
		val64 = exec_vmread64(vmcs_shadow_fields[idx]);
		vmx_log("CPU%d: vmcs02_to_vmcs12: field %x value %llx\n", vcpu->cpu_id, vmcs_shadow_fields[idx], val64);
		vmcs12_write_field(vmcs12, vmcs_shadow_fields[idx], val64);
	}

	exec_vmclear(vbh_pa(vcpu->nested.vmcs02));
}

static void copy_vmcs12_to_vmcs02(struct vbh_vcpu_vmx *vcpu)
{
	u64 vmcs12 = (u64)&vcpu->nested.vmcs12;
	u64 val64;
	u32 idx;

	/* load shadow VMCS */
	exec_vmptrld(vbh_pa(vcpu->nested.vmcs02));

	for (idx = 0; vmcs_shadow_fields[idx] != ~0U; idx++) {
		val64 = vmcs12_read_field(vmcs12, vmcs_shadow_fields[idx]);
		vmx_log("CPU%d: vmcs12_to_vmcs02: field %x value %llx\n", vcpu->cpu_id, vmcs_shadow_fields[idx], val64);
		exec_vmwrite64(vmcs_shadow_fields[idx], val64);
	}

	exec_vmclear(vbh_pa(vcpu->nested.vmcs02));
}

static void invalid_shadow_mmu_pages(struct vbh_vcpu_vmx *vcpu,
				     struct shadow_ept_root *sp)
{
	struct shadow_page *p, *n;

	sspinlock_obtain(&sp->lock);
	if (!list_empty(&sp->sp_list)) {
		list_for_each_entry_safe(p, n, &sp->sp_list, list) {
			vbh_memset(hpa2hva(p->hpa), 0, PAGE_SIZE);
			/* No need to clean the mapping in root level(assume
			 * root level is level 4).
			 *
			 * For level 3 shadow page, its mapping is still
			 * in level 4 root ept so not to put it in
			 * invalid list.
			 * For level 2/1 shadow pages, as their mappings
			 * are cleanned in level 3 shadow pages, put them
			 * in invalid list.
			 */
			if (p->level < 3) {
				p->level = 0;
				list_move(&p->list, &sp->invalid_list);
			}
			vmx_log("CPU%d: invalid shadow page hpa 0x%llx\n",
				vcpu->cpu_id, p->hpa);
		}
	}
	sspinlock_release(&sp->lock);
}

static void release_shadow_mmu_pages(struct vbh_vcpu_vmx *vcpu,
				     struct shadow_ept_root *sp)
{
	struct shadow_page *p, *n;

	sspinlock_obtain(&sp->lock);
	if (!list_empty(&sp->sp_list)) {
		list_for_each_entry_safe(p, n, &sp->sp_list, list) {
			list_del(&p->list);
			vmx_log("CPU%d: release shadow page hpa 0x%llx\n",
				vcpu->cpu_id, p->hpa);
			vbh_memset(hpa2hva(p->hpa), 0, PAGE_SIZE);
			vbh_free(vcpu->vbh, hpa2hva(p->hpa));
			vbh_memset((void *)p, 0, sizeof(struct shadow_page));
			vbh_free(vcpu->vbh, p);
		}
	}
	if (!list_empty(&sp->invalid_list)) {
		list_for_each_entry_safe(p, n, &sp->invalid_list, list) {
			list_del(&p->list);
			vmx_log("CPU%d: release shadow page hpa 0x%llx\n",
				vcpu->cpu_id, p->hpa);
			vbh_free(vcpu->vbh, hpa2hva(p->hpa));
			vbh_memset((void *)p, 0, sizeof(struct shadow_page));
			vbh_free(vcpu->vbh, p);
		}
	}
	vbh_memset(hpa2hva(sp->hpa), 0, PAGE_SIZE);
	sspinlock_release(&sp->lock);
}

static void release_shadow_ept_root(struct vbh_vcpu_vmx *vcpu,
				    struct shadow_ept_root *sp)
{
	if (!sp)
		return;
	sspinlock_obtain(&vcpu->vbh->nested_mmu_lock);
	sp->count--;
	vmx_log("CPU%d: release shadow hpa 0x%llx for gpa 0x%llx usage count %d\n",
		vcpu->cpu_id, sp->hpa, sp->gpa, sp->count);
	if (sp->count)
		goto out;

	list_del(&sp->list);
	release_shadow_mmu_pages(vcpu, sp);
	vbh_free(vcpu->vbh, hpa2hva(sp->hpa));
	vbh_memset((void *)sp, 0, sizeof(struct shadow_ept_root));
	vbh_free(vcpu->vbh, sp);
	vmx_log("CPU%d: release done\n", vcpu->cpu_id);
out:
	sspinlock_release(&vcpu->vbh->nested_mmu_lock);
}

static void release_current_shadow_ept_root(struct vbh_vcpu_vmx *vcpu)
{
	struct shadow_ept_root *sp = vcpu->nested.current_shadow_root;
	if (!sp)
		return;
	vcpu->nested.current_shadow_root = NULL;
	release_shadow_ept_root(vcpu, sp);
}

static struct shadow_ept_root *find_shadow_ept_root(struct vbh_vcpu_vmx *vcpu, u64 gpa)
{
	struct shadow_ept_root *sp;

	if (!list_empty(&vcpu->vbh->nested_root_ept_list)) {
		list_for_each_entry(sp, &vcpu->vbh->nested_root_ept_list, list) {
			if (sp->gpa == gpa)
				return sp;
		}
	}

	return NULL;
}

static struct shadow_ept_root *get_shadow_ept_root(struct vbh_vcpu_vmx *vcpu,
						   u64 gpa, bool create)
{
	struct shadow_ept_root *sp;

	sspinlock_obtain(&vcpu->vbh->nested_mmu_lock);
	sp = find_shadow_ept_root(vcpu, gpa);
	if (sp) {
		vmx_log("CPU%d: found shadow hpa 0x%llx for gpa 0x%llx usage count %d\n",
			vcpu->cpu_id, sp->hpa, sp->gpa, sp->count);
		sp->count++;
	} else if (create) {
		void *hva;
		sp = vbh_malloc(vcpu->vbh, sizeof(struct shadow_ept_root));
		if (!sp)
			return NULL;
		hva = vbh_malloc(vcpu->vbh, PAGE_SIZE);
		if (!hva) {
			vbh_free(vcpu->vbh, sp);
			return NULL;
		}
		sp->hpa = vbh_pa(hva);
		sp->gpa = gpa;
		sp->count = 1;
		INIT_LIST_HEAD(&sp->list);
		INIT_LIST_HEAD(&sp->sp_list);
		INIT_LIST_HEAD(&sp->invalid_list);
		sspinlock_init(&sp->lock);
		list_add(&sp->list, &vcpu->vbh->nested_root_ept_list);
		vmx_log("CPU%d: new shadow hpa 0x%llx for gpa 0x%llx\n",
			vcpu->cpu_id, sp->hpa, sp->gpa);
	}
	sspinlock_release(&vcpu->vbh->nested_mmu_lock);
	return sp;
}

static void release_current_vmcs12(struct vbh_vcpu_vmx *vcpu)
{
	copy_vmcs02_to_vmcs12(vcpu);

	//vbh_stac();
	vbh_memcpy((void *)hpa2hva(vcpu->nested.current_vmcs12_ptr),
		PAGE_SIZE, (void *)&vcpu->nested.vmcs12, PAGE_SIZE);
	//vbh_clac();
	if (vcpu->vbh->enable_shadow_ept)
		release_current_shadow_ept_root(vcpu);
}

static void vcpu_set_shadow_vmcs(struct vbh_vcpu_vmx *vcpu)
{
	u32 val32;

	/*
	 * Set shadow bit indicator in the VMCS header
	 */
	vcpu->nested.vmcs02->hdr.shadow_vmcs = 1;

	/*
	 * This method of using the same bitmap for VMRead and VMWrite is not typical
	 * Since we do not worry about KVM erroneously writing to Read-Only fields
	 * taking the liberty to use the same bitmap.
	 */

	exec_vmwrite64(VMREAD_BITMAP, vbh_pa(vcpu->vbh->vmcs_shadow_bitmap));
	exec_vmwrite64(VMWRITE_BITMAP, vbh_pa(vcpu->vbh->vmcs_shadow_bitmap));

	/* Set Enable Shadow VMCS bit in Secondary Proc Exec Controls */

	val32 = exec_vmread32(SECONDARY_VM_EXEC_CONTROL);
	val32 |= SECONDARY_EXEC_SHADOW_VMCS;
	exec_vmwrite32(SECONDARY_VM_EXEC_CONTROL, val32);

	/* Set VMCS Link pointer */
	exec_vmwrite64(VMCS_LINK_POINTER, vbh_pa(vcpu->nested.vmcs02));
	vmx_log("CPU%d: set shadow vmcs02 0x%llx\n", vcpu->cpu_id, (u64)vbh_pa(vcpu->nested.vmcs02));
}

static void vcpu_clear_shadow_vmcs(struct vbh_vcpu_vmx *vcpu)
{
	uint32_t val32;

	/* clear Enable Shadow VMCS bit in Secondary Proc Exec Controls */
	val32 = exec_vmread32(SECONDARY_VM_EXEC_CONTROL);
	val32 &= ~SECONDARY_EXEC_SHADOW_VMCS;
	exec_vmwrite32(SECONDARY_VM_EXEC_CONTROL, val32);

	exec_vmwrite64(VMCS_LINK_POINTER, ~0UL);

	/*
	 * Clear shadow bit indicator in the VMCS02 header
	 */
	vcpu->nested.vmcs02->hdr.shadow_vmcs = 0;

	vmx_log("CPU%d: clear shadow vmcs02 0x%llx\n", vcpu->cpu_id, (u64)vbh_pa(vcpu->nested.vmcs02));
}

int invvpid_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	//TODO:
	nested_vmx_result(VMX_SUCCEED, 0);
	return 0;
}

int invept_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	int ret;
	struct {
		u64 eptp, gpa;
	} operand = {0, 0};
	u64 type = 0;
	struct shadow_ept_root *sp_root;

	ret = get_invvpid_ept_operand(vcpu, &operand, sizeof(operand), &type);
	if (!ret) {
		//TODO: type check
		if (vcpu->vbh->enable_shadow_ept) {
			if (type == 1) {
				u64 ept_gpa = operand.eptp & PAGE_MASK;
				sp_root = get_shadow_ept_root(vcpu, ept_gpa, false);
				if (sp_root) {
					vmx_log("CPU%d: invept shadow ept hpa 0x%llx gpa 0x%llx\n",
						vcpu->cpu_id, sp_root->hpa, sp_root->gpa);
					exec_invept(type, sp_root->eptp, 0);
					release_shadow_ept_root(vcpu, sp_root);
				} else
					vmx_log("CPU%d: Not to invept L1 ept 0x%llx as couldn't find shadow ept\n",
						vcpu->cpu_id, ept_gpa);
			} else if (type == 2)
				exec_invept(2, 0, 0);
		} else
			exec_invept(type, operand.eptp, 0);

		nested_vmx_result(VMX_SUCCEED, 0);
	}

	return ret;
}

int vmclear_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	struct nested_vmx *nested = &vcpu->nested;
	u64 vmcs12_gpa;

	if (!vcpu->nested.vmxon)
		return -EPERM;

	vmcs12_gpa = get_vmptr_gpa(vcpu);
	vmx_log("%s: CPU%d clear 0x%llx current 0x%llx\n", __func__, vcpu->cpu_id, vmcs12_gpa, vcpu->nested.current_vmcs12_ptr);

	if (vcpu->vbh->enable_shadow_vmcs) {
		if (vcpu->nested.current_vmcs12_ptr == vmcs12_gpa) {
			release_current_vmcs12(vcpu);
			/*
			 * Switch to vmcs01
			 */
			exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));

			vcpu_clear_shadow_vmcs(vcpu);
			nested->current_vmcs12_ptr = INVALID_GPA;
		}
	} else {
		//TODO: audit if this vmcs12_gpa is valid?
		// If pCPU has vmptrld two VMCS and want to
		// vmclear the 1st one, then we can hit this
		// case. Better to maintain a list of the
		// vmcs on this pCPU?
		exec_vmclear(vmcs12_gpa);
		if (vcpu->nested.current_vmcs12_ptr == vmcs12_gpa)
			nested->current_vmcs12_ptr = INVALID_GPA;
	}

	/*
	 * Linux could issue vmclear even before vmptrld.
	 * This is not against ISDM spec.
	 */
	nested_vmx_result(VMX_SUCCEED, 0);

	return 0;
}

int vmptrld_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	struct nested_vmx *nested = &vcpu->nested;
	uint64_t vmcs12_gpa, vmcs12_hpa;

	if (!vcpu->nested.vmxon)
		return -EPERM;

	vmcs12_gpa = get_vmptr_gpa(vcpu);
	vmx_log("CPU%d: vmptrld gpa 0x%llx current 0x%llx\n", vcpu->cpu_id, vmcs12_gpa, nested->current_vmcs12_ptr);

	/* TODO: audit vmptr.
	 * 1. check if vmptr is using TEE memory.
	 * 2. check if vmptr is valid page(aligned).
	 * 3. check if vmptr is vmxon page.
	 * 4. more?
	 */

	vmcs12_hpa = gpa2hpa(vmcs12_gpa);

	if (vcpu->vbh->enable_shadow_vmcs) {
		/* Sync current L2 VMCS to guest memory */
		if ((nested->current_vmcs12_ptr != INVALID_GPA) &&
			(nested->current_vmcs12_ptr != vmcs12_gpa)) {
			release_current_vmcs12(vcpu);
		}

		/*
		 * TODO: Handle the case where L1 issues VMPtrld
		 * on the same pointer twice without a VMClear
		 * in between.
		 */

		/* Copy vmcs12 from L1 guest memory */
		//vbh_stac();
		vbh_memcpy((void *)&nested->vmcs12, PAGE_SIZE, hpa2hva(vmcs12_hpa), PAGE_SIZE);
		//vbh_clac();

		copy_vmcs12_to_vmcs02(vcpu);

		/*
		 * Switch to vmcs01
		 */
		exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));

		vcpu_set_shadow_vmcs(vcpu);
	}

	nested->current_vmcs12_ptr = vmcs12_gpa;
	nested_vmx_result(VMX_SUCCEED, 0);

	return 0;
}

/* Emulation of VMREAD.
 * VMREAD r/m64, r64
 * VMREAD r/m32, r32
 *
 * We will only see VMREAD from L1 for fields not in the shadow.
 *
 * TODO Validate referenced VMCS field is correct
 * TODO Support for memory operand
 */
int vmread_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	u32 instr_info = vcpu->instr_info;
	u64 vmcs12 = (u64)&vcpu->nested.vmcs12;
	u32 reg2, reg1;
	u64 vmcs_value;
	u32 vmcs_field;

	if ((vcpu->nested.current_vmcs12_ptr == INVALID_GPA) || !vcpu->nested.vmxon)
		return -EPERM;

	reg2 = (instr_info >> 28) & 0xf;
	vmcs_field = (u32)vcpu->regs[reg2];

	if (vcpu->vbh->enable_shadow_vmcs)
		vmcs_value = vmcs12_read_field(vmcs12, vmcs_field);
	else {
		exec_vmptrld(vcpu->nested.current_vmcs12_ptr);
		vmcs_value = exec_vmreadl(vmcs_field);
		exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));
	}

	if (instr_info & (1 << 10)) {
		reg1 = (instr_info >> 3) & 0xf;
		vcpu->regs[reg1] = vmcs_value;
	} else
		write_to_memory_operand(vcpu, vmcs_value);

	vmx_log("vmread: CPU%d: vmcs 0x%llx vmcs_field: %x vmcs_value: %llx\n", vcpu->cpu_id, vcpu->nested.current_vmcs12_ptr, vmcs_field, vmcs_value);
	nested_vmx_result(VMX_SUCCEED, 0);
	return 0;
}

/* Emulation of VMWRITE.
 * VMWRITE r64, r/m64
 * VMWRITE r32, r/m32
 *
 * We will only see VMWRITE from L1 for fields not in the shadow.
 *
 * TODO Validate referenced VMCS field is correct
 * TODO Support for memory operand
 */
int vmwrite_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	u32 instr_info = vcpu->instr_info;
	u64 vmcs12 = (u64)&vcpu->nested.vmcs12;
	u32 reg2, reg1;
	u64 vmcs_value = 0UL;
	u32 vmcs_field;

	if ((vcpu->nested.current_vmcs12_ptr == INVALID_GPA) || !vcpu->nested.vmxon)
		return -EPERM;

	reg2 = (instr_info >> 28) & 0xf;
	vmcs_field = (u32)vcpu->regs[reg2];
	if (instr_info & (1 << 10)) {
		reg1 = (instr_info >> 3) & 0xf;
		vmcs_value = vcpu->regs[reg1];
	} else
		vmcs_value = read_from_memory_operand(vcpu);

	//TODO: read only check
#if 0
	if (vmx_vmcs_field_is_rdonly(vmcs_field)) {
		nested_vmx_result(VMX_FAIL_VALID, VMXERR_VMWRITE_RO_COMPONENT);
		return -EINVAL;
	} else {

	}
#endif
	if (vcpu->vbh->enable_shadow_vmcs) {
		vmcs12_write_field(vmcs12, vmcs_field, vmcs_value);
	} else {
		exec_vmptrld(vcpu->nested.current_vmcs12_ptr);
		exec_vmwritel(vmcs_field, vmcs_value);
		exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));
	}

	vmx_log("vmwrite: CPU%d: vmcs 0x%llx vmcs_field: %x vmcs_value: %llx\n",
		vcpu->cpu_id, vcpu->nested.current_vmcs12_ptr, vmcs_field, vmcs_value);
	nested_vmx_result(VMX_SUCCEED, 0);
	return 0;
}

extern void __vmexit(void);
int vmxon_handler(struct vbh_vcpu_vmx *vcpu)
{
	vcpu->nested.vmxon_gpa = get_vmptr_gpa(vcpu);
	vmx_log("vmxon gpa 0x%llx\n", vcpu->nested.vmxon_gpa);

	/*
	 * ACRN does not perform following checks and assumes L1 hypervisor does it right
	 * 1. vCPU processor mode
	 * 2. Control Register CR0 and CR4 values
	 * 3. Operand type (Register/Memory)
	 * 4. Memory operand value and alignment check
	 * 5. Revision ID encoded in the address pointed to by Memory operand
	 */

	/*
	 * flag to indicate vCPU is in VMX operation
	 */
	vcpu->nested.vmxon = true;
	vcpu->nested.current_vmcs12_ptr = INVALID_GPA;
	vcpu->nested.current_shadow_root = NULL;

	if (vcpu->vbh->enable_shadow_vmcs) {
		u32 value32;

		exec_vmptrld(vbh_pa(vcpu->nested.vmcs02));

		load_host_state_area(vbh_pa(vcpu->cr3));

		/* nested has different vmexit entry from L1 vmexits */
		exec_vmwritel(HOST_RIP, (u64)__vmexit);

		exec_vmclear(vbh_pa(vcpu->nested.vmcs02));
		/*
		 * Switch to vmcs01
		 */

		exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));

		/*
		 * Set Enable Shadow VMCS bit in Secondary Proc Exec Controls
		 */
		value32 = exec_vmread32(SECONDARY_VM_EXEC_CONTROL);
		value32 |= SECONDARY_EXEC_SHADOW_VMCS;
		exec_vmwrite32(SECONDARY_VM_EXEC_CONTROL, value32);
	}

	nested_vmx_result(VMX_SUCCEED, 0);
	return 0;
}

int handle_vmxoff(struct vbh_vcpu_vmx *vcpu)
{
	//TODO:
	nested_vmx_result(VMX_SUCCEED, 0);
	return 0;
}

static u64 get_mmu_page(struct vbh_vcpu_vmx *vcpu, int level)
{
	struct shadow_ept_root *sp_root = vcpu->nested.current_shadow_root;
	struct shadow_page *sp;
	void *hva;

	sp = list_first_entry_or_null(&sp_root->invalid_list, struct shadow_page, list);
	if (sp) {
		sp->level = level;
		list_move(&sp->list, &sp_root->sp_list);
		return sp->hpa;
	}

	sp = vbh_malloc(vcpu->vbh, sizeof(struct shadow_page));
	if (!sp)
		return INVALID_HPA;

	hva = vbh_malloc(vcpu->vbh, PAGE_SIZE);
	if (!hva) {
		vbh_free(vcpu->vbh, sp);
		return INVALID_HPA;
	}

	sp->hpa = vbh_pa(hva);
	sp->level = level;
	INIT_LIST_HEAD(&sp->list);
	list_add(&sp->list, &sp_root->sp_list);
	vmx_log("CPU%d: alloc shadow page hpa 0x%llx\n",
		vcpu->cpu_id, sp->hpa);

	return sp->hpa;
}

struct shadow_walker {
	struct {
		u16 level;
		u16 offset;
		u64 user_pte;
	} pt[5];
};

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#define MMIO_VALUE	((3ULL << 52) | 0x6)
#define MMIO_MASK	((3ULL << 52) | 0x7)
#define SHADOW_EPT_NOTHANDLED	0
#define SHADOW_EPT_HANDLED	1
static int handle_ept_violation(struct vbh_vcpu_vmx *vcpu)
{
	u64 gpa = exec_vmread64(GUEST_PHYSICAL_ADDRESS);
	u64 *parent = hpa2hva(vcpu->nested.eptp & PAGE_MASK);
	int level = 4;
	u64 pte, pte_hpa, pte_pro;
	struct shadow_walker walker;
	bool updated = false;

	vmx_log("CPU%d: handle for gpa 0x%llx L1 EPTP: va 0x%llx pa 0x%llx\n",
		vcpu->cpu_id, gpa, (u64)parent, hva2hpa(parent));

	while (level) {
		walker.pt[level - 1].level = level;
		walker.pt[level - 1].offset = (gpa >> ((level - 1) * 9 + 12)) & 0x1ff;
		pte = parent[walker.pt[level - 1].offset];
		walker.pt[level - 1].user_pte = pte;

		//last level pte
		if (level == 1 || (pte & (1 << 7))) {
			if (!(pte & 1) && ((pte & MMIO_MASK) != MMIO_VALUE)) {
				vmx_log("CPU%d: NOT present: level %d offset %d user_pte 0x%llx\n",
					vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
					walker.pt[level - 1].user_pte);
				// last level not present, let KVM to handle
				return SHADOW_EPT_NOTHANDLED;
			}

			vmx_log("CPU%d: last_level: level %d offset %d user_pte 0x%llx\n",
				vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
				walker.pt[level - 1].user_pte);
			break;
		}

		if (pte & 1) {
			vmx_log("CPU%d: normal: level %d offset %d user_pte 0x%llx\n",
				vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
				walker.pt[level - 1].user_pte);
			pte_hpa = gpa2hpa(pte & PT64_BASE_ADDR_MASK);
			parent = hpa2hva(pte_hpa);
			level--;
			continue;
		}
		vmx_log("CPU%d: NOT present: level %d offset %d user_pte 0x%llx\n",
			vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
			walker.pt[level - 1].user_pte);
		// not present, let KVM to handle
		return SHADOW_EPT_NOTHANDLED;
	}

	parent = hpa2hva(vcpu->nested.current_shadow_root->hpa);
	level = 4;

	//TODO: need to worry about the other CPU is releasing this shadow_root?
	//Seems not needed as current CPU should already hold a count for this
	//shadow root.
	sspinlock_obtain(&vcpu->nested.current_shadow_root->lock);
	while (level) {
		pte = parent[walker.pt[level - 1].offset];

		if (level == 1) {
			//last level pte
			//TODO: audit user_pte gpa to make sure it is not used by TEE.
			if (pte == walker.pt[level - 1].user_pte) {
				// shadow EPT entry is already the same with EPT12
				// so we need to back to L1 to update this entry first.
				parent[walker.pt[level - 1].offset] = 0;
				vmx_log("CPU%d: last level %d offset %d new_pte 0x%llx the same with EPT12, No update\n",
					vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
					parent[walker.pt[level - 1].offset]);
			} else {
				parent[walker.pt[level - 1].offset] = walker.pt[level - 1].user_pte;
				updated = true;
				vmx_log("CPU%d: last level %d offset %d new_pte 0x%llx\n",
					vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
					parent[walker.pt[level - 1].offset]);
			}
			break;
		} else if (walker.pt[level - 1].user_pte & (1 << 7)) {
			// large pte from guest ept, so just update shadow ept and return
			if (pte == walker.pt[level - 1].user_pte) {
				parent[walker.pt[level - 1].offset] = 0;
				vmx_log("CPU%d: large level %d offset %d new_pte 0x%llx the same with EPT12, No update\n",
					vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
					parent[walker.pt[level - 1].offset]);
			} else {
				if ((pte & 1) && !(pte & (1 << 7))) {
					//TODO: release the child mmu as the original pte is not large
					vmx_log("CPU%d: original pte is 0x%llx new 0x%llx is large, needs to release child mmu\n",
						vcpu->cpu_id, pte, walker.pt[level - 1].user_pte);
				}

				//TODO: audit user_pte gpa to make sure it is not used by TEE.
				parent[walker.pt[level - 1].offset] = walker.pt[level - 1].user_pte;
				updated = true;
				vmx_log("CPU%d: large level %d offset %d new_pte 0x%llx\n",
					vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
					parent[walker.pt[level - 1].offset]);
			}
			break;
		} else if ((pte & 1) && !(pte & (1 << 7))) {
			// 4k pte from guest ept, as well as shadow ept entry
			/* TODO:
			 * 1. check if the mmu page is still shadowing the same gpa?
			 * 2. check if the flags of the shadow entry and guest entry the same?
			 */

			/* already configured */
			vmx_log("CPU%d: normal: level %d offset %d configured_pte 0x%llx\n",
				vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
				pte);
			parent = hpa2hva(pte & PT64_BASE_ADDR_MASK);
			level--;
			continue;
		}

		//all other case, will create new mmu page

		pte_hpa = get_mmu_page(vcpu, level - 1);
		if (pte_hpa == INVALID_HPA) {
			vmx_log("CPU%d: failed to get mmu page\n", vcpu->cpu_id);
			sspinlock_release(&vcpu->nested.current_shadow_root->lock);
			return -ENOMEM;
		}
		pte_pro = walker.pt[level - 1].user_pte & ~PT64_BASE_ADDR_MASK;
		parent[walker.pt[level - 1].offset] = pte_hpa | pte_pro;

		vmx_log("CPU%d: normal: level %d offset %d new_pte 0x%llx\n",
			vcpu->cpu_id, walker.pt[level - 1].level, walker.pt[level - 1].offset,
			parent[walker.pt[level - 1].offset]);

		parent = hpa2hva(pte_hpa);
		level--;
	}
	sspinlock_release(&vcpu->nested.current_shadow_root->lock);

	if (updated) {
		vmx_log("CPU%d: handled in VBH, updated %d re-enter VM\n", vcpu->cpu_id, updated);
		return SHADOW_EPT_HANDLED;
	}

	vmx_log("CPU%d: Not handled in VBH, updated %d back to L1\n", vcpu->cpu_id, updated);

	return SHADOW_EPT_NOTHANDLED;
}

static int nested_load_mmu(struct vbh_vcpu_vmx *vcpu)
{
	u64 ept_gpa;
	u16 ept_flags;

	if (!vcpu->vbh->enable_shadow_ept)
		return 0;

	vcpu->nested.eptp = exec_vmread64(EPT_POINTER);

	ept_gpa = vcpu->nested.eptp & PAGE_MASK;
	if (vcpu->nested.current_shadow_root &&
			vcpu->nested.current_shadow_root->gpa == ept_gpa)
		goto out;

	if (vcpu->nested.current_shadow_root &&
			vcpu->nested.current_shadow_root->gpa != ept_gpa) {
		vmx_log("CPU%d: release old gpa 0x%llx and shadow for new gpa 0x%llx\n",
			vcpu->cpu_id, vcpu->nested.current_shadow_root->gpa, ept_gpa);
		release_current_shadow_ept_root(vcpu);
	}

	vcpu->nested.current_shadow_root = get_shadow_ept_root(vcpu, ept_gpa, true);
	if (!vcpu->nested.current_shadow_root) {
		vmx_log("CPU%d: cannot get current shadow root\n", vcpu->cpu_id);
		return 7;
	}

	ept_flags = vcpu->nested.eptp & (PAGE_SIZE - 1);
	vcpu->nested.current_shadow_root->eptp = vcpu->nested.current_shadow_root->hpa | ept_flags;
	vbh_invept(vcpu->vbh, vcpu->nested.current_shadow_root->eptp);
out:
	//vmx_log("CPU%d: update EPTP with 0x%llx(hpa 0x%llx gpa 0x%llx), old 0x%llx\n", vcpu->cpu_id,
	//	vcpu->nested.current_shadow_root->hpa | ept_flags, vcpu->nested.current_shadow_root->hpa,
	//	vcpu->nested.current_shadow_root->gpa, vcpu->nested.eptp);
	exec_vmwrite64(EPT_POINTER, vcpu->nested.current_shadow_root->eptp);

	return 0;
}

static void nested_restore_mmu(struct vbh_vcpu_vmx *vcpu)
{
	if (!vcpu->vbh->enable_shadow_ept)
		return;

	exec_vmwrite64(EPT_POINTER, vcpu->nested.eptp);
}

extern int __nested_vcpu_run(unsigned long *, int);

static int nested_vcpu_run_vmcs12(struct vbh_vcpu_vmx *vcpu, bool launch)
{
	u32 error = 0;

	exec_vmptrld(vcpu->nested.current_vmcs12_ptr);

	/* save the host states */
	save_host_state_area(&vcpu->nested.host_state);

	/* load the actual host states */
	load_host_state_area(vbh_pa(vcpu->cr3));

	/* HOST_RSP is updated in the asm code */
	exec_vmwritel(HOST_RIP, (u64)__vmexit);

	vmx_log("CPU%d: launch %d vmcs12_ptr 0x%llx\n",
		vcpu->cpu_id, launch, vcpu->nested.current_vmcs12_ptr);

	if (__nested_vcpu_run(vcpu->regs, launch)) {
		error = exec_vmread32(VM_INSTRUCTION_ERROR);
		vmx_log("CPU%d: error %d\n", vcpu->cpu_id, error);
	}

	/* restore the host states */
	restore_host_state_area(&vcpu->nested.host_state);

	/* update some of the vmcs01 guest fields */
	exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));
	exec_vmwritel(GUEST_RIP, vcpu->nested.host_state.rip);
	exec_vmwritel(GUEST_RSP, vcpu->nested.host_state.rsp);
	exec_vmwritel(GUEST_RFLAGS, 0x2);

	if (error)
		nested_vmx_result(VMX_FAIL_VALID, error);

	return error;
}

static int nested_vcpu_run_vmcs02(struct vbh_vcpu_vmx *vcpu)
{
	u32 error = 0;
	u32 exit_reason;
	bool launch = true;

	/*
	 * Clear shadow bit indicator in the VMCS02 header
	 * vmcs02 is always cleared at this point so it is
	 * safe to modify the shadow-VMCS indicator.
	 */
	vcpu->nested.vmcs02->hdr.shadow_vmcs = 0;

	/* load vmcs02 */
	exec_vmptrld(vbh_pa(vcpu->nested.vmcs02));

	error = nested_load_mmu(vcpu);
	if (error) {
		vmx_log("CPU%d: failed to load mmu\n", vcpu->cpu_id);
		goto clear_vmcs02;
	}

	//vmx_log("CPU%d: shadow vmcs 0x%llx vmcs12 ptr 0x%llx\n",
	//	vcpu->cpu_id, (u64)vbh_pa(vcpu->nested.vmcs02),
	//	vcpu->nested.current_vmcs12_ptr);

retry:
	if (__nested_vcpu_run(vcpu->regs, launch)) {
		error = exec_vmread32(VM_INSTRUCTION_ERROR);
		vmx_log("CPU%d: error %d\n", vcpu->cpu_id, error);
	}

	exit_reason = exec_vmread32(VM_EXIT_REASON);
	if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
		int ret = handle_ept_violation(vcpu);
		if (ret < 0) {
			vmx_log("CPU%d: failed to handle ept violation\n", vcpu->cpu_id);
			error = 7;
		} else if (ret == SHADOW_EPT_HANDLED) {
			u32 idt_vectoring_info = exec_vmread32(IDT_VECTORING_INFO_FIELD);
			//TODO: this can be optimized to let L0 directly handle
			if (!(idt_vectoring_info & 0x80000000)) {
				launch = false;
				goto retry;
			}
		}
	}

	nested_restore_mmu(vcpu);

	//TODO: check if neccessary to copy vmcs02 to vmcs12

clear_vmcs02:
	/* clear vmcs02 */
	exec_vmclear(vbh_pa(vcpu->nested.vmcs02));

	/*
	 * Set the shadow bit back
	 */
	vcpu->nested.vmcs02->hdr.shadow_vmcs = 1;

	/* update some of the vmcs01 guest fields */
	exec_vmptrld(vbh_pa(vcpu->pcpu_vmcs));
	exec_vmwritel(GUEST_RIP, vcpu->nested.vmcs12.host_rip);
	exec_vmwritel(GUEST_RSP, vcpu->nested.vmcs12.host_rsp);
	exec_vmwritel(GUEST_RFLAGS, 0x2);

	if (error)
		nested_vmx_result(VMX_FAIL_VALID, error);

	return error;
}

int vmlaunch_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	if (vcpu->vbh->enable_shadow_vmcs)
		return nested_vcpu_run_vmcs02(vcpu);
	else
		return nested_vcpu_run_vmcs12(vcpu, true);
}

int vmresume_vmexit_handler(struct vbh_vcpu_vmx *vcpu)
{
	if (vcpu->vbh->enable_shadow_vmcs)
		return nested_vcpu_run_vmcs02(vcpu);
	else
		return nested_vcpu_run_vmcs12(vcpu, false);
}

void nested_flush_tlb_with_range(struct vbh_vcpu_vmx *vcpu,
				 u64 ept_gpa, u64 start_gfn,
				 u64 pages)
{
	struct shadow_ept_root *sp_root = get_shadow_ept_root(vcpu, ept_gpa, false);
	u64 *sptep;
	u32 offset, page_count;
	u64 pte_hpa, pte;
	int level;

	if (!sp_root)
		return;

	vmx_log("CPU%d: flush_tlb_range, ept_gpa 0x%llx start 0x%llx count 0x%llx\n",
		vcpu->cpu_id, ept_gpa, start_gfn, pages);

	sspinlock_obtain(&sp_root->lock);
	while (pages) {
		pte_hpa = sp_root->hpa;
		level = 4;
		while (1) {
			sptep = hpa2hva(pte_hpa);
			page_count = 1 << ((level - 1) * 9);
			offset = (start_gfn / page_count) & 0x1ff;
			pte = sptep[offset];

			if (level == 1 || !pte || pte & (1 << 7))
				break;
			level--;
			pte_hpa = pte & PT64_BASE_ADDR_MASK;
			continue;
		}

		if (level == 1) {
			page_count = (512 - offset) > pages ? pages : (512 - offset);
			pages -= page_count;
			start_gfn += page_count;
			vbh_memset((void *)&sptep[offset], 0, sizeof(u64) * page_count);
		} else {
			sptep[offset] = 0;
			if (page_count >= pages)
				pages = 0;
			else {
				pages -= page_count;
				start_gfn += page_count;
			}
		}

		if (pages)
			vmx_log("CPU%d: clean at level %d offset %d pte 0x%llx count %d, left %lld\n",
				vcpu->cpu_id, level, offset, sptep[offset], page_count, pages);
		else
			vmx_log("CPU%d: done at level %d offset %d pte 0x%llx count %d\n",
				vcpu->cpu_id, level, offset, sptep[offset], page_count);
	}
	sspinlock_release(&sp_root->lock);

	release_shadow_ept_root(vcpu, sp_root);
}

void nested_flush_tlb(struct vbh_vcpu_vmx *vcpu, u64 ept_gpa)
{
	struct shadow_ept_root *sp_root = get_shadow_ept_root(vcpu, ept_gpa, false);

	if (!sp_root)
		return;

	vmx_log("CPU%d: flush_tlb_all, ept_gpa 0x%llx hpa 0x%llx\n",
		vcpu->cpu_id, ept_gpa, sp_root->hpa);

	invalid_shadow_mmu_pages(vcpu, sp_root);
	release_shadow_ept_root(vcpu, sp_root);
}
