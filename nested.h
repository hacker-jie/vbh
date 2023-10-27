#ifndef __VBH_NESTED_H
#define __VBH_NESTED_H

/* Encoding of VMCS field values */
#define VMX_VMCS_FIELD_ACCESS_HIGH(v)   (((v) >> 0U)  & 0x1U)
#define VMX_VMCS_FIELD_INDEX(v)         (((v) >> 1U)  & 0x1ffU)
#define VMX_VMCS_FIELD_TYPE(v)          (((v) >> 10U) & 0x3U)
#define VMX_VMCS_FIELD_TYPE_CTL         0U
#define VMX_VMCS_FIELD_TYPE_VMEXIT      1U
#define VMX_VMCS_FIELD_TYPE_GUEST       2U
#define VMX_VMCS_FIELD_TYPE_HOST        3U
#define VMX_VMCS_FIELD_WIDTH(v)         (((v) >> 13U) & 0x3U)
#define VMX_VMCS_FIELD_WIDTH_16         0U
#define VMX_VMCS_FIELD_WIDTH_64         1U
#define VMX_VMCS_FIELD_WIDTH_32         2U
#define VMX_VMCS_FIELD_WIDTH_NATURAL    3U

#define VBH_NESTED_FLUSH_TLB_RANGE     0xABCD0001
#define VBH_NESTED_FLUSH_TLB_ALL       0xABCD0002

int invvpid_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int invept_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmclear_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmptrld_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmread_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmwrite_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmxon_handler(struct vbh_vcpu_vmx *vcpu);
int vmlaunch_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
int vmresume_vmexit_handler(struct vbh_vcpu_vmx *vcpu);
void nested_flush_tlb_with_range(struct vbh_vcpu_vmx *vcpu,
				 u64 ept_gpa, u64 start_gfn,
				 u64 pages);
void nested_flush_tlb(struct vbh_vcpu_vmx *vcpu, u64 ept_gpa);

#endif
