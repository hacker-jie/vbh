#ifndef __VBH_VBH_OPS_H
#define __VBH_VBH_OPS_H

void vbh_vmcs_clear(struct vbh_data *vbh, int cpu);
unsigned long segment_base(struct vbh_desc_ptr *gdt, u16 selector);
unsigned int segment_limit(struct vbh_desc_ptr *gdt, u16 selector);
void load_host_state_area(u64 cr3_pa);
void save_host_state_area(struct host_state *state);
void restore_host_state_area(struct host_state *state);
void load_execution_control(struct vbh_data *vbh,
			    struct vmcs_config *vmcs_config_ptr,
			    unsigned long ept, bool is_primary);
u64 construct_eptp(unsigned long root_hpa, struct vmx_capability *vmx_cap);
void load_vmentry_control(struct vmcs_config *vmcs_config_ptr);
void load_vmexit_control(struct vmcs_config *vmcs_config_ptr);
void vbh_invept(struct vbh_data *vbh, u64 eptp);

void build_vmcs_config(struct vmcs_config *vmcs_config_p, bool is_primary_os);
bool is_xsaves_supported(void);
#endif
