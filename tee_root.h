#ifndef __TEE_ROOT_H
#define __TEE_ROOT_H

#include "vbh.h"

#define OPTEE_VMCALL_SMC    0x6F707400

struct tee_vcpu_vmx {
	struct vmcs *pcpu_vmcs;

	unsigned long *regs;
	bool instruction_skipped;
	bool skip_instruction_not_used;
	u32  instr_info;
	unsigned long exit_qualification;
};

struct tee_vcpu_data {
	struct tee_vcpu_vmx  vcpu_vmx;
	struct vmcs_config   vmcs_config;
	unsigned long reg_scratch[NR_VCPU_REGS];
};

struct tee_root_vm {
	unsigned long ept_pa;
	unsigned long mem_size;
	bool launched;

	struct tee_vcpu_data  *vcpu_data;
};

int handle_tee_create(struct vbh_data *vbh, unsigned long ept_pa,
		unsigned long mem_size, unsigned long img_va,
		unsigned long img_size);

int handle_te_run(struct vbh_data *vbh, struct vmcs *host_vmcs);
#endif
