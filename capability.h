#ifndef __VBH_CAPS_H
#define __VBH_CAPS_H

struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
};

struct vmx_capability {
	u32 ept;
	u32 vpid;
};

#endif
