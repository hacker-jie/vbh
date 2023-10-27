#ifndef _VBH_H_
#define _VBH_H_

#include "linux-kernel.h"
#include "capability.h"
#include "vmx_ops.h"
#include "vmcs.h"
#include "regs.h"
#include "types.h"
#include "lock.h"
#include "cpu.h"
#include "regs.h"

enum regs {
	VCPU_REGS_RAX = __VCPU_REGS_RAX,
	VCPU_REGS_RCX = __VCPU_REGS_RCX,
	VCPU_REGS_RDX = __VCPU_REGS_RDX,
	VCPU_REGS_RBX = __VCPU_REGS_RBX,
	VCPU_REGS_RSP = __VCPU_REGS_RSP,
	VCPU_REGS_RBP = __VCPU_REGS_RBP,
	VCPU_REGS_RSI = __VCPU_REGS_RSI,
	VCPU_REGS_RDI = __VCPU_REGS_RDI,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8  = __VCPU_REGS_R8,
	VCPU_REGS_R9  = __VCPU_REGS_R9,
	VCPU_REGS_R10 = __VCPU_REGS_R10,
	VCPU_REGS_R11 = __VCPU_REGS_R11,
	VCPU_REGS_R12 = __VCPU_REGS_R12,
	VCPU_REGS_R13 = __VCPU_REGS_R13,
	VCPU_REGS_R14 = __VCPU_REGS_R14,
	VCPU_REGS_R15 = __VCPU_REGS_R15,
#endif
	VCPU_REGS_RIP = __VCPU_REGS_RIP,
	VCPU_REGS_CR2 = __VCPU_REGS_CR2,
	NR_VCPU_REGS
};

typedef enum _INTERRUPTION_TYPE
{
    INTERRUPTION_TYPE_EXTERNAL_INTERRUPT                = 0,
    INTERRUPTION_TYPE_NON_MASKABLE_INTERRUPT            = 2,
    INTERRUPTION_TYPE_HARDWARE_EXCEPTION,
    INTERRUPTION_TYPE_SOFTWARE_INTERRUPT,
    INTERRUPTION_TYPE_PRIVILEGED_SOFTWARE_EXCEPTION,
    INTERRUPTION_TYPE_SOFTWARE_EXCEPTION,
    INTERRUPTION_TYPE_OTHER_EVENT,
}INTERRUPTION_TYPE;

typedef union _vm_entry_int_info
{
    struct
    {
        u32           vector                :       8;
        u32           interruption_type     :       3;
        u32           deliver_error_code    :       1;
        u32           reserved              :       19;
        u32           valid                 :       1;
    }fields;

    u32               value;
} vm_entry_int_info;

/*  Bitfields problem: compiler might lay the bit field out differently
    depending on the endianness of the target platform.
    We need pack/unpack functions to maintain compatibility. */
static __always_inline u32 vm_entry_info_pack(vm_entry_int_info vm_entry_info)
{
	return ((vm_entry_info.fields.vector << 0) | (vm_entry_info.fields.interruption_type << 8) | (vm_entry_info.fields.deliver_error_code << 11) | (vm_entry_info.fields.valid << 31));
}

struct host_state {
	unsigned long rsp, rip;
	unsigned long cr0, cr3, cr4;
	u16 cs_selector, ss_selector, ds_selector, es_selector;
	unsigned long fs_base, gs_base, tr_base;
	u16 fs_selector, gs_selector, tr_selector;
	unsigned long gdtr_base, idtr_base;
	u32 ia32_sysenter_cs;
	unsigned long ia32_sysenter_esp, ia32_sysenter_eip;
	u64 ia32_efer, ia32_pat;
};

struct shadow_page {
	struct list_head list;
	u64 hpa;
	u8 level;
};

struct shadow_ept_root {
	struct list_head list;
	struct list_head sp_list;
	struct list_head invalid_list;
	sspinlock_t lock;
	u32 count;
	u64 hpa;
	u64 eptp;
	u64 gpa;
};

struct nested_vmx {
	struct vmcs12 vmcs12;
	u32 magic_code;
	bool vmxon;
	u64 vmxon_gpa;
	u64 current_vmcs12_ptr;
	struct vmcs *vmcs02;
	struct host_state host_state;
	struct shadow_ept_root *current_shadow_root;
	u64 eptp;
};

struct vbh_data;
struct vbh_vcpu_vmx {
	struct nested_vmx nested;
	struct vmcs     *pcpu_vmcs;
	struct vmcs     *vmxarea;
	u64             vcpu_stack;
	unsigned long   *regs;
	u64 cr2;
	void *cr3;
	bool            instruction_skipped;
	bool            skip_instruction_not_used;
	u32 instr_info;
	unsigned long exit_qualification;
	int cpu_id;
	struct vbh_data *vbh;
};

struct vbh_vcpu_data {
	struct vbh_vcpu_vmx vcpu_vmx;
	struct vmcs_config vmcs_config;
	struct vbh_desc_ptr host_gdt;
	unsigned long reg_scratch[NR_VCPU_REGS];
	struct list_head list;
	int pcpu;
} __aligned(PAGE_SIZE);

struct vbh_iommu_context_tbl {
	struct list_head list;

	u64 pa;
	u8 bus;
};

struct vbh_iommu {
	struct list_head list;
	struct list_head context_list;

	int  id;
	u64  virt_io_base;
	u64  reg_size;
	u64  root_tbl_pa;
};

struct vbh_device_id {
	struct list_head list;

	u8 bus;
	u8 devfn;
};

struct vbh_iommu_pgd {
	struct list_head list;
	struct list_head device_list;

	u64 pa;
	u8 level;
	bool identity;
};

struct root_kvm_ept {
	struct list_head list;
	u64 ept_gpa;
};

struct root_kvm {
	struct list_head list;
	u64 pa;
	u64 ept_gpa;
	sspinlock_t lock;
	struct list_head ept_list;
};

struct ram_metadata {
	union {
		u16 metadata;
		struct {
			u16 ept_mapped		:1;
			u16 iommu_mapped	:1;
			u16 id			:14;
		} fields;
	};
};

struct ram_tracker {
	struct list_head list;
	u64 start_pfn;
	u64 count;
	struct ram_metadata metadata[];
};

struct vbh_data {
	u64 magic_code;
#define VBH_DATA_MAGIC_CODE	0xaabbccdd
	struct vbh_vcpu_data *vcpus[NR_CPUS];
	struct tee_root_vm  *tee_vm;
	struct list_head vcpu_head;
	struct list_head iommu_list;
	struct list_head iommu_pgd_list;
	void *host_cr3;
	unsigned long *vmx_io_bitmap_a_switch;
	unsigned long *vmx_io_bitmap_b_switch;
	unsigned long *vmx_msr_bitmap_switch;
	unsigned long *vmx_eptp_pml4;
	u64 eptp;
	int ept_walks;
	struct vmx_capability vmx_cap;
	struct mem_pools *mps;
	struct list_head kvm_head;
	sspinlock_t kvm_lock;
	sspinlock_t host_mmu_lock;
	struct list_head ram_trackers;
	bool xsaves_supported;
	bool mpx_supported;
	unsigned long *vmcs_shadow_bitmap;
	bool enable_shadow_vmcs;
	bool enable_shadow_ept;
	sspinlock_t nested_mmu_lock;
	struct list_head nested_root_ept_list;
} __aligned(PAGE_SIZE);

/* CR0 constants */
#define PE BIT(0)
#define MP BIT(1)
#define EM BIT(2)
#define TS BIT(3)
#define ET BIT(4)
#define NE BIT(5)
#define WP BIT(16)
#define AM BIT(18)
#define NW BIT(29)
#define CD BIT(30)
#define PG BIT(31)

/* CR4 constants */
#define VME BIT(0)
#define PVI BIT(1)
#define TSD BIT(2)
#define DE  BIT(3)
#define PSE BIT(4)
#define PAE BIT(5)
#define MCE BIT(6)
#define PGE BIT(7)
#define PCE BIT(8)
#define OSFXSR BIT(9)
#define OSXMMEXCPT BIT(10)
#define VMXE BIT(13)
#define SMXE BIT(14)
#define PCIDE BIT(17)
#define OSXSAVE BIT(18)
#define SMEP BIT(20)
#define SMAP BIT(21)

//TODO: This is for debugging purpose which can make module unloaded.
//It should be removed in the final release.
#define KVM_HC_ROOT_VMXOFF	0xdeadbeef

void build_vmcs_config(struct vmcs_config *vmcs_config_p, bool is_primary_os);

#endif
