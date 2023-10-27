#ifndef _VBH_COMMON_H_
#define _VBH_COMMON_H_

#include <linux/types.h>
#include <linux/bits.h>
#include <asm/vmx.h>

#include "lock.h"
#include "capability.h"
#include "vmx_ops.h"
#include "vmcs.h"
#include "regs.h"
#include "types.h"

/* Get exception mask for X. See exception_injection_mask field in struct vbh_vcpu_vmx */
#define VCPU_INJECT_EXCEPTION_MASK(X)       (BIT(X))	
#define NUMBER_OF_RESERVED_EXCEPTIONS       32

/*
    Custom additional info structure per exception. 
    Fields in each structure can be garbage or good to use.
    In order to see that, at the end of every structure we
    can find an BITMAP. If bit k is set, field k is not garbage.
    
    TODO: Each new field included in the structure 
    must also be included in the structure-specific enumeration.
    The fields in the enumeration and the structure MUST HAVE the same order!  
*/

enum page_fault_field_encoding
{
    /* Write fields from page_fault_additional_info 
    in the same order */
    virtual_address,
    page_fault_field_encoding_end
};

typedef struct _page_fault_additional_info
{
    u64         virtual_address;                                            /* Value to set CR2 */

    /* See  page_fault_field_encoding */
    DECLARE_BITMAP(field_is_ok, page_fault_field_encoding_end);             /* Bitmap to see if a field in struct is garbage or good to use */
}page_fault_additional_info;

typedef struct _exception_additional_info
{
    /* Common fields here */
    u32     exception_error_code;       /* Exception error code - valid only for some exceptions. */

    /* Specific fields per exception here.
    If the byte has_specific_info is set in global vector exception_info, 
    then a structure specific to that exception must be found in the union below. */
    union
    {
        page_fault_additional_info  page_fault_specific;
    } specific_additional_info;
}exception_additional_info;

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

struct vbh_vcpu_vmx {
    struct vmcs     *pcpu_vmcs;
    struct vmcs     *vmxarea;
    u64             vcpu_stack;
    unsigned long   *regs;
    u64 cr2;
    bool            instruction_skipped;
    bool            skip_instruction_not_used;
    struct
    {
        u32                         exception_injection_mask;                       /* Each bit selects an exception. If the bit is set, the according exception will be injected in guest.*/
        exception_additional_info   additional_info[NUMBER_OF_RESERVED_EXCEPTIONS]; /* Exception additional info. Common & specific per exception */
    }vcpu_exception;
};

struct vbh_vcpu_data {
	struct vmcs_config vmcs_config;
	struct vbh_vcpu_vmx vcpu_vmx;
	struct desc_ptr host_gdt;
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
	struct list_head vcpu_head;
	struct list_head iommu_list;
	struct list_head iommu_pgd_list;
	pgd_t *host_cr3;
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
} __aligned(PAGE_SIZE);

DECLARE_PER_CPU(int , force_hw_vmxoff);

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

#define vbh_va(x) __va(x)

extern void vmx_switch_and_exit_handle_vmexit(void);

extern int setup_ept_tables(struct vbh_data *vbh);
extern void set_page_protection(unsigned long *root, u64 pa);
bool vbh_control_gpa_access_in_range(unsigned long *root, u64 gpa, size_t size,
				     bool read, bool write, bool execute);
bool vbh_update_pfn_status(struct vbh_data *vbh, u64 pfn,
			   bool guest_mapping, bool normal_page);

extern int protect_intel_iommu(struct vbh_data *vbh);
extern void handle_iommu_mmio_write(struct vbh_data *vbh, u64 reg, u64 val);
void handle_iommu_context_table_write(struct vbh_data *vbh, u64 pa, u64 val);
void handle_iommu_page_table_write(struct vbh_data *vbh, u64 pa, u64 val, u8 level);
int borrow_iommu_page(struct vbh_data *vbh, u64 pfn);
int return_iommu_page(struct vbh_data *vbh, u64 pfn);

static inline bool vbh_has_vmx_invept_context(struct vbh_data *vbh)
{
	return vbh->vmx_cap.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline void vbh_invept(struct vbh_data *vbh)
{
	if (vbh_has_vmx_invept_context(vbh))
		exec_invept(VMX_EPT_EXTENT_CONTEXT, vbh->eptp, 0);
	else
		exec_invept(VMX_EPT_EXTENT_GLOBAL, vbh->eptp, 0);
}

#endif
