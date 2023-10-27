#ifndef __VBH_PTABLE_H
#define __VBH_PTABLE_H

#include <asm/page.h>

#include "vbh.h"

#define EPT_MAX_LEVEL 4

#define EPT_LEVEL_STRIDE 9
#define EPT_STRIDE_MASK ((1 << EPT_LEVEL_STRIDE) - 1)
#define EPT_PAGE_MASK ((1 << 12) - 1)
#define EPT_LARGEPAGE_SUPPORTED 2
#define EPT_MAX_PAGING_LEVEL 4
#define EPT_PAGE_SHIFT 12
#define PAGE_SHIFT 12
#define PTE_READ 1
#define PTE_WRITE 2
#define PTE_EXECUTE 4
#define PTE_MEM_TYPE_WB 0x30
#define EPT_PTE_LARGE_PAGE (1 << 7)

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define INVALID_HPA	(1ULL << 52)
#define INVALID_GPA	(1ULL << 52)

enum {
	PT_PAGE_TABLE_LEVEL   = 1,
	PT_DIRECTORY_LEVEL    = 2,
	PT_PDPE_LEVEL         = 3,
	/* set max level to the biggest one */
	PT_MAX_HUGEPAGE_LEVEL = PT_PDPE_LEVEL,
};

int is_large_pte(u64 pte);
int is_last_spte(u64 pte, int level);
u64 pte_to_pa(u64 pte);
unsigned long level_to_pages(unsigned long level);
int pfn_level_offset(unsigned long pfn, unsigned long level);
u64 pte_table_addr(u64 pteval);
u64 *sptep_for_gfn(u64 *parent, u64 pfn, int level, int target_level);
void dump_entries(unsigned long *parent, u64 gpa);
void set_page_protection(unsigned long *root, u64 pa);
int vbh_control_gpa_access_in_range(struct vbh_data *vbh, bool pre_deprivilege,
				    u64 gpa, size_t size, bool read, bool write,
				    bool execute, bool *flush);
int vbh_update_pfn_status(struct vbh_data *vbh, u64 pfn,
			  bool guest_mapping, bool normal_page, bool *flush);
void *vbh_va(u64 hpa);
u64 vbh_pa(void *hpa);
void gva2gpa(struct vbh_vcpu_vmx *vcpu, u64 gva, u64 *gpa, u64 *err_code);
u64 gpa2hpa(u64 gpa);
u64 *hpa2hva(u64 hpa);
u64 hva2hpa(void *hpa);
#endif
