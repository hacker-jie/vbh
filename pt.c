#include <linux/types.h>

#include "pt.h"
#include "pt_setup.h"
#include "lock.h"

void *vbh_va(u64 hpa)
{
	return __va(hpa);
}

u64 vbh_pa(void *hva)
{
	//This is to translate VBH's va to pa. As VBH's va is mapped during
	//setup so it can be translated by the cloned page table.
	return (u64)__pa(hva);
}

void gva2gpa(struct vbh_vcpu_vmx *vcpu, u64 gva, u64 *gpa, u64 *err_code)
{
	//TODO: work L1 CR3 to get the GPA
	//As L1 is using the same page table with hypervisor
	//so gpa can be get by __pa(). This is not the right
	//way but a dirty and quick way.
	*gpa = __pa(gva);
}

u64 gpa2hpa(u64 gpa)
{
	//L1 is 1:1 mapping so gpa == hpa
	return gpa;
}

u64 *hpa2hva(u64 hpa)
{
	//TODO: if hypervisor use 1:1 mapping page table, hpa == hva.
	//Currently as hypervisor still use the same page table as
	//L1 linux kernel, so __va() can be used. This is not
	//the right way but a dirty and quick way.
	return (u64 *)__va(hpa);
}

u64 hva2hpa(void *hva)
{
	//TODO: When hypervisor use the same page table as L1 linux
	//kernel, it can use __pa to translate its own va to pa. But
	//if to translate the va for a guest memory, this is not the
	//right way but a dirty and quick way. After there is identical
	//mapping, a guest memory's hva should be the same to hpa. So
	//probably needs to implementations for hva2hpa, one is for hypervisor
	//its own memory which is allocated during setup, the other is
	//for guest memory.
	return (u64)__pa(hva);
}
int is_large_pte(u64 pte)
{
	return pte & EPT_PTE_LARGE_PAGE;
}

int is_last_spte(u64 pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return 1;
	if (is_large_pte(pte))
		return 1;
	return 0;
}

u64 pte_to_pa(u64 pte)
{
	return pte & PT64_BASE_ADDR_MASK;
}

unsigned long level_to_pages(unsigned long level)
{
	return (1 << (level-1)*EPT_LEVEL_STRIDE);
}

int pfn_level_offset(unsigned long pfn, unsigned long level)
{
	return (pfn >> (level - 1)*EPT_LEVEL_STRIDE) & EPT_STRIDE_MASK;
}

u64 pte_table_addr(u64 pteval)
{
	return pteval & ~EPT_PAGE_MASK;
}

u64 *sptep_for_gfn(u64 *parent, u64 gfn, int level, int target_level)
{
	u64 *sptep;
	int offset;

	if (level < target_level || target_level < 1)
		return NULL;

	while (1) {
		offset = pfn_level_offset(gfn, level);
		sptep = &parent[offset];
		if (level == target_level)
			break;
		if (!*sptep)
			return NULL;
		level--;
		parent = __va(pte_to_pa(*sptep));
	}

	return sptep;
}

#if 0
void dump_entries(unsigned long *parent, u64 gpa)
{
	unsigned long pfn = gpa >> PAGE_SHIFT;
	u64 pteval;
	unsigned long level;
	unsigned long offset;

	level = 4;
	while (level > 0) {
		offset = pfn_level_offset(pfn, level);
		pteval = parent[offset];
		pr_err("level %lu pteval %llx\n", level, pteval);
		if ((pteval & EPT_PTE_LARGE_PAGE) == EPT_PTE_LARGE_PAGE)
			break;
		level--;
		parent = phys_to_virt(pte_table_addr(pteval));
	}
}
#endif

static unsigned long *get_ept_entry(unsigned long *parent, u64 gpa, int *target_level)
{
	unsigned long pfn = gpa >> PAGE_SHIFT;
	unsigned long offset;
	u64 pteval;
	int level = 4;

	if (target_level)
		*target_level = 1;
	while (level > 0) {
		offset = pfn_level_offset(pfn, level);
		pteval = parent[offset];
		if ((pteval & EPT_PTE_LARGE_PAGE) == EPT_PTE_LARGE_PAGE) {
			if (target_level)
				*target_level = level;
			break;
		}
		level--;
		if (level == 0)
			break;
		parent = vbh_va(pte_table_addr(pteval));
	}

	return parent + offset;
}

static bool set_ept_entry_prot(unsigned long *entry, bool read, bool write, bool execute)
{
	unsigned long prot, new_entry, old_prot;

	prot = new_entry = 0;

	if (read)
		prot |= PTE_READ;
	if (write)
		prot |= PTE_WRITE;
	if (execute)
		prot |= PTE_EXECUTE;

	old_prot = *entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE);
	new_entry = *entry & (~(PTE_READ | PTE_WRITE | PTE_EXECUTE));
	new_entry |= prot;
	*entry = new_entry;

	//if (old_prot != prot)
		//trace_printk("set ptep 0x%llx for gfn 0x%llx with value 0x%llx\n",
		//	(u64)entry, (((u64)*entry & PT64_BASE_ADDR_MASK) >> 12), (u64)*entry);

	if ((old_prot & PTE_READ) &&
	    (!(prot & PTE_READ) ||
	     (((old_prot ^ prot) & PTE_WRITE) == PTE_WRITE)))
		return true;

	return false;
}

static int vbh_split_large_ept(struct vbh_data *vbh, bool pre_deprivilege,
				unsigned long *parent, u64 gfn, int start_level)
{
	u64 nr_pages =  1 << ((start_level - 1) * 9);
	u64 start_gfn = (gfn / nr_pages) * nr_pages;
	unsigned long *pte;

	if (!parent || start_level == 1)
		return -EINVAL;

	//trace_printk("split large EPT %s: EPT level %d parent 0x%llx start_gfn 0x%llx pages %lld\n",
	//		pre_deprivilege ? "before_deprivilege" : "after_deprivilege",
	//		start_level, (u64)parent, start_gfn, nr_pages);

	while (nr_pages) {
		pte = pte_for_address(vbh, pre_deprivilege,
				parent, start_gfn, start_level, 1);
		if (!pte)
			return -ENOMEM;
		//Todo: Add EPT memory type
		*pte = (start_gfn << EPT_PAGE_SHIFT) | PTE_MEM_TYPE_WB |
			PTE_READ | PTE_WRITE | PTE_EXECUTE;
		//trace_printk("set ept for gfn 0x%llx pte 0x%llx value 0x%llx\n", start_gfn, (u64)pte, (u64)*pte);
		nr_pages -= 1;
		start_gfn += 1;
	}

	//trace_printk("splite large EPT done\n");

	return 0;
}

static int control_page_access(struct vbh_data *vbh, bool pre_deprivilege,
			       u64 gpa, bool read, bool write, bool execute,
			       bool *flush)
{
	int target_level;
	int ret;
	unsigned long *ptep = get_ept_entry(vbh->vmx_eptp_pml4, gpa, &target_level);

	if (target_level != 1) {
		//split large ept to 4K
		unsigned long *parent = (unsigned long *)((unsigned long)ptep & PAGE_MASK);
		//trace_printk("Found large EPT: EPT level %d petp 0x%llx value 0x%llx offset 0 ptep 0x%llx gpa 0x%llx\n",
		//		target_level, (u64)ptep, (u64)*ptep, (u64)parent, gpa);
		*ptep = 0;
		ret = vbh_split_large_ept(vbh, pre_deprivilege,
					parent, gpa >> EPT_PAGE_SHIFT,
					target_level);
		if (ret)
			return ret;

		ptep = get_ept_entry(vbh->vmx_eptp_pml4, gpa, &target_level);
		if (target_level != 1) {
			pr_err("%s: failed to split for gpa 0x%llx target_level %d ptep 0x%llx value 0x%llx\n",
				__func__, gpa, target_level, (u64)ptep, (u64)*ptep);
			return -EINVAL;
		}
	}

	if (flush)
		*flush |= set_ept_entry_prot(ptep, read, write, execute);
	else
		set_ept_entry_prot(ptep, read, write, execute);

	return 0;
}

int vbh_control_gpa_access_in_range(struct vbh_data *vbh,
				    bool pre_deprivilege, u64 gpa,
				    size_t size, bool read,
				    bool write, bool execute, bool *flush)
{
	u64 end_gpa = gpa + size;
	int ret;

	if (size % PAGE_SIZE)
		BUG_ON(printk("Invalid size %ld. Buggy code?\n", size));

	if (!vbh->vmx_eptp_pml4) {
		pr_err("No EPTP found for deprivilege os\n");
		return -EINVAL;
	}

	while (gpa < end_gpa) {
		ret = control_page_access(vbh, pre_deprivilege,
					  gpa, read, write, execute,
					  flush);
		if (ret)
			return ret;

		gpa += PAGE_SIZE;
	}

	return 0;
}
/*
 * This routine is to update the EPT ptes in host EPT, when KVM is
 * mapping/unmapping guest pages.
 *
 * Note - "flush" is returned to indicate the caller shall perform
 * the EPT invalidation. It is not done in this routine, so that the
 * invalidation can be performed only once for batch requests.
 */
int vbh_update_pfn_status(struct vbh_data *vbh, u64 pfn,
			  bool guest_mapping, bool normal_page, bool *flush)
{
	bool readable, writable, executible;
	u64  pa = (pfn << EPT_PAGE_SHIFT);
	u64  size = (1 << EPT_PAGE_SHIFT);
	int ret;

	readable = writable = executible = (guest_mapping ? false : true);

	// For EPT page table pages, always grant read accesses.
	if (unlikely (!normal_page))
		readable = true;

	sspinlock_obtain(&vbh->host_mmu_lock);
	ret = vbh_control_gpa_access_in_range(vbh, false, pa, size,
					      readable, writable, executible,
					      flush);
	sspinlock_release(&vbh->host_mmu_lock);

	return ret;
}
