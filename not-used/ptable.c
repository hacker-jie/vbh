// SPDX-License-Identifier: GPL-2.0

#include <linux/ioport.h>
#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */

#include "vmx_common.h"
#include "page_tracker.h"
#include "ptable.h"

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

int highest_level_possible_for_addr(unsigned long pfn, unsigned long nr_pages)
{
	int support, level = 1;

	support = EPT_LARGEPAGE_SUPPORTED;

	while (support && !(pfn & EPT_STRIDE_MASK)) {
		nr_pages >>= EPT_LEVEL_STRIDE;
		if (!nr_pages)
			break;
		pfn >>= EPT_LEVEL_STRIDE;
		level++;
		support--;
	}
	return level;
}

static unsigned long *pte_for_address(unsigned long *parent, unsigned long pfn,
				unsigned long *target_level)
{
	unsigned long *pte;
	unsigned long level, offset;
	unsigned long pte_pfn;

	level = EPT_MAX_PAGING_LEVEL;

	while (1) {
		offset = pfn_level_offset(pfn, level);
		pte = &parent[offset];

		if (level == *target_level)
			break;

		if (!*pte) {
			u64 pteval;
			void *page;

			page = (void *)get_zeroed_page(GFP_KERNEL);
			if (!vbh_record_pages(__pa(page), PAGE_SIZE))
				return NULL;
			pte_pfn = __pa(page) >> PAGE_SHIFT;
			//Todo: Add EPT memory type
			pteval = (pte_pfn << EPT_PAGE_SHIFT) | PTE_READ |
				PTE_WRITE | PTE_EXECUTE;
			*pte = pteval;
		}

		level--;
		parent = phys_to_virt(pte_table_addr(*pte));
	}

	return pte;
}

static int build_pte_guest_phys_addr(unsigned long *parent,
				unsigned long start_pfn, long nr_pages)
{
	unsigned long *pte;
	unsigned long level;
	unsigned long pages;

	while (nr_pages > 0) {
		u64 pteval = 0;

		level = 1;
		pte = pte_for_address(parent, start_pfn, &level);
		if (!pte)
			return -ENOMEM;

		pages = 1;
		if (level > 1) {
			pteval |= EPT_PTE_LARGE_PAGE;
			pages = level_to_pages(level);
		}

	    //Todo: Add EPT memory type
	    *pte = pteval | (start_pfn << EPT_PAGE_SHIFT) | PTE_MEM_TYPE_WB |
			PTE_READ | PTE_WRITE | PTE_EXECUTE;
		nr_pages -= pages;
		start_pfn += pages;
	}

	return 0;
}

int setup_ept_tables(struct vbh_data *vbh)
{
	// Parse iomem_resource for physical addres ranges
    // Parse only the siblings
	struct resource *root, *entry;
	unsigned long start, end;
	long nr_pages, size;
	int ret;

	root = &iomem_resource;
	entry = root->child;

	while (1) {
		// Round the size to 4k boundary
		pr_err("<EPT> Name: %s", entry->name);
	    start = (entry->start >> 12) << 12;
	    end = entry->end & 0xFFF;
		if (end)
			end = ((entry->end >> 12) << 12) + 0x1000;

		size = end - start;
		nr_pages = size >> 12;

		ret = build_pte_guest_phys_addr(vbh->vmx_eptp_pml4,
					(start >> PAGE_SHIFT), nr_pages);
		if (ret)
			return ret;

		if (!entry->sibling)
			break;
		entry = entry->sibling;
	}

	return 0;
}

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

static unsigned long *get_ept_entry(unsigned long *parent, u64 gpa)
{
	unsigned long pfn = gpa >> PAGE_SHIFT;
	u64 pteval;
	unsigned long level;
	unsigned long offset;

	level = 4;
	while (level > 0) {
		offset = pfn_level_offset(pfn, level);
		pteval = parent[offset];
		if ((pteval & EPT_PTE_LARGE_PAGE) == EPT_PTE_LARGE_PAGE)
			break;
		level--;
		if (level == 0)
			break;
		parent = phys_to_virt(pte_table_addr(pteval));
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

	if ((old_prot & PTE_READ) &&
	    (!(prot & PTE_READ) ||
	     (((old_prot ^ prot) & PTE_WRITE) == PTE_WRITE)))
		return true;

	return false;
}

static bool control_page_access(unsigned long *root, u64 gpa,
				bool read, bool write, bool execute)
{
	unsigned long *ptep = get_ept_entry(root, gpa);
	return set_ept_entry_prot(ptep, read, write, execute);
}

void set_page_protection(unsigned long *root, u64 pa)
{
	if (!root)
		BUG_ON(printk("NULL root. Buggy code?\n"));

	control_page_access(root, pa, false, false, false);
}

bool vbh_control_gpa_access_in_range(unsigned long *root, u64 gpa, size_t size,
				     bool read, bool write, bool execute)
{
	bool invept = false;
	u64 end_gpa = gpa + size;

	WARN_ON(size % PAGE_SIZE);

	if (!root)
		BUG_ON(printk("NULL root. Buggy code?\n"));

	while (gpa < end_gpa) {
		invept |= control_page_access(root, gpa, read, write, execute);
		gpa += PAGE_SIZE;
	}

	return invept;
}

/*
 * This routine is to update the EPT ptes in host EPT, when KVM is
 * mapping/unmapping guest pages.
 *
 * Note - "flush" is returned to indicate the caller shall perform
 * the EPT invalidation. It is not done in this routine, so that the
 * invalidation can be performed only once for batch requests.
 */
bool vbh_update_pfn_status(struct vbh_data *vbh, u64 pfn,
			   bool guest_mapping, bool normal_page)
{
	bool readable, writable, executible;
	u64  pa = (pfn << EPT_PAGE_SHIFT);
	u64  size = (1 << EPT_PAGE_SHIFT);
	bool flush;

	readable = writable = executible = (guest_mapping ? false : true);

	// For EPT page table pages, always grant read accesses.
	if (unlikely (!normal_page))
		readable = true;

	sspinlock_obtain(&vbh->host_mmu_lock);
	flush = vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, pa, size,
					       readable, writable, executible);
	sspinlock_release(&vbh->host_mmu_lock);

	return flush;
}
