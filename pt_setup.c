// SPDX-License-Identifier: GPL-2.0

#include <linux/ioport.h>
#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */

#include "vbh.h"
#include "page_tracker_setup.h"
#include "pt.h"
#include "mem_ops.h"

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

unsigned long *pte_for_address(struct vbh_data *vbh, bool pre_deprivilege,
			       unsigned long *parent, unsigned long pfn,
			       unsigned long start_level,
			       unsigned long target_level)
{
	unsigned long *pte;
	unsigned long level, offset;
	unsigned long pte_pfn;

	level = start_level;

	while (1) {
		offset = pfn_level_offset(pfn, level);
		pte = &parent[offset];

		if (level == target_level)
			break;

		if (!*pte) {
			u64 pteval;
			void *page;

			if (pre_deprivilege) {
				page = (void *)get_zeroed_page(GFP_KERNEL);
				if (!vbh_record_pages(vbh_pa(page), PAGE_SIZE))
					return NULL;
			} else {
				page = vbh_malloc(vbh, PAGE_SIZE);
				if (!page)
					return NULL;
			}
			pte_pfn = vbh_pa(page) >> EPT_PAGE_SHIFT;
			//Todo: Add EPT memory type
			pteval = (pte_pfn << EPT_PAGE_SHIFT) | PTE_READ |
				PTE_WRITE | PTE_EXECUTE;
			*pte = pteval;
			//trace_printk("construct ept for pfn 0x%llx: level %ld(%ld) pte 0x%llx value 0x%llx\n", (u64)pfn, level, target_level, (u64)pte, (u64)*pte);
		}

		level--;
		parent = phys_to_virt(pte_table_addr(*pte));
	}

	return pte;
}

static int build_pte_guest_phys_addr(struct vbh_data *vbh,
				     unsigned long start_pfn,
				     long nr_pages,
				     bool system_ram)
{
	unsigned long *parent = vbh->vmx_eptp_pml4;
	unsigned long *pte;
	unsigned long level, target_level = 2, start_level = EPT_MAX_PAGING_LEVEL;
	unsigned long pages;
	unsigned long count = level_to_pages(target_level);

	while (nr_pages > 0) {
		u64 pteval = 0;

		if (system_ram && nr_pages >= count &&
				(start_pfn % count) == 0) {
			level = target_level;
			pteval |= EPT_PTE_LARGE_PAGE;
			pages = count;
		} else {
			level = 1;
			pages = 1;
		}

		pte = pte_for_address(vbh, true, parent, start_pfn, start_level, level);
		if (!pte)
			return -ENOMEM;

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
	bool system_ram;
	int ret;

	root = &iomem_resource;
	entry = root->child;

	while (1) {
		// Round the size to 4k boundary
		start = (entry->start >> 12) << 12;
		end = entry->end & 0xFFF;
		if (end)
			end = ((entry->end >> 12) << 12) + 0x1000;

		size = end - start;
		nr_pages = size >> 12;

		if ((entry->flags & IORESOURCE_SYSTEM_RAM) == IORESOURCE_SYSTEM_RAM)
			system_ram = true;
		else
			system_ram = false;

		pr_err("<EPT> Name: %s start 0x%lx end 0x%lx system_ram %d",
			entry->name, start, end, system_ram);

		ret = build_pte_guest_phys_addr(vbh, (start >> EPT_PAGE_SHIFT),
						nr_pages, system_ram);
		if (ret)
			return ret;

		if (!entry->sibling)
			break;
		entry = entry->sibling;
	}

	return 0;
}
