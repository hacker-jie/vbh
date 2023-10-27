#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/dmar.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/intel-iommu.h>
#include <asm/io.h>

#include "vmx_common.h"
#include "vbh_trace.h"

static struct dma_pte *find_page_pte(struct vbh_iommu_pgd *pgd, u64 pfn, bool present)
{
	u64 index;
	struct dma_pte *pte, *parent;
	u8 level;

	if (!pgd->identity)
		return NULL;

	level = pgd->level;
	parent = phys_to_virt(pgd->pa);
	while (level > 0) {
		u64 addr;

		index = (pfn >> ((level - 1) * 9)) & 0x1ff;
		pte = &parent[index];
		if (present && !dma_pte_present(pte))
			return NULL;
		if (dma_pte_superpage(pte) || level == 1)
			return pte;

		addr = dma_pte_addr(pte);
		if (addr == 0)
			return NULL;
		parent = phys_to_virt(addr);
		level--;
	}

	return NULL;
}

// remove pfn from pgd page table
int borrow_iommu_page(struct vbh_data *vbh, u64 pfn)
{
	struct vbh_iommu_pgd *pgd;
	struct dma_pte *pte;

	// the first pgd is host iommu page table pgd
	pgd = list_first_entry(&vbh->iommu_pgd_list, struct vbh_iommu_pgd, list);
	if (pgd == NULL) {
		pr_err("pgd list is empty\n");
		return -EINVAL;
	}
	pte = find_page_pte(pgd, pfn, true);
	if (pte != NULL) {
		// remove this page from pgd
		pte->val = 0;
	}

	return 0;
}

int return_iommu_page(struct vbh_data *vbh, u64 pfn)
{
	struct vbh_iommu_pgd *pgd;
	struct dma_pte *pte;
	u64 addr = pfn << VTD_PAGE_SHIFT;

	// the first pgd is host iommu page table pgd
	pgd = list_first_entry(&vbh->iommu_pgd_list, struct vbh_iommu_pgd, list);
	if (pgd == NULL) {
		pr_err("pgd list is empty\n");
		return -EINVAL;
	}
	pte = find_page_pte(pgd, pfn, false);
	if ((pte != NULL) && (pte->val == 0)) {
		// return this page to host
		pte->val = addr | DMA_PTE_READ | DMA_PTE_WRITE;
	}

	return 0;
}

static int check_iommu_page(struct vbh_data *vbh, u64 pfn)
{
	/*
	bool iommu_mapped, ept_mapped;
	u16 vid;

	if (!vbh_get_ram_metadata(vbh, pfn << VTD_PAGE_SHIFT, &ept_mapped, &iommu_mapped, vid)) {
		pr_err("pfn: 0x%llx isn't in vbh's page tracker\n", pfn);
		return -EINVAL;
	}
	if (iommu_mapped) {
		pr_err("pfn: 0x%llx has been mapped in iommu page table\n", pfn);
		return -EINVAL;
	}

	if (ept_mapped) {
		pr_err("pfn: 0x%llx has been mapped in other vm's ept.\n", pfn);
		return -EINVAL;
	}

	if (vid == IOMMU_PTID) {
		pr_err("pfn: 0x%llx is other domain's page table.\n", pfn);
		return -EINVAL;
	} */

	return 0;
}

static int set_page_iommu_mapped(struct vbh_data *vbh, u64 pfn)
{
	int status;

	status = check_iommu_page(vbh, pfn);
	if (status < 0)
		return status;

	/*
	// set pfn as iommu mapped in vbh page tracker
	if (!vbh_set_ram_metadata_in_range(vbh, pfn << VTD_PAGE_SHIFT, VTD_PAGE_SIZE, false, true, RESERVED_VMID)) {
		pr_err("set iommu map for pfn: 0x%llx failed\n");
		return -EINVAL;
	}
	*/

	return 0;
}

static int clear_page_iommu_mapped(struct vbh_data *vbh, u64 pfn)
{
	/*
	bool iommu_mapped;

	if (!vbh_get_ram_metadata(vbh, addr, NULL, &iommu_mapped, NULL)) {
		pr_err("pfn: 0x%llx isn't in vbh's page tracker\n", pfn);
		return -EINVAL;
	}
	if (!iommu_mapped) {
		pr_err("pfn: 0x%llx hasn't been mapped in iommu page table\n", pfn);
		return -EINVAL;
	}

	// set pfn as iommu not mapped in vbh page tracker
	if (!vbh_set_ram_metadata_in_range(vbh, addr, VTD_PAGE_SIZE, false, false, RESERVED_VMID)) {
		pr_err("set iommu map for pfn: 0x%llx failed\n");
		return -EINVAL;
	} */

	return 0;
}

static int set_page_iommu_table(struct vbh_data *vbh, u64 pfn)
{
	int status;

	status = check_iommu_page(vbh, pfn);
	if (status < 0)
		return status;
	/*
	// set pfn as iommu mapped in vbh page tracker
	if (!vbh_set_ram_metadata_in_range(vbh, pfn << VTD_PAGE_SHIFT, VTD_PAGE_SIZE, false, false, IOMMU_PTID)) {
		pr_err("set iommu map for pfn: 0x%llx failed\n");
		return -EINVAL;
	}
	*/

	return 0;
}

static int clear_page_entry(struct vbh_data *vbh, struct dma_pte *old, u8 level)
{
	u64 addr = dma_pte_addr(old);
	int status;

	if (addr == 0)
		return 0;

	if ((level == 1) && dma_pte_present(old)) {
		status = clear_page_iommu_mapped(vbh, addr >> VTD_PAGE_SHIFT);
		if (status < 0)
			return status;

		status = return_iommu_page(vbh, addr >> VTD_PAGE_SHIFT);
	} else if (level > 1 && !dma_pte_superpage(old)) {
		int idx;
		struct dma_pte *tbl;

		tbl = (struct dma_pte *)phys_to_virt(addr);
		for (idx = 0; idx < 512; idx++)
			clear_page_entry(vbh, &tbl[idx], level - 1);

		// remove Write protect for this page table
		vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, addr, 1 << VTD_PAGE_SHIFT, true, true, true);
		// remove iommu page table tag for this page table
		//if (!vbh_set_ram_metadata_in_range(vbh, addr, VTD_PAGE_SIZE, false, false, RESERVED_VMID))
			//pr_err("Remove iommu page table pfn: 0x%llx from vbh page tracker failed\n");
		status = return_iommu_page(vbh, addr >> VTD_PAGE_SHIFT);
	} else if (level > 1 && dma_pte_superpage(old)) {
		u64 page_num = (level - 1) << 9;
		u64 idx;

		for (idx = 0; idx < page_num; idx++) {
			status = clear_page_iommu_mapped(vbh, (addr >> VTD_PAGE_SHIFT) + idx);
			if (status < 0)
				return status;

			status = return_iommu_page(vbh, (addr >> VTD_PAGE_SHIFT) + idx);
			if (status < 0)
				return status;
		}
	}

	return status;
}

static int split_large_page(struct vbh_data *vbh, struct dma_pte *parent, u8 level,
			    u64 *start_addr, bool identity)
{
	struct page *tmp_page;
	u64 pte_val, page_addr;
	int idx, status;
	struct dma_pte *pte;

	tmp_page =  alloc_page(GFP_KERNEL);
	if (!tmp_page)
		return -ENOMEM;

	page_addr = (u64)page_to_pfn(tmp_page) << PAGE_SHIFT;
	pte_val = page_addr | DMA_PTE_READ | DMA_PTE_WRITE;
	parent->val = pte_val;

	if (!identity)
		borrow_iommu_page(vbh, page_addr >> PAGE_SHIFT);
	// mark new page as iommu page table in vbh page tracker
	 status = set_page_iommu_table(vbh, page_addr >> PAGE_SHIFT);
	 if (status < 0) {
		pr_err("Add new iommu page table into vbh page tracker failed, addr: 0x%llx\n", page_addr);
		return status;
	}

	pte = (struct dma_pte *)page_address(tmp_page);
	if (level == 2) {
		for (idx = 0; idx < 512; idx++) {
			pte->val = (*start_addr) | DMA_PTE_READ | DMA_PTE_WRITE;
			pte++;
			*start_addr += VTD_PAGE_SIZE;
		}
	} else {
		for (idx = 0; idx < 512; idx++) {
			status = split_large_page(vbh, pte + idx, level - 1, start_addr, identity);
			if (status < 0) {
				pr_err("split large page error, level: %d, idx: 0x%x\n", level, idx);
				return status;
			}
		}
	}

	return 0;
}

static int __protect_iommu_page_table(struct vbh_data *vbh, struct dma_pte *ent,
				      u8 level, u64 start_iova, bool identity)
{
	u64 addr;
	int status = 0;

	if (!dma_pte_present(ent))
		return 0;

	addr = dma_pte_addr(ent);

	if (level > 1) {
		if (!dma_pte_superpage(ent)) {
			u64 next_iova;
			int index;
			struct dma_pte *next_tbl;
			u8 next_level = level - 1;

			// protect table
			vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, addr, 1 << VTD_PAGE_SHIFT, true, false, false);
			if (!identity)
				borrow_iommu_page(vbh, addr << VTD_PAGE_SHIFT);
			// mark this page as iommu page table in vbh page tracker
			status = set_page_iommu_table(vbh, addr >> VTD_PAGE_SHIFT);
			if (status < 0) {
				pr_err("Add iommu page table into vbh page tracker failed, addr: 0x%llx\n", addr);
				return status;
			}

			next_tbl = (struct dma_pte *)phys_to_virt(addr);

			for (index = 0; index < 512; index++) {
				next_iova = start_iova | ((u64)index << (((next_level - 1) * 9) + 12));
				status = __protect_iommu_page_table(vbh, &next_tbl[index], next_level, next_iova, identity);
				if (status < 0)
					return status;
			}
		} else if (identity) {
			u64 start = start_iova;

			// check identity huge page entry
			if (start_iova != addr) {
				pr_err("huge page entry isn't identity map, gfn: 0x%llx, entry: 0x%llx\n", start_iova, addr);
				return -EINVAL;
			}

			pr_info("huge identity page detected: gfn: 0x%llx, pha: 0x%llx, level: %d\n", start_iova, addr, level);

			status = split_large_page(vbh, ent, level, &start, identity);
		} else {
			u64 start = addr;
			u64 page_num = 1 << ((level - 1) * 9);
			u64 idx;

			pr_info("huge page detected: gfn: 0x%llx, pha: 0x%llx, level: %d\n", start_iova, addr, level);

			// set the whole pages as iommu mapped
			for (idx = 0; idx < page_num; idx++) {
				status = set_page_iommu_mapped(vbh, (addr >> VTD_PAGE_SHIFT) + idx);
				if (status < 0)
					return status;
			}

			status = split_large_page(vbh, ent, level, &start, identity);
		}
	} else if (identity) {
		//u16 vm_id;

		// check identity PTE
		if (start_iova != addr) {
			pr_err("PTE isn't identity map, gfn: 0x%llx, entry: 0x%llx\n", start_iova, addr);
			return -EINVAL;
		}

		// remove vbh memory from this identity map
		//if (!vbh_get_ram_metadata(vbh, addr, VTD_PAGE_SIZE, NULL, NULL, &vm_id)) {
		//	pr_err("pa: 0x%llx isn't in vbh page tracker\n", addr);
		//	return -EINVAL;
		//}

		//if (vd_id == VBH_ID)
			//ent->val = 0;
	} else {
		status = set_page_iommu_mapped(vbh, addr >> VTD_PAGE_SHIFT);
		if (status < 0)
			return status;

		status = borrow_iommu_page(vbh, addr >> VTD_PAGE_SHIFT);
	}

	return status;
}

static int protect_iommu_page_table(struct vbh_data *vbh, u8 bus, u8 devfn,
				    u64 pgd, u8 aw, bool identity)
{
	int status;
	struct vbh_iommu_pgd *iommu_pgd;
	struct vbh_device_id *dev_id;
	bool found_pgd = false;

	list_for_each_entry(iommu_pgd, &vbh->iommu_pgd_list, list) {
		if (iommu_pgd->pa != pgd)
			continue;

		found_pgd = true;
		list_for_each_entry(dev_id, &iommu_pgd->device_list, list) {
			if (dev_id->bus == bus && dev_id->devfn == devfn) {
				pr_info("bus:0x%x, devfn: 0x%x has already in this pgd: 0x%llx\n", bus, devfn, pgd);
				return 0;
			}
		}

		break;
	}

	if (!found_pgd) {
		struct dma_pte top;

		top.val = pgd | DMA_PTE_READ | DMA_PTE_WRITE;
		status = __protect_iommu_page_table(vbh, &top, aw + 3, 0, identity);
		if (status < 0)
			return status;

		iommu_pgd = (struct vbh_iommu_pgd *)vbh_malloc(vbh, sizeof(*iommu_pgd));
		if (!iommu_pgd)
			return -ENOMEM;
		iommu_pgd->pa = pgd;
		iommu_pgd->level = aw + 2;
		iommu_pgd->identity = identity;

		pr_info("add pgd 0x%llx\n", pgd);
		INIT_LIST_HEAD(&iommu_pgd->device_list);
		list_add_tail(&iommu_pgd->list, &vbh->iommu_pgd_list);
	}

	// Add device info into pgd
	dev_id = (struct vbh_device_id *)vbh_malloc(vbh, sizeof(*dev_id));
	if (!dev_id)
		return -ENOMEM;
	pr_info("add bus: %x, devfn: %x into pgd->device_list\n", bus, devfn);
	dev_id->bus = bus;
	dev_id->devfn = devfn;

	list_add_tail(&dev_id->list, &iommu_pgd->device_list);

	return 0;
}

static void remove_iommu_page_table(struct vbh_data *vbh, u8 bus, u8 devfn,
				    u64 old_pgd, u8 aw)
{
	struct vbh_iommu_pgd *pgd, *tmp1;
	struct vbh_device_id *dev_id, *tmp2;

	list_for_each_entry_safe(pgd, tmp1, &vbh->iommu_pgd_list, list) {
		if (pgd->pa != old_pgd)
			continue;

		list_for_each_entry_safe(dev_id, tmp2, &pgd->device_list, list) {
			if (dev_id->bus == bus && dev_id->devfn == devfn) {
				pr_info("remove bus: %x, devfn: %x from pgd->device_list\n", bus, devfn);
				list_del(&dev_id->list);
				vbh_free(vbh, (void *)dev_id);
				break;
			}
		}

		if (list_empty(&pgd->device_list)) {
			struct dma_pte top;

			pr_info("clear pgd 0x%llx, bus, %x, devfn: %x\n", old_pgd, bus, devfn);
			top.val = old_pgd | DMA_PTE_READ | DMA_PTE_WRITE;
			clear_page_entry(vbh, &top, aw + 3);
			list_del(&pgd->list);
			vbh_free(vbh, (void *)pgd);
		}

		return;
	}
}

int protect_intel_iommu(struct vbh_data *vbh)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	u64 pgd = 0;
	u8 aw;

	INIT_LIST_HEAD(&vbh->iommu_list);
	INIT_LIST_HEAD(&vbh->iommu_pgd_list);

	for_each_iommu(iommu, drhd) {
		u64   addr, rtaddr_reg;
		struct root_entry  *rt;
		int index, bus, hi = 1, entry_num = 256;
		bool sm;
		struct vbh_iommu *vbh_iommu;

		vbh_iommu = (struct vbh_iommu *)vbh_malloc(vbh, sizeof(*vbh_iommu));
		if (!iommu)
			return -ENOMEM;

		vbh_iommu->id = iommu->seq_id;
		vbh_iommu->virt_io_base = (u64)iommu->reg;
		vbh_iommu->reg_size = iommu->reg_size;
		INIT_LIST_HEAD(&vbh_iommu->context_list);

		list_add_tail(&vbh_iommu->list, &vbh->iommu_list);

		// protect iommu mmio
		for (addr = iommu->reg_phys; (addr & PAGE_MASK) < (iommu->reg_phys + iommu->reg_size); addr += PAGE_SIZE)
			vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, addr, PAGE_SIZE, true, false, false);

		// protect iommu root table
		rtaddr_reg = dmar_readq(iommu->reg + DMAR_RTADDR_REG);
		addr = rtaddr_reg & VTD_PAGE_MASK;
		if (!addr)
			return -EINVAL;
		vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, addr, PAGE_SIZE, true, false, false);
		vbh_iommu->root_tbl_pa = addr;

		// protect iommu context table
		rt = (struct root_entry *)phys_to_virt(addr);

		sm = !!(rtaddr_reg & DMA_RTADDR_SMT);
		if (sm) {
			hi = 2;
			entry_num = 128;
		}

		for (bus = 0; bus < 256; bus++) {
			int i;

			if (!(rt[bus].lo & 1) && !(rt[bus].hi & 1))
				continue;

			for (i = 0; i < hi; i++) {
				u64 ctx_tbl = 0;
				struct context_entry *ctx;
				int  devfn;
				struct vbh_iommu_context_tbl *iommu_context_tbl;

				if (i == 0)
					ctx_tbl = rt[bus].lo & VTD_PAGE_MASK;
				else
					ctx_tbl = rt[bus].hi & VTD_PAGE_MASK;

				if (!ctx_tbl)
					continue;

				vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, ctx_tbl, PAGE_SIZE, true, false, false);

				iommu_context_tbl = (struct vbh_iommu_context_tbl *)vbh_malloc(vbh, sizeof(*iommu_context_tbl));
				if (!iommu_context_tbl)
					return -ENOMEM;
				iommu_context_tbl->pa = ctx_tbl;
				iommu_context_tbl->bus = bus;
				list_add_tail(&iommu_context_tbl->list, &vbh_iommu->context_list);

				ctx = (struct context_entry *)phys_to_virt(ctx_tbl);

				for (devfn = 0; devfn < entry_num; devfn++) {
					int status = 0;
					bool identity = true;

					if (!sm)
						index = devfn;
					else
						index = devfn * 2;
					if (!(ctx[index].lo & 1))
						continue;
					if (pgd == 0) {
						pgd = ctx[index].lo & VTD_PAGE_MASK;
						aw = ctx[index].hi & 0x7;
					} else if (pgd != (ctx[index].lo & VTD_PAGE_MASK)) {
						pr_info("new iommu page table found at 0000:%2x:%2x.%2x.\n", bus, devfn >> 3, devfn & 0x7);
						identity = false;
					}

					status = protect_iommu_page_table(vbh, (u8)bus, (u8)devfn, ctx[index].lo & VTD_PAGE_MASK, aw, identity);
					if (status < 0) {
						pr_err("protect iommu page table at 0x%llx fail\n", ctx[index].lo & VTD_PAGE_MASK);
						return status;
					}
				}
			}
		}
	}

	return 0;
}

void handle_iommu_mmio_write(struct vbh_data *vbh, u64 reg, u64 val)
{
	struct vbh_iommu *iommu;

	list_for_each_entry(iommu, &vbh->iommu_list, list) {
		u64 offset;

		if (reg >= iommu->virt_io_base && reg < iommu->virt_io_base + iommu->reg_size) {
			offset = reg - iommu->virt_io_base;

			// protect Global command register and Root entry table
			if (offset != DMAR_GCMD_REG && offset != DMAR_RTADDR_REG) {
				writel((u32)val, (void *)reg);
			}
		}
	}
}

void handle_iommu_context_table_write(struct vbh_data *vbh, u64 pa, u64 val)
{
	struct vbh_iommu *iommu;
	bool found = false;
	struct vbh_iommu_context_tbl *tbl;

	list_for_each_entry(iommu, &vbh->iommu_list, list) {
		list_for_each_entry(tbl, &iommu->context_list, list) {
			if (pa >= tbl->pa && pa < tbl->pa + PAGE_SIZE) {
				found = true;
				break;
			}
		}

		if (found)
			break;
	}

	if (!found) {
		pr_err("context table write hypercall isn't in tracked context table, pa: 0x%llx\n", pa);
		return;
	}

	trace_context_table_write(iommu->id, pa, val);

	// write context entry low
	if (pa % 16 == 0) {
		struct context_entry *entry;
		u8 aw;
		u8 devfn;

		entry = (struct context_entry *)phys_to_virt(pa);
		devfn = (pa - tbl->pa) / sizeof(*entry);

		aw = entry->hi & 0x7;

		if (val & 1) {
			// protect this new pgd
			if (protect_iommu_page_table(vbh, tbl->bus, devfn,
						     val & VTD_PAGE_MASK, aw, false) < 0) {
				pr_err("protect new pgd: 0x%llx failed\n", val & VTD_PAGE_MASK);
				return;
			}
		} else if (val == 0) {
			// Clear pgd
			u64 old = entry->lo & VTD_PAGE_MASK;

			// If iommu driver clear entyr->hi first, aw will be 0,
			// here set aw to 57bit by default
			if (aw == 0)
				aw = 3;

			remove_iommu_page_table(vbh, tbl->bus, devfn, old, aw);
		}

		entry->lo = val;
	} else {
		// write context entry high
		u64 *ptr;

		ptr = (u64 *)phys_to_virt(pa);

		*ptr = val;
	}
}

void handle_iommu_page_table_write(struct vbh_data *vbh, u64 pa, u64 val, u8 level)
{
	u64 *ptr;

	trace_iommu_page_table_write(pa, val, level);

	ptr = (u64 *)phys_to_virt(pa);

	if (val != 0) {
		u64 addr;

		addr = val & VTD_PAGE_MASK;
		if (level > 1) {
			if ((val & DMA_PTE_LARGE_PAGE) == 0) {
				// protect new page table
				vbh_control_gpa_access_in_range(vbh->vmx_eptp_pml4, addr, PAGE_SIZE, true, false, false);
				// mark this page as iommu page table in vbh page tracker
				if (set_page_iommu_table(vbh, addr >> VTD_PAGE_SHIFT) < 0) {
					pr_err("Add iommu page table into vbh page tracker failed, addr: 0x%llx\n", addr);
					return;
				}
			} else {
				u64 idx, new;
				u64 page_num = (level - 1) << 9;

				for (idx = 0 ; idx < page_num; idx++) {
					new = (addr >> VTD_PAGE_SHIFT) + idx;
					if (set_page_iommu_mapped(vbh, new) < 0) {
						pr_err("set large page 0x%llx as iommu mapped failed\n", new);
						return;
					}
					if (borrow_iommu_page(vbh, new) < 0) {
						pr_err("remove large pfn: 0x%llx from privmary vm failed\n", new);
						return;
					}
				}
			}
		} else {
			u64 pfn = addr >> VTD_PAGE_SHIFT;

			if (set_page_iommu_mapped(vbh, pfn) < 0) {
				pr_err("set page 0x%llx as iommu mapped failed\n", pfn);
				return;
			}
			if (borrow_iommu_page(vbh, pfn) < 0) {
				pr_err("remove pfn: 0x%llx from privmary vm failed\n", pfn);
				return;
			}
		}
	} else {
		struct dma_pte old = *(struct dma_pte *)ptr;

		clear_page_entry(vbh, &old, level);
	}

	*ptr = val;
}
