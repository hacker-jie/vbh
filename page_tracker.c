#include <linux/types.h>
#include <asm/page.h>

#include "page_tracker.h"

bool vbh_get_ram_metadata(struct vbh_data *vbh, u64 pa, bool *ept_mapped,
			  bool *iommu_mapped, u16 *id)
{
	struct ram_tracker *p;
	u64 pfn = pa >> PAGE_SHIFT;

	if (list_empty(&vbh->ram_trackers))
		return false;

	list_for_each_entry(p, &vbh->ram_trackers, list) {
		if (pfn >= p->start_pfn && pfn < (p->start_pfn + p->count)) {
			struct ram_metadata *metadata = p->metadata;
			int index = pfn - p->start_pfn;
			if (ept_mapped)
				*ept_mapped = metadata[index].fields.ept_mapped;
			if (iommu_mapped)
				*iommu_mapped = metadata[index].fields.iommu_mapped;
			if (id)
				*id = metadata[index].fields.id;
			return true;
		}
	}

	return false;
}

u8 vbh_set_ram_metadata_in_range(struct vbh_data *vbh, u64 pa, size_t size,
				   bool *ept_map, bool *iommu_map, u16 id)
{
	u64 pfn = pa >> PAGE_SHIFT;
	u64 end_pfn = (pa + size) >> PAGE_SHIFT;
	struct ram_tracker *p;

	BUG_ON(size % PAGE_SIZE);

	if (list_empty(&vbh->ram_trackers))
		return RET_NO_TRACKER;

	list_for_each_entry(p, &vbh->ram_trackers, list) {
		struct ram_metadata *metadata = p->metadata;
		int index;
		while (pfn >= p->start_pfn && pfn < (p->start_pfn + p->count)) {
			index = pfn - p->start_pfn;
			switch (id) {
			case RESERVED_VMID:
				/* IOMMU PT doesn't have any VM ID knowledge yet so
				 * it can only use RESERVED_VMID.
				 * Probably there is one case that IOMMU also requires
				 * to know the VM ID. For example:
				 * 1. When pass through device to secure VM, VFIO pin
				 * all VM memory and IOMMU created mappings without
				 * setting VM ID. At this moment, secure VM EPT is
				 * still empty.
				 * 2. Some malicious VM ask hypervisor to creat its EPT
				 * mapping with the same pfn used by IOMMU PT. But
				 * hypervisor doesn't know if this pfn belongs to this
				 * malicious VM or not. Hypervisor cannot refuse to creat
				 * mapping with this pfn because if do this then hypervisor
				 * cannot create any EPT mappings with any pfn mapped by
				 * IOMMU PT already. So hypervisor created mappings in
				 * malicious VM EPT.
				 * 3. In secure VM, because secure OS software didn't access
				 * this pfn thus no EPT violation happened and hypervisor
				 * didn't discover this malicious  mapping for secure VM.
				 * In this case, malicious VM can access the device DMA.
				 */
				if (metadata[index].fields.id != RESERVED_VMID) {
					pr_err("tracker setting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				}
				if (iommu_map && *iommu_map) {
					metadata[index].fields.iommu_mapped = 1;
				 } else {
					pr_err("tracker setting for pa %llx with invalid info.\n", pa);
					return RET_INVALID_INPUT;
				}
				break;
			case IOMMU_ID:
				/* For IOMMU PT and host device iommu pages.
				 * Since IOMMU PT doesn't have any VM ID knowledge,
				 * to make sure the IOMMU PT pages won't be abused by any
				 * other VM, add a seperate ID for it.
				 */
				if (metadata[index].fields.id != IOMMU_ID) {
					if (metadata[index].fields.id == RESERVED_VMID)
						metadata[index].fields.id = id;
					else {
						pr_err("tracker setting for pa %llx with invalid info.\n", pa);
						return RET_REJECT;
					}
				}
				break;
			case VBH_ID:
				if (metadata[index].fields.id != RESERVED_VMID &&
						metadata[index].fields.id != VBH_ID) {
					pr_err("tracker setting for pa %llx with invalid info.\n", pa);
					return RET_REJECT;
				}
				metadata[index].fields.id = id;
				break;
			default:
				/*
				 * Policies for setting metadata:
				 * If the id equals to the id in metadata, then
				 * it is safe to change the mapping status.
				 * If the id not equals to the id in metadata,
				 * 	a. if metadata id is reserved ID, means no
				 * 	one is using it yet, can safely change the
				 *	mapping status.
				 * 	b. if metadata id is not reserved ID, refuse
				 *	to do anything.
				 */
				if (id == metadata[index].fields.id) {
					metadata[index].fields.ept_mapped = 1;
				} else if (metadata[index].fields.id == RESERVED_VMID) {
					if (ept_map && *ept_map) {
						metadata[index].fields.ept_mapped = 1;
						metadata[index].fields.id = id;
					} else {
						pr_err("tracker setting for pa %llx with invalid info.\n", pa);
						return RET_INVALID_INPUT;
					}
				} else {
					pr_err("tracker setting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				}
				break;
			}
			pfn++;
			if (pfn == end_pfn)
				return RET_SUCCESS;
		}
	}

	if (pfn == end_pfn)
		return RET_SUCCESS;

	pr_err("tracker setting for pa %llx not found.\n", pa);
	return RET_NOT_FOUND;
}

u8 vbh_unset_ram_metadata_in_range(struct vbh_data *vbh, u64 pa, size_t size,
				     bool *ept_map, bool *iommu_map, u16 id)
{
	u64 pfn = pa >> PAGE_SHIFT;
	u64 end_pfn = (pa + size) >> PAGE_SHIFT;
	struct ram_tracker *p;

	BUG_ON(size % PAGE_SIZE);

	if (list_empty(&vbh->ram_trackers))
		return RET_NO_TRACKER;

	list_for_each_entry(p, &vbh->ram_trackers, list) {
		struct ram_metadata *metadata = p->metadata;
		int index;
		while (pfn >= p->start_pfn && pfn < (p->start_pfn + p->count)) {
			index = pfn - p->start_pfn;
			switch (id) {
			case RESERVED_VMID:
				if (metadata[index].fields.id != RESERVED_VMID) {
					pr_err("tracker unsetting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				}
				if (iommu_map && !*iommu_map)
					metadata[index].fields.iommu_mapped = 0;
				else {
					pr_err("tracker unsetting for pa %llx with invalid info.\n", pa);
					return RET_INVALID_INPUT;
				}
				break;
			case IOMMU_ID:
				/* If the pfn metadata records other ID, it means it doesn't
				 * belong to IOMMU page table. */
				if (metadata[index].fields.id != IOMMU_ID) {
					pr_err("tracker unsetting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				} else {
					/* Give back the pfn to depriviledged host.
					 * And do more to ensure the correctness of metadata.
					 */
					metadata[index].fields.id = RESERVED_VMID;
					metadata[index].fields.ept_mapped = 0;
					metadata[index].fields.iommu_mapped = 0;
				}
				break;
			case VBH_ID:
				if (metadata[index].fields.id != VBH_ID) {
					pr_err("tracker unsetting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				}
				/* Give back the pfn to depriviledged host.
				 * Do more to ensure correctness. */
				metadata[index].fields.id = RESERVED_VMID;
				metadata[index].fields.ept_mapped = 0;
				metadata[index].fields.iommu_mapped = 0;
				break;
			default:
				/*
				 * Policies for unsetting ept_mapped for VM:
				 * If id equals to the id in metadata, it means this pfn has
				 * been mapped to a VM before, so safe to do unset ept_mapped,
				 * but need to keep iommu_mapped as before.
				 * If id equals to RESERVED_VMID, this is a meaningless behavior.
				 * Otherwise, this should be rejected.
				 */
				if (id == metadata[index].fields.id && ept_map && !*ept_map) {
					metadata[index].fields.ept_mapped = 0;
					metadata[index].fields.id = RESERVED_VMID;
					break;
				}
				if (metadata[index].fields.id == RESERVED_VMID) { 
					if (ept_map && !*ept_map) {
						/* This is meaningless, but we can just do it. */
						metadata[index].fields.ept_mapped = 0;
					} else {
						pr_err("tracker unsetting for pa %llx with invalid info.\n", pa);
						return RET_INVALID_INPUT;
					}
				} else {
					pr_err("tracker unsetting for pa %llx is rejected.\n", pa);
					return RET_REJECT;
				}
				break;
			}
			pfn++;
			if (pfn == end_pfn)
				return RET_SUCCESS;
		}
	}

	if (pfn == end_pfn)
		return RET_SUCCESS;

	pr_err("tracker unsetting for pa %llx not found.\n", pa);
	return RET_NOT_FOUND;
}
