#ifndef _VBH_PAGE_TRACKER_H
#define _VBH_PAGE_TRACKER_H_

#include "vbh.h"

struct vbh_page {
	struct list_head list;
	u64 pa;
	size_t size;
};

/*
 * Return value for page tracker setting and unsetting.
 */
#define RET_SUCCESS		0
#define RET_NO_TRACKER		1 /* global tracker doesn't exist */
#define RET_INVALID_INPUT	2 /* invalid input request */
#define RET_REJECT		3 /* page can not be (un)set since it belongs to others */
#define RET_NOT_FOUND		4 /* page not found in tracker */

#define RESERVED_VMID           0
/* IOMMU_ID for both host device iommu pages and VM iommu PT. */
#define IOMMU_ID                1
/* VBH pages */
#define VBH_ID                  2

bool vbh_get_ram_metadata(struct vbh_data *vbh, u64 pa, bool *ept_mapped,
			  bool *iommu_mapped, u16 *vm_id);
u8 vbh_set_ram_metadata_in_range(struct vbh_data *vbh, u64 pa, size_t size,
				   bool *ept_map, bool *iommu_map, u16 id);
u8 vbh_unset_ram_metadata_in_range(struct vbh_data *vbh, u64 pa, size_t size,
                                   bool *ept_map, bool *iommu_map, u16 id);
#endif
