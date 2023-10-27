#ifndef __VBH_PT_SETUP_H
#define __VBH_PT_SETUP_H

int setup_ept_tables(struct vbh_data *vbh);
unsigned long *pte_for_address(struct vbh_data *vbh, bool pre_deprivilege,
			       unsigned long *parent, unsigned long pfn,
			       unsigned long start_level,
			       unsigned long target_level);

#endif
