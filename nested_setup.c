#include <linux/kernel.h>

#include "vbh.h"
#include "nested.h"

#include "vmcs.h"

extern u32 vmcs_shadow_fields[];

void setup_vmcs_shadow_bitmap(unsigned long *vmcs_shadow_bitmap)
{
	u16 field_index, bit_pos;
	u32 field, array_index;
	u32 *fields = vmcs_shadow_fields;

	/*
	 * Set all the bits to 1s first and clear the bits for
	 * the corresponding fields lets its guest to access Shadow VMCS
	 */
	memset((void *)vmcs_shadow_bitmap, 0xff, PAGE_SIZE);

	/*
	 * Refer to Section 24.6.15 VMCS Shadowing Bitmap Addresses & 30.3 VMX Instructions - VMWRITE/VMREAD
	 */

	for (field_index = 0; fields[field_index] != ~0U; field_index++) {
		field = vmcs_shadow_fields[field_index];
		bit_pos = field % 64;
		array_index = field / 64;
		clear_bit(bit_pos, &vmcs_shadow_bitmap[array_index]);

		if (VMX_VMCS_FIELD_WIDTH(field) == VMX_VMCS_FIELD_WIDTH_64) {
			bit_pos = (field + 1) % 64;
			array_index = (field + 1) / 64;
			clear_bit(bit_pos, &vmcs_shadow_bitmap[array_index]);
		}
	}
}
