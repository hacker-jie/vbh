/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VBH_VMX_OPS_H
#define __VBH_VMX_OPS_H

void exec_vmclear(u64 phys_addr);
void exec_vmptrld(u64 phys_addr);
u64 exec_vmread64(u32 field_full);
void exec_vmwritel(u32 field, unsigned long value);
unsigned long exec_vmreadl(u32 field);
u32 exec_vmread32(u32 field);
u16 exec_vmread16(u32 field);
void exec_vmwrite64(u32 field_full, u64 value);
void exec_vmwrite32(u32 field, u32 value);
void exec_vmwrite16(u32 field, u16 value);
void exec_invept(unsigned long ext, u64 eptp, u64 gpa);

#endif
