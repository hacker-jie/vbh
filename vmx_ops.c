#include <linux/types.h>
/**
 * @pre addr != NULL && addr is 4KB-aligned
 * @pre addr != VMXON pointer
 */
void exec_vmclear(u64 phys_addr)
{

	/* pre-conditions can avoid VMfail
	 * here no need check RFLAGS since it will generate #GP or #UD
	 * except VMsuccess. SDM 30.3
	 */
	asm volatile (
		"vmclear %0\n"
		:
		: "m"(phys_addr)
		: "cc", "memory");
}

/**
 * @pre addr != NULL && addr is 4KB-aligned
 * @pre addr != VMXON pointer
 */
void exec_vmptrld(u64 phys_addr)
{
	/* pre-conditions can avoid VMfail
	 * here no need check RFLAGS since it will generate #GP or #UD
	 * except VMsuccess. SDM 30.3
	 */
	asm volatile (
		"vmptrld %0\n"
		:
		: "m"(phys_addr)
		: "cc", "memory");
}

u64 exec_vmread64(u32 field_full)
{
	u64 value;

	asm volatile (
		"vmread %%rdx, %%rax "
		: "=a" (value)
		: "d"(field_full)
		: "cc");

	return value;
}

unsigned long exec_vmreadl(u32 field)
{
	u64 value;

	value = exec_vmread64(field);

	return (unsigned long)value;
}

u32 exec_vmread32(u32 field)
{
	u64 value;

	value = exec_vmread64(field);

	return (u32)value;
}

u16 exec_vmread16(u32 field)
{
        u64 value;

        value = exec_vmread64(field);

        return (u16)value;
}

void exec_vmwrite64(u32 field_full, u64 value)
{
	asm volatile (
		"vmwrite %%rax, %%rdx "
		: : "a" (value), "d"(field_full)
		: "cc");
}

void exec_vmwritel(u32 field, unsigned long value)
{
	exec_vmwrite64(field, (u64)value);
}

void exec_vmwrite32(u32 field, u32 value)
{
	exec_vmwrite64(field, (u64)value);
}

void exec_vmwrite16(u32 field, u16 value)
{
	exec_vmwrite64(field, (u64)value);
}

void exec_invept(unsigned long ext, u64 eptp, u64 gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile("invept %1, %0\n\t"
			:
			: "r"(ext), "m"(operand)
			: "cc", "memory"
	);
}
