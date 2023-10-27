#ifndef __VBH_CPU_H
#define __VBH_CPU_H

struct vbh_desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed)) ;

static inline u64 msr_read(u32 reg)
{
	u32 msrl, msrh;

	asm volatile (" rdmsr ":"=a"(msrl), "=d"(msrh) : "c" (reg));
	return (((u64)msrh << 32U) | msrl);
}

#define vbh_rdmsr(msr, low, high)		\
do {						\
	u64 __val = msr_read(msr);		\
	(void)((low) = (u32)__val);		\
	(void)((high) = (u32)(__val >> 32));	\
} while(0)					\

#define vbh_rdmsrl(msr, val)			\
	((val) = msr_read((msr)))

static inline void msr_write(u32 reg, u64 msr_val)
{
	asm volatile (" wrmsr " : : "c" (reg), "a" ((u32)msr_val), "d" ((u32)(msr_val >> 32U)));
}

static inline unsigned long vbh_read_cr2(void)
{
	unsigned long val;
	asm volatile("mov %%cr2,%0\n\t" : "=r" (val));
	return val;
}

static inline void vbh_write_cr2(unsigned long val)
{
	asm volatile("mov %0,%%cr2": : "r" (val));
}

static inline unsigned long vbh_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r"(val));
	return val;
}

static inline unsigned long vbh_read_cr4(void)
{
	unsigned long val;
	asm volatile("mov %%cr4,%0\n\t" : "=r"(val));
	return val;
}

static inline void vbh_store_gdt(struct vbh_desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

static inline void vbh_store_idt(struct vbh_desc_ptr *dtr)
{
	asm volatile("sidt %0":"=m" (*dtr));
}

static inline u16 vbh_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static inline void vbh_read_cpuid(unsigned int *eax, unsigned int *ebx,
				  unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

/*
 * stac/clac pair is used to access guest's memory protected by SMAP,
 * following below flow:
 *
 *      stac();
 *      #access guest's memory.
 *      clac();
 *
 * Notes:Avoid inserting another stac/clac pair between stac and clac,
 *      As once clac after multiple stac will invalidate SMAP protection
 *      and hence Page Fault crash.
 *      Logging message to memory buffer will induce this case,
 *      please disable SMAP temporlly or don't log messages to shared
 *      memory buffer, if it is evitable for you for debug purpose.
 */
static inline void vbh_stac(void)
{
	asm volatile ("stac" : : : "memory");
}

static inline void vbh_clac(void)
{
	asm volatile ("clac" : : : "memory");
}

#endif
