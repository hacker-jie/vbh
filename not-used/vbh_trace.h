#if !defined(_VBT_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _VBT_TRACE_H_

#include <linux/types.h>
#include <linux/stringify.h>
#include <linux/tracepoint.h>
#include <linux/trace_events.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM vbh

TRACE_EVENT(context_table_write,
	TP_PROTO(int id, unsigned long addr, unsigned long val),

	TP_ARGS(id, addr, val),

	TP_STRUCT__entry(
		__field(int, id)
		__field(unsigned long, addr)
		__field(unsigned long, val)
		),

	TP_fast_assign(
		__entry->id = id;
		__entry->addr = addr;
		__entry->val = val;
	),

	TP_printk("iommu%d write context table, pa 0x%lx val 0x%lx\n",
		__entry->id,
		__entry->addr,
		__entry->val)
);

TRACE_EVENT(iommu_page_table_write,
	TP_PROTO(unsigned long addr, unsigned long val, int level),

	TP_ARGS(addr, val, level),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, val)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->val = val;
		__entry->level = level;
	),

	TP_printk("write iommu page table, pa 0x%lx val 0x%lx level %d\n",
		__entry->addr,
		__entry->val,
		__entry->level)

);
#endif /* _VBH_TRACE_H_ */

/* This part must be out of protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../../../arch/x86/kvm/vmx/vbh
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE vbh_trace

#include <trace/define_trace.h>
