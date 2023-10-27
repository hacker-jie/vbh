// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include <linux/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/desc.h>
//#include <asm/msr.h>
#include <asm/tlbflush.h>
//#include <linux/kvm_host.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include <asm/special_insns.h>
#include <asm/fpu/internal.h>
#include <asm/kvm_para.h>

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>
#include <linux/intel-iommu.h>

#include "vbh.h"
#include "vbh_ops.h"
#include "cpu.h"
#include "mem_setup.h"
#include "pt_setup.h"
#include "page_tracker_setup.h"
#include "pt.h"
#include "nested_setup.h"
#include "mem_ops.h"
#include "tee_nonroot.h"

static bool __read_mostly use_shadow_vmcs = 1;
module_param_named(use_shadow_vmcs, use_shadow_vmcs, bool, S_IRUGO);

static bool __read_mostly use_shadow_ept = 1;
module_param_named(use_shadow_ept, use_shadow_ept, bool, S_IRUGO);

#define VMX_EPTP_MT_WB						0x6ull
#define VMX_EPTP_PWL_4						0x18ull

#define	NR_LOAD_MSRS						8
#define NR_STORE_MSRS						8

#define is_aligned(POINTER, BYTE_COUNT) \
		(((uintptr_t)(const void *)(POINTER)) % (BYTE_COUNT) == 0)

//DEFINE_SPINLOCK(vbh_load_lock);
static bool vbh_loaded;

static int vmxon_success;

DECLARE_BITMAP(switch_done, NR_CPUS);
DECLARE_BITMAP(all_cpus, NR_CPUS);

static unsigned long rflags_value;
static unsigned long is_vmlaunch_fail;
static bool __read_mostly switch_on_load = 1;
module_param_named(switch_vmx_on_load, switch_on_load, bool, 0444);
MODULE_PARM_DESC(switch_vmx_on_load, "Switch to non root when module is load");

static void set_msr_state(void);
static noinline void load_guest_state_registers(void);
static int switch_to_nonroot_per_cpu(void *data);

static u16 read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static void vmxon_setup_revid(void *vmxon_region)
{
	u32 rev_id = 0;
	u32 msr_high_value = 0;

	rdmsr(MSR_IA32_VMX_BASIC, rev_id, msr_high_value);

	memcpy(vmxon_region, &rev_id, 4);
}

static int cpu_vmxon(u64 addr, int cpu)
{
	vmxon_success = 1;

	// Do vmxon
	asm volatile ("vmxon %0" : : "m"(addr));

	// Check whether vmxon succeeds or not
	asm volatile("jbe vmxon_fail\n");
	asm volatile("jmp vmxon_finish\n"
			"vmxon_fail:\n"
			"pushfq\n");

	asm volatile("popq %0\n"
		: "=m"(rflags_value)
		:
		: "memory");

	vmxon_success = 0;
	pr_err("<1>CPU-%d: vmxon has failed. rflags_value=%lx\n",
				cpu, rflags_value);

	asm volatile("vmxon_finish:\n");
	if (vmxon_success)
		pr_err("<1>CPU-%d: vmxon has succeeded.\n", cpu);

	return rflags_value == 0 ? 0 : -EIO;
}

static void setup_vmcs_config(void *data)
{
	int cpu = smp_processor_id();
	struct vbh_data *vbh = data;
	struct vmcs_config *vmcs_config_p = &vbh->vcpus[cpu]->vmcs_config;

	build_vmcs_config(vmcs_config_p, true);
}

static int setup_vmx_cap(struct vmx_capability *vmx_cap)
{
	u32 vmx_msr_low, vmx_msr_high, msr_ctl, msr_ctl2;
	int ret = 0;

	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, vmx_msr_low, vmx_msr_high);
	msr_ctl = vmx_msr_high | vmx_msr_low;

	if (!(msr_ctl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)) {
		pr_err("%s(): VBH cannot run on CPUs which do not support secondary "
		       "proc-based VM-execution controls.\n", __func__);
		ret = -1;
	} else {
		rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, vmx_msr_low, vmx_msr_high);
		msr_ctl2 = vmx_msr_high | vmx_msr_low;

		if (!(msr_ctl2 & SECONDARY_EXEC_ENABLE_EPT)) {
			pr_err("%s(): VBH cannot run on CPUs which do not support EPT.\n",
			       __func__);
			ret = -1;
		} else {
			rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_cap->ept, vmx_cap->vpid);
			if (!(msr_ctl2 & SECONDARY_EXEC_ENABLE_VPID) && vmx_cap->vpid) {
				pr_err("%s(): VPID CAP should not exist if not support "
				       "1-setting enable VPID VM-execution control\n", __func__);
				vmx_cap->vpid = 0;
			}
		}
	}

	return ret;
}

static noinline void load_guest_state_registers(void)
{
	exec_vmwritel(GUEST_CR0, read_cr0() & ~X86_CR0_TS);
	exec_vmwritel(GUEST_CR3, __read_cr3());
	exec_vmwritel(GUEST_CR4, native_read_cr4());
}

static noinline void load_guest_state_segment_registers(int cpu)
{
	u16 selector;
	u64 base;
	u32 access_rights;
	u32 limit;

	base = 0;
	limit = 0xffffffff;

	asm ("mov %%cs, %%ax\n"
			: "=a"(selector));
	exec_vmwrite16(GUEST_CS_SELECTOR, selector);

	asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
	//24.4.1 Guest Register State
	access_rights = access_rights >> 8;
	access_rights = access_rights & 0xf0ff;
	exec_vmwrite32(GUEST_CS_AR_BYTES, access_rights);
	exec_vmwritel(GUEST_CS_BASE, base);
	exec_vmwrite32(GUEST_CS_LIMIT, limit);

	asm ("mov %%ss, %%ax;\n"
		: "=a"(selector));

	exec_vmwrite16(GUEST_SS_SELECTOR, selector);

	if (selector == 0) {
		access_rights = 0x10000;
	} else {
		asm("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
	}

	exec_vmwrite32(GUEST_SS_AR_BYTES, access_rights);
	exec_vmwritel(GUEST_SS_BASE, base);
	exec_vmwrite32(GUEST_SS_LIMIT, limit);
}

static noinline void load_guest_state_area(struct vbh_data *vbh, int cpu)
{
	struct vbh_desc_ptr *host_gdt = &vbh->vcpus[cpu]->host_gdt;
	u16 selector;
	u64 base;
	u32 limit;
	u32 access_rights;
	struct desc_ptr dt;
	u16 tr;

	load_guest_state_registers();

	load_guest_state_segment_registers(cpu);

	base = 0;
	limit = 0xffffffff;

	asm ("mov %%ds, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(GUEST_DS_SELECTOR, selector);
	if (selector == 0) {
		exec_vmwrite32(GUEST_DS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
		exec_vmwrite32(GUEST_DS_AR_BYTES, access_rights);
		exec_vmwritel(GUEST_DS_BASE, base);
		exec_vmwrite32(GUEST_DS_LIMIT, limit);
	}

	asm ("mov %%es, %%ax\n"
			: "=a"(selector));
	exec_vmwrite16(GUEST_ES_SELECTOR, selector);
	if (selector == 0) {
		exec_vmwrite32(GUEST_ES_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
		exec_vmwrite32(GUEST_ES_AR_BYTES, access_rights);
		exec_vmwritel(GUEST_ES_BASE, base);
		exec_vmwrite32(GUEST_ES_LIMIT, limit);
	}

	// get base for fs and gs from the register
	asm ("mov %%fs, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(GUEST_FS_SELECTOR, selector);
	if (selector == 0) {
		exec_vmwrite32(GUEST_FS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
		exec_vmwrite32(GUEST_FS_AR_BYTES, access_rights);
	}

	exec_vmwritel(GUEST_FS_BASE, msr_read(MSR_FS_BASE));
	exec_vmwrite32(GUEST_FS_LIMIT, limit);

	asm ("mov %%gs, %%ax\n"
		: "=a"(selector));
	exec_vmwrite16(GUEST_GS_SELECTOR, selector);
	if (selector == 0) {
		exec_vmwrite32(GUEST_GS_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(selector));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
		exec_vmwrite32(GUEST_GS_AR_BYTES, access_rights);
	}
	exec_vmwritel(GUEST_GS_BASE, msr_read(MSR_GS_BASE));
	exec_vmwrite32(GUEST_GS_LIMIT, limit);

	asm volatile ("str %0" : "=r" (tr));
	exec_vmwrite16(GUEST_TR_SELECTOR, tr);
	if (tr == 0) {
		exec_vmwrite32(GUEST_TR_AR_BYTES, 0x10000);
	} else {
		asm ("lar %%ax, %%rax\n"
			: "=a"(access_rights) : "a"(tr));
		//24.4.1 Guest Register State
		access_rights = access_rights >> 8;
		access_rights = access_rights & 0xf0ff;
		exec_vmwritel(GUEST_TR_BASE, segment_base(host_gdt, tr));
		exec_vmwrite32(GUEST_TR_LIMIT, segment_limit(host_gdt, tr));
		exec_vmwrite32(GUEST_TR_AR_BYTES, access_rights);
	}

	exec_vmwrite16(GUEST_LDTR_SELECTOR, read_ldt());
	exec_vmwritel(GUEST_LDTR_BASE, base);
	exec_vmwrite32(GUEST_LDTR_LIMIT, limit);
	exec_vmwrite32(GUEST_LDTR_AR_BYTES, 0x10000);

	native_store_gdt(&dt);
	exec_vmwritel(GUEST_GDTR_BASE, dt.address);
	exec_vmwrite32(GUEST_GDTR_LIMIT, dt.size);

	store_idt(&dt);
	exec_vmwritel(GUEST_IDTR_BASE, dt.address);
	exec_vmwrite32(GUEST_IDTR_LIMIT, dt.size);

	//MSR state
	set_msr_state();
}

static noinline void set_msr_state(void)
{
	u32 high, low;
	unsigned long a;

	exec_vmwrite64(GUEST_IA32_DEBUGCTL, 0);

	rdmsr(MSR_IA32_SYSENTER_CS, low, high);
	exec_vmwrite32(GUEST_SYSENTER_CS, low);

	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	exec_vmwritel(GUEST_SYSENTER_ESP, a);

	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	exec_vmwritel(GUEST_SYSENTER_EIP, a);

	rdmsrl(MSR_EFER, a);
	exec_vmwrite64(GUEST_IA32_EFER, a);

	rdmsrl(MSR_IA32_CR_PAT, a);
	exec_vmwrite64(GUEST_IA32_PAT, a);

	//Guest non register state
	exec_vmwrite32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	exec_vmwrite32(GUEST_INTERRUPTIBILITY_INFO, 0);
	exec_vmwritel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	exec_vmwrite64(VMCS_LINK_POINTER, -1ull);

	//TODO:  why this one doesn't work on vmware?
	//exec_vmwrite32(VMX_PREEMPTION_TIMER_VALUE, 0);
}

static void enable_feature_control(void)
{
	u64 old, test_bits;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if ((old & test_bits) != test_bits)
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
}

static bool is_vmx_supported(void)
{
	int recx = 0, redx = 0;
	int eax = 1, ebx = 0;
	int feature_value = 0;

	// First check whether cpu supports vmx
	__cpuid(&eax, &ebx, &recx, &redx);

	if (!((recx >> 5) & 1)) {
		pr_err("<1>CPU doesn't support vmx.\n");
		return false;
	}

	pr_err("<1>CPU supports vmx.\n");

	rdmsrl(MSR_IA32_FEATURE_CONTROL, feature_value);

	// For now, we do not take care of the VMXON in SMX operation.
	if (feature_value & 1) {
		if ((feature_value >> 2) & 1) {
			pr_err("<1>MSR 0x3A:Lock bit is on. VMXON bit is on. OK\n");
		} else {
			pr_err("<1>MSR 0x3A:Lock bit is on. VMXON bit is off. Cannot turn on vmxon\n");
			return false;
		}
	}

	pr_err("<1>BIOS supports vmx.\n");

	return true;
}

bool is_mpx_supported(void)
{
	u64 host_xcr0 = 0;

	if (boot_cpu_has(X86_FEATURE_XSAVE))
		host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	/* FIXME: also need to check vmexit_ctrl:
	 * VM_EXIT_CLEAR_BNDCFGS
	 * VM_ENTRY_LOAD_BNDCFGS
	 */
	return host_xcr0 & (XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR);
}

static bool is_shadow_vmcs_supported(void)
{
	u64 vmx_msr;

	if (!use_shadow_vmcs)
		return false;

	/* check if the cpu supports writing r/o exit information fields */
	rdmsrl(MSR_IA32_VMX_MISC, vmx_msr);
	if (!(vmx_msr & MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS))
		return false;

	return true;
}

 /*turn on vmxe*/
static void enable_vmxe(void)
{
	unsigned long cr4_value;

	cr4_value = native_read_cr4();

	if (cr4_value & X86_CR4_VMXE) {
		pr_err("<1> %s:  vmxe is already on.\n", __func__);
		return;
	}

	asm volatile("movq %cr4, %rax\n"
			"bts $13, %rax\n"
			"movq %rax, %cr4\n");

	pr_err("<1> turned on cr4.vmxe\n");
}

static void disable_vmxe(void)
{
	unsigned long cr4 = native_read_cr4();
	if (cr4 & X86_CR4_VMXE) {
		if (!(cr4_read_shadow() & X86_CR4_VMXE)) {
			unsigned long flags;
			pr_info("%s: VMXE in shadow is cleared by host already\n", __func__);
			local_irq_save(flags);
			__cr4_set(cr4 & ~X86_CR4_VMXE);
			local_irq_restore(flags);
		} else
			cr4_clear_bits(X86_CR4_VMXE);

		pr_info("%s: clear cr4 shadow vmxe=%s.\n", __func__, cr4_read_shadow() & X86_CR4_VMXE ? "true" : "false");
	}
}

extern void vmx_switch_and_exit_handle_vmexit(void);
static int switch_to_nonroot_per_cpu(void *data)
{
	struct vbh_data *vbh = (struct vbh_data *)data;
	struct vbh_vcpu_vmx *vcpu_ptr;
	struct desc_ptr dt;
	int cpu;
	u64 phys_addr, host_rsp, host_rflags;
	struct vmcs_config *vmcs_config_ptr;
	unsigned long flags;

	int32_t instruction_error_code = 0;

	cpu = get_cpu();
	local_irq_save(flags);

	pr_err("%s: cpu <%d> Enter.\n", __func__, cpu);

	vcpu_ptr = &vbh->vcpus[cpu]->vcpu_vmx;
	vcpu_ptr->cr3 = vbh->host_cr3;
	vcpu_ptr->cpu_id = cpu;

	vmcs_config_ptr = &vbh->vcpus[cpu]->vmcs_config;

	native_store_gdt(&dt);
	vbh->vcpus[cpu]->host_gdt.size = dt.size;
	vbh->vcpus[cpu]->host_gdt.address = dt.address;

	enable_feature_control();

	vcpu_ptr->regs = vbh->vcpus[cpu]->reg_scratch;

	// enable vmx
	enable_vmxe();

	phys_addr = vbh_pa(vcpu_ptr->vmxarea);

	if (cpu_vmxon(phys_addr, cpu) != 0)
		return -1;

	exec_vmptrld(vbh_pa(vcpu_ptr->pcpu_vmcs));

	load_guest_state_area(vbh, cpu);

	load_host_state_area(vbh_pa(vcpu_ptr->cr3));

	load_execution_control(vbh, vmcs_config_ptr, vbh->eptp, true);

	load_vmexit_control(vmcs_config_ptr);

	load_vmentry_control(vmcs_config_ptr);

	asm("movq %%rsp, %%rax\n"
		: "=a"(host_rsp));
	exec_vmwritel(GUEST_RSP, host_rsp);

	host_rsp = vcpu_ptr->vcpu_stack + 16384;
	host_rsp -= 8;
	*(u64 *)host_rsp = (u64)cpu;
	host_rsp -= 8;
	*(u64 *)host_rsp = (u64)vbh;
	host_rsp -= 8;
	*(u64 *)host_rsp = (u64)vcpu_ptr->regs;
	exec_vmwritel(HOST_RSP, host_rsp);
	pr_info("%s: CPU%d host_rsp 0x%llx\n", __func__, cpu, host_rsp);

	asm("pushfq\n");
	asm("popq %0\n"
		: "=m"(host_rflags) : : "memory");
	exec_vmwritel(GUEST_RFLAGS, host_rflags);

	// host rip vmx_handle_vm_exit
	exec_vmwritel(HOST_RIP,
			(unsigned long)vmx_switch_and_exit_handle_vmexit);

	// guest rip
	asm("movq $0x681e, %rdx");
	asm("movq $vmentry_point, %rax");
	asm("vmwrite %rax, %rdx");

	pr_err("<1>Ready to call VMLAUNCH.\n");

	asm volatile("vmlaunch \n\t");
	asm volatile("jbe vmlaunch_fail\n");
	asm volatile("jmp vmentry_point\n"
				 "vmlaunch_fail:\n");

	is_vmlaunch_fail = 1;

	// read RFlag
	asm volatile("popq %0\n"
			: "=m"(rflags_value)
			:
			: "memory");

	pr_err("<1> VMLaunch has failed, rflags_value=%lx\n",
					rflags_value);

	// Read error
	instruction_error_code = exec_vmread32(VM_INSTRUCTION_ERROR);
	pr_err("<1> VMLaunch has failed, instruction_error_code=%d\n",
					instruction_error_code);

	asm volatile("vmentry_point:\n");

	if (!is_vmlaunch_fail) {
		pr_err("<1> CPU-%d: VmLaunch Done. Enter guest mode.\n", cpu);
	}

	bitmap_set(switch_done, cpu, 1);
	put_cpu();

	local_irq_restore(flags);

	return 0;
}

//switch to non-root API
static int vmx_switch_to_nonroot(struct vbh_data *vbh)
{
	int cpu;
	struct task_struct *thread_ptr;

	//on_each_cpu(switch_to_nonroot_per_cpu, NULL, true);

	int cpus = num_online_cpus();

	bitmap_zero(switch_done, cpus);

	//spin_lock(&vbh_load_lock);

	if (vbh_loaded) {
		pr_err("Warning: vbh is loaded already!\n");
		//spin_unlock(&vbh_load_lock);
		return -1;
	}

	for_each_online_cpu(cpu) {
		thread_ptr = kthread_create(switch_to_nonroot_per_cpu,
					    vbh, "vmx-switch-%d", cpu);
		kthread_bind(thread_ptr, cpu);
		wake_up_process(thread_ptr);
	}

	while (!bitmap_equal((const unsigned long *)&all_cpus,
		(const unsigned long *)&switch_done, cpus)) {
		schedule();
	}

	vbh_loaded = 1;
	//spin_unlock(&vbh_load_lock);

#if 0
	if (intel_iommu_enabled) {
		kernel_deprivileged = true;
	}
#endif

	setup_tee_env();

	pr_err("%s: exit.\n", __func__);

	return 0;
}

pgd_t *init_process_cr3(void)
{
	struct task_struct *task;

	for_each_process(task)
		if (task->pid == (pid_t) 1)
			return task->mm->pgd;

	return NULL;
}

static void *vbh_alloc_pages(size_t size, int node)
{
	int order = get_order(size);
	size_t new_size = size;
	void *va = NULL;

	BUG_ON(size % PAGE_SIZE);

	if (node == NUMA_NO_NODE) {
		va = alloc_pages_exact(new_size, GFP_KERNEL | __GFP_ZERO);
	} else {
		struct page *page;
		new_size = (1 << order) * PAGE_SIZE;
		page = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, order);
		if (page)
			va = page_address(page);
	}

	if (va) {
		if (vbh_record_pages(vbh_pa(va), new_size))
			return va;

		if (node == NUMA_NO_NODE)
			free_pages_exact(va, new_size);
		else
			free_pages((unsigned long)va, order);
	}

	return NULL;
}

static int vbh_setup_config_pages(struct vbh_data *vbh)
{
	vbh->vmx_io_bitmap_a_switch = vbh_alloc_pages(PAGE_SIZE, NUMA_NO_NODE);
	if (!vbh->vmx_io_bitmap_a_switch) {
		pr_err("%s: No page for io_bitmap_a\n", __func__);
		return -ENOMEM;
	}
	vbh->vmx_io_bitmap_b_switch = vbh_alloc_pages(PAGE_SIZE, NUMA_NO_NODE);
	if (!vbh->vmx_io_bitmap_b_switch) {
		pr_err("%s: No page for io_bitmap_b\n", __func__);
		return -ENOMEM;
	}
	vbh->vmx_msr_bitmap_switch = vbh_alloc_pages(PAGE_SIZE, NUMA_NO_NODE);
	if (!vbh->vmx_msr_bitmap_switch) {
		pr_err("%s: No page for msr_bitmap\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static int vbh_create_vcpu_data(struct vbh_data *vbh, int cpu)
{
	struct vbh_vcpu_data *vcpu_data;

	vcpu_data = vbh_alloc_pages(sizeof(struct vbh_vcpu_data),
				    cpu_to_node(cpu));
	if (!vcpu_data) {
		pr_err("%s: Cannot allocate vbh_vcpu data\n", __func__);
		return -ENOMEM;
	}

	vcpu_data->pcpu = cpu;
	vcpu_data->vcpu_vmx.vbh = vbh;
	vbh->vcpus[cpu] = vcpu_data;
	list_add(&vcpu_data->list, &vbh->vcpu_head);

	return 0;
}

static struct vmcs *alloc_vmcs_cpu(int cpu, struct vmcs_config *vmcs_config_ptr)
{
	int node = cpu_to_node(cpu);
	struct vmcs *vmcs;
	size_t size = (1 << vmcs_config_ptr->order) * PAGE_SIZE;

	vmcs = vbh_alloc_pages(size, node);
	if (!vmcs)
		return NULL;

	memset(vmcs, 0, vmcs_config_ptr->size);
	vmcs->hdr.revision_id = vmcs_config_ptr->revision_id; /* vmcs revision id */
	return vmcs;
}

static int vbh_config_vcpu_data(struct vbh_vcpu_data *vcpu_data, int cpu)
{
	struct vbh_vcpu_vmx *vcpu_vmx_ptr;
	struct vmcs_config *vmcs_config_ptr;
	u64 phys_addr;

	vcpu_vmx_ptr = &vcpu_data->vcpu_vmx;
	vmcs_config_ptr = &vcpu_data->vmcs_config;

	vcpu_vmx_ptr->vcpu_stack = (u64)vbh_alloc_pages(16384, cpu_to_node(cpu));
	if (!vcpu_vmx_ptr) {
		pr_err("%s: failed to allocate vcpu_vmx\n", __func__);
		return -ENOMEM;
	}
	memset((void *)vcpu_vmx_ptr->vcpu_stack, 0, 16384);

	vcpu_vmx_ptr->vmxarea = vbh_alloc_pages(PAGE_SIZE, cpu_to_node(cpu));
	phys_addr = vbh_pa(vcpu_vmx_ptr->vmxarea);
	if (!is_aligned(vcpu_vmx_ptr->vmxarea, 0x1000) ||
		!is_aligned(phys_addr, 0x1000)) {
		pr_err("%s: vmxon region address is not aligned va 0x%llx pa 0x%llx\n",
			__func__, (u64)vcpu_vmx_ptr->vmxarea, phys_addr);
		return -ENOMEM;
	}

	// setup revision id in vmxon region
	vmxon_setup_revid(vcpu_vmx_ptr->vmxarea);

	vcpu_vmx_ptr->pcpu_vmcs = alloc_vmcs_cpu(cpu, vmcs_config_ptr);
	if (!vcpu_vmx_ptr->pcpu_vmcs) {
		pr_err("%s: failed to allocate pcpu_vmcs\n", __func__);
		return -ENOMEM;
	}

	vcpu_vmx_ptr->nested.vmcs02 = alloc_vmcs_cpu(cpu, vmcs_config_ptr);
	if (!vcpu_vmx_ptr->nested.vmcs02) {
		pr_err("%s: failed to allocate vmcs02\n", __func__);
		return -ENOMEM;
	}
	vcpu_vmx_ptr->nested.magic_code = 0x12345678;

	return 0;
}

#define MAX_HOSTMEM_TRACKER_SIZE	((1 << (MAX_ORDER - 1)) * PAGE_SIZE)
static int __create_ram_tracker(struct vbh_data *vbh, u64 start_pfn, u64 end_pfn)
{
	size_t tracker_size, tracker_fields_size, max_size, left_size;
	unsigned long i, max_count, cycles, left;
	struct ram_tracker *t;
	u64 total_pages;

	if (start_pfn > end_pfn)
		return 0;

	total_pages = end_pfn - start_pfn + 1;
	tracker_size = sizeof(struct ram_metadata) * total_pages;

	tracker_fields_size = offsetof(struct ram_tracker, metadata);
	max_count = (MAX_HOSTMEM_TRACKER_SIZE - tracker_fields_size) / sizeof(struct ram_metadata);
	max_size =  max_count * sizeof(struct ram_metadata) + tracker_fields_size;

	cycles = total_pages / max_count;
	left = total_pages % max_count;
	left_size = ALIGN(left * sizeof(struct ram_metadata) + tracker_fields_size, PAGE_SIZE);

	pr_info("%s: total_pages %lld tracker_size %ld fields_size %ld max_count %ld max_size %ld cycles %ld left %ld left_size %ld start_pfn 0x%llx\n",
		__func__, total_pages, tracker_size, tracker_fields_size, max_count, max_size, cycles, left, left_size, start_pfn);

	for (i = 0; i < cycles; i++) {
		t = vbh_alloc_pages(max_size, NUMA_NO_NODE);
		if (!t)
			return -ENOMEM;
		t->start_pfn = i * max_count + start_pfn;
		t->count = max_count;
		list_add_tail(&t->list, &vbh->ram_trackers);
		pr_info("%s: track from 0x%llx to 0x%llx\n", __func__, t->start_pfn, t->start_pfn + t->count - 1);
	}

	t = vbh_alloc_pages(left_size, NUMA_NO_NODE);
	if (!t)
		return -ENOMEM;

	t->start_pfn = i * max_count + start_pfn;
	t->count = left;
	list_add_tail(&t->list, &vbh->ram_trackers);
	pr_info("%s: track from 0x%llx to 0x%llx\n", __func__, t->start_pfn, t->start_pfn + t->count - 1);

	return 0;
}

/*
 * Note: currently the implementation is based on iomem_resouce
 * which is have resource inserted by ascending order. In this
 * case, when insert the ram tracker to ram_trackers list, it
 * can put the new one into the tail so that the ram_trackers list
 * is also ascending order. But if this is changed for not using
 * iomem_resouce, the ascending order should also be considered
 * otherwise it may break the ram metadata set/unset functions
 * for multiple pages.
 */
static int vbh_create_ram_tracker(struct vbh_data *vbh)
{
	struct resource *root, *entry;
	int ret;
	u64 start_pfn, end_pfn;

	root = &iomem_resource;
	entry = root->child;

	while (1) {
		if ((entry->flags & IORESOURCE_SYSTEM_RAM) == IORESOURCE_SYSTEM_RAM) {
			start_pfn = PFN_UP(entry->start);
			end_pfn = PFN_DOWN(entry->end);
			pr_info("%s: Name: %s flags 0x%lx start: 0x%llx(0x%llx) end 0x%llx(0x%llx)\n",
				__func__, entry->name, entry->flags, entry->start, start_pfn,
				entry->end, end_pfn);
			ret = __create_ram_tracker(vbh, start_pfn, end_pfn);
			if (ret)
				return ret;
		}

		if (!entry->sibling)
			break;

		entry = entry->sibling;
	}

	return 0;
}

static int __init cpu_switch_init(void)
{
	struct vbh_data *vbh_global;
	int cpu, ret = 0;
	vbh_loaded = 0;

	if (!is_vmx_supported())
		return -EINVAL;
#if 0
	if (!intel_iommu_enabled)
		pr_err("SECURITY_HOLE, intel iommu isn't enabled, device could access security vm memory, please don't use security vm on this kernel.\n");
#endif

	ret = vbh_page_cache_create();
	if (ret)
		goto out;

	vbh_global = vbh_alloc_pages(sizeof(struct vbh_data), NUMA_NO_NODE);
	if (!vbh_global) {
		pr_err("%s: Cannot allocate vbh data\n", __func__);
		ret = -ENOMEM;
		goto free_vbh_page_cache;
	}

	vbh_global->magic_code = VBH_DATA_MAGIC_CODE;
	INIT_LIST_HEAD(&vbh_global->vcpu_head);
	INIT_LIST_HEAD(&vbh_global->kvm_head);
	sspinlock_init(&vbh_global->kvm_lock);
	sspinlock_init(&vbh_global->host_mmu_lock);
	INIT_LIST_HEAD(&vbh_global->ram_trackers);
	vbh_setup_config_pages(vbh_global);

	vbh_global->host_cr3 = init_process_cr3();
	if (!vbh_global->host_cr3)
		goto free_vbh_page_cache;

	if (setup_vmx_cap(&vbh_global->vmx_cap)) {
		ret = -EINVAL;
		pr_err("%s(): invalid vmx capability.", __func__);
		goto free_vbh_page_cache;
	}

	vbh_global->vmx_eptp_pml4 = vbh_alloc_pages(PAGE_SIZE, NUMA_NO_NODE);
	if (!vbh_global->vmx_eptp_pml4) {
		pr_err("%s: no eptp_pml4\n", __func__);
		goto free_vbh_page_cache;
	}
	vbh_global->eptp = construct_eptp(vbh_pa(vbh_global->vmx_eptp_pml4),
					  &vbh_global->vmx_cap);
	if (vbh_global->vmx_cap.ept & VMX_EPT_PAGE_WALK_4_BIT)
		vbh_global->ept_walks = 4;
	else
		vbh_global->ept_walks = 5;

	vbh_global->vmcs_shadow_bitmap = vbh_alloc_pages(PAGE_SIZE, NUMA_NO_NODE);
	if (vbh_global->vmcs_shadow_bitmap) {
		setup_vmcs_shadow_bitmap(vbh_global->vmcs_shadow_bitmap);
		vbh_global->enable_shadow_vmcs = is_shadow_vmcs_supported();
		if (vbh_global->enable_shadow_vmcs)
			pr_info("%s: VBH: use shadow vmcs 0x%llx(0x%llx) for nested\n",
				__func__, (u64)vbh_global->vmcs_shadow_bitmap, vbh_pa(vbh_global->vmcs_shadow_bitmap));
		else
			pr_info("%s: VBH: NOT use shadow vmcs for nested\n", __func__);
	}
	vbh_global->enable_shadow_ept = use_shadow_ept;
	sspinlock_init(&vbh_global->nested_mmu_lock);
	INIT_LIST_HEAD(&vbh_global->nested_root_ept_list);

	for_each_online_cpu(cpu) {
		ret = vbh_create_vcpu_data(vbh_global, cpu);
		if (ret) {
			pr_err("%s: Cannot allocate vbh_vcpu data for CPU%d\n",
				__func__, cpu);
			goto free_vbh_page_cache;
		}
	}

	if (is_xsaves_supported())
		vbh_global->xsaves_supported = true;
	if (is_mpx_supported())
		vbh_global->mpx_supported = true;

	on_each_cpu(setup_vmcs_config, (void *)vbh_global, true);

	for_each_online_cpu(cpu) {
		bitmap_set(all_cpus, cpu, 1);
		ret = vbh_config_vcpu_data(vbh_global->vcpus[cpu], cpu);
		if (ret) {
			pr_err("%s: Cannot config vbh_vcpu data for CPU%d\n",
				__func__, cpu);
			goto free_vbh_page_cache;
		}
	}

	if (setup_ept_tables(vbh_global))
		goto free_vbh_page_cache;

	ret = vbh_create_ram_tracker(vbh_global);
	if (ret)
		goto free_vbh_page_cache;

	ret = create_mem_pools(vbh_global);
	if (ret)
		goto free_vbh_page_cache;

	vbh_mem_status(vbh_global);

#if 0
	ret = protect_intel_iommu(vbh_global);
	if (ret < 0) {
		pr_err("protect intel iommu failed\n");
		goto free_vbh_page_cache;
	}
#endif

	ret = vbh_protect_pages(vbh_global);
	if (ret)
		goto free_vbh_page_cache;

	if (switch_on_load)
		vmx_switch_to_nonroot(vbh_global);

	return 0;

free_vbh_page_cache:
	vbh_page_cache_free();
out:
	return ret;
}

static void unload_vbh_per_cpu(void *info)
{
	// Turn off vm
	if (vmxon_success) {
		pr_err("<1> kernel_hardening_unload: Ready to send VMXOFF.\n");
		*(u64 *)info = kvm_hypercall0(KVM_HC_ROOT_VMXOFF);
	}

	disable_vmxe();
}

static void cpu_switch_exit(void)
{
	int cpus;
	struct vbh_data *vbh = NULL;

	cpus = num_online_cpus();

	pr_err("<1> Trying to unload...");

	on_each_cpu(unload_vbh_per_cpu, (void *)&vbh, true);

	vbh_loaded = 0;

	BUG_ON(!vbh || (vbh->magic_code != VBH_DATA_MAGIC_CODE));

	destroy_mem_pools(vbh);

	vbh_page_cache_free();

	pr_err("module vmx-switch unloaded\n");
}

module_init(cpu_switch_init);
module_exit(cpu_switch_exit);
MODULE_LICENSE("GPL v2");
