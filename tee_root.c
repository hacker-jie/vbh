#include "tee_root.h"
#include "mem_ops.h"
#include "pt.h"
#include "vmx_ops.h"
#include "vbh_ops.h"

void process_ept_mem(struct vbh_data *vbh, unsigned long *parent,
		     unsigned long end_pfn, unsigned long level,
		     bool is_last_entry, bool protect)
{
	unsigned long *pt;
	unsigned long pt_pa = *parent & PT64_BASE_ADDR_MASK;
	bool flush = false;

	if (pt_pa == 0)
		return;

	pt = (unsigned long *)vbh_va(pt_pa);

	//TODO: return error check
	vbh_control_gpa_access_in_range(vbh, false, pt_pa,
					PAGE_SIZE, !protect, !protect, !protect,
					&flush);

	if (level != 1) {
		int idx;
		int end_idx = (1 << EPT_LEVEL_STRIDE) - 1;
		bool end = false;

		if (is_last_entry)
			end_idx = pfn_level_offset(end_pfn, level - 1);

		for (idx = 0; idx <= end_idx; idx++) {
			if (is_last_entry && idx == end_idx)
				end = true;

			process_ept_mem(vbh, pt + idx, end_pfn,
					level - 1, end, protect);
		}
	} else
		memset(pt, 0, PAGE_SIZE);
}

static void process_tee_ept(struct vbh_data *vbh, bool protect)
{
	int idx;
	unsigned long end_pfn = vbh->tee_vm->mem_size >> EPT_PAGE_SHIFT;
	int end_idx = pfn_level_offset(end_pfn, EPT_MAX_LEVEL);
	bool end = false;
	unsigned long *parent = (unsigned long *)vbh_va(vbh->tee_vm->ept_pa);
	bool flush = false;

	for (idx = 0; idx <= end_idx; idx++) {
		if (idx == end_idx)
			end = true;

		process_ept_mem(vbh, parent + idx, end_pfn,
				EPT_MAX_LEVEL, end, protect);
	}

	//TODO: return error check
	vbh_control_gpa_access_in_range(vbh, false, vbh->tee_vm->ept_pa,
					PAGE_SIZE, !protect, !protect, !protect,
					&flush);

	// invalid root eptp
	vbh_invept(vbh, vbh->eptp);
}

static struct vmcs *alloc_vmcs(struct vbh_data *vbh, struct vmcs_config *vmcs_config)
{
	struct vmcs *vmcs;

	if (vmcs_config->size > PAGE_SIZE) {
		pr_err("vmcs size %x should be smaller than one page\n", vmcs_config->size);
		return NULL;
	}

	// allocate one page as VMCS
	vmcs = (struct vmcs *)vbh_malloc(vbh, PAGE_SIZE);
	if (!vmcs)
		return NULL;

	memset(vmcs, 0, vmcs_config->size);
	vmcs->hdr.revision_id = vmcs_config->revision_id;

	return vmcs;
}

static int construct_vcpu_data(struct vbh_data *vbh)
{
	struct tee_vcpu_data *vcpu_data;
	struct tee_vcpu_vmx *vcpu_vmx;

	vcpu_data = (struct tee_vcpu_data *)vbh_malloc(vbh, sizeof(struct tee_vcpu_data));
	if (!vcpu_data)
		return -ENOMEM;

	vbh->tee_vm->vcpu_data = vcpu_data;

	build_vmcs_config(&vcpu_data->vmcs_config, false);

	vcpu_vmx = &vcpu_data->vcpu_vmx;
	vcpu_vmx->pcpu_vmcs = alloc_vmcs(vbh, &vcpu_data->vmcs_config);
	if (!vcpu_vmx->pcpu_vmcs) {
		pr_err("failed to allocate TE vmcs\n");
		return -ENOMEM;
	}

	vcpu_vmx->regs = vcpu_data->reg_scratch;

	return 0;
}

static void destroy_vcpu_data(struct vbh_data *vbh)
{
	if (vbh->tee_vm->vcpu_data) {
		struct tee_vcpu_data *vcpu_data = vbh->tee_vm->vcpu_data;

		if (vcpu_data->vcpu_vmx.pcpu_vmcs) {
			vbh_free(vbh, vcpu_data->vcpu_vmx.pcpu_vmcs);
		}

		vbh_free(vbh, (void *)vcpu_data);
	}
}

static void guest_memory_write(unsigned long ept_pa, u64 gpa, void *hva, unsigned long size)
{
	unsigned long remain;

	remain = size;
	while (remain > 0) {
		unsigned long write_num, page_offset, gfn;
		unsigned long *entry4, *entry3, *entry2, *entry1;
		unsigned long offset4, offset3, offset2, offset1;
		void *dst;

		gfn = gpa >> PAGE_SHIFT;
		page_offset = gpa & (PAGE_SIZE - 1);
		if (page_offset + remain > PAGE_SIZE)
			write_num = PAGE_SIZE - page_offset;
		else
			write_num = remain;

		offset4 = pfn_level_offset(gfn, 4);
		entry4 = (unsigned long *)vbh_va(ept_pa) + offset4;
		offset3 = pfn_level_offset(gfn, 3);
		entry3 = (unsigned long *)vbh_va((*entry4) & PAGE_MASK) + offset3;
		offset2 = pfn_level_offset(gfn, 2);
		entry2 = (unsigned long *)vbh_va((*entry3) & PAGE_MASK) + offset2;
		offset1 = pfn_level_offset(gfn, 1);
		entry1 = (unsigned long *)vbh_va((*entry2) & PAGE_MASK) + offset1;

		dst = (void *)vbh_va(((*entry1) & PAGE_MASK) + page_offset);
		memcpy(dst, hva, write_num);

		gpa += write_num;
		hva += write_num;
		remain -= write_num;
	}
}

#define BOOT_GDT_OFFSET 0x500
#define BOOT_IDT_OFFSET 0x520
static void prepare_guest_segment_register(struct tee_root_vm *tee_vm)
{
	u64 gdt[4] = {0x0, 0x00af9b000000ffff, 0x00cf93000000ffff, 0x008f8b000000ffff};
	u64 idt = 0;

	guest_memory_write(tee_vm->ept_pa, BOOT_GDT_OFFSET, (void *)gdt, 32);
	guest_memory_write(tee_vm->ept_pa, BOOT_IDT_OFFSET, (void *)&idt, 8);

	exec_vmwrite16(GUEST_CS_SELECTOR, 0x8);
	exec_vmwritel(GUEST_CS_BASE, 0x0);
	exec_vmwrite32(GUEST_CS_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_CS_AR_BYTES, 0xa09b);

	exec_vmwrite16(GUEST_DS_SELECTOR, 0x10);
	exec_vmwritel(GUEST_DS_BASE, 0x0);
	exec_vmwrite32(GUEST_DS_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_DS_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_ES_SELECTOR, 0x10);
	exec_vmwritel(GUEST_ES_BASE, 0x0);
	exec_vmwrite32(GUEST_ES_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_ES_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_ES_SELECTOR, 0x10);
	exec_vmwritel(GUEST_ES_BASE, 0x0);
	exec_vmwrite32(GUEST_ES_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_ES_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_FS_SELECTOR, 0x10);
	exec_vmwritel(GUEST_FS_BASE, 0x0);
	exec_vmwrite32(GUEST_FS_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_FS_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_GS_SELECTOR, 0x10);
	exec_vmwritel(GUEST_GS_BASE, 0x0);
	exec_vmwrite32(GUEST_GS_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_GS_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_SS_SELECTOR, 0x10);
	exec_vmwritel(GUEST_SS_BASE, 0x0);
	exec_vmwrite32(GUEST_SS_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_SS_AR_BYTES, 0xc093);

	exec_vmwrite16(GUEST_TR_SELECTOR, 0x18);
	exec_vmwritel(GUEST_TR_BASE, 0x0);
	exec_vmwrite32(GUEST_TR_LIMIT, 0xfffff);
	exec_vmwrite32(GUEST_TR_AR_BYTES, 0x808b);

	exec_vmwrite16(GUEST_LDTR_SELECTOR, 0x0);
	exec_vmwritel(GUEST_LDTR_BASE, 0x0);
	exec_vmwrite32(GUEST_LDTR_LIMIT, 0xffff);
	exec_vmwrite32(GUEST_LDTR_AR_BYTES, 0x82);

	exec_vmwritel(GUEST_GDTR_BASE, BOOT_GDT_OFFSET);
	exec_vmwrite32(GUEST_GDTR_LIMIT, 31);

	exec_vmwritel(GUEST_IDTR_BASE, BOOT_IDT_OFFSET);
	exec_vmwrite32(GUEST_IDTR_LIMIT, 7);
}

#define GUEST_PML4_TABLE 0x9000
#define GUEST_PDP_TABLE 0xa000
#define GUEST_PD_TABLE 0xb000
static void prepare_guest_page_table(struct tee_root_vm *tee_vm)
{
	u64 val, i;

	// 0 .. 512GB
	val = GUEST_PDP_TABLE | 0x3;
	guest_memory_write(tee_vm->ept_pa, GUEST_PML4_TABLE, (void *)&val, 8);

	// 0 .. 1GB
	val = GUEST_PD_TABLE | 0x3;
	guest_memory_write(tee_vm->ept_pa, GUEST_PDP_TABLE, (void *)&val, 8);

	// 512 2MB Large page
	for (i = 0; i < 512; i++) {
		val = (i << 21) | 0x83;
		guest_memory_write(tee_vm->ept_pa, GUEST_PD_TABLE + (i << 3), (void *)&val, 8);
	}

	exec_vmwritel(GUEST_CR3, GUEST_PML4_TABLE);
}

#define IMG_START_GPA  0x0
#define GUEST_BOOT_STACK 0x8000
static int load_guest_elf_img(struct tee_root_vm *tee_vm, unsigned long img_va, unsigned long img_size)
{
	struct elf64_hdr {
		u8   ident[16];
		u16  type;
		u16  machine;
		u32  version;
		u64  entry;
		u64  phoff;
		u64  shoff;
		u32  flags;
		u16  ehsize;
		u16  phentsize;
		u16  phnum;
		u16  shentsize;
		u16  shnum;
		u16  shstrndx;
	} *ehdr;
	struct elf64_phdr {
		u32  type;
		u32  flags;
		u64  offset;
		u64  vaddr;
		u64  paddr;
		u64  filesz;
		u64  memsz;
		u64  align;
	} *phdr;
	u16  idx;

	ehdr = (struct elf64_hdr *)img_va;
	if ((ehdr->ident[0] != 127) || (ehdr->ident[1] != 69)
	    || (ehdr->ident[2] != 76) || (ehdr->ident[3] != 70)
	    || (ehdr->ident[5] != 1)) {
		pr_err("img has invalid elf64 header\n");
		return -EINVAL;
	}

	if (ehdr->phentsize != sizeof(struct elf64_phdr)) {
		pr_err("elf64 phentsize %d isn't equal to sizeof(struct elf64_phdr) %ld\n",
				ehdr->phentsize, sizeof(struct elf64_phdr));
		return -EINVAL;
	}

	if (ehdr->phoff < sizeof(struct elf64_hdr)) {
		pr_err("ehdr->phoff %llx is smaller than sizeof(struct elf64_hdr) %lx\n",
				ehdr->phoff, sizeof(struct elf64_hdr));
		return -EINVAL;
	}

	for (idx = 0; idx < ehdr->phnum; idx++) {
		void *hva;
		u64 gpa;

		phdr = (struct elf64_phdr *)(img_va + ehdr->phoff + idx * sizeof(struct elf64_phdr));

		if ((phdr->type != 1) || (phdr->filesz == 0))
			continue;

		hva = (void *)(img_va + phdr->offset);
		gpa = phdr->paddr + IMG_START_GPA;

		guest_memory_write(tee_vm->ept_pa, gpa, hva, phdr->filesz);
	}

	exec_vmwritel(GUEST_RIP, ehdr->entry);
	exec_vmwritel(GUEST_RFLAGS, 0x2);
	exec_vmwritel(GUEST_RSP, GUEST_BOOT_STACK);

	return 0;
}

static int prepare_guest_state(struct tee_root_vm *tee_vm, unsigned long img_va, unsigned long img_size)
{
	prepare_guest_segment_register(tee_vm);
	prepare_guest_page_table(tee_vm);
	// enable 64 bit page mode
	exec_vmwritel(GUEST_CR0, X86_CR0_PG | X86_CR0_PE | X86_CR0_NE | X86_CR0_ET);
	exec_vmwritel(CR0_READ_SHADOW, 0xe0000011);
	exec_vmwritel(CR0_GUEST_HOST_MASK, ~0x8);
	exec_vmwritel(GUEST_CR4, X86_CR4_PAE | X86_CR4_VMXE);
	exec_vmwritel(CR4_READ_SHADOW, 0x20);
	exec_vmwritel(CR4_GUEST_HOST_MASK, ~0x178e);
	//exec_vmwritel(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
	exec_vmwritel(GUEST_IA32_EFER, 0x500);
	// MSRs
	exec_vmwritel(GUEST_IA32_DEBUGCTL, 0);
	exec_vmwrite32(GUEST_SYSENTER_CS, 0);
	exec_vmwritel(GUEST_SYSENTER_ESP, 0);
	exec_vmwritel(GUEST_SYSENTER_EIP, 0);
	exec_vmwritel(GUEST_IA32_PAT, 0x0007040600070406);
	exec_vmwritel(GUEST_BNDCFGS, 0);
	//Guest non register state
	exec_vmwrite32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	exec_vmwrite32(GUEST_INTERRUPTIBILITY_INFO, 0);
	exec_vmwritel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	exec_vmwrite64(VMCS_LINK_POINTER, -1ull);

	return load_guest_elf_img(tee_vm, img_va, img_size);
}

static int prepare_vmcs(struct vbh_data *vbh, unsigned long img_va,
			unsigned long img_size)
{
	struct tee_root_vm *tee_vm = vbh->tee_vm;
	struct vmcs *vmcs_ptr;
	struct vmcs_config *vmcs_config;
	int ret;
	u64 eptp;

	if (tee_vm == NULL
	    || tee_vm->vcpu_data == NULL
	    || tee_vm->vcpu_data->vcpu_vmx.pcpu_vmcs == NULL) {
		pr_err("tee_vm structure isn't complete\n");
		return -EINVAL;
	}

	vmcs_ptr = tee_vm->vcpu_data->vcpu_vmx.pcpu_vmcs;

	exec_vmptrld(vbh_pa(vmcs_ptr));

	ret = prepare_guest_state(tee_vm, img_va, img_size);

	/* load host states, delay it to TEE run, otherwise
	   host couldn't recovery at TEE vmexit, it seems
	   host use different GDT between two vmcalls. */
	//load_host_state_area(vbh_pa(vbh->host_cr3));

	vmcs_config = &tee_vm->vcpu_data->vmcs_config;
	eptp = construct_eptp(tee_vm->ept_pa, &vbh->vmx_cap);
	load_execution_control(vbh, vmcs_config, eptp, false);

	load_vmexit_control(vmcs_config);

	load_vmentry_control(vmcs_config);

	exec_vmclear(vbh_pa(vmcs_ptr));

	return ret;
}

int handle_tee_create(struct vbh_data *vbh, unsigned long ept_pa,
		unsigned long mem_size, unsigned long img_va,
		unsigned long img_size)
{
	struct tee_root_vm  *tee_vm;
	int ret;

	tee_vm = vbh_malloc(vbh, sizeof(struct tee_root_vm));
	if (!tee_vm)
		return -ENOMEM;

	tee_vm->ept_pa = ept_pa;
	tee_vm->mem_size = mem_size;
	vbh->tee_vm = tee_vm;

	process_tee_ept(vbh, true);

	ret = construct_vcpu_data(vbh);
	if (ret < 0) {
		pr_err("failed to construct_vcpu_data\n");
		goto destroy_vcpu;
	}

	ret = prepare_vmcs(vbh, img_va, img_size);
	if (ret < 0) {
		pr_err("prepare_vmcs() failed\n");
		goto destroy_vcpu;
	}

	return 0;

destroy_vcpu:
	destroy_vcpu_data(vbh);
	process_tee_ept(vbh, false);
	vbh_free(vbh, (void *)tee_vm);
	return ret;
}

struct injection_info {
	bool valid;
	bool suspend;

	u32 vector;
	u32 type;
};

static int get_intr_info(struct injection_info *inject)
{
	u32 intr_info;

	intr_info = exec_vmread32(VM_EXIT_INTR_INFO);
	if ((intr_info & INTR_INFO_VALID_MASK) == 0)
		return -EINVAL;

	inject->valid = true;
	inject->vector = intr_info & INTR_INFO_VECTOR_MASK;
	inject->type = intr_info & INTR_INFO_INTR_TYPE_MASK;

	return 0;
}

static void skip_emulated_instruction(struct tee_vcpu_vmx *vcpu)
{
	unsigned long rip;

	if (!vcpu->skip_instruction_not_used) {
		rip = exec_vmreadl(GUEST_RIP);
		rip += exec_vmread32(VM_EXIT_INSTRUCTION_LEN);
		exec_vmwritel(GUEST_RIP, rip);
	}
}

static int tee_vm_exit_handler(struct tee_root_vm *tee_vm, struct injection_info *inject)
{
	struct tee_vcpu_vmx *vcpu;
	u32 vmexit_reason;
	int status = -EPERM;

	vcpu = &tee_vm->vcpu_data->vcpu_vmx;

	vmexit_reason = exec_vmread32(VM_EXIT_REASON);
	vcpu->skip_instruction_not_used = true;

	vcpu->instr_info = exec_vmread32(VMX_INSTRUCTION_INFO);
	vcpu->exit_qualification = exec_vmreadl(EXIT_QUALIFICATION);

	switch (vmexit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		//pr_err("TEE vm exit_reason: EXIT_REASON_EXCEPTION_NMI or EXCEPTION_EXIT\n");
		//status = get_intr_info(inject);
		status = 0;
		break;
	case EXIT_REASON_CPUID:
		pr_err("TEE vm exit_reason: EXIT_REASON_CPUID\n");
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		pr_err("TEE vm exit_reason: EXIT_REASON_EPT_MISCONFIG\n");
		break;
	case EXIT_REASON_EPT_VIOLATION:
		pr_err("TEE vm exit_reason: EXIT_REASON_EPT_VIOLATION\n");
		break;
	case EXIT_REASON_VMCALL:
		vcpu->skip_instruction_not_used = false;
		pr_err("TEE vm exit_reason: EXIT_REASON_VMCALL, nr: 0x%lx\n", vcpu->regs[VCPU_REGS_RAX]);
		if (vcpu->regs[VCPU_REGS_RAX] ==  OPTEE_VMCALL_SMC) {
			inject->valid = true;
			inject->suspend = true;
		}
		status = 0;
		break;
	case EXIT_REASON_CR_ACCESS:
		pr_err("TEE vm exit_reason: EXIT_REASON_CR_ACCESS\n");
		break;
	case EXIT_REASON_MSR_READ:
		pr_err("TEE vm exit_reason: EXIT_REASON_MSR_READ\n");
		break;
	case EXIT_REASON_MSR_WRITE:
		pr_err("TEE vm exit_reason: EXIT_REASON_MSR_WRITE\n");
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		pr_err("TEE vm exit_reason: EXIT_REASON_IO_INSTRUCTION\n");
		break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		status = get_intr_info(inject);
		break;
	default:
		pr_err("TEE Unhandled vmexit reason 0x%x.\n", vmexit_reason);
		break;
	}

	skip_emulated_instruction(vcpu);

	return status;
}

#if 0
static void vmx_dump_sel(char *name, uint32_t sel)
{
	pr_err("%s sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016lx\n",
	       name, exec_vmread16(sel),
	       exec_vmread32(sel + GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR),
	       exec_vmread32(sel + GUEST_ES_LIMIT - GUEST_ES_SELECTOR),
	       exec_vmreadl(sel + GUEST_ES_BASE - GUEST_ES_SELECTOR));
}

static void vmx_dump_dtsel(char *name, uint32_t limit)
{
	pr_err("%s                           limit=0x%08x, base=0x%016lx\n",
	       name, exec_vmread32(limit),
	       exec_vmreadl(limit + GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
}

void dump_vmcs(void)
{
	u32 vmentry_ctl, vmexit_ctl;
	u32 cpu_based_exec_ctrl, pin_based_exec_ctrl, secondary_exec_control;
	unsigned long cr4;
	u64 efer;
	int i, n;

	vmentry_ctl = exec_vmread32(VM_ENTRY_CONTROLS);
	vmexit_ctl = exec_vmread32(VM_EXIT_CONTROLS);
	cpu_based_exec_ctrl = exec_vmread32(CPU_BASED_VM_EXEC_CONTROL);
	pin_based_exec_ctrl = exec_vmread32(PIN_BASED_VM_EXEC_CONTROL);
	cr4 = exec_vmreadl(GUEST_CR4);
	efer = exec_vmread64(GUEST_IA32_EFER);
	secondary_exec_control = exec_vmread32(SECONDARY_VM_EXEC_CONTROL);

	pr_err("*** Guest State ***\n");
	pr_err("CR0: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       exec_vmreadl(GUEST_CR0), exec_vmreadl(CR0_READ_SHADOW),
	       exec_vmreadl(CR0_GUEST_HOST_MASK));
	pr_err("CR4: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       cr4, exec_vmreadl(CR4_READ_SHADOW), exec_vmreadl(CR4_GUEST_HOST_MASK));
	pr_err("CR3 = 0x%016lx\n", exec_vmreadl(GUEST_CR3));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT) &&
	    (cr4 & X86_CR4_PAE) && !(efer & EFER_LMA)) {
		pr_err("PDPTR0 = 0x%016llx  PDPTR1 = 0x%016llx\n",
		       exec_vmread64(GUEST_PDPTR0), exec_vmread64(GUEST_PDPTR1));
		pr_err("PDPTR2 = 0x%016llx  PDPTR3 = 0x%016llx\n",
		       exec_vmread64(GUEST_PDPTR2), exec_vmread64(GUEST_PDPTR3));
	}
	pr_err("RSP = 0x%016lx  RIP = 0x%016lx\n",
	       exec_vmreadl(GUEST_RSP), exec_vmreadl(GUEST_RIP));
	pr_err("RFLAGS=0x%08lx         DR7 = 0x%016lx\n",
	       exec_vmreadl(GUEST_RFLAGS), exec_vmreadl(GUEST_DR7));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       exec_vmreadl(GUEST_SYSENTER_ESP),
	       exec_vmread32(GUEST_SYSENTER_CS), exec_vmreadl(GUEST_SYSENTER_EIP));
	vmx_dump_sel("CS:  ", GUEST_CS_SELECTOR);
	vmx_dump_sel("DS:  ", GUEST_DS_SELECTOR);
	vmx_dump_sel("SS:  ", GUEST_SS_SELECTOR);
	vmx_dump_sel("ES:  ", GUEST_ES_SELECTOR);
	vmx_dump_sel("FS:  ", GUEST_FS_SELECTOR);
	vmx_dump_sel("GS:  ", GUEST_GS_SELECTOR);
	vmx_dump_dtsel("GDTR:", GUEST_GDTR_LIMIT);
	vmx_dump_sel("LDTR:", GUEST_LDTR_SELECTOR);
	vmx_dump_dtsel("IDTR:", GUEST_IDTR_LIMIT);
	vmx_dump_sel("TR:  ", GUEST_TR_SELECTOR);
	if ((vmexit_ctl & (VM_EXIT_SAVE_IA32_PAT | VM_EXIT_SAVE_IA32_EFER)) ||
	    (vmentry_ctl & (VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER)))
		pr_err("EFER =     0x%016llx  PAT = 0x%016llx\n",
		       efer, exec_vmread64(GUEST_IA32_PAT));
	pr_err("DebugCtl = 0x%016llx  DebugExceptions = 0x%016lx\n",
	       exec_vmread64(GUEST_IA32_DEBUGCTL),
	       exec_vmreadl(GUEST_PENDING_DBG_EXCEPTIONS));
	if (vmentry_ctl & VM_ENTRY_LOAD_BNDCFGS)
		pr_err("BndCfgS = 0x%016llx\n", exec_vmread64(GUEST_BNDCFGS));
	pr_err("Interruptibility = %08x  ActivityState = %08x\n",
	       exec_vmread32(GUEST_INTERRUPTIBILITY_INFO),
	       exec_vmread32(GUEST_ACTIVITY_STATE));
	if (secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
		pr_err("InterruptStatus = %04x\n",
		       exec_vmread16(GUEST_INTR_STATUS));

	pr_err("*** Host State ***\n");
	pr_err("RIP = 0x%016lx  RSP = 0x%016lx\n",
	       exec_vmreadl(HOST_RIP), exec_vmreadl(HOST_RSP));
	pr_err("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x TR=%04x\n",
	       exec_vmread16(HOST_CS_SELECTOR), exec_vmread16(HOST_SS_SELECTOR),
	       exec_vmread16(HOST_DS_SELECTOR), exec_vmread16(HOST_ES_SELECTOR),
	       exec_vmread16(HOST_FS_SELECTOR), exec_vmread16(HOST_GS_SELECTOR),
	       exec_vmread16(HOST_TR_SELECTOR));
	pr_err("FSBase=%016lx GSBase=%016lx TRBase=%016lx\n",
	       exec_vmreadl(HOST_FS_BASE), exec_vmreadl(HOST_GS_BASE),
	       exec_vmreadl(HOST_TR_BASE));
	pr_err("GDTBase=%016lx IDTBase=%016lx\n",
	       exec_vmreadl(HOST_GDTR_BASE), exec_vmreadl(HOST_IDTR_BASE));
	pr_err("CR0=%016lx CR3=%016lx CR4=%016lx\n",
	       exec_vmreadl(HOST_CR0), exec_vmreadl(HOST_CR3),
	       exec_vmreadl(HOST_CR4));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       exec_vmreadl(HOST_IA32_SYSENTER_ESP),
	       exec_vmread32(HOST_IA32_SYSENTER_CS),
	       exec_vmreadl(HOST_IA32_SYSENTER_EIP));
	if (vmexit_ctl & (VM_EXIT_LOAD_IA32_PAT | VM_EXIT_LOAD_IA32_EFER))
		pr_err("EFER = 0x%016llx  PAT = 0x%016llx\n",
		       exec_vmread64(HOST_IA32_EFER),
		       exec_vmread64(HOST_IA32_PAT));

	pr_err("*** Control State ***\n");
	pr_err("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
	       pin_based_exec_ctrl, cpu_based_exec_ctrl, secondary_exec_control);
	pr_err("EntryControls=%08x ExitControls=%08x\n", vmentry_ctl, vmexit_ctl);
	pr_err("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
	       exec_vmread32(EXCEPTION_BITMAP),
	       exec_vmread32(PAGE_FAULT_ERROR_CODE_MASK),
	       exec_vmread32(PAGE_FAULT_ERROR_CODE_MATCH));
	pr_err("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
	       exec_vmread32(VM_ENTRY_INTR_INFO_FIELD),
	       exec_vmread32(VM_ENTRY_EXCEPTION_ERROR_CODE),
	       exec_vmread32(VM_ENTRY_INSTRUCTION_LEN));
	pr_err("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
	       exec_vmread32(VM_EXIT_INTR_INFO),
	       exec_vmread32(VM_EXIT_INTR_ERROR_CODE),
	       exec_vmread32(VM_EXIT_INSTRUCTION_LEN));
	pr_err("        reason=%08x qualification=%016lx\n",
	       exec_vmread32(VM_EXIT_REASON), exec_vmreadl(EXIT_QUALIFICATION));
	pr_err("IDTVectoring: info=%08x errcode=%08x\n",
	       exec_vmread32(IDT_VECTORING_INFO_FIELD),
	       exec_vmread32(IDT_VECTORING_ERROR_CODE));
	pr_err("TSC Offset = 0x%016llx\n", exec_vmread64(TSC_OFFSET));
	if (secondary_exec_control & SECONDARY_EXEC_TSC_SCALING)
		pr_err("TSC Multiplier = 0x%016llx\n",
		       exec_vmread64(TSC_MULTIPLIER));
	if (cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW) {
		if (secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
			u16 status = exec_vmread16(GUEST_INTR_STATUS);
			pr_err("SVI|RVI = %02x|%02x ", status >> 8, status & 0xff);
		}
		pr_cont("TPR Threshold = 0x%02x\n", exec_vmread32(TPR_THRESHOLD));
		if (secondary_exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
			pr_err("APIC-access addr = 0x%016llx ", exec_vmread64(APIC_ACCESS_ADDR));
		pr_cont("virt-APIC addr = 0x%016llx\n", exec_vmread64(VIRTUAL_APIC_PAGE_ADDR));
	}
	if (pin_based_exec_ctrl & PIN_BASED_POSTED_INTR)
		pr_err("PostedIntrVec = 0x%02x\n", exec_vmread16(POSTED_INTR_NV));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT))
		pr_err("EPT pointer = 0x%016llx\n", exec_vmread64(EPT_POINTER));
	n = exec_vmread32(CR3_TARGET_COUNT);
	for (i = 0; i + 1 < n; i += 4)
		pr_err("CR3 target%u=%016lx target%u=%016lx\n",
		       i, exec_vmreadl(CR3_TARGET_VALUE0 + i * 2),
		       i + 1, exec_vmreadl(CR3_TARGET_VALUE0 + i * 2 + 2));
	if (i < n)
		pr_err("CR3 target%u=%016lx\n",
		       i, exec_vmreadl(CR3_TARGET_VALUE0 + i * 2));
	if (secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
		pr_err("PLE Gap=%08x Window=%08x\n",
		       exec_vmread32(PLE_GAP), exec_vmread32(PLE_WINDOW));
	if (secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
		pr_err("Virtual processor ID = 0x%04x\n",
		       exec_vmread16(VIRTUAL_PROCESSOR_ID));
}
#endif

extern int __nested_vcpu_run(unsigned long *, int);
extern void __vmexit(void);

int handle_te_run(struct vbh_data *vbh, struct vmcs *host_vmcs)
{
	struct tee_root_vm *tee_vm;
	struct tee_vcpu_vmx *vcpu;
	struct vmcs *vmcs_ptr;
	int status;
	struct injection_info inject = {false, 0, 0};

	tee_vm = vbh->tee_vm;
	if (tee_vm == NULL
	    || tee_vm->vcpu_data == NULL
	    || tee_vm->vcpu_data->vcpu_vmx.pcpu_vmcs == NULL) {
		pr_err("tee_vm structure isn't complete\n");
		return -EINVAL;
	}

	vcpu = &tee_vm->vcpu_data->vcpu_vmx;
	vmcs_ptr = vcpu->pcpu_vmcs;

	exec_vmptrld(vbh_pa(vmcs_ptr));

	load_host_state_area(vbh_pa(vbh->host_cr3));

	exec_vmwritel(HOST_RIP, (u64)__vmexit);

	#if 0
	dump_vmcs();
	#endif

	while (1) {
		if (!tee_vm->launched) {
			status = __nested_vcpu_run(vcpu->regs, true);
			tee_vm->launched = true;
		} else
			status = __nested_vcpu_run(vcpu->regs, false);

		if (status == 1) {
			pr_err("Tee Vmlauch or Vmresume failed\n");
			break;
		}

		status = tee_vm_exit_handler(tee_vm, &inject);
		if ((status < 0) || ((status == 0) && (inject.valid)))
			break;
	}

	exec_vmclear(vbh_pa(vmcs_ptr));
	tee_vm->launched = false;

	if (status == 0 && inject.valid) {
		exec_vmptrld(vbh_pa(host_vmcs));

		if (!inject.suspend) {
			u32 intr;

			intr = inject.vector | inject.type | INTR_INFO_VALID_MASK;
			exec_vmwrite32(VM_ENTRY_INTR_INFO_FIELD, intr);
		} else
			status = OPTEE_VMCALL_SMC;
	} else {
		destroy_vcpu_data(vbh);
		process_tee_ept(vbh, false);
		vbh_free(vbh, (void *)tee_vm);
		exec_vmptrld(vbh_pa(host_vmcs));
		status = -EINVAL;
	}

	return status;
}
