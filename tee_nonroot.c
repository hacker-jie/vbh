#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/kvm_para.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/sched.h>

#include "tee_nonroot.h"
#include "pt.h"

#define TEE_GUEST_MEM (1 << 30)  // 16MB at first
#define TEE_IMAGE_PATH "/home/test/access.elf"

struct tee_vm {
	unsigned long *eptp;
	void *img_va;
	unsigned long img_size;

	unsigned long guest_mem_size;
};

static void *allocate_page(void)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL);
	if (page)
		return page_address(page);
	else
		return NULL;
}

int allocate_ept_mem(unsigned long *parent, unsigned long end_pfn,
		unsigned long level, bool is_last_entry)
{
	unsigned long *pt, pt_pfn;
	u64 pteval;

	pt = (unsigned long *)allocate_page();
	if (!pt)
		return -ENOMEM;
	pt_pfn = __pa((void *)pt) >> PAGE_SHIFT;
	pteval = (pt_pfn << EPT_PAGE_SHIFT) | PTE_READ | PTE_WRITE | PTE_EXECUTE;
	if (level == 1)
		pteval |= PTE_MEM_TYPE_WB;
	*parent = pteval;

	if (level != 1) {
		int status, idx;
		int end_idx = (1 << EPT_LEVEL_STRIDE) - 1;
		bool end = false;

		if (is_last_entry)
			end_idx = pfn_level_offset(end_pfn, level - 1);

		for (idx = 0; idx <= end_idx; idx++) {
			if (is_last_entry && idx == end_idx)
				end = true;

			status = allocate_ept_mem(pt + idx, end_pfn,
						  level - 1, end);
			if (status < 0)
				return status;
		}
	}

	return 0;
}

int pre_allocate_ept(struct tee_vm *tee, unsigned long mem_size)
{
	int idx, status;
	unsigned long end_pfn = mem_size >> EPT_PAGE_SHIFT;
	int end_idx = pfn_level_offset(end_pfn, EPT_MAX_LEVEL);
	bool end = false;

	tee->eptp = (unsigned long *)allocate_page();
	if (!tee->eptp)
		return -ENOMEM;

	for (idx = 0; idx <= end_idx; idx++) {
		if (idx == end_idx)
			end = true;

		status = allocate_ept_mem(tee->eptp + idx, end_pfn,
					  EPT_MAX_LEVEL, end);
		if (status < 0)
			return status;
	}

	return 0;
}

void free_ept_mem(unsigned long *parent, unsigned long end_pfn,
		  unsigned long level, bool is_last_entry)
{
	unsigned long *pt;
	unsigned long pt_pa = *parent & PT64_BASE_ADDR_MASK;

	if (pt_pa == 0)
		return;

	pt = (unsigned long *)__va(pt_pa);

	if (level != 1) {
		int idx;
		int end_idx = (1 << EPT_LEVEL_STRIDE) - 1;
		bool end = false;

		if (is_last_entry)
			end_idx = pfn_level_offset(end_pfn, level - 1);

		for (idx = 0; idx <= end_idx; idx++) {
			if (is_last_entry && idx == end_idx)
				end = true;

			free_ept_mem(pt + idx, end_pfn,
				     level - 1, end);
		}
	}

	free_page((unsigned long)pt);
}

void free_ept(struct tee_vm *tee, unsigned long mem_size)
{
	int idx;
	unsigned long end_pfn = mem_size >> EPT_PAGE_SHIFT;
	int end_idx = pfn_level_offset(end_pfn, EPT_MAX_LEVEL);
	bool end = false;

	if (!tee->eptp)
		return;

	for (idx = 0; idx <= end_idx; idx++) {
		if (idx == end_idx)
			end = true;

		free_ept_mem(tee->eptp + idx, end_pfn,
			     EPT_MAX_LEVEL, end);
	}

	free_page((unsigned long)tee->eptp);
}

int load_tee_image(struct tee_vm *tee)
{
	struct file *file;
	loff_t file_size, pos;
	ssize_t bytes = 0;
	int ret;
	void *virt;

	file = filp_open(TEE_IMAGE_PATH, O_RDONLY, 0);
	if (IS_ERR(file)) {
		pr_err("failed to open TEE image file: %s\n", TEE_IMAGE_PATH);
		return PTR_ERR(file);
	}

	if (!S_ISREG(file_inode(file)->i_mode)) {
		pr_err("TEE image file isn't a regular file\n");
		ret = -EINVAL;
		goto out;
	}

	file_size = i_size_read(file_inode(file));
	if ((file_size < 0) || (file_size > SIZE_MAX)) {
		pr_err("TEE image file size is invalid");
		ret = -EINVAL;
		goto out;
	}

	//page_num = (file_size + PAGE_SIZE - 1) / PAGE_SIZE;
	//order = fls(page_num);
	//if (page_num > (1 << order))
	//	order++;
	//page = alloc_pages(GFP_KERNEL, order);
	//if (!page) {
	//	pr_err("Not enough mem in alloc_pages() for IE image\n");
	//	ret = -ENOMEM;
	//	goto out;
	//}

	virt = vzalloc(file_size);
	if (virt == NULL) {
		pr_err("Not enough mem in vzalloc for TEE image\n");
		ret = -ENOMEM;
		goto out;
	}
	pos = 0;
	while (pos < file_size) {
		bytes = kernel_read(file, virt + pos, file_size - pos, &pos);
		if (bytes < 0) {
			pr_err("Read Image file fail: %lx\n", bytes);
			vfree(virt);
			ret = bytes;
			goto out;
		}

		if (bytes == 0)
			break;
	}

	if (pos != file_size) {
		pr_err("Read Image file fail, end_pos: %llx != file_size: %llx\n", pos, file_size);
		vfree(virt);
		ret = -EIO;
	}

	tee->img_va = virt;
	tee->img_size = file_size;
	ret = 0;
out:
	fput(file);
	return ret;
}

void unload_tee_image(struct tee_vm *tee)
{
	vfree(tee->img_va);
}

static int tee_run(void *data)
{
	struct tee_vm *tee = (struct tee_vm *)data;
	int status;

	while (1) {
		status = kvm_hypercall0(TEE_HYPERCALL_RUN);

		if (status < 0)
			break;

		if (status == OPTEE_VMCALL_SMC) { 
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
			set_current_state(TASK_RUNNING);
		}

		if (need_resched())
			schedule();
	}

	free_ept(tee, tee->guest_mem_size);
	kfree(tee);

	return 0;
}

void setup_tee_env(void)
{
	int status;
	struct tee_vm  *tee;
	unsigned long guest_mem_size = TEE_GUEST_MEM;
	struct task_struct *thread_ptr;

	tee = kzalloc(sizeof(struct tee_vm), GFP_KERNEL);

	if ((guest_mem_size & ((1 << 20) - 1)) != 0) {
		pr_err("guest memory size should be aligned to MB: 0x%lx\n", guest_mem_size);
		return;
	}

	tee->guest_mem_size = guest_mem_size;
	status = pre_allocate_ept(tee, guest_mem_size);
	if (status < 0) {
		pr_err("pre_allocate_ept fail: %d\n", status);
		goto out;
	}

	status = load_tee_image(tee);
	if (status < 0) {
		pr_err("load_tee_image fail: %d\n", status);
		goto out;
	}

	status = kvm_hypercall4(TEE_HYPERCALL_CREATE, (unsigned long)__pa(tee->eptp),
			   guest_mem_size, (unsigned long)tee->img_va,
			   tee->img_size);
	
	// TEE image has been copied into te guest memory, free it own
	unload_tee_image(tee);

	if (status  < 0) {
		pr_err("TE_HYPERCALL_CREATE failed\n");
		goto out;
	}

	thread_ptr = kthread_create(tee_run, tee, "tee-run");
	wake_up_process(thread_ptr);

	return;
out:
	free_ept(tee, guest_mem_size);
	kfree(tee);

	return;
}
