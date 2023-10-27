#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <asm/bitops.h>

#include "mem.h"
#include "pt.h"
#include "page_tracker.h"

struct vbh_data;

static const struct mp_element mpes[MEM_POOL_COUNT] = {
	{ ELEMENT_BASE_SIZE, INITIAL_SIZE_128M },
	{ ELEMENT_BASE_SIZE * (1 << 1), INITIAL_SIZE_128M },
	{ ELEMENT_BASE_SIZE * (1 << 2), INITIAL_SIZE_64M },
	{ ELEMENT_BASE_SIZE * (1 << 3), INITIAL_SIZE_32M },
	{ PAGE_SIZE, INITIAL_SIZE_128M },
};

static int protect_mem_pools(struct vbh_data *vbh, u64 pa, u64 size)
{
	if (vbh_set_ram_metadata_in_range(vbh, pa, size, NULL, NULL, VBH_ID))
		BUG_ON(printk("invalid pa 0x%llx size %lld. Buggy code?\n", pa, size));

	return vbh_control_gpa_access_in_range(vbh, true, pa, size,
					       false, false, false, NULL);
}

static int create_mem_pool(struct vbh_data *vbh, int element_size,
			   int total_pool_size, struct list_head *head)
{
	unsigned long max_pool_size = MAX_BITMAP_BITS * element_size;
	unsigned long header_size = sizeof(struct mem_pool);
	struct mem_pool *pool, *n;
	int count, i;
	size_t size = PAGE_ALIGN(max_pool_size + header_size);
	u32 free_count;

	if (size >= MAX_MEMPOOL_SIZE)
		size = MAX_MEMPOOL_SIZE;

	free_count = (size - header_size) / element_size;
	if (free_count > MAX_BITMAP_BITS)
		free_count = MAX_BITMAP_BITS;
	count = DIV_ROUND_UP(total_pool_size, size);

	for (i = 0; i < count; i++) {
		pool = alloc_pages_exact(size, GFP_KERNEL | __GFP_ZERO);
		if (!pool)
			goto free;

		list_add_tail(&pool->list, head);

		if (protect_mem_pools(vbh, vbh_pa(pool), size))
			goto free;

		pool->size = size;
		pool->element_size = element_size;
		pool->total_count = free_count;
		atomic_set(&pool->free_count, free_count);
		pool->last_bitmap_index = DIV_ROUND_UP(free_count, BITS_PER_LONG);
		pool->last_bitmap_bit = free_count % BITS_PER_LONG;
		if (!pool->last_bitmap_bit)
			pool->last_bitmap_bit = BITS_PER_LONG;
		//pr_info("%s: element size %d: last_bitmap_index %d, last_bitmap_bit %d free_count %d\n",
		//		__func__, element_size, pool->last_bitmap_index, pool->last_bitmap_bit,
		//		atomic_read(&pool->free_count));
	}

	if (i != 0) {
		pool = list_last_entry(head, struct mem_pool, list);
		pool->last_pool = true;
	}

	return i;
free:
	if (list_empty(head))
		return 0;

	list_for_each_entry_safe(pool, n, head, list) {
		// Save size as pool pages might be cleared before free_pages
		size_t size = pool->size;
		list_del(&pool->list);
		free_pages_exact((void *)pool, size);
	}

	return 0;
}

static int initialize_mem_pool(struct vbh_data *vbh,
			struct mem_pool_head *mp_head,
			int element_size, int initial_size)
{
	INIT_LIST_HEAD(&mp_head->head);

	mp_head->count = create_mem_pool(vbh, element_size, initial_size,
					 &mp_head->head);
	if (mp_head->count == 0)
		return -ENOMEM;

	mp_head->element_size = element_size;

	return 0;
}

static void uninitialize_mem_pool(struct vbh_data *vbh,
				  struct mem_pool_head *mp_head)
{
	struct mem_pool *pool, *n;

	if (list_empty(&mp_head->head))
		return;

	list_for_each_entry_safe(pool, n, &mp_head->head, list) {
		// Save size as pool pages might be cleared before free_pages
		size_t size = pool->size;
		list_del(&pool->list);
		free_pages_exact((void *)pool, size);
	}
}

int create_mem_pools(struct vbh_data *vbh)
{
	int i, ret;
	struct mem_pools *vbh_mpools = NULL;

	vbh_mpools = alloc_pages_exact(sizeof(struct mem_pools),
				GFP_KERNEL | __GFP_ZERO);
	if (!vbh_mpools) {
		pr_err("%s: failed to create mem pools\n", __func__);
		return -ENOMEM;
	}

	ret = protect_mem_pools(vbh, vbh_pa(vbh_mpools), sizeof(struct mem_pools));
	if (ret)
		return -EINVAL;

	for (i = 0; i < MEM_POOL_COUNT; i++) {
		vbh_mpools->mpels[i] = mpes[i];
		ret = initialize_mem_pool(vbh, &vbh_mpools->mp[i],
					  mpes[i].element_size,
					  mpes[i].initial_size);
		if (ret) {
			pr_err("%s: failed to initialize mem pool %d\n",
				__func__, i);
			goto err;
		}
	}

	vbh_mpools->initialized = true;
	vbh->mps = vbh_mpools;

	return 0;
err:
	for (; i > 0; i--)
		uninitialize_mem_pool(vbh, &vbh_mpools->mp[i - 1]);

	free_pages_exact((void *)vbh_mpools, sizeof(struct mem_pools));

	return -ENOMEM;
}

void destroy_mem_pools(struct vbh_data *vbh)
{
	size_t size = sizeof(struct mem_pools);
	int i;

	if (!vbh || !vbh->mps)
		return;

	for (i = 0; i < MEM_POOL_COUNT; i++)
		uninitialize_mem_pool(vbh, &vbh->mps->mp[i]);

	free_pages_exact((void *)vbh->mps, size);
}
