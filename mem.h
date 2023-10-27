#ifndef __VBH_MEM_H
#define	__VBH_MEM_H

#include <asm/page.h>
#include "lock.h"

#define INITIAL_SIZE_128M (128 * 1024 * 1024)
#define INITIAL_SIZE_64M (64 * 1024 * 1024)
#define INITIAL_SIZE_32M (32 * 1024 * 1024)

#define MAX_BITMAP_LEN	512
#define BITMAP_LOCK_COVERS	4
#define MAX_BITMAP_LOCK	(MAX_BITMAP_LEN / BITMAP_LOCK_COVERS)
#define MAX_BITMAP_BITS	(MAX_BITMAP_LEN * BITS_PER_LONG)

#define MAX_MEMPOOL_SIZE ((1 << (MAX_ORDER - 1)) * PAGE_SIZE)

struct mem_pool {
	// Use one page as bitmap, so one mem_pool maximum size is:
	// 32bytes mem pool: 1M
	// 64bytes mem pool: 2M
	// ...
	// 512bytes mem pool: 16M
	u64 bitmaps[MAX_BITMAP_LEN]; // Max one page
	slock_t bitmap_lock[MAX_BITMAP_LOCK];
	struct list_head list;
	size_t size;
	u16 last_bitmap_index;
	u16 last_bitmap_bit;
	atomic_t free_count;
	u32 total_count;
	int element_size;
	bool last_pool;
} __aligned(PAGE_SIZE);

struct mem_pool_head {
	u32 element_size;
	u32 count;
	struct list_head head;
};

#define MEM_POOL_COUNT		5
#define ELEMENT_BASE_SIZE	32

struct mp_element {
	u32 element_size;
	u32 initial_size;
};

struct mem_pools {
	struct mem_pool_head mp[MEM_POOL_COUNT];
	struct mp_element mpels[MEM_POOL_COUNT];
	bool initialized;
} __aligned(PAGE_SIZE);

#endif
