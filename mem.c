#include "mem.h"
#include "vbh.h"

//#define VBH_RTMM_DEBUG
#undef VBH_RTMM_DEBUG

#ifdef VBH_RTMM_DEBUG
#define rtmm_pr(format...) trace_printk(format)
//#define rtmm_pr(format...) pr_info(format)
#else
#define rtmm_pr(format...)
#endif

static int size_to_index(struct vbh_data *vbh, int size)
{
	int i;

	for (i = 0; i < MEM_POOL_COUNT; i++) {
		if (size <= vbh->mps->mpels[i].element_size)
			break;
	}

	if (i == MEM_POOL_COUNT)
		return -EINVAL;

	return i;
}

static void *__malloc_from_mem_pool(struct mem_pool *pool, int element_size)
{
	void *base_va = (void *)pool + sizeof(struct mem_pool), *va;
	int i, bit;
	bool available = false;
	u64 mask;

retry:
	for (i = 0; i < pool->last_bitmap_index; i++) {
		if (i + 1 == pool->last_bitmap_index)
			mask = (1ULL << pool->last_bitmap_bit) - 1;
		else
			mask = ~0ULL;
		if (pool->bitmaps[i] != mask) {
			slock_t *slock = &pool->bitmap_lock[(i / BITMAP_LOCK_COVERS)];
			available = true;
			if (!slock_trylock(slock)) {
				rtmm_pr("%s: lock holded: pool 0x%llx base_va 0x%llx index %d bitmap 0x%llx element %d\n",
					__func__, (u64)pool, (u64)base_va, i, pool->bitmaps[i], element_size);
				continue;
			}
			if (pool->bitmaps[i] != mask) {
				bit = ffz(pool->bitmaps[i]);
				pool->bitmaps[i] |= (1ULL << bit);
				slock_unlock(slock);
			} else {
				int end = DIV_ROUND_UP(i, BITMAP_LOCK_COVERS) * BITMAP_LOCK_COVERS;
				for (i++; i < end; i++) {
					if (i + 1 == pool->last_bitmap_index)
						mask = (1ULL << pool->last_bitmap_bit) - 1;
					else
						mask = ~0ULL;
					if (pool->bitmaps[i] != mask) {
						bit = ffz(pool->bitmaps[i]);
						pool->bitmaps[i] |= (1ULL << bit);
						slock_unlock(slock);
						break;
					}
					rtmm_pr("%s: not found: pool 0x%llx base_va 0x%llx index %d bitmap 0x%llx element %d\n",
						__func__, (u64)pool, (u64)base_va, i, pool->bitmaps[i], element_size);
				}

				// No available memory to allocate, try another
				if (i == end) {
					i--;
					available = false;
					slock_unlock(slock);
					continue;
				}
			}

			atomic_dec(&pool->free_count);
			va = base_va + (i * BITS_PER_LONG + bit) * element_size;
			rtmm_pr("%s: pool 0x%llx base_va 0x%llx index %d bit %d bitmap 0x%llx va 0x%llx element %d\n",
				__func__, (u64)pool, (u64)base_va, i, bit, pool->bitmaps[i], (u64)va, element_size);
			return va;
		}
	}

	if (available) {
		available = false;
		goto retry;
	}

	pr_err("%s: finally no more memory for element size %d\n", __func__, element_size);
	return NULL;
}

static void *__vbh_malloc(struct mem_pool_head *mp_head, int size)
{
	struct mem_pool *pool;
	void *va;
	BUG_ON(mp_head->element_size < size);

	list_for_each_entry(pool, &mp_head->head, list) {
		if(pool->last_pool) {
			//TODO: ask nonroot to create new pool
			;
		}
		if (atomic_read(&pool->free_count)) {
			va = __malloc_from_mem_pool(pool,
					mp_head->element_size);
			if (va)
				return va;
		}
	}

	return NULL;
}

void *vbh_malloc(struct vbh_data *vbh, int size)
{
	int index = size_to_index(vbh, size);

	if (index < 0) {
		pr_err("%s: size(%d) is too large\n", __func__, size);
		return NULL;
	}

	if (!vbh)
		return NULL;

	return __vbh_malloc(&vbh->mps->mp[index], size);
}

static void __free_to_mem_pool(struct mem_pool *pool, int element_size, u64 va)
{
	u64 base_va = (u64)pool + sizeof(struct mem_pool), diff;
	slock_t *slock;
	int i, bit;

	BUG_ON(va < base_va);

	diff = va - base_va;

	i = diff / (element_size * BITS_PER_LONG);
	bit = diff / element_size % BITS_PER_LONG;

	rtmm_pr("%s: pool 0x%llx base_va 0x%llx index %d bit %d bitmap 0x%llx va 0x%llx element %d\n",
		__func__, (u64)pool, (u64)base_va, i, bit , pool->bitmaps[i], (u64)va, element_size);

	BUG_ON(base_va + (i * BITS_PER_LONG + bit) * element_size != va);

	BUG_ON(!(pool->bitmaps[i] & (1ULL << bit)));

	//TODO: need to clear? Probably not as mem_pool can only be used by VBH
	//memset((void *)va, 0, element_size);

	slock = &pool->bitmap_lock[(i / BITMAP_LOCK_COVERS)];
	slock_lock(slock);
	pool->bitmaps[i] &= ~(1ULL << bit);
	slock_unlock(slock);
	atomic_inc(&pool->free_count);
}

void vbh_free(struct vbh_data *vbh, void *virt)
{
	struct mem_pool *pool;
	u64 va = (u64)virt;
	int i;

	if (!vbh)
		return;

	for (i = 0; i < MEM_POOL_COUNT; i++) {
		list_for_each_entry(pool, &vbh->mps->mp[i].head, list) {
			if (va < ((u64)pool + pool->size) && va > (u64)pool) {
				__free_to_mem_pool(pool, vbh->mps->mp[i].element_size, va);
				return;
			}
		}
	}
	BUG_ON(1);
}

static inline void memcpy_erms(void *d, const void *s, size_t slen)
{
	asm volatile ("rep; movsb"
		: "=&D"(d), "=&S"(s)
		: "c"(slen), "0" (d), "1" (s)
		: "memory");
}

/*
 * @brief  Copies at most slen bytes from src address to dest address, up to dmax.
 *
 *   INPUTS
 *
 * @param[in] d        pointer to Destination address
 * @param[in] dmax     maximum  length of dest
 * @param[in] s        pointer to Source address
 * @param[in] slen     maximum number of bytes of src to copy
 *
 * @return pointer to destination address.
 *
 * @pre d and s will not overlap.
 */
void *vbh_memcpy(void *d, size_t dmax, const void *s, size_t slen)
{
	if ((slen != 0U) && (dmax != 0U) && (dmax >= slen)) {
		/* same memory block, no need to copy */
		if (d != s) {
			memcpy_erms(d, s, slen);
		}
	}
	return d;
}

static inline void memset_erms(void *base, u8 v, size_t n)
{
	asm volatile("rep ; stosb"
			: "+D"(base)
			: "a" (v), "c"(n));
}

void *vbh_memset(void *base, u8 v, size_t n)
{
	/*
	 * Some CPUs support enhanced REP MOVSB/STOSB feature. It is recommended
	 * to use it when possible.
	 */
	if ((base != NULL) && (n != 0U)) {
		memset_erms(base, v, n);
        }

	return base;
}

//for debug purpose
void vbh_mem_status(struct vbh_data *vbh)
{
	struct mem_pool_head *mph;
	struct mem_pool *pool;
	int i, j, pool_index;
	bool clean = true;

	for (i = 0; i < MEM_POOL_COUNT; i++) {
		mph = &vbh->mps->mp[i];
		pool_index = 0;
		list_for_each_entry(pool, &mph->head, list) {
			if (pool->total_count != atomic_read(&pool->free_count))
				pr_err("%s: element %d pool%d are not clean: total %d used %d\n",
					__func__, pool->element_size, pool_index, pool->total_count,
					pool->total_count - atomic_read(&pool->free_count));

			for (j = 0; j < pool->last_bitmap_index; j++) {
				if (pool->bitmaps[j] != 0) {
					clean = false;
					pr_err("%s: bitmap index %d, bitmap 0x%llx\n",
							__func__, j, pool->bitmaps[j]);
				}
			}

			pool_index++;
		}
	}

	if (clean)
		pr_err("%s: mempools are clean\n", __func__);
}
