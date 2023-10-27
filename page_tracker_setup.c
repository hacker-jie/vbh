#include <linux/kernel.h>
#include <linux/slab.h>

#include "page_tracker.h"
#include "pt.h"

/* Note: vbh_page_cache and vbh_page_head are used for
 * tracking the page in two scenarios:
 * 1. before deprivileging the host.
 * 2. after root mode performs the vmxoff to turn off VBH.
 */
static struct kmem_cache *vbh_page_cache;
LIST_HEAD(vbh_page_head);

int vbh_page_cache_create(void)
{
	vbh_page_cache = kmem_cache_create("vbh_page_cache",
					   sizeof(struct vbh_page),
					   0, SLAB_ACCOUNT, NULL);
	if (!vbh_page_cache)
		return -ENOMEM;

	return 0;
}

static void vbh_delete_pages(struct vbh_page *p)
{
	list_del(&p->list);
	free_pages_exact(__va(p->pa), p->size);
	kmem_cache_free(vbh_page_cache, p);
}

void vbh_page_cache_free(void)
{
	struct vbh_page *p, *n;

	if (!vbh_page_cache) {
		WARN_ON(pr_warn("%s: invalid free\n", __func__));
		return;
	}

	if (list_empty(&vbh_page_head)) {
		kmem_cache_destroy(vbh_page_cache);
		return;
	}

	list_for_each_entry_safe(p, n, &vbh_page_head, list)
		vbh_delete_pages(p);

	kmem_cache_destroy(vbh_page_cache);
}

struct vbh_page *vbh_record_pages(u64 pa, size_t size)
{
	struct vbh_page *p;

	if (!vbh_page_cache)
		return NULL;

	p = (struct vbh_page *)kmem_cache_zalloc(vbh_page_cache, GFP_KERNEL_ACCOUNT);
	if (!p)
		return NULL;

	list_add_tail(&p->list, &vbh_page_head);
	p->pa = pa;
	// must be page aligned
	BUG_ON(size % PAGE_SIZE);
	p->size = size;

	return p;
}

int vbh_protect_pages(struct vbh_data *vbh)
{
	struct vbh_page *p;
	int ret;

	list_for_each_entry(p, &vbh_page_head, list) {
		BUG_ON(p->size % PAGE_SIZE);
		if (vbh_set_ram_metadata_in_range(vbh, p->pa, p->size, NULL, NULL, VBH_ID))
			BUG_ON(printk("invalid pa 0x%llx size %ld. Buggy code?\n", p->pa, p->size));
		ret = vbh_control_gpa_access_in_range(vbh, true, p->pa, p->size,
						      false, false, false, NULL);
		if (ret) {
			pr_err("%s: failed to protect pages\n", __func__);
			return ret;
		}
	}

	return 0;
}
