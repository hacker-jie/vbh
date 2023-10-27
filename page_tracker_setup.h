#ifndef __VBH_PAGE_TRACKER_SETUP_H
#define __VBH_PAGE_TRACKER_SETUP_H

int vbh_page_cache_create(void);
void vbh_page_cache_free(void);
struct vbh_page *vbh_record_pages(u64 pa, size_t size);
int vbh_protect_pages(struct vbh_data *vbh);

#endif
