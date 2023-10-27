#ifndef __VBH_MEM_OPS_H
#define __VBH_MEM_OPS_H

void *vbh_malloc(struct vbh_data *vbh, int size);
void vbh_free(struct vbh_data *vbh, void *virt);
void *vbh_memcpy(void *d, size_t dmax, const void *s, size_t slen);
void *vbh_memset(void *base, u8 v, size_t n);
void vbh_mem_status(struct vbh_data *vbh);
#endif
