//This header file is mostly used to include
//linux kernel headers which finally should not
//be used in VBH. These headers are mostly used
//for debug purpose. If not for debug purpose, VBH
//should implement seperately
#ifndef __VBH_LINUX_KERNEL_H
#define __VBH_LINUX_KERNEL_H

#include <linux/list.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/bits.h>
#include <linux/threads.h>
#include <asm/vmx.h>
#include <asm/page.h>
#include <asm-generic/bug.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/asm/processor-flags.h>
#include <asm/desc_defs.h>
#include <asm/msr-index.h>

#endif
