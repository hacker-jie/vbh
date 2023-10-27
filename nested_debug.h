#ifndef __VBH_NESTED_DEBUG_H
#define __VBH_NESTED_DEBUG_H

//#define VBH_NESTED_DEBUG
#undef VBH_NESTED_DEBUG

#ifdef VBH_NESTED_DEBUG
#define vmx_log(format...) trace_printk(format)
#define vmx_err(format...) trace_printk(format)
//#define vmx_log(format...) pr_err(format)
//#define vmx_err(format...) pr_err(format)
#else
#define vmx_log(format...)
#define vmx_err(format...)
#endif

#endif
