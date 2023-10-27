#ifndef __TE_NONROOT_H
#define __TE_NONROOT_H

#define TEE_HYPERCALL_CREATE  0x100
#define TEE_HYPERCALL_RUN  0x101

#define OPTEE_VMCALL_SMC 0x6F707400

void setup_tee_env(void);

#endif
