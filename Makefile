KERNEL_MODULE_NAME := vmx-switch
KERNEL_MODULE_OBJECT_FILE_LIST := vmexit.o vbh_rt.o vbh_setup.o page_tracker.o page_tracker_setup.o mem_setup.o mem.o lock.o vmx_ops.o pt_setup.o pt.o vbh_ops.o nested.o nested_setup.o tee_nonroot.o tee_root.o
KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

INCLUDES = -I.

ccflags-y += $(INCLUDES) -O2 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
ldflags-y += -z noexecstack -z relro -z now

obj-m += vmx-switch.o

$(KERNEL_MODULE_NAME)-y += $(KERNEL_MODULE_OBJECT_FILE_LIST)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
