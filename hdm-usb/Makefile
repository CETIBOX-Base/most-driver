# USAGE:
#
#   make ARCH=<architecture> CROSS_COMPILE=<binutils prefix> KDIR=<path to kernel src>
#
# EXAMPLES:
#
# Native making for PC:
#
#   make KDIR=/lib/modules/$(shell uname -r)/build/
#
# Cross making for embedded platform:
#
#   make ARCH=arm \
#        CROSS_COMPILE=/opt/freescale/usr/local/gcc-4.6.2-glibc-2.13-linaro-multilib-2011.12/fsl-linaro-toolchain/bin/arm-none-linux-gnueabi- \
#        KDIR=~/imx6/sdk/ltib/rpm/BUILD/linux
#
ifneq ($(KERNELRELEASE),)
obj-m := hdm_usb.o
obj-m += mostcore.o
mostcore-y := ../mostcore/core.o

CFLAGS_hdm_usb.o := -DNO_NET_AIM -I$(src)/../mostcore
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
endif

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean
