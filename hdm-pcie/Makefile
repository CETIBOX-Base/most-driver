# Makefile
#

ifndef KDIR
    KDIR=/lib/modules/$(shell uname -r)/build/
endif

obj-m := hdm_pcie.o
hdm_pcie-y := medusa.o dci.o debug.o
CFLAGS_medusa.o := -I$(src)/../mostcore
CFLAGS_dci.o := -I$(src)/../mostcore
CFLAGS_debug.o := -I$(src)/../mostcore

ifeq ($(TESTING),y)
	obj-m += medusa-tester.o
	CFLAGS_medusa-tester.o := -I$(src)/../mostcore
else
	# default
	obj-m += mostcore.o
	mostcore-y := ../mostcore/core.o ../mostcore/sysfs.o ../mostcore/mbo.o
endif

ifeq ($(SGDMA_DESCR_FORMAT),1)
	KCPPFLAGS_DEF := -DSGDMA_DESCR_FORMAT=1
else
	# default
	KCPPFLAGS_DEF := -DSGDMA_DESCR_FORMAT=0
endif


PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) KCPPFLAGS="$(KCPPFLAGS_DEF)" modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean

help:
	@echo 'This is Makefile for Medusa HDM'
	@echo '==============================='
	@echo ''
	@echo 'There are two main ways to build Medusa HDM.'
	@echo '1. Medusa HDM depending on standard mostcore. This is default way.'
	@echo '2. Medusa HDM depending on special medusa-tester module used for stress testing of HDM.'
	@echo ''
	@echo 'To build HDM depending on medusa-tester use "TESTING=y" (see below).'
	@echo ''
	@echo 'USAGE'
	@echo '====='
	@echo ''
	@echo '  make [ [<environment variable>=<value> ... ] [<target>]'
	@echo ''
	@echo '<target> may be "modules", "modules_install", "clean" or "help" (without quotes).'
	@echo 'Default <target> is "modules"'
	@echo ''
	@echo 'Environment variables'
	@echo '====================='
	@echo ''
	@echo 'ARCH defines target architecture.'
	@echo ''
	@echo 'CROSS_COMPILE defines binutils prefix.'
	@echo ''
	@echo 'KDIR defines path to kernel sources.'
	@echo 'If KDIR is not defined then it is set to /lib/modules/$$(shell uname -r)/build/'
	@echo ''
	@echo 'TESTING defines if medusa-tester is built and used instead of mostcore.'
	@echo 'Value "y" (without quotes) builds medusa-tester.'
	@echo 'Other values or undefined TESTING build mostcore.'
	@echo ''
	@echo 'SGDMA_DESCR_FORMAT defines SGDMA buffer descriptor format.'
	@echo 'See Medusa design specification.'
	@echo 'Possible values are 0 or 1.'
	@echo 'Nonzero number as value is treated as 1.'
	@echo 'Default SGDMA_DESCR_FORMAT is 0.'
	@echo ''
	@echo 'EXAMPLES'
	@echo '========'
	@echo ''
	@echo 'Native making for PC:'
	@echo '  make KDIR=/lib/modules/$$(uname -r)/build/'
	@echo 'or'
	@echo '  make'
	@echo ''
	@echo 'Cross making for embedded platform:'
	@echo '  make ARCH=arm \'
	@echo '       CROSS_COMPILE=/opt/freescale/usr/local/gcc-4.6.2-glibc-2.13-linaro-multilib-2011.12/fsl-linaro-toolchain/bin/arm-none-linux-gnueabi- \'
	@echo '       KDIR=~/imx6/sdk/ltib/rpm/BUILD/linux'
	@echo ''
