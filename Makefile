# Makefile
#

ifndef KDIR
    KDIR=/lib/modules/$(shell uname -r)/build/
endif

obj-m := mostcore.o
mostcore-y := mostcore/core.o

obj-m += aim_cdev.o
aim_cdev-y := aim-cdev/cdev.o
CFLAGS_cdev.o := -I$(src)/mostcore

obj-m += aim_mlb150.o
aim_mlb150-y := aim-mlb150/mlb150.o
CFLAGS_mlb150.o := -I$(src)/mostcore

obj-m += aim_network.o
aim_network-y := aim-network/networking.o
CFLAGS_networking.o := -I$(src)/mostcore

obj-m += aim_sound.o
aim_sound-y := aim-sound/sound.o
CFLAGS_sound.o := -I$(src)/mostcore

obj-m += aim_v4l2.o
aim_v4l2-y := aim-v4l2/video.o
CFLAGS_video.o := -Idrivers/media/video -I$(src)/mostcore

obj-hdm-$(CONFIG_HDM_I2C) += hdm_i2c.o hdm_i2c_mx6q.o
hdm_i2c-y := hdm-i2c/hdm_i2c.o
hdm_i2c_mx6q-y := hdm-i2c/platform/plat_imx6q.o
CFLAGS_hdm_i2c.o := -I$(src)/mostcore

obj-hdm-$(CONFIG_HDM_DIM2) += hdm_dim2.o hdm_dim2_mx6q.o
hdm_dim2-y := hdm-dim2/dim2_hdm.o hdm-dim2/dim2_hal.o hdm-dim2/dim2_sysfs.o
hdm_dim2_mx6q-y := hdm-dim2/platform/dim2_mx6q_dt.o
CFLAGS_dim2_hdm.o := -I$(src)/mostcore -I$(src)/aim-network

obj-hdm-$(CONFIG_HDM_USB) += hdm_usb.o
hdm_usb-y := hdm-usb/hdm_usb.o
CFLAGS_hdm_usb.o := -I$(src)/mostcore -I$(src)/aim-network

obj-hdm-$(CONFIG_HDM_PCIE) += hdm_pcie.o
hdm_pcie-y := hdm-pcie/medusa.o hdm-pcie/dci.o hdm-pcie/debug.o
CFLAGS_medusa.o := -I$(src)/mostcore
CFLAGS_dci.o := -I$(src)/mostcore
CFLAGS_debug.o := -I$(src)/mostcore
EXTRA_CFLAGS += -DSGDMA_DESCR_FORMAT=0

obj-hdm-$(CONFIG_HDM_I2S) += hdm_i2s.o
hdm_i2s-y := hdm-i2s/hdm_i2s.o
CFLAGS_hdm_i2s.o := -I$(src)/mostcore
EXTRA_CFLAGS += -DCONFIG_OF_ADDRESS -DCONFIG_OF

ifeq ($(MAKECMDGOALS)$(M)$(obj-hdm-m),)
  $(error NOT ANY HDM IS ENABLED, run 'make help' for more information)
endif

obj-m += $(obj-hdm-m)


PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	@echo 'This is Makefile for the Big HDM package'
	@echo '========================================'
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
	@echo 'HDM build options'
	@echo '-----------------'
	@echo ''
	@echo 'These options, if defined as "m", enable bulding respecting HDM:'
	@echo ''
	@echo '  CONFIG_HDM_I2C'
	@echo '  CONFIG_HDM_DIM2'
	@echo '  CONFIG_HDM_USB'
	@echo '  CONFIG_HDM_PCIE'
	@echo '  CONFIG_HDM_I2S'
	@echo ''
	@echo 'EXAMPLES'
	@echo '========'
	@echo ''
	@echo 'Native making for PC including USB HDM:'
	@echo '  make CONFIG_HDM_USB=m KDIR=/lib/modules/$$(uname -r)/build/'
	@echo 'or'
	@echo '  make CONFIG_HDM_USB=m'
	@echo ''
	@echo 'Cross making for embedded platform:'
	@echo '  make ARCH=arm \'
	@echo '       CROSS_COMPILE=/opt/freescale/usr/local/gcc-4.6.2-glibc-2.13-linaro-multilib-2011.12/fsl-linaro-toolchain/bin/arm-none-linux-gnueabi- \'
	@echo '       KDIR=~/imx6/sdk/ltib/rpm/BUILD/linux'
	@echo ''
