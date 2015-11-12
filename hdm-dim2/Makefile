# Makefile
#

obj-m	:= dim2hdm.o dim2mx6q.o mostcore.o aim_network.o

dim2hdm-objs := dim2_hdm.o dim2_hal.o dim2_sysfs.o
dim2mx6q-y = platform/dim2_mx6q.o
mostcore-y = ../mostcore/core.o
aim_network-y = ../aim-network/networking.o

CFLAGS_dim2_hdm.o := -I$(src)/../mostcore -I$(src)/../aim-network/
CFLAGS_networking.o := -I$(src)/../mostcore

PWD	:= $(shell pwd)

modules:
	$(MAKE)	-C $(KDIR)	M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../aim-network clean
