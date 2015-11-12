# Makefile
#

obj-m := hdm_i2c.o plat_imx6q.o mostcore.o
plat_imx6q-y = platform/plat_imx6q.o
mostcore-y = ../mostcore/core.o

CFLAGS_hdm_i2c.o := -I$(src)/../mostcore

PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean
