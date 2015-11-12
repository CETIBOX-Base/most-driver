# Makefile
#

obj-m := hdm_i2s.o mostcore.o
mostcore-y = ../mostcore/core.o

CFLAGS_hdm_i2s.o := -I$(src)/../mostcore

PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean