# Makefile
#

obj-m := hdm_i2s.o

hdm_i2s-objs := i2s_hdm.o i2s_clkgen.o
CFLAGS_i2s_hdm.o := -I$(MOST_CORE)
EXTRA_CFLAGS += -DCONFIG_OF_ADDRESS -DCONFIG_OF
KBUILD_EXTRA_SYMBOLS := $(MOST_CORE)/../Module.symvers

PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
