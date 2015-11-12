obj-m := aim_network.o
aim_network-y := networking.o
CFLAGS_networking.o := -I$(src)/../mostcore

obj-m += mostcore.o
mostcore-y := ../mostcore/core.o

obj-m += aim_cdev.o
aim_cdev-y := ../aim-cdev/cdev.o
CFLAGS_cdev.o := -I$(src)/../mostcore

obj-m += hdm_dim2.o hdm_dim2_mx6q.o
hdm_dim2-y := ../hdm-dim2/dim2_hdm.o ../hdm-dim2/dim2_hal.o
hdm_dim2_mx6q-y := ../hdm-dim2/platform/dim2_mx6q.o
CFLAGS_dim2_hdm.o := -I$(src)/../mostcore -I$(src)

obj-m += hdm_i2c.o hdm_i2c_mx6q.o
hdm_i2c-y = ../hdm-i2c/i2c_hdm.o
hdm_i2c_mx6q-y = ../hdm-i2c/platform/i2c_mx6q.o
CFLAGS_i2c_hdm.o := -I$(src)/../mostcore


PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../mostcore clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../aim-cdev clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../hdm-dim2 clean
	$(MAKE) -C $(KDIR) M=$(PWD)/../hdm-i2c clean

