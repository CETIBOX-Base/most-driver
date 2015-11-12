# Makefile
#

ifneq ($(KERNELRELEASE),)
obj-m	:= cdev.o\

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE)	-C $(KDIR)	M=$(PWD) modules
endif

clean:
	rm -f *~ *.o *.ko
	rm -f .built_in.o.cmd built_in.o
	rm -f .*.cmd *.ko *.mod.c
