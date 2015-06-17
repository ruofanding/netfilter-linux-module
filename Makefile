obj-m := netfilter.o


KVERSION = $(shell uname -r)


KDIR := /lib/modules/${KVERSION}/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
Debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
