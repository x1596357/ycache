# ycache Makefile
	obj-m := ycache.o
	ycache-objs := ./src/ycache.o ./src/tmem.o
	KERNELDIR ?=/lib/modules/`uname -r`/build
	EXTRA_CFLAGS += -DDEBUG -O2
default:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules
clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean