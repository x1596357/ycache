# ycache Makefile
	obj-m := checkDep.o
	KERNELDIR ?=/lib/modules/`uname -r`/build
default:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules
clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	