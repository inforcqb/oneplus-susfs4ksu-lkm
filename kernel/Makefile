# susfs - SUSFS loadable kernel module (LKM)
#
# Build against DDK kernel headers (same image that builds kernelsu.ko):
#   make -C $KDIR M=$PWD ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# SELinux private headers (security.h/ss/*.h/flask.h) are exposed via:
#   -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
#   -I$(objtree)/security/selinux        (generated flask.h lives here)

obj-m += susfs.o

susfs-objs := susfs_main.o

# SELinux private headers are only needed once selinux hooks are added.
# Uncomment when the selinux feature lands:
# ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
# ccflags-y += -I$(objtree)/security/selinux

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
