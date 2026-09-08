# susfs - SUSFS loadable kernel module (LKM)
#
# Build against DDK kernel headers (same image that builds kernelsu.ko):
#   make -C $KDIR M=$PWD ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# SELinux private headers (security.h/ss/*.h/flask.h) are exposed via:
#   -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
#   -I$(objtree)/security/selinux        (generated flask.h lives here)

obj-m += susfs.o

susfs-objs := susfs_main.o patch_memory.o symbol_resolver.o lsm_hook.o susfs_uname.o

# 5.14+ replaced __flush_dcache_area/__flush_icache_range with
# dcache_clean_inval_poc/caches_clean_inval_pou.  Detect which to use.
KSU_NEW_DCACHE_FLUSH := $(shell grep -q __flush_dcache_area $(srctree)/arch/arm64/include/asm/cacheflush.h; echo $$?)
ccflags-y += -DKSU_NEW_DCACHE_FLUSH=$(KSU_NEW_DCACHE_FLUSH)

# Match SukiSU's build flags: upstream code declares after statements and
# casts symbol addresses (unsigned long) to function pointers.
ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# SELinux private headers are only needed once selinux hooks are added.
# Uncomment when the selinux feature lands:
# ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
# ccflags-y += -I$(objtree)/security/selinux

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
