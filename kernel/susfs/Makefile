# susfs - SUSFS support for KernelSU-Next
#
# Built as part of kernelsu (not as standalone module)

susfs-objs := susfs.o susfs_core.o

kernelsu-objs += susfs/susfs.o
kernelsu-objs += susfs/susfs_core.o

ccflags-y += -I$(srctree)/include/uapi
