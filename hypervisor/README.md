# Hypervisor kernel module example

This directory contains a simple Linux kernel module example and a Makefile for building it.

## Files

- `hypervisor.c`: kernel module source file. It registers initialization and cleanup routines and prints simple log messages.
- `Makefile`: kernel build system wrapper to compile the module against the current kernel headers.

## Build

```bash
cd hypervisor
make modules
```

## Install

```bash
sudo insmod hypervisor/hypervisor.ko
sudo dmesg | tail
```

## Remove

```bash
sudo rmmod hypervisor
```

## Clean

```bash
make clean
```

## Notes

- I initially intended to build a full "hypervisor" through AMD-V (SVM) on linux, but I wasn't able to find a tutorial explaining how to do it or a documented implementation (they were either for windows, for Intel VT-x (VMX), or both). The time allocated to the project being only 24h, I had to stop at trying to understand the inner workings and abandon the idea of actually implementing it. 
- A linux development environment with kernel headers installed is required.
