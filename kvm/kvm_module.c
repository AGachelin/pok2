#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define MEMORY_SIZE 0x400000 // 4MB

int main() {
    int kvm, vm, vcpufd;
    void *vm_mem;
    struct kvm_userspace_memory_region mem;

    // Open the KVM device
    kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        perror("Failed to open /dev/kvm");
        return 1;
    }

    // Create a new VM
    vm = ioctl(kvm, KVM_CREATE_VM, 0); // ioctl (input/output control) system call with code KVM_CREATE_VM to create a new virtual machine
    if (vm < 0) {
        perror("Failed to create VM");
        return 1;
    }

    // Allocate memory for the VM
    vm_mem = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (vm_mem == MAP_FAILED) {
        perror("Failed to allocate memory");
        close(vm);
        close(kvm);
        return 1;
    }

    // Map memory to the VM
    mem.slot = 0;
    mem.guest_phys_addr = 0x0;
    mem.memory_size = MEMORY_SIZE;
    mem.userspace_addr = (uint64_t)vm_mem;

    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &mem) < 0) {
        perror("Failed to set user memory region");
        munmap(vm_mem, MEMORY_SIZE);
        close(vm);
        close(kvm);
        return 1;
    }

    // Create a vCPU (virtual CPU)
    vcpufd = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpufd < 0) {
        perror("Failed to create vCPU");
        munmap(vm_mem, MEMORY_SIZE);
        close(vm);
        close(kvm);
        return 1;
    }

    printf("VM and vCPU successfully created.\n");

    // Cleanup
    close(vcpufd);
    munmap(vm_mem, MEMORY_SIZE);
    close(vm);
    close(kvm);
    
    return 0;
}