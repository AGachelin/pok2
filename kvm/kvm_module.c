#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>


#define MEMORY_SIZE 0x400000 // 4MB
#define KVM_EXIT_IO 2        // VM exit reason for I/O
static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _)
{
    (void)_;
    keep_running = 0;
}

void handle_io_exit(struct kvm_run *run) {
    if (run->io.direction == KVM_EXIT_IO_OUT) {
        printf("Guest wrote to port 0x%x: value=0x%x\n",
               run->io.port,
               *((uint8_t *)run + run->io.data_offset));
    } else {
        printf("Guest read from port 0x%x\n", run->io.port);
    }
}


int main() {
    int kvm, vm, vcpufd;
    void *vm_mem;
    struct kvm_userspace_memory_region mem;
    struct kvm_run *run;
    signal(SIGINT, sig_handler);
    int result = 0;

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
        result = 1;
        goto cleanup;
    }

    // Map memory to the VM
    mem.slot = 0;
    mem.guest_phys_addr = 0x0;
    mem.memory_size = MEMORY_SIZE;
    mem.userspace_addr = (uint64_t)vm_mem;

    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &mem) < 0) {
        perror("Failed to set user memory region");
        result = 1;
        goto cleanup;
    }

    // Create a vCPU (virtual CPU)
    vcpufd = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpufd < 0) {
        perror("Failed to create vCPU");
        result = 1;
        goto cleanup;
    }

    printf("VM and vCPU successfully created.\n");
    
    // Get the vCPU's registers and print the instruction pointer (RIP)
    struct kvm_regs regs;
    ioctl(vcpufd, KVM_GET_REGS, &regs);
    printf("RIP: 0x%llx\n", regs.rip);

    run = (struct kvm_run *)vm_mem;

    // Run the vCPU loop
    while (keep_running) {
        if (ioctl(vcpufd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN failed");
            result = 1;
            break;
        }

        // Handle VM exits
        switch (run->exit_reason) {
            case KVM_EXIT_IO:
            case KVM_EXIT_IO_OUT:
            case KVM_EXIT_IO_IN:
                handle_io_exit(run);
                break;
            case KVM_EXIT_MMIO:
                printf("Guest MMIO (memory mapped input/output) access at address 0x%llx\n", run->mmio.phys_addr);
                break;
            case KVM_EXIT_HLT:
                printf("Guest halted.\n");
                goto cleanup;
            default:
                printf("Unhandled exit reason: %d\n", run->exit_reason); // the meaning of the codes can be found in kvm.h, after the struct kvm_run definition
                goto cleanup;
        }
    }
    goto cleanup;

// Cleanup resources
cleanup:
    munmap(vm_mem, MEMORY_SIZE);
    close(vcpufd);
    close(vm);
    close(kvm);
    printf("cleanup successful");
    return result;
}