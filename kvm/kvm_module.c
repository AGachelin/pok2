#include <linux/kvm.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main() {
    int kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        perror("Failed to open /dev/kvm");
        return 1;
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0); // ioctl (input/output control) system call with code KVM_CREATE_VM to create a new virtual machine
    if (vm < 0) {
        perror("Failed to create VM");
        return 1;
    }
    printf("VM created successfully.\n");
    close(kvm);
    return 0;
}