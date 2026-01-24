#include <linux/kvm.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>


int check_kvm(){
    int kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        return 1;
    }
    printf("KVM setup is functional.\n");
    close(kvm);
    return 0;
}

int check_virtualization_support() {
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) // sets eax, ebx, ecx, edx to the output of CPUID
                         : "a"(1)); // executes CPUID with EAX=1, which returns information about the processor features
    if (ecx & (1 << 5)) {
        printf("Intel VT-x (VMX) is supported.\n");
        return 0;
    } else if (edx & (1 << 12)) {
        printf("AMD-V (SVM) is supported.\n");
        return 0;
    } else {
        printf("Virtualization is not supported.\n");
        return 1;
    }
}

int main() {
    int res = check_kvm();
    if(!res){
        return check_virtualization_support();
    }
    else {
        perror("Failed to open /dev/kvm");
        return 1;
    }
}