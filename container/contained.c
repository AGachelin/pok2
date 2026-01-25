#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_SIZE 1024 * 64
// flags for new UTS and PID namespaces (i.e namespace isolation) ; SIGCHLD to notify parent on child termination
#define FLAGS (CLONE_NEWUTS | CLONE_NEWPID | SIGCHLD)

char* create_stack() {
    char* stack = (char*)malloc(STACK_SIZE);
    if (!stack) {
        perror("Failed to allocate stack");
        exit(1);
    }
    return stack + STACK_SIZE;
}

void fn(){
    printf("inside container\n");
}

int main() {
    char* stack_top = create_stack();
    printf("Stack created at address: %p\n", stack_top);
    if (syscall(SYS_clone, FLAGS, stack_top, 0, 0, 0) == -1) { // calling clone via syscall
        perror("Failed to create clone");
        free(stack_top - STACK_SIZE);
        exit(1);
    }
    printf("Container created successfully.\n");
    free(stack_top - STACK_SIZE);
    return 0;
}