#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

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

int fn(void *){
    printf("inside container\n");
    char *cmd[] = {"/bin/sh", NULL};
    if(execvp(cmd[0],cmd)){
        perror("could not execute shell");
        exit(1);
    }
}

int main() {
    char* stack_top = create_stack();
    printf("Stack created at address: %p\n", stack_top);
    pid_t pid = clone(fn, stack_top, FLAGS, 0);
    if (pid == -1) {
        perror("Failed to create clone");
        free(stack_top - STACK_SIZE);
        exit(1);
    }
    printf("Container created successfully.\n");
    waitpid(pid, NULL, 0);
    free(stack_top - STACK_SIZE);
    return 0;
}