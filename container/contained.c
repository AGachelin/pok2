#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <string.h>

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

void set_hostname(const char* hostname) {
    if (sethostname(hostname, strlen(hostname)) == -1) {
        perror("Failed to set hostname");
        exit(1);
    }
}

void set_env(){
    clearenv();
    if(setenv("PS1", "container:# ", 1) != 0) {
        perror("Failed to set PS1");
        exit(1);
    }
    if(setenv("TERM", "xterm-256color", 0) != 0) {
        perror("Failed to set TERM");
        exit(1);
    }
    if(setenv("PS1","[\\u@\\h \\W]\\$ ",0) != 0) {
        perror("Failed to set PS1");
        exit(1);
    }
    if(setenv("PATH", "/bin/:/sbin/:/usr/bin:/usr/sbin", 0) != 0) {
        perror("Failed to set PATH");
        exit(1);
    }
}

void set_fs(const char *folder)
{
        chroot(folder);
        chdir("/");
}


int fn(void *){
    printf("inside container\n");
    set_hostname("container");
    set_env();
    set_fs("fs"); //should contain a minimal filesystem, i used https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-minirootfs-3.23.0-x86_64.tar.gz
    mount("proc","/proc","proc",0,0);
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