// source : https://blog.lizzie.io/linux-containers-in-500-loc.html
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
#include <sys/socket.h>

#define STACK_SIZE 1024 * 64
#define FLAGS (CLONE_NEWUTS | CLONE_NEWPID | SIGCHLD)

struct child_config {
	int argc;
	uid_t uid;
	int fd;
	char *hostname;
	char **argv;
	char *mount_dir;
};

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
    set_hostname("container");
    set_env();
    set_fs("fs");
    mount("proc","/proc","proc",0,0);
    char *cmd[] = {"/bin/sh", NULL};
    if(execvp(cmd[0],cmd)){
        perror("could not execute shell");
        exit(1);
    }
}

int main() {
    int err = 0;
    struct child_config config = {0};
    int sockets[2] = {0};
    config.hostname = "container";
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
		fprintf(stderr, "socketpair failed: %m\n");
		goto error;
	}
	if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)) {
		fprintf(stderr, "fcntl failed: %m\n");
		goto error;
	}
	config.fd = sockets[1];
    char* stack_top = create_stack();
    printf("Stack created at address: %p\n", stack_top);
    pid_t pid = clone(fn, stack_top, FLAGS, &config);
    if (pid == -1) {
        perror("Failed to create clone");
        goto error;
    }
    printf("Container created successfully.\n");
    waitpid(pid, NULL, 0);
    

error:
    err=1;
cleanup:
    free(stack_top - STACK_SIZE);
	if (sockets[0]) close(sockets[0]);
	if (sockets[1]) close(sockets[1]);
    return err;
}