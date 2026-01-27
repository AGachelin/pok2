// source : https://blog.lizzie.io/linux-containers-in-500-loc.html
#define _GNU_SOURCE
#include <sched.h>
#include <grp.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/limits.h>

#define STACK_SIZE 1024 * 64
#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000
#define FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD)

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

int set_hostname(const char* hostname) {
    if (sethostname(hostname, strlen(hostname)) == -1) {
        perror("Failed to set hostname");
        return -1;
    }
    return 0;
}

int pivot_root(const char *new_root, const char *put_old)
{
       return syscall(SYS_pivot_root, new_root, put_old);
}

int mounts(struct child_config *config)
{
	fprintf(stderr, "=> remounting everything with MS_PRIVATE...\n");
    // make sure that mount changes don't propagate to or from the host, MS_REC makes it recursive
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		fprintf(stderr, "failed to remount with MS_PRIVATE : %m\n");
		return -1;
	}
	fprintf(stderr, "remounted.\n");

	fprintf(stderr, "=> making a temp directory and a bind mount there...\n");
	char mount_dir[] = "/tmp/tmp.XXXXXX";
	if (!mkdtemp(mount_dir)) {
		fprintf(stderr, "failed making a directory : %m\n");
		return -1;
	}

	if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
		fprintf(stderr, "bind mount failed : %m\n");
		return -1;
	}

	char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
	memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
	if (!mkdtemp(inner_mount_dir)) {
		fprintf(stderr, "failed making the inner directory : %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, "=> pivoting root...\n");
	if (pivot_root(mount_dir, inner_mount_dir)) {
		fprintf(stderr, "failed to pivot root : %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

    // find the old root directory name
	char *old_root_dir = basename(inner_mount_dir);
	char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
	strcpy(&old_root[1], old_root_dir);

    // unmount and remove the old root
	fprintf(stderr, "=> unmounting %s...\n", old_root);
	if (chdir("/")) {
		fprintf(stderr, "chdir failed : %m\n");
		return -1;
	}
	if (umount2(old_root, MNT_DETACH)) {
		fprintf(stderr, "umount of the old root failed : %m\n");
		return -1;
	}
	if (rmdir(old_root)) {
		fprintf(stderr, "failed to remove old root: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}


int handle_child_userns(pid_t child_pid, int fd) {
	int map_file = 0;
	int has_userns = -1;
    // check if the child created a user namespace
	if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
		fprintf(stderr, "couldn't read from child\n");
		return -1;
	}
	if (has_userns) {
		char path[PATH_MAX] = {0};
        // write the UID (User ID) and GID (Group ID) maps
		for (char **file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
			if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
			    > sizeof(path)) {
				fprintf(stderr, "failed to build path %m\n");
				return -1;
			}
			fprintf(stderr, "writing %s...\n", path);
			if ((map_file = open(path, O_WRONLY)) == -1) {
				fprintf(stderr, "open failed: %m\n");
				return -1;
			}
            // write the mapping (so that the container's root user maps to a non-privileged user on the host):
            // UID 0 inside the namespace maps to UID USERNS_OFFSET on the host
            // for USERNS_COUNT UIDs
			if (dprintf(map_file, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
				fprintf(stderr, "dprintf failed: %m\n");
				close(map_file);
				return -1;
			}
			close(map_file);
		}
	}
    // notify the child that the mapping is done
	if (write(fd, & (int) { 0 }, sizeof(int)) != sizeof(int)) {
		fprintf(stderr, "couldn't notify child: %m\n");
		return -1;
	}
	return 0;
}

int userns(struct child_config *config)
{
	fprintf(stderr, "=> trying to create a user namespace...\n");
	int has_userns = !unshare(CLONE_NEWUSER);
    if (!has_userns) {
        fprintf(stderr, "user namespace creation failed : %m\n");
	}

    // notify the parent about whether a user namespace was created
	if (write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
		fprintf(stderr, "couldn't notify parent: %m\n");
		return -1;
	}

	int result = 0;
    // wait for the parent to set up UID/GID mappings
	if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
		fprintf(stderr, "couldn't read: %m\n");
		return -1;
	}
	if (result) return -1;
	fprintf(stderr, "=> switching to uid %d / gid %d...\n", config->uid, config->uid);
	if (setgroups(1, & (gid_t) { config->uid }) || // remove all groups except the one we are mapping to
	    setresgid(config->uid, config->uid, config->uid) || //sets real/effective/saved GID
	    setresuid(config->uid, config->uid, config->uid)) { //sets real/effective/saved UID
		fprintf(stderr, "Failed to set UID, GID or to remove groups : %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int child(void *arg){
	struct child_config *config = arg;
	if (set_hostname(config->hostname)
	    || mounts(config)
	    || userns(config)
	    //|| capabilities()
	    //|| syscalls()
        ) {
		close(config->fd);
		return -1;
	}
	if (close(config->fd)) {
		fprintf(stderr, "close failed : %m\n");
		return -1;
	}
	if (execve(config->argv[0], config->argv, NULL)) {
		fprintf(stderr, "execve failed : %m.\n");
		return -1;
	}
	return 0;
}

int main() {
    int err = 0;
    struct child_config config = {0};
    int sockets[2] = {0};
    config.hostname = "container";
    config.argv = (char *[]) { "/bin/sh", NULL };
    config.mount_dir = "fs"; // path to a valid root filesystem, i used i used https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-minirootfs-3.23.0-x86_64.tar.gz
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
    pid_t pid = clone(child, stack_top, FLAGS, &config);
    if (pid == -1) {
        perror("Failed to create clone");
        goto clear_resources;
    }
    close(sockets[1]);
	sockets[1] = 0;
    printf("Container created successfully.\n");
	if (handle_child_userns(pid, sockets[0])) {
		err = 1;
		goto kill_and_finish_child;
	}

	goto finish_child;

kill_and_finish_child:
	if (pid) kill(pid, SIGKILL);
finish_child:;
	int child_status = 0;
	waitpid(pid, &child_status, 0);
	err |= WEXITSTATUS(child_status);
    
clear_resources:
    free(stack_top - STACK_SIZE);
error:
    err=1;
cleanup:
	if (sockets[0]) close(sockets[0]);
	if (sockets[1]) close(sockets[1]);
    return err;
}