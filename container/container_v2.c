// source : https://blog.lizzie.io/linux-containers-in-500-loc.html
// command to compile : gcc container.c -o container -lseccomp -lcap
#define _GNU_SOURCE
#include <sched.h>
#include <grp.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/capability.h> // libcap-dev should be installed
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <seccomp.h> // libseccomp-dev should be installed

#define STACK_SIZE (1024 * 1024)
#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000
#define FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD)
#define MEMORY "1073741824"
#define SHARES "256"
#define PIDS "64"
#define WEIGHT "10"
#define FD_COUNT 64
#define ALLOW(syscall) seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall), 0)
#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

struct child_config {
	int argc;
	uid_t uid;
	int fd;
	char *hostname;
	char **argv;
	char *mount_dir;
	int seccomp_blacklist;
};

struct cgrp_setting {
	char name[256];
	char value[256];
};

struct cgrp_control {
	char control[256];
	struct cgrp_setting **settings;
};

struct cgrp_v2 {
	struct cgrp_setting **settings;
};

// cgroup setting to add the current process to the cgroup's tasks file
struct cgrp_setting add_to_tasks = {
	.name = "tasks",
	.value = "0"
};

// cgroup setting to add the current process to the cgroup's cgroup.procs file, for cgroup v2
struct cgrp_setting add_to_cgroup = {
	.name = "cgroup.procs",
	.value = "0"
};

// array of pointers to cgroup controllers
struct cgrp_control *cgrps[] = {
    // controller for memory limits
	&(struct cgrp_control){
		.control = "memory",
        // array of pointers to cgroup settings for this controller
		.settings = (struct cgrp_setting *[]){
			&(struct cgrp_setting){
				.name = "memory.limit_in_bytes",
				.value = MEMORY
			},
			&(struct cgrp_setting){
				.name = "memory.kmem.limit_in_bytes",
				.value = MEMORY
			},
			&add_to_tasks,
			NULL
		}
	},
    // controller for CPU shares
	&(struct cgrp_control){
		.control = "cpu",
		.settings = (struct cgrp_setting *[]){
			&(struct cgrp_setting){
				.name = "cpu.shares",
				.value = SHARES
			},
			&add_to_tasks,
			NULL
		}
	},
    // controller for PIDs limit
	&(struct cgrp_control){
		.control = "pids",
		.settings = (struct cgrp_setting *[]){
			&(struct cgrp_setting){
				.name = "pids.max",
				.value = PIDS
			},
			&add_to_tasks,
			NULL
		}
	},
    // controller to manage block IO weight i.e disk IO priority
	&(struct cgrp_control){
		.control = "blkio",
		.settings = (struct cgrp_setting *[]){
			&(struct cgrp_setting){
				.name = "blkio.weight",
				.value = WEIGHT
			},
			&add_to_tasks,
			NULL
		}
	},
	NULL
};

// updated cgroup v2 structure
struct cgrp_v2 cgrp = {
	.settings = (struct cgrp_setting *[]){
		&(struct cgrp_setting){
			.name = "memory.max",
			.value = MEMORY
		},
		&(struct cgrp_setting){
			.name = "cpu.weight",
			.value = SHARES
		},
		&(struct cgrp_setting){
			.name = "pids.max",
			.value = PIDS
		},
		&(struct cgrp_setting){
			.name = "io.weight",
			.value = WEIGHT
		},
		&add_to_cgroup,
		NULL
	}
};

int is_cgroup_v2(void)
{
	struct stat st;
	return stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0;
}

int resources(struct child_config *config)
{
	fprintf(stderr, "=> setting cgroups...\n");
    // iterate over each cgroup controller
	for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
		char dir[PATH_MAX] = {0};
		fprintf(stderr, "%s...\n", (*cgrp)->control);
		if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s",
			     (*cgrp)->control, config->hostname) == -1)
			return -1;
		if (mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR)) { // grants rwx permissions only to owner i.e root
			fprintf(stderr, "mkdir %s failed: %m\n", dir);
			return -1;
		}
        // iterate over each setting for the current cgroup controller and write it to the appropriate file
		for (struct cgrp_setting **setting = (*cgrp)->settings; *setting; setting++) {
			char path[PATH_MAX] = {0};
			int fd;
			if (snprintf(path, sizeof(path), "%s/%s", dir,
				     (*setting)->name) == -1) {
				fprintf(stderr, "snprintf failed: %m\n");
				return -1;
			}
			fd = open(path, O_WRONLY);
			if (fd == -1) {
				fprintf(stderr, "opening %s failed: %m\n", path);
				return -1;
			}
			if (write(fd, (*setting)->value, strlen((*setting)->value)) == -1) {
				fprintf(stderr, "writing to %s failed: %m\n", path);
				close(fd);
				return -1;
			}
			close(fd);
		}
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, "=> setting rlimit...\n");
    // sets the file descriptor limit (maximum number of open files) for the current process
	if (setrlimit(RLIMIT_NOFILE, &(struct rlimit){
		.rlim_max = FD_COUNT,
		.rlim_cur = FD_COUNT,
	})) {
		fprintf(stderr, "failed: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int resources_v2(struct child_config *config)
{
	char dir[PATH_MAX] = {0};
	fprintf(stderr, "=> setting cgroups v2...\n");

    // only one unified hierarchy exists in cgroup v2 instead of multiple hierarchies for each controller
	if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s",
		     config->hostname) < 0)
		return -1;

	if (mkdir(dir, 0700) && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %m\n", dir);
		return -1;
	}

    // iterate over each cgroup setting and write it to the appropriate file	
    for (struct cgrp_setting **s = cgrp.settings; *s; s++) {
		char path[PATH_MAX] = {0};
		int fd;
		if (snprintf(path, sizeof(path), "%s/%s", dir, (*s)->name) < 0)
			return -1;
		fd = open(path, O_WRONLY);
		if (fd == -1) {
			fprintf(stderr, "open %s failed: %m\n", path);
			return -1;
		}
		if (write(fd, (*s)->value, strlen((*s)->value)) == -1) {
			fprintf(stderr, "write %s failed: %m\n", path);
			close(fd);
			return -1;
		}
		close(fd);
	}

	fprintf(stderr, "done.\n");
	// rlimit stays unchanged
    fprintf(stderr, "=> setting rlimit...\n");
	if (setrlimit(RLIMIT_NOFILE, &(struct rlimit){
		.rlim_cur = FD_COUNT,
		.rlim_max = FD_COUNT,
	})) {
		fprintf(stderr, "failed: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int free_resources(struct child_config *config)
{   
    // clean up cgroups created for the container
	fprintf(stderr, "=> cleaning cgroups...\n");
	for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
		char dir[PATH_MAX] = {0};
		char task[PATH_MAX] = {0};
		int task_fd;
        // open the tasks file for the current cgroup controller
		if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s",
			     (*cgrp)->control, config->hostname) == -1 ||
		    snprintf(task, sizeof(task), "/sys/fs/cgroup/%s/tasks",
			     (*cgrp)->control) == -1) {
			fprintf(stderr, "snprintf failed: %m\n");
			return -1;
		}
		task_fd = open(task, O_WRONLY);
		if (task_fd == -1) {
			fprintf(stderr, "opening %s failed: %m\n", task);
			return -1;
		}
        // remove the tasks from the cgroup by writing "0" to the tasks file
		if (write(task_fd, "0", 1) == -1) {
			fprintf(stderr, "writing to %s failed: %m\n", task);
			close(task_fd);
			return -1;
		}
		close(task_fd);
        // remove the cgroup directory, it is now allowed as there are no tasks associated with it
		if (rmdir(dir)) {
			fprintf(stderr, "rmdir %s failed: %m\n", dir);
			return -1;
		}
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int free_resources_v2(struct child_config *config)
{
	char dir[PATH_MAX] = {0};
	int fd;

	fprintf(stderr, "=> cleaning cgroups v2...\n");

	if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s",
		     config->hostname) < 0)
		return -1;

    // Move process back to root cgroup
    fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
    if (fd == -1) {
        fprintf(stderr, "open cgroup.procs failed: %m\n");
        return -1;
    }

	if (write(fd, "0", 1) == -1) {
		fprintf(stderr, "write cgroup.procs failed: %m\n");
		close(fd);
		return -1;
	}
	close(fd);

    // Remove container cgroup
    if (rmdir(dir)) {
        fprintf(stderr, "rmdir %s failed: %m\n", dir);
        return -1;
    }

	fprintf(stderr, "done.\n");
	return 0;
}

char *create_stack(void)
{
	char *stack = malloc(STACK_SIZE);
	if (!stack) {
		perror("Failed to allocate stack");
		exit(1);
	}
	return stack + STACK_SIZE;
}

int set_hostname(const char *hostname)
{
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
		fprintf(stderr, "failed to remount with MS_PRIVATE: %m\n");
		return -1;
	}
	fprintf(stderr, "remounted.\n");

	fprintf(stderr, "=> making a temp directory and a bind mount there...\n");
	char mount_dir[] = "/tmp/tmp.XXXXXX";
	if (!mkdtemp(mount_dir)) {
		fprintf(stderr, "failed making a directory: %m\n");
		return -1;
	}

	if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
		fprintf(stderr, "bind mount failed: %m\n");
		return -1;
	}

	char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
	memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
	if (!mkdtemp(inner_mount_dir)) {
		fprintf(stderr, "failed making the inner directory: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, "=> pivoting root...\n");
	if (pivot_root(mount_dir, inner_mount_dir)) {
		fprintf(stderr, "failed to pivot root: %m\n");
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
		fprintf(stderr, "chdir failed: %m\n");
		return -1;
	}
	if (umount2(old_root, MNT_DETACH)) {
		fprintf(stderr, "umount of the old root failed: %m\n");
		return -1;
	}
	if (rmdir(old_root)) {
		fprintf(stderr, "failed to remove old root: %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int handle_child_userns(pid_t child_pid, int fd)
{
	int map_file;
	int has_userns = -1;
    // check if the child created a user namespace
	if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
		fprintf(stderr, "couldn't read from child\n");
		return -1;
	}
	if (has_userns) {
		char path[PATH_MAX] = {0};
        // write the UID (User ID) and GID (Group ID) maps
		for (char **file = (char *[]){ "uid_map", "gid_map", 0 }; *file; file++) {
			if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
			    > sizeof(path)) {
				fprintf(stderr, "failed to build path: %m\n");
				return -1;
			}
			fprintf(stderr, "writing %s...\n", path);
			map_file = open(path, O_WRONLY);
			if (map_file == -1) {
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
	if (write(fd, &(int){ 0 }, sizeof(int)) != sizeof(int)) {
		fprintf(stderr, "couldn't notify child: %m\n");
		return -1;
	}
	return 0;
}

int userns(struct child_config *config)
{
	fprintf(stderr, "=> trying to create a user namespace...\n");
	int has_userns = !unshare(CLONE_NEWUSER);
	if (!has_userns)
		fprintf(stderr, "user namespace creation failed: %m\n");

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
	if (result)
		return -1;
	
	fprintf(stderr, "=> switching to uid %d / gid %d...\n", config->uid, config->uid);
	if (setgroups(1, &(gid_t){ config->uid }) || // remove all groups except the one we are mapping to
	    setresgid(config->uid, config->uid, config->uid) || //sets real/effective/saved GID
	    setresuid(config->uid, config->uid, config->uid)) { //sets real/effective/saved UID
		fprintf(stderr, "Failed to set UID, GID or to remove groups : %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

// capabilities define what the root user can do
// we drop the unnecessary ones
// see the source of the code linked at the top for the explanation of each dropped capability
int capabilities(void)
{
	fprintf(stderr, "=> dropping capabilities...\n");
	int drop_caps[] = {
		CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE,
		CAP_BLOCK_SUSPEND, CAP_DAC_READ_SEARCH, CAP_FSETID,
		CAP_IPC_LOCK, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_MKNOD,
		CAP_SETFCAP, CAP_SYSLOG, CAP_SYS_ADMIN, CAP_SYS_BOOT,
		CAP_SYS_MODULE, CAP_SYS_NICE, CAP_SYS_RAWIO,
		CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_WAKE_ALARM
	};
	size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
	
	fprintf(stderr, "bounding...\n");
    // drop the capabilities from the bounding set (i.e the maximum set of capabilities that can be held by any process)
	for (size_t i = 0; i < num_caps; i++) {
		if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
			fprintf(stderr, "prctl failed: %m\n");
			return 1;
		}
	}
	
	fprintf(stderr, "inheritable...\n");
	cap_t caps = cap_get_proc();
	if (!caps || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR) ||
	    cap_set_proc(caps)) {
		fprintf(stderr, "failed: %m\n");
		if (caps)
			cap_free(caps);
		return 1;
	}
	cap_free(caps);
	fprintf(stderr, "done.\n");
	return 0;
}

// blacklist dangerous syscalls using seccomp
int blacklist_syscalls(void)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	fprintf(stderr, "=> filtering syscalls (blacklist)...\n");
	if (!ctx)
		goto fail;
	
	if (seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
	                      SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
	                      SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
	                      SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
	                      SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
	                      SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
	                      SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
	                      SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
	                      SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
	                      SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0) ||
	    seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0) ||
	    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) ||
	    seccomp_load(ctx))
		goto fail;

	seccomp_release(ctx);
	fprintf(stderr, "done.\n");
	return 0;

fail:
	if (ctx)
		seccomp_release(ctx);
	fprintf(stderr, "failed: %m\n");
	return 1;
}

// whitelist syscalls (safer than blacklist, but may break functionality if a needed syscall is not allowed and a pain to make and maintain)
// this one should work for the most basic commands inside the container like sh, ls, ps, cat, cd... I didn't allow any networking related syscalls
int whitelist_syscalls(void)
{
	scmp_filter_ctx ctx;
	fprintf(stderr, "=> applying seccomp allowlist (whitelist)...\n");
	
	ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (!ctx)
		goto fail;
	if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1))
		goto fail;

    ALLOW(read);
    ALLOW(write);
    ALLOW(open);
    ALLOW(close);
    ALLOW(stat);
    ALLOW(fstat);
    ALLOW(lstat);
    ALLOW(execve);
    ALLOW(exit);
    ALLOW(exit_group);
    ALLOW(rt_sigaction);
    ALLOW(rt_sigprocmask);
    ALLOW(rt_sigreturn);
    ALLOW(brk);
    ALLOW(mmap);
    ALLOW(mprotect);
    ALLOW(munmap);
    ALLOW(uname);
    ALLOW(getuid);
    ALLOW(getgid);
    ALLOW(geteuid);
    ALLOW(getegid);
    ALLOW(getpid);
    ALLOW(getppid);
    ALLOW(getpgrp);
    ALLOW(setsid);
    ALLOW(setgid);
    ALLOW(setuid);
    ALLOW(setpgid);
    ALLOW(wait4);
    ALLOW(waitpid);
    ALLOW(sched_yield);
    ALLOW(sched_getaffinity);
    ALLOW(sched_setaffinity);
    ALLOW(set_tid_address);
    ALLOW(set_robust_list);
    ALLOW(futex);
    ALLOW(clone);
    ALLOW(fork);
    ALLOW(vfork);
    ALLOW(arch_prctl);
    ALLOW(getcwd);
    ALLOW(ioctl);
    ALLOW(fcntl);
    ALLOW(getpgid);
    ALLOW(lseek);
    ALLOW(writev);
    ALLOW(poll);
    ALLOW(getdents64);
    ALLOW(chdir);
    ALLOW(unlink);
    ALLOW(mkdir);
    ALLOW(rmdir);
    ALLOW(rename);
    ALLOW(dup2);
    ALLOW(utime);
    ALLOW(utimes);
    ALLOW(readdir);
    ALLOW(pipe);
    ALLOW(pipe2);
    ALLOW(newfstatat);
    ALLOW(sendfile);
    ALLOW(sysinfo);

	if (seccomp_load(ctx))
		goto fail;
	seccomp_release(ctx);
	fprintf(stderr, "done.\n");
	return 0;

fail:
	if (ctx)
		seccomp_release(ctx);
	fprintf(stderr, "failed: %m\n");
	return 1;
}

int apply_seccomp(int use_blacklist)
{
	return use_blacklist ? blacklist_syscalls() : whitelist_syscalls();
}

int child(void *arg)
{
	struct child_config *config = arg;
	if (set_hostname(config->hostname) ||
	    mounts(config) ||
	    userns(config) ||
        capabilities() ||
	    apply_seccomp(config->seccomp_blacklist)) {
		close(config->fd);
		return -1;
	}
	if (close(config->fd)) {
		fprintf(stderr, "close failed: %m\n");
		return -1;
	}
	if (execve(config->argv[0], config->argv, NULL)) {
		fprintf(stderr, "execve failed: %m\n");
		return -1;
	}
	return 0;
}

int main(void)
{
	int err = 0;
	struct child_config config = {0};
	int sockets[2] = {0};
	
	config.hostname = "container";
	config.argv = (char *[]){ "/bin/sh", NULL };
	config.mount_dir = "fs";
	config.seccomp_blacklist = 1;

	if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
		fprintf(stderr, "socketpair failed: %m\n");
		goto error;
	}
	if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)) {
		fprintf(stderr, "fcntl failed: %m\n");
		goto error;
	}
	config.fd = sockets[1];
	
	char *stack_top = create_stack();
	printf("Stack created at address: %p\n", stack_top);
	
	int is_v2 = is_cgroup_v2();
	if (is_v2) {
		if (resources_v2(&config)) {
			err = 1;
			goto clear_resources;
		}
	} else {
		if (resources(&config)) {
			err = 1;
			goto clear_resources;
		}
	}

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
	if (pid)
		kill(pid, SIGKILL);

finish_child:
	{
		int child_status = 0;
		waitpid(pid, &child_status, 0);
		err |= WEXITSTATUS(child_status);
	}

clear_resources:
	if (is_v2) {
		free_resources_v2(&config);
	} else {
		free_resources(&config);
	}
	free(stack_top - STACK_SIZE);
error:
    err=1;
cleanup:
	if (sockets[0])
		close(sockets[0]);
	if (sockets[1])
		close(sockets[1]);
	return err;
}