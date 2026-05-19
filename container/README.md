# Container experiments

This directory contains two user-space container proofs-of-concept for linux. The sources used are specified at the top of the programs.

## Files

- `contained.c`: minimal container example using `CLONE_NEWUTS` and `CLONE_NEWPID`, with a `chroot("fs")` into a minimal filesystem.
- `container_v2.c`: extended container example with complete isolation (additional namespaces, cgroup setup, seccomp usage, root capabilities), only lacking a networking setup. It runs `/bin/sh` by default ; a custom command can be specified. 

## Build

- `gcc contained.c -o contained`
- `gcc container_v2.c -o container_v2 -lseccomp -lcap`

## Run

- `sudo ./contained`
- `sudo ./container_v2 <command>`

## Requirements

- `container_v2.c` depends on the libseccomp and libcap development headers.
- `contained.c` expects a `fs` directory with a minimal root filesystem like the Alpine minirootfs tarball.