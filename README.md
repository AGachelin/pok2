# Container & Virtualization experiments on linux (student project)
## Project structure

- `container/`: contains two user-space container experiments for with different isolation levels.
- `hypervisor/`: contains a simple Linux kernel module build example (aborted experiment).
- `kvm/`: userspace KVM example that creates a tiny virtual machine and handles KVM exits.

## Build & run

### Container experiments

- Build the minimal container example:
  - `gcc container/contained.c -o container/contained`
- Build the extended container example:
  - `gcc container/container_v2.c -o container/container_v2 -lseccomp -lcap`
- Run as root:
  - `sudo ./container/contained`
  - `sudo ./container/container_v2`
- `container/contained.c` requires a minimal root filesystem in the `container/fs` directory.

### Hypervisor example

- Build the kernel module:
  - `cd hypervisor`
  - `make modules`
- Load the module:
  - `sudo insmod hypervisor/hypervisor.ko`
- Remove the module:
  - `sudo rmmod hypervisor`
- Clean build artifacts:
  - `make clean`

### KVM example

- Build the userspace KVM program:
  - `gcc kvm/kvm_module.c -o kvm/kvm_example`
- Run the example:
  - `sudo ./kvm/kvm_example`
- Requires a host Linux kernel with KVM support and access to `/dev/kvm`.

## Notes

- Root privileges are required to run the scripts.
- The `hypervisor/` example is an aborted experiment aiming at understanding virtualization hardware extensions (Intel VT-x and AMD-V).
