# KVM userspace example

This directory contains a userspace KVM experiment that creates a simple virtual machine and executes a tiny guest program. I used  https://en.ittrip.xyz/c-language/c-kvm-hypervisor-guide and https://lwn.net/Articles/658511/.

## Files

- `kvm_module.c`: userspace KVM program that opens `/dev/kvm`, creates a VM and vCPU, maps memory, sets registers, and runs a short guest program.
- `test_setup.c`: small script checking whether kvm is supported.

## Build

```bash
gcc kvm_module.c -o kvm_example
```

## Run

```bash
sudo ./kvm_example
```

## Notes

- The guest code reads two number, writes the sum to port `0x3f8` and then halts.