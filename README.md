# Scylla: Securing Blockchain Wallet Files using eBPF

<img src="misc/logo.png" width="128"/>


## Introduction

In this repository, we introduce **Scylla**, an  solution  designed to enhance the security of blockchain (BC) and Distributed Ledger Technology (DLT) wallet-related files by preventing unauthorized access through the utilization of extended Berkeley Packet Filter (eBPF). The proposed solution employs fine-grained access control mechanisms, providing robust protection for critical files, including account files. This is achieved by actively monitoring system calls of processes directed towards these sensitive files.

## Publication

Scylla was approved for publication as a full-paper in the [IEEE Global Communications Conference (GLOBECOM 2024)](https://globecom2024.ieee-globecom.org/). The full paper can be found here: [https://ieeexplore.ieee.org/document/10901795](https://ieeexplore.ieee.org/document/10901795)

If you wish to reference Scylla, you can use the following citation:
```
J. C. Caroly, E. J. Scheid, M. F. Franco and L. Z. Granville, "Securing Blockchain Wallet Files Using eBPF," GLOBECOM 2024 - 2024 IEEE Global Communications Conference, Cape Town, South Africa, 2024, pp. 553-558, doi: 10.1109/GLOBECOM52923.2024.10901795.
```
.bib
```
@INPROCEEDINGS{globecom2024eBPF,
  author={Jeison C. Caroly and Scheid, Eder J. and Muriel Figueredo Franco and Lisandro Zambenedetti Granville},
  booktitle={IEEE Global Communications Conference (GLOBECOM 2024)}, 
  title={{Securing Blockchain Wallet Files Using eBPF}}, 
  year={2024},
  address={Cape Town, South Africa},
  pages={1--6},
  month = {12},
}
```


## Key Features

- **Fine-grained Access Control:** **Scylla** implements fine-grained access control measures to protect critical files, ensuring that only authorized processes can access them.

- **Automatic Execution:** The solution is designed to be executed automatically during system boot time.

- **Protection Based on Inodes:** **Scylla** can be ajusted to protects itself and user-defined files based on their *inodes*, providing an additional layer of security.

- **Tamper Protection:** Unauthorized processes cannot read, write, delete, rename, or rmdir protected files. Read/write attempts are intercepted with eBPF kprobes on `vfs_read`/`vfs_write`. Delete, rename, and rmdir are denied in-kernel with BPF LSM hooks (`inode_unlink`, `inode_rename`, `inode_rmdir`) before the filesystem change occurs. Scylla also sends `SIGKILL` to the offending process.

Deletion/rename denial requires a kernel with `CONFIG_BPF_LSM` and BTF support, and `bpf` in the active LSM list. On Ubuntu this is usually enabled by adding `bpf` to the kernel `lsm=` boot parameter, for example:

```
lsm=lockdown,capability,landlock,yama,apparmor,bpf
```

Then run `sudo update-grub` and reboot. Verify with `cat /sys/kernel/security/lsm` — the list must include `bpf`. Run Scylla as root or with the required BPF capabilities.

If BPF LSM is not active, Scylla still attaches `security_inode_unlink`/`rename`/`rmdir` kprobes and, when the config stores a resolvable path, sets the immutable file flag so delete/rename fail even if the kill races with the syscall. Turn Scylla off to restore the original flags.

## How it Works

During execution, **Scylla** actively monitors the system calls of processes aiming to access sensitive files. This proactive approach allows it to intercept and prevent unauthorized attempts to read, modify, delete, or rename a file. Evaluations of **Scylla** demonstrate its capability to achieve these security objectives without introducing significant overhead to legitimate processes.

## Comparison to Other Tools

In comparative evaluations of functionality, **Scylla** has proven to outperform *inotify*, a Linux kernel subsystem designed for monitoring changes in the filesystem. Unlike *inotify*, **Scylla** goes beyond monitoring, actively preventing unauthorized file access and providing a more robust security solution for BC wallet-related files.

## Getting Started

To use **Scylla**, follow these steps:

1. Clone the repository: `git clone git@github.com:ComputerNetworks-UFRGS/scylla.git`
2. Follow the installation instructions in the provided documentation [TODO]
3. Execute **Scylla** during the boot time to enable automatic protection.

## Contributing

We welcome contributions from the community. If you find issues or have suggestions for improvements, please create an issue or submit a pull request.

## License

This project is licensed under the [Apache License 2.0](LICENSE) - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

We would like to express our gratitude to the open-source community and contributors for their valuable feedback and contributions to enhance **Scylla**.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Language](https://img.shields.io/badge/Language-Python-green.svg)](https://www.python.org/)
[![Language](https://img.shields.io/badge/Made_with-eBPF-yellow.svg)](https://ebpf.io/)
