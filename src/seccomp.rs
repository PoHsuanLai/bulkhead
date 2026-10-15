//! The default seccomp filter, written as a classic BPF program in plain safe Rust and handed to
//! bubblewrap (`--seccomp FD`), which installs it just before running the command.
//!
//! Nothing here links a library or calls the kernel: a filter is a list of eight-byte
//! instructions, and this file lays them out. The program is an allow-list-by-exception:
//!
//! - a different architecture than the one built for is killed (so the 32-bit and x32 entry
//!   points cannot be used to dodge the number checks);
//! - listed system calls fail with `EPERM`: `ptrace`, the key-ring calls, `bpf`,
//!   `perf_event_open`, `userfaultfd`, `mount` and the new mount API, `setns`, `pivot_root`,
//!   `chroot`, module loading, `kexec`, `reboot`, `io_uring`, `process_vm_*`, `open_by_handle_at`
//!   and similar;
//! - `clone` and `unshare` fail with `EPERM` when their flags ask for any new namespace, so a
//!   command cannot make a user namespace of its own (and with it the capabilities inside);
//! - `clone3` fails with `ENOSYS`: its flags live in memory a filter cannot read, and libc falls
//!   back to `clone`, which is checked.
//!
//! Everything else is allowed: the sandbox's other walls (namespaces, no capabilities, read-only
//! root) stay the main defence, and this removes the kernel surface a command has no use for.

/// Why no filter could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SeccompFault {
    /// This CPU architecture has no system call table here.
    #[error("no seccomp table for this architecture")]
    Unsupported,
    /// The program grew past what a one-byte jump can cross.
    #[error("the seccomp program is too long")]
    TooLong,
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

/// Every `CLONE_NEW*` flag except time: mount, cgroup, uts, ipc, user, pid, net.
const NEW_NAMESPACES: u32 = 0x7E02_0000;

/// System calls that are the same number on every architecture (the newer, unified ones).
const COMMON_DENY: &[u32] = &[
    425, // io_uring_setup
    426, // io_uring_enter
    427, // io_uring_register
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    438, // pidfd_getfd
    442, // mount_setattr
];

/// `clone3`, the same number everywhere.
const CLONE3: u32 = 435;

/// One architecture's numbers.
struct Table {
    audit_arch: u32,
    /// The bit that marks the x32 calling convention, where there is one.
    x32_bit: Option<u32>,
    clone: u32,
    unshare: u32,
    deny: &'static [u32],
}

#[cfg(target_arch = "x86_64")]
const TABLE: Option<Table> = Some(Table {
    audit_arch: 0xC000_003E,
    x32_bit: Some(0x4000_0000),
    clone: 56,
    unshare: 272,
    deny: &[
        101, // ptrace
        103, // syslog
        134, // uselib
        155, // pivot_root
        156, // _sysctl
        161, // chroot
        163, // acct
        165, // mount
        166, // umount2
        167, // swapon
        168, // swapoff
        169, // reboot
        172, // iopl
        173, // ioperm
        175, // init_module
        176, // delete_module
        179, // quotactl
        212, // lookup_dcookie
        246, // kexec_load
        248, // add_key
        249, // request_key
        250, // keyctl
        298, // perf_event_open
        300, // fanotify_init
        304, // open_by_handle_at
        308, // setns
        310, // process_vm_readv
        311, // process_vm_writev
        312, // kcmp
        313, // finit_module
        320, // kexec_file_load
        321, // bpf
        323, // userfaultfd
    ],
});

#[cfg(target_arch = "aarch64")]
const TABLE: Option<Table> = Some(Table {
    audit_arch: 0xC000_00B7,
    x32_bit: None,
    clone: 220,
    unshare: 97,
    deny: &[
        18,  // lookup_dcookie
        39,  // umount2
        40,  // mount
        41,  // pivot_root
        51,  // chroot
        60,  // quotactl
        89,  // acct
        104, // kexec_load
        105, // init_module
        106, // delete_module
        116, // syslog
        117, // ptrace
        142, // reboot
        217, // add_key
        218, // request_key
        219, // keyctl
        224, // swapon
        225, // swapoff
        241, // perf_event_open
        262, // fanotify_init
        265, // open_by_handle_at
        268, // setns
        270, // process_vm_readv
        271, // process_vm_writev
        272, // kcmp
        273, // finit_module
        280, // bpf
        282, // userfaultfd
        294, // kexec_file_load
    ],
});

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const TABLE: Option<Table> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Insn {
    fn load(offset: u32) -> Self {
        Self {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    fn eq(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: JEQ_K,
            jt,
            jf,
            k,
        }
    }

    fn any_bit(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: JSET_K,
            jt,
            jf,
            k,
        }
    }

    fn ret(k: u32) -> Self {
        Self {
            code: RET_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// The kernel's `struct sock_filter`, in native byte order.
    fn bytes(self) -> [u8; 8] {
        let mut out = [0_u8; 8];
        out[..2].copy_from_slice(&self.code.to_ne_bytes());
        out[2] = self.jt;
        out[3] = self.jf;
        out[4..].copy_from_slice(&self.k.to_ne_bytes());
        out
    }
}

/// What to do about one system call.
#[derive(Debug, Clone, Copy)]
enum Rule {
    /// Fail with `EPERM`.
    Deny(u32),
    /// Fail with `EPERM` when the first argument has a namespace flag.
    DenyIfNamespaces(u32),
    /// Fail with `ENOSYS`.
    Unimplemented(u32),
}

impl Rule {
    fn len(self) -> usize {
        match self {
            Rule::Deny(_) | Rule::Unimplemented(_) => 1,
            Rule::DenyIfNamespaces(_) => 4,
        }
    }
}

/// The jump from the instruction at `from` to the one at `to`, as a one-byte offset.
fn jump(from: usize, to: usize) -> Result<u8, SeccompFault> {
    u8::try_from(to - from - 1).map_err(|_| SeccompFault::TooLong)
}

/// The default filter, as the bytes bubblewrap reads from its `--seccomp` descriptor.
pub fn default_filter() -> Result<Vec<u8>, SeccompFault> {
    let table = TABLE.as_ref().ok_or(SeccompFault::Unsupported)?;
    let rules: Vec<Rule> = table
        .deny
        .iter()
        .chain(COMMON_DENY)
        .map(|nr| Rule::Deny(*nr))
        .chain([
            Rule::DenyIfNamespaces(table.clone),
            Rule::DenyIfNamespaces(table.unshare),
            Rule::Unimplemented(CLONE3),
        ])
        .collect();

    let mut prog = vec![
        Insn::load(OFF_ARCH),
        Insn::eq(table.audit_arch, 1, 0),
        Insn::ret(RET_KILL_PROCESS),
        Insn::load(OFF_NR),
    ];
    if let Some(bit) = table.x32_bit {
        prog.push(Insn::any_bit(bit, 0, 1));
        prog.push(Insn::ret(RET_KILL_PROCESS));
    }
    let allow_at = prog.len() + rules.iter().map(|r| r.len()).sum::<usize>();
    let (eperm_at, enosys_at) = (allow_at + 1, allow_at + 2);

    for rule in rules {
        match rule {
            Rule::Deny(nr) => {
                let to = jump(prog.len(), eperm_at)?;
                prog.push(Insn::eq(nr, to, 0));
            }
            Rule::Unimplemented(nr) => {
                let to = jump(prog.len(), enosys_at)?;
                prog.push(Insn::eq(nr, to, 0));
            }
            Rule::DenyIfNamespaces(nr) => {
                prog.push(Insn::eq(nr, 0, 3));
                prog.push(Insn::load(OFF_ARG0));
                let to = jump(prog.len(), eperm_at)?;
                prog.push(Insn::any_bit(NEW_NAMESPACES, to, 0));
                prog.push(Insn::load(OFF_NR));
            }
        }
    }
    prog.push(Insn::ret(RET_ALLOW));
    prog.push(Insn::ret(RET_ERRNO | EPERM));
    prog.push(Insn::ret(RET_ERRNO | ENOSYS));
    Ok(prog.into_iter().flat_map(Insn::bytes).collect())
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    /// What the filter answers for one call: a tiny interpreter of the three instruction kinds
    /// used here, so the program is checked without a kernel.
    fn run(filter: &[u8], arch: u32, nr: u32, arg0: u32) -> u32 {
        let prog: Vec<Insn> = filter
            .chunks(8)
            .map(|c| Insn {
                code: u16::from_ne_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect();
        let (mut pc, mut acc) = (0_usize, 0_u32);
        loop {
            let i = prog[pc];
            pc += 1;
            let skip = match i.code {
                LD_W_ABS => {
                    acc = match i.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        _ => arg0,
                    };
                    0
                }
                JEQ_K => usize::from(if acc == i.k { i.jt } else { i.jf }),
                JSET_K => usize::from(if acc & i.k != 0 { i.jt } else { i.jf }),
                _ => return i.k,
            };
            pc += skip;
        }
    }

    const X86: u32 = 0xC000_003E;
    const CLONE_NEWUSER: u32 = 0x1000_0000;
    const CLONE_VM: u32 = 0x100;

    /// Each row is one call and what the filter must say; the row names the case.
    #[test]
    fn the_filter_blocks_what_a_command_has_no_use_for_and_allows_the_rest() {
        let filter = default_filter().expect("filter");
        assert_eq!(filter.len() % 8, 0);
        let eperm = RET_ERRNO | EPERM;
        let rows: [(&str, u32, u32, u32, u32); 14] = [
            ("read", X86, 0, 0, RET_ALLOW),
            ("execve", X86, 59, 0, RET_ALLOW),
            ("ptrace", X86, 101, 0, eperm),
            ("keyctl", X86, 250, 0, eperm),
            ("bpf", X86, 321, 0, eperm),
            ("perf_event_open", X86, 298, 0, eperm),
            ("mount", X86, 165, 0, eperm),
            ("io_uring_setup", X86, 425, 0, eperm),
            ("clone for a thread", X86, 56, CLONE_VM, RET_ALLOW),
            ("clone into a user namespace", X86, 56, CLONE_NEWUSER, eperm),
            ("unshare a user namespace", X86, 272, CLONE_NEWUSER, eperm),
            ("unshare nothing", X86, 272, 0, RET_ALLOW),
            ("clone3", X86, 435, 0, RET_ERRNO | ENOSYS),
            ("x32 entry point", X86, 0x4000_0000, 0, RET_KILL_PROCESS),
        ];
        for (name, arch, nr, arg0, want) in rows {
            assert_eq!(run(&filter, arch, nr, arg0), want, "{name}");
        }
        assert_eq!(
            run(&filter, 0x4000_0003, 0, 0),
            RET_KILL_PROCESS,
            "another architecture"
        );
    }
}
