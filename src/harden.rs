//! The hardening a caller chooses, as typed values with safe defaults.
//!
//! Nothing here runs anything. `Limits` says how much a sandbox may use, `LimitPolicy` says how
//! (or whether) that is enforced, and `Hardening` gathers the choices that `BwrapSandbox` turns
//! into a command line. A person who accepts no limits has to say so with `AcceptNoLimits`; the
//! default is the strict choice, and a sandbox that cannot apply it refuses to start.

use crate::AbsPath;
use serde::{Deserialize, Serialize};

/// A size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bytes(pub u64);

impl Bytes {
    /// `n` mebibytes.
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    /// `n` gibibytes.
    pub const fn gib(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024)
    }
}

/// The page size limits are rounded to: the kernel rounds cgroup memory limits down to it, so a
/// limit that is not a multiple would read back differently from what was set.
const PAGE: u64 = 4096;

/// What one sandbox may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Memory for everything in the sandbox together (swap is not allowed on top).
    pub memory: Bytes,
    /// Processes and threads in the sandbox together.
    pub pids: u32,
    /// CPU seconds one process may use before the kernel stops it.
    pub cpu_seconds: u32,
    /// The size of each in-memory scratch directory (`/tmp`, `/var/tmp`, `/run`, ...).
    pub tmpfs: Bytes,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory: Bytes::gib(2),
            pids: 256,
            cpu_seconds: 900,
            tmpfs: Bytes::mib(256),
        }
    }
}

impl Limits {
    /// The limits when every number is usable: none zero, memory a whole number of pages.
    pub(crate) fn usable(&self) -> bool {
        self.memory.0 >= PAGE
            && self.memory.0 % PAGE == 0
            && self.pids > 0
            && self.cpu_seconds > 0
            && self.tmpfs.0 > 0
    }
}

/// The explicit statement that the person accepts a sandbox with no resource limits. Without
/// it, a sandbox that cannot apply limits does not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptNoLimits;

/// How limits are enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitPolicy {
    /// In a transient systemd user scope (cgroup): memory, pids and CPU seconds, for the whole
    /// sandbox. The default. Refuses to start where systemd cannot apply them.
    Cgroup(Limits),
    /// Per-process kernel limits only (`ulimit`): CPU seconds, and address space for the
    /// memory. There is no cap on the number of processes. For hosts without a user manager;
    /// weaker, so it is chosen, never a silent fallback.
    Rlimit(Limits),
    /// No resource limits, accepted by the person.
    Unlimited(AcceptNoLimits),
}

impl Default for LimitPolicy {
    fn default() -> Self {
        LimitPolicy::Cgroup(Limits::default())
    }
}

impl LimitPolicy {
    /// The limits, where the policy has any.
    pub fn limits(&self) -> Option<&Limits> {
        match self {
            LimitPolicy::Cgroup(l) | LimitPolicy::Rlimit(l) => Some(l),
            LimitPolicy::Unlimited(_) => None,
        }
    }
}

/// Whether the default seccomp filter is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Seccomp {
    /// The default filter (`seccomp`): no nested user namespaces, `ptrace`, `bpf`, key rings,
    /// mounts, `io_uring` and similar. A sandbox that cannot install it is not created.
    #[default]
    Default,
    /// No filter, chosen by the person.
    Off,
}

/// Whether `/opt` is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptDir {
    /// Not there.
    #[default]
    Hidden,
    /// Visible, read-only.
    ReadOnly,
}

/// Everything a caller chooses about hardening.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Hardening {
    /// Resource limits.
    pub limits: LimitPolicy,
    /// The syscall filter.
    pub seccomp: Seccomp,
    /// Whether `/opt` is visible (read-only).
    pub opt: OptDir,
    /// Extra host paths made visible read-only at the same path: the escape hatch for a
    /// toolchain that lives outside `/usr` (`/nix`, a version manager under a home directory).
    pub extra_ro: Vec<AbsPath>,
}
