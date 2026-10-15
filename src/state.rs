//! Whether a command can be confined here, and if not, why.

use serde::{Deserialize, Serialize};

/// Why a command cannot run in the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CannotSandbox {
    /// No sandbox program (`bwrap`) is installed.
    #[error("no sandbox program is installed")]
    NotInstalled,
    /// The program is there but the kernel refuses it (user namespaces are off).
    #[error("the kernel refuses unprivileged sandboxes here")]
    NamespacesDenied,
    /// The program is there but AppArmor (Ubuntu 24.04 and later) blocks user namespaces for it.
    #[error(
        "AppArmor blocks the sandbox: allow user namespaces for bubblewrap with an AppArmor \
         profile (see the bulkhead README), or set kernel.apparmor_restrict_unprivileged_userns to 0"
    )]
    RestrictedByAppArmor,
    /// This platform has no sandbox backend.
    #[error("this platform has no sandbox")]
    Unsupported,
    /// The working directory cannot be the one writable place (`/`, or it is not a directory).
    #[error("the working directory cannot be sandboxed")]
    BadWorkingDir,
    /// Resource limits were asked for and cannot be applied here (no systemd user manager that
    /// delegates the cgroup controllers, no `sh`, or bubblewrap without `--size`).
    #[error("resource limits cannot be applied here")]
    LimitsUnavailable,
    /// The seccomp filter was asked for and cannot be installed here.
    #[error("the syscall filter cannot be installed here")]
    SeccompUnavailable,
    /// The limits are not usable numbers (zero, or memory not a whole number of pages).
    #[error("the resource limits are not usable")]
    BadLimits,
}

/// Whether this command can run in the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "v", rename_all = "snake_case")]
pub enum SandboxState {
    /// It can.
    Ready,
    /// It cannot, for this reason.
    Cannot(CannotSandbox),
}
