//! Whether a command can be confined here, and if not, why.

use serde::{Deserialize, Serialize};

/// Why a command cannot run in the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum CannotSandbox {
    /// No sandbox program (`bwrap`) is installed.
    #[error("no sandbox program is installed")]
    NotInstalled,
    /// The program is there but the kernel refuses it (user namespaces are off).
    #[error("the kernel refuses unprivileged sandboxes here")]
    NamespacesDenied,
    /// This platform has no sandbox backend.
    #[error("this platform has no sandbox")]
    Unsupported,
    /// The working directory cannot be the one writable place (`/`, or it is not a directory).
    #[error("the working directory cannot be sandboxed")]
    BadWorkingDir,
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
