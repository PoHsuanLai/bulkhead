//! The sandboxed shell tool.
//!
//! - `Sandbox` and `Job`: the seam. `BwrapSandbox` runs a command under bubblewrap (a separate
//!   process, read-only root, write only to the working directory, no network, cleared
//!   environment); `FakeSandbox` records what it was asked and answers from a script.
//! - `Shell`: the terminal table over a sandbox. It never runs a command unsandboxed; when the
//!   sandbox cannot confine one it refuses with the reason.
//! - `agent`, `net`, `forward`: the confinement of a long-running agent process: its bubblewrap
//!   arguments, the three network modes, and the forwarder and bridge of the endpoint-only mode.
//! - `redact`, `Tail`, `shown`: output is bounded and secrets are masked before anyone reads it.
//! - `sandbox_env`: the environment is cleared and rebuilt from an allowlist.
//!
//! Whether a command may run at all is the caller's decision; this crate only runs what it is
//! given, and only inside the sandbox.

mod agent;
mod bwrap;
mod bwrap_job;
mod bwrap_kill;
pub mod cli;
mod confinement;
mod env;
pub mod fake;
#[cfg(unix)]
pub mod forward;
mod net;
mod output;
mod path;
mod redact;
mod sandbox;
mod state;
mod tool;

pub use agent::{
    Access, AgentRun, Bind, INSIDE_FORWARDER, INSIDE_SOCKET, Overlay, agent_bwrap_args,
    present_hidden,
};
pub use bwrap::{BwrapSandbox, Detected, HIDDEN, bwrap_args};
pub use bwrap_job::BwrapJob;
pub use env::{SANDBOX_HOME, SANDBOX_PATH, dropped, sandbox_env};
pub use net::{AgentNet, EndpointBind, NetFault, NetworkMode, RESOLVER_FILES};
pub use output::{Shown, Tail, shown};
pub use path::{AbsPath, PathFault, RootState};
pub use redact::{MASK, redact};
pub use sandbox::{
    Argv, ByteLimit, Captured, Cut, EnvVar, ExitReport, Job, KILLED, Network, RunSpec, Sandbox,
    StartFault,
};
pub use state::{CannotSandbox, SandboxState};
pub use tool::{
    DEFAULT_KEEP, Launch, MAX_KEEP, MAX_TERMINALS, Shell, ShellFault, Snapshot, TermId,
};
