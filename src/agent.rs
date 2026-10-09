//! The command line that confines a long-running agent process : bubblewrap
//! as a separate program, built as plain arguments so a test reads them. Unlike a terminal
//! command, an agent talks over its stdio, so this file only builds the arguments; the process
//! and its pipes are the caller's.
//!
//! What the agent gets: the host read-only; `/home`, `/root`, `/run`, `/tmp` and the like empty;
//! the session's working directory writable; each extra bind the caller names for this
//! program (its own program directory read-only, its own login and state directory read-write);
//! the network per `NetworkMode`; an environment that is exactly what the caller passes (set on
//! the bubblewrap process, never in its arguments, so a key is not on a command line);
//! no capabilities; a new session; death with its parent.

use crate::AbsPath;
use crate::bwrap::HIDDEN;
use crate::confinement::{Share, confinement};
use crate::net::{AgentNet, EndpointBind};
use crate::sandbox::{Argv, EnvVar};

/// Where the forwarder and its socket appear inside the sandbox.
pub const INSIDE_FORWARDER: &str = "/run/bulkhead/forward";
/// The socket's path inside the sandbox.
pub const INSIDE_SOCKET: &str = "/run/bulkhead/ep.sock";

/// How an extra path is bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// Visible, not writable.
    ReadOnly,
    /// Visible and writable: only for the program's own state.
    ReadWrite,
}

/// One extra path made visible inside the sandbox at the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Bind {
    /// The path, on the host and inside.
    pub path: AbsPath,
    /// How.
    pub access: Access,
}

/// One host file shown inside the sandbox at another path, read-only: a file the caller wrote for this
/// run, over the agent's own file of that name. The agent cannot change it, and the host's file is
/// not touched (bubblewrap mounts over it).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Overlay {
    /// The file on the host.
    pub from: AbsPath,
    /// Where the agent sees it.
    pub to: AbsPath,
}

/// Everything needed to confine one agent process.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentRun {
    /// The agent command.
    pub argv: Argv,
    /// The session's working directory, writable.
    pub cwd: AbsPath,
    /// The whole environment (already built). It is not in the arguments: a command line is
    /// readable by every process of the user, a process's environment only by its owner. The
    /// caller starts bubblewrap with exactly this environment and nothing else
    /// (`env_clear`, then these), and bubblewrap passes it on.
    pub env: Vec<EnvVar>,
    /// The network.
    pub net: AgentNet,
    /// The extra binds, in order.
    pub binds: Vec<Bind>,
    /// Files the caller wrote for this run, mounted after the binds so they win over them.
    pub overlays: Vec<Overlay>,
}

impl Bind {
    /// `path`, visible at the same path inside, with `access`.
    pub fn new(path: AbsPath, access: Access) -> Self {
        Self { path, access }
    }
}

impl Overlay {
    /// The host file `from`, shown inside at `to`, read-only.
    pub fn new(from: AbsPath, to: AbsPath) -> Self {
        Self { from, to }
    }
}

impl AgentRun {
    /// A run of `argv` in `cwd`, with `env` and `net`, and no extra binds or overlays.
    pub fn new(argv: Argv, cwd: AbsPath, env: Vec<EnvVar>, net: AgentNet) -> Self {
        Self {
            argv,
            cwd,
            env,
            net,
            binds: Vec::new(),
            overlays: Vec::new(),
        }
    }

    /// The same run with one more extra bind, after the ones already there.
    #[must_use]
    pub fn with_bind(mut self, bind: Bind) -> Self {
        self.binds.push(bind);
        self
    }

    /// The same run with one more overlay, after the ones already there.
    #[must_use]
    pub fn with_overlay(mut self, overlay: Overlay) -> Self {
        self.overlays.push(overlay);
        self
    }
}

/// The `bwrap` arguments for `run`, hiding the `hidden` directories. Pure.
pub fn agent_bwrap_args(run: &AgentRun, hidden: &[&str]) -> Vec<String> {
    let share = match run.net {
        AgentNet::Host => Share::HostNet,
        AgentNet::None | AgentNet::Endpoint(_) => Share::Nothing,
    };
    let mut args = confinement(share, hidden);
    for bind in &run.binds {
        let flag = match bind.access {
            Access::ReadOnly => "--ro-bind",
            Access::ReadWrite => "--bind",
        };
        let path = bind.path.as_str();
        args.extend([flag, path, path].map(str::to_owned));
    }
    for overlay in &run.overlays {
        args.extend(["--ro-bind", overlay.from.as_str(), overlay.to.as_str()].map(str::to_owned));
    }
    let cwd = run.cwd.as_str();
    args.extend(["--bind", cwd, cwd, "--chdir", cwd].map(str::to_owned));
    if let AgentNet::Endpoint(bind) = &run.net {
        args.extend([
            "--ro-bind".to_owned(),
            bind.forwarder.as_str().to_owned(),
            INSIDE_FORWARDER.to_owned(),
            "--bind".to_owned(),
            bind.socket.as_str().to_owned(),
            INSIDE_SOCKET.to_owned(),
        ]);
    }
    args.push("--".to_owned());
    args.extend(inner(run));
    args
}

/// The words bubblewrap runs: the agent itself, or the forwarder that starts it.
fn inner(run: &AgentRun) -> Vec<String> {
    match &run.net {
        AgentNet::Endpoint(bind) => forwarder_words(bind, run.argv.words()),
        AgentNet::None | AgentNet::Host => run.argv.words().to_vec(),
    }
}

fn forwarder_words(bind: &EndpointBind, agent: &[String]) -> Vec<String> {
    let mut out = vec![
        INSIDE_FORWARDER.to_owned(),
        "run".to_owned(),
        "--listen".to_owned(),
        format!("127.0.0.1:{}", bind.port),
        "--socket".to_owned(),
        INSIDE_SOCKET.to_owned(),
        "--".to_owned(),
    ];
    out.extend(agent.iter().cloned());
    out
}

/// The directories to empty: those of `HIDDEN` that exist on this host.
pub fn present_hidden() -> Vec<&'static str> {
    present_hidden_where(|d| std::path::Path::new(d).is_dir())
}

/// The directories of `HIDDEN` for which `exists` is true. The host's view is supplied by the
/// caller, so a test or another host can answer it.
pub fn present_hidden_where(exists: impl Fn(&str) -> bool) -> Vec<&'static str> {
    HIDDEN.iter().copied().filter(|d| exists(d)).collect()
}
