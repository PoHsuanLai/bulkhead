//! The command line that confines a long-running agent process : bubblewrap
//! as a separate program, built as plain arguments so a test reads them. Unlike a terminal
//! command, an agent talks over its stdio, so this file only builds the arguments; the process
//! and its pipes are the caller's.
//!
//! What the agent gets: an allow-list root (`root`): `/usr`, `/etc` minus its secrets, the
//! `/bin` and `/lib*` links, fresh `/tmp` and `/run`, and nothing of `/home`, `/var`, `/mnt`;
//! the session's working directory writable; each extra bind the caller names for this
//! program (its own program directory read-only, its own login and state directory read-write);
//! the network per `NetworkMode`; an environment that is exactly what the caller passes (set on
//! the bubblewrap process, never in its arguments, so a key is not on a command line);
//! no capabilities; a new session; death with its parent.

use crate::confinement::{Share, confinement};
use crate::enter::{INSIDE_ENTER, plan_for};
use crate::net::{AgentNet, EndpointBind};
use crate::profile::Profile;
use crate::sandbox::{Argv, EnvVar};
use crate::{AbsPath, RootState};

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
    /// Paths inside `cwd` made read-only again after the workspace is bound writable (a `.git`
    /// directory, say). Added with `with_protect`.
    pub protect: Vec<AbsPath>,
    /// The exec stage program on the host (read-only inside). When set, bubblewrap starts it
    /// and it applies Landlock to itself before it starts the agent (see `enter`). Added with
    /// `with_landlock`.
    pub enter: Option<AbsPath>,
}

/// Why a path cannot be protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtectFault {
    /// The path is not strictly inside the working directory.
    #[error("a protected path must be inside the working directory")]
    OutsideCwd,
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
    /// A run of `argv` in `cwd`, with `env` and `net`, and no extra binds or overlays. In the
    /// allow-list mode the proxy variables (`AgentNet::proxy_env`) are put into `env`, over any
    /// of the same names the caller gave, so the agent cannot be started without them.
    pub fn new(argv: Argv, cwd: AbsPath, mut env: Vec<EnvVar>, net: AgentNet) -> Self {
        let proxy = net.proxy_env();
        env.retain(|v| !proxy.iter().any(|p| p.name == v.name));
        env.extend(proxy);
        Self {
            argv,
            cwd,
            env,
            net,
            binds: Vec::new(),
            overlays: Vec::new(),
            protect: Vec::new(),
            enter: None,
        }
    }

    /// The same run, started through the exec stage at `enter` (the `bulkhead-enter` program),
    /// which applies Landlock inside the sandbox and reports the level it reached.
    #[must_use]
    pub fn with_landlock(mut self, enter: AbsPath) -> Self {
        self.enter = Some(enter);
        self
    }

    /// The same run with one more extra bind, after the ones already there.
    #[must_use]
    pub fn with_bind(mut self, bind: Bind) -> Self {
        self.binds.push(bind);
        self
    }

    /// The same run with `path` read-only inside the writable workspace. The path must be
    /// strictly inside `cwd`. When the arguments are built, a path that does not exist is
    /// skipped (nothing to protect) and so is a symbolic link (a bind would follow it out of the
    /// workspace); skipping never makes the sandbox more open than without the path.
    pub fn with_protect(mut self, path: AbsPath) -> Result<Self, ProtectFault> {
        let inside = path
            .as_str()
            .strip_prefix(self.cwd.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
            || self.cwd.is_root() == RootState::Root && path.is_root() == RootState::Below;
        if !inside {
            return Err(ProtectFault::OutsideCwd);
        }
        self.protect.push(path);
        Ok(self)
    }

    /// The same run with one more overlay, after the ones already there.
    #[must_use]
    pub fn with_overlay(mut self, overlay: Overlay) -> Self {
        self.overlays.push(overlay);
        self
    }
}

/// The `bwrap` arguments for `run`. Pure.
pub fn agent_bwrap_args(run: &AgentRun, profile: &Profile) -> Vec<String> {
    let share = match run.net {
        AgentNet::Host => Share::HostNet,
        AgentNet::None | AgentNet::Endpoint(_) | AgentNet::Allowlist(_) => Share::Nothing,
    };
    let mut args = confinement(share, profile);
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
    // After the writable workspace, so each layers read-only over it.
    for path in run.protect.iter().filter(|p| protectable(p)) {
        let path = path.as_str();
        args.extend(["--ro-bind", path, path].map(str::to_owned));
    }
    if let Some(enter) = &run.enter {
        args.extend(["--ro-bind", enter.as_str(), INSIDE_ENTER].map(str::to_owned));
    }
    if let AgentNet::Endpoint(bind) | AgentNet::Allowlist(bind) = &run.net {
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
    args.extend(inner(run, profile));
    args
}

/// Whether `path` exists and is not a symbolic link (judged without following it).
fn protectable(path: &AbsPath) -> bool {
    std::fs::symlink_metadata(path.as_str()).is_ok_and(|m| !m.file_type().is_symlink())
}

/// The words bubblewrap runs: the agent itself, behind the exec stage when there is one, behind
/// the forwarder when the mode has one.
fn inner(run: &AgentRun, profile: &Profile) -> Vec<String> {
    let agent = match &run.enter {
        Some(_) => {
            let mut words = vec![INSIDE_ENTER.to_owned()];
            words.extend(plan_for(run, profile).words());
            words.extend(run.argv.words().iter().cloned());
            words
        }
        None => run.argv.words().to_vec(),
    };
    match &run.net {
        AgentNet::Endpoint(bind) | AgentNet::Allowlist(bind) => forwarder_words(bind, &agent),
        AgentNet::None | AgentNet::Host => agent,
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
