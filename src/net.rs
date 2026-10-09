//! The network a sandboxed agent process gets . Three modes, and the mode is
//! a choice made per program by the caller, never a fallback.
//!
//! - `None`: a new network namespace with only a loopback. Nothing outside is reachable.
//! - `EndpointOnly`: the same namespace, plus a forwarder inside it on `127.0.0.1:<port>` that
//!   hands every connection to one unix socket bind-mounted from outside; outside, the caller bridges
//!   that socket to one loopback address (a per-session model endpoint). The agent
//!   sees an http base URL on its own loopback and nothing else.
//! - `Host`: the host's network, unfiltered. Weaker: the agent can reach any address and can send
//!   whatever it holds (its own login, a key) anywhere.

use crate::AbsPath;
use serde::{Deserialize, Serialize};

/// Where a host keeps the resolver file `/etc/resolv.conf` points at, when it is a link into a
/// directory the sandbox empties (`/run`): systemd-resolved, NetworkManager, resolvconf, connman.
/// With the host's network, each that exists is bound back read-only so names resolve; the rest
/// of `/run` (the session bus, other sockets) stays hidden.
pub const RESOLVER_FILES: &[&str] = &[
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/run/NetworkManager/resolv.conf",
    "/run/NetworkManager/no-stub-resolv.conf",
    "/run/resolvconf/resolv.conf",
    "/run/connman/resolv.conf",
];

/// The `bwrap` words that bind the resolver files back, each only if the host has it.
pub(crate) fn resolver_binds() -> Vec<String> {
    RESOLVER_FILES
        .iter()
        .flat_map(|f| ["--ro-bind-try", f, f])
        .map(str::to_owned)
        .collect()
}

/// What the caller allows a program. `None` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkMode {
    /// No network.
    #[default]
    None,
    /// Only the model endpoint the caller opens for the session.
    EndpointOnly,
    /// The host's network.
    Host,
}

/// Where the forwarder sits inside the sandbox and what it forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointBind {
    /// The forwarder program on the host (read-only inside).
    pub forwarder: AbsPath,
    /// The unix socket on the host that the caller's bridge listens on (bound inside).
    pub socket: AbsPath,
    /// The loopback port the agent connects to inside (the endpoint's own port).
    pub port: u16,
}

impl EndpointBind {
    /// The forwarder program, its host socket, and the loopback port the agent connects to.
    pub fn new(forwarder: AbsPath, socket: AbsPath, port: u16) -> Self {
        Self {
            forwarder,
            socket,
            port,
        }
    }
}

/// A mode with what it needs: the thing `agent_bwrap_args` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentNet {
    /// Loopback only.
    None,
    /// The forwarder and its socket.
    Endpoint(EndpointBind),
    /// The host's network.
    Host,
}

/// Why a mode could not be made into a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the endpoint-only mode needs an endpoint, and the other modes take none")]
#[non_exhaustive]
pub struct NetFault;

impl AgentNet {
    /// The plan for `mode`, given the endpoint when there is one. A mismatch is a fault, never a
    /// silent downgrade or upgrade.
    pub fn of(mode: NetworkMode, endpoint: Option<EndpointBind>) -> Result<Self, NetFault> {
        match (mode, endpoint) {
            (NetworkMode::None, None) => Ok(AgentNet::None),
            (NetworkMode::Host, None) => Ok(AgentNet::Host),
            (NetworkMode::EndpointOnly, Some(bind)) => Ok(AgentNet::Endpoint(bind)),
            _ => Err(NetFault),
        }
    }

    /// The mode this plan carries out.
    pub fn mode(&self) -> NetworkMode {
        match self {
            AgentNet::None => NetworkMode::None,
            AgentNet::Endpoint(_) => NetworkMode::EndpointOnly,
            AgentNet::Host => NetworkMode::Host,
        }
    }
}
