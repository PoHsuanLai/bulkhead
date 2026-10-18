//! The network a sandboxed agent process gets. Four modes, and the mode is a choice made per
//! program by the caller, never a fallback.
//!
//! - `None`: a new network namespace with only a loopback. Nothing outside is reachable.
//! - `EndpointOnly`: the same namespace, plus a forwarder inside it on `127.0.0.1:<port>` that
//!   hands every connection to one unix socket bind-mounted from outside; outside, the caller bridges
//!   that socket to one loopback address (a per-session model endpoint). The agent
//!   sees an http base URL on its own loopback and nothing else.
//! - `Allowlist`: the same namespace and forwarder, but outside the socket is served by a
//!   filtering proxy (`egress`) instead of the plain bridge. The agent gets `HTTPS_PROXY` and
//!   `HTTP_PROXY` pointing at the forwarder, and the namespace stops anything that ignores them.
//!   The proxy lets `CONNECT host:port` and plain `http://` requests through to the hosts a
//!   typed policy names (deny wins over allow; exact hosts and `*.domain` wildcards; ports 443
//!   and 80 unless the policy lists others) and refuses names that resolve to loopback, private,
//!   link-local or shared addresses. What it does not do: it filters by name, not by content. It
//!   does not look inside a tunnel, so an allowed host can still receive whatever the agent
//!   sends it (its own login, a key, the files it reads). It does not check that a plain
//!   request's `Host` header matches its address, and it does not stop an allowed host that
//!   fronts for others. The allow list is the person's decision, never a default.
//! - `Host`: the host's network, unfiltered. Weaker: the agent can reach any address and can send
//!   whatever it holds (its own login, a key) anywhere. It also shares the network namespace
//!   itself, which means every loopback service of the host, and the abstract unix sockets (they
//!   live in the network namespace, not the file system): an abstract X11 or D-Bus socket
//!   is reachable even though `/tmp` and `/run` are empty. The filtered ways out are
//!   `EndpointOnly` (one forwarded endpoint) and `Allowlist` (named hosts); `Host` should be
//!   chosen per program by the person, never as a default.

use crate::AbsPath;
use crate::sandbox::{EnvVar, Network};
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
    /// Only the hosts an egress policy allows, through a filtering proxy.
    Allowlist,
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
    /// The same forwarder and socket, served outside by the filtering proxy.
    Allowlist(EndpointBind),
    /// The host's network.
    Host,
}

/// Why a mode could not be made into a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the endpoint-only and allow-list modes need a forwarder bind, and the other modes take none"
)]
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
            (NetworkMode::Allowlist, Some(bind)) => Ok(AgentNet::Allowlist(bind)),
            _ => Err(NetFault),
        }
    }

    /// The mode this plan carries out.
    pub fn mode(&self) -> NetworkMode {
        match self {
            AgentNet::None => NetworkMode::None,
            AgentNet::Endpoint(_) => NetworkMode::EndpointOnly,
            AgentNet::Allowlist(_) => NetworkMode::Allowlist,
            AgentNet::Host => NetworkMode::Host,
        }
    }

    /// The forwarder bind, for the two modes that have one.
    pub fn bind(&self) -> Option<&EndpointBind> {
        match self {
            AgentNet::Endpoint(bind) | AgentNet::Allowlist(bind) => Some(bind),
            AgentNet::None | AgentNet::Host => None,
        }
    }

    /// The loopback port the agent connects to inside, when there is a forwarder.
    pub fn port(&self) -> Option<u16> {
        self.bind().map(|bind| bind.port)
    }

    /// The network namespace this plan gives the sandbox: the host's for `Host`, a namespace of
    /// its own for every other mode.
    pub(crate) fn network(&self) -> Network {
        match self {
            AgentNet::Host => Network::Host,
            AgentNet::None | AgentNet::Endpoint(_) | AgentNet::Allowlist(_) => Network::Off,
        }
    }

    /// The variables that make the agent use the proxy: only the allow-list mode has any.
    /// `NO_PROXY` is empty, so nothing is exempt. `AgentRun::new` puts these into the
    /// environment over whatever the caller gave under the same names.
    pub fn proxy_env(&self) -> Vec<EnvVar> {
        let AgentNet::Allowlist(bind) = self else {
            return Vec::new();
        };
        let url = format!("http://127.0.0.1:{}", bind.port);
        let var = |name: &str, value: &str| EnvVar {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        let mut vars: Vec<EnvVar> = PROXY_VARS.iter().map(|n| var(n, &url)).collect();
        vars.extend(NO_PROXY_VARS.iter().map(|n| var(n, "")));
        vars
    }
}

/// The variables that name the proxy, in both spellings tools read.
const PROXY_VARS: [&str; 4] = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"];
/// The variables that exempt hosts from it: set, and empty.
const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
