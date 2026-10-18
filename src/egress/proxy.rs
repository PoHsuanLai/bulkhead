//! The filtering proxy of the allow-list network mode. It listens on a unix socket (the one the
//! forwarder inside the sandbox hands every connection to), reads one proxy request, asks the
//! policy, and either answers a refusal or connects out and copies bytes both ways.
//!
//! It never reads or keeps what passes through a tunnel. The journal gets the host, the port and
//! the verdict, and nothing else: no headers, no path, no body.

use super::host::Host;
use super::policy::{EgressPolicy, Refusal};
use super::request::{BadRequest, HEAD_DEADLINE, Request, Target, parse_head, read_head};
use super::resolve::Resolver;
use crate::forward::{Duplex, Listening, splice};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long one connect attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What happened to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// A `CONNECT` tunnel was opened.
    Tunnelled,
    /// A plain http request was forwarded.
    Relayed,
    /// The policy said no.
    Refused(Refusal),
    /// The name did not resolve, or nothing answered.
    Unreachable,
    /// The request was not understood (no target is known).
    Malformed,
}

/// One line of the journal: where, and the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where the request wanted to go, when it could be read.
    pub target: Option<Target>,
    /// What was done.
    pub outcome: Outcome,
}

/// Where verdicts go. Called from the proxy's threads.
pub trait Journal: Send + Sync + std::fmt::Debug {
    /// Notes one request.
    fn record(&self, entry: &Entry);
}

/// A journal that keeps nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl Journal for Silent {
    fn record(&self, _entry: &Entry) {}
}

enum Failure {
    Refused(Refusal),
    Unreachable,
}

/// The policy, the resolver and the journal: everything one request needs.
#[derive(Debug, Clone)]
pub struct Gate {
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
    journal: Arc<dyn Journal>,
}

fn reply<W: Write>(to: &mut W, status: &str, body: &str) {
    let text = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = to.write_all(text.as_bytes());
    let _ = to.flush();
}

impl Gate {
    /// A gate over `policy`, resolving with `resolver` and noting verdicts in `journal`.
    pub fn new(
        policy: EgressPolicy,
        resolver: Arc<dyn Resolver>,
        journal: Arc<dyn Journal>,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            resolver,
            journal,
        }
    }

    /// Checks `target` and connects to an address that passed. The name is resolved once, every
    /// address it gave is checked, and the connection goes to one of those addresses: there is
    /// no second lookup to rebind.
    fn dial(&self, target: &Target) -> Result<TcpStream, Failure> {
        self.policy
            .check(&target.host, target.port)
            .map_err(Failure::Refused)?;
        let addrs = match &target.host {
            Host::Addr(addr) => vec![*addr],
            Host::Name(name) => self
                .resolver
                .resolve(name, target.port)
                .map_err(|_| Failure::Unreachable)?,
        };
        if addrs.is_empty() {
            return Err(Failure::Unreachable);
        }
        for addr in &addrs {
            self.policy.check_addr(*addr).map_err(Failure::Refused)?;
        }
        addrs
            .iter()
            .find_map(|addr| {
                TcpStream::connect_timeout(&SocketAddr::new(*addr, target.port), CONNECT_TIMEOUT)
                    .ok()
            })
            .ok_or(Failure::Unreachable)
    }

    fn note(&self, target: Option<Target>, outcome: Outcome) {
        self.journal.record(&Entry { target, outcome });
    }

    fn refuse<S: Duplex>(&self, client: &mut S, target: Target, failure: &Failure) {
        let (status, why, outcome) = match failure {
            Failure::Refused(why) => ("403 Forbidden", why.to_string(), Outcome::Refused(*why)),
            Failure::Unreachable => (
                "502 Bad Gateway",
                "could not connect".to_owned(),
                Outcome::Unreachable,
            ),
        };
        reply(client, status, &format!("{target}: {why}\n"));
        client.finish();
        self.note(Some(target), outcome);
    }

    /// Serves one client connection: one request, then bytes both ways until either side ends.
    pub fn serve<S: Duplex>(&self, mut client: S) {
        let head = match read_head(&mut client, HEAD_DEADLINE) {
            Ok(head) => head,
            Err(BadRequest::Closed) => return,
            Err(_) => return self.bad(&mut client),
        };
        let Ok(request) = parse_head(&head.bytes[..head.end]) else {
            return self.bad(&mut client);
        };
        let target = request.target().clone();
        let mut upstream = match self.dial(&target) {
            Ok(upstream) => upstream,
            Err(failure) => return self.refuse(&mut client, target, &failure),
        };
        let _ = client.limit_reads(None);
        let (first, outcome) = match request {
            Request::Tunnel(_) => {
                reply_established(&mut client);
                (&head.bytes[head.end..], Outcome::Tunnelled)
            }
            Request::Relay(_) => (&head.bytes[..], Outcome::Relayed),
        };
        if upstream.write_all(first).is_err() {
            return;
        }
        self.note(Some(target), outcome);
        splice(client, upstream);
    }

    fn bad<S: Duplex>(&self, client: &mut S) {
        reply(client, "400 Bad Request", "bad proxy request\n");
        client.finish();
        self.note(None, Outcome::Malformed);
    }
}

fn reply_established<W: Write>(to: &mut W) {
    let _ = to.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let _ = to.flush();
}

/// The host side: a unix socket whose every connection is served by a [`Gate`]. Dropping it
/// stops accepting and removes the socket file.
#[derive(Debug)]
pub struct Proxy {
    _listening: Listening,
}

impl Proxy {
    /// Listens on `path` (which must not exist) and serves each connection through `gate`.
    pub fn start(path: &Path, gate: Gate) -> io::Result<Self> {
        Listening::start(path, move |client, held| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.serve(client);
                drop(held);
            });
        })
        .map(|listening| Self {
            _listening: listening,
        })
    }
}
