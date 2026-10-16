//! Name resolution, behind a small trait so a test answers it without a network. The proxy
//! resolves a name once, checks every address, and connects to an address it checked.

use std::io;
use std::net::{IpAddr, ToSocketAddrs};

/// Turns a host name into addresses.
pub trait Resolver: Send + Sync + std::fmt::Debug {
    /// The addresses of `name`. An empty list or an error is a failed lookup.
    fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The system resolver (`getaddrinfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        let found = (name, port).to_socket_addrs()?;
        Ok(found.map(|a| a.ip()).collect())
    }
}
