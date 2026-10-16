//! What the proxy lets through: a typed policy, and the verdicts it gives. Pure, so a table
//! tests it.
//!
//! Deny entries win over allow entries. An empty allow list is a fault, never "allow
//! everything". A name that resolves to a loopback, link-local, private, unspecified, multicast
//! or shared (CGNAT) address is refused unless that exact address is allow-listed, so an allowed
//! name cannot be pointed at the host's own services or the local network.

use super::host::{Host, HostPattern};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The ports a policy allows when it names none.
pub const DEFAULT_PORTS: [u16; 2] = [443, 80];

/// Why a policy cannot be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyFault {
    /// No allow entries: that would mean nothing is allowed, and is surely a mistake.
    #[error("an egress policy needs at least one allow entry")]
    NoAllow,
    /// No ports, or port 0.
    #[error("an egress policy needs at least one port, and port 0 is not one")]
    BadPorts,
}

/// The ports the agent may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports(Vec<u16>);

impl Ports {
    /// These ports; none, or port 0, is a fault.
    pub fn new(ports: Vec<u16>) -> Result<Self, PolicyFault> {
        if ports.is_empty() || ports.contains(&0) {
            return Err(PolicyFault::BadPorts);
        }
        Ok(Self(ports))
    }

    /// Whether `port` is one of them.
    pub fn allows(&self, port: u16) -> bool {
        self.0.contains(&port)
    }
}

impl Default for Ports {
    fn default() -> Self {
        Self(DEFAULT_PORTS.to_vec())
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// A deny entry names the host.
    #[error("the host is denied")]
    Denied,
    /// No allow entry names the host (an address literal included, unless listed exactly).
    #[error("the host is not on the allow list")]
    NotListed,
    /// The port is not one the policy allows.
    #[error("the port is not allowed")]
    Port,
    /// The name resolves to an address in a special range (loopback, private and the like).
    #[error("the name resolves to an address that is not public")]
    SpecialAddress,
}

/// The egress policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    allow: Vec<HostPattern>,
    deny: Vec<HostPattern>,
    ports: Ports,
}

impl EgressPolicy {
    /// A policy; an empty `allow` is a fault.
    pub fn new(
        allow: Vec<HostPattern>,
        deny: Vec<HostPattern>,
        ports: Ports,
    ) -> Result<Self, PolicyFault> {
        if allow.is_empty() {
            return Err(PolicyFault::NoAllow);
        }
        Ok(Self { allow, deny, ports })
    }

    /// Whether the agent may ask for `host` on `port`. This is the check before any lookup.
    pub fn check(&self, host: &Host, port: u16) -> Result<(), Refusal> {
        if !self.ports.allows(port) {
            return Err(Refusal::Port);
        }
        if self.deny.iter().any(|p| p.matches(host)) {
            return Err(Refusal::Denied);
        }
        if self.allow.iter().any(|p| p.matches(host)) {
            Ok(())
        } else {
            Err(Refusal::NotListed)
        }
    }

    /// Whether the proxy may connect to `addr`, an address the checked name resolved to (or the
    /// literal the agent gave, which `check` already matched against an exact entry).
    pub fn check_addr(&self, addr: IpAddr) -> Result<(), Refusal> {
        if self.deny.iter().any(|p| p.is_addr(addr)) {
            return Err(Refusal::Denied);
        }
        if special(addr) && !self.allow.iter().any(|p| p.is_addr(addr)) {
            return Err(Refusal::SpecialAddress);
        }
        Ok(())
    }
}

/// Whether `addr` is in a range a name must not lead to. An IPv4 address inside an IPv6 one is
/// judged as the IPv4 address.
pub fn special(addr: IpAddr) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(a) => special_v4(a),
        IpAddr::V6(a) => special_v6(a),
    }
}

fn special_v4(a: Ipv4Addr) -> bool {
    let [first, second, ..] = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_multicast()
        || a.is_broadcast()
        // 0.0.0.0/8, "this network".
        || first == 0
        // 100.64.0.0/10, shared address space (carrier-grade NAT; tailnets live here).
        || (first == 100 && second & 0xc0 == 0x40)
        // 240.0.0.0/4, reserved.
        || first >= 240
}

fn special_v6(a: Ipv6Addr) -> bool {
    let first = a.segments()[0];
    a.is_loopback()
        || a.is_unspecified()
        || a.is_multicast()
        // fe80::/10 link-local, fec0::/10 site-local (deprecated, still routed on some networks).
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
        // fc00::/7 unique local.
        || first & 0xfe00 == 0xfc00
}
