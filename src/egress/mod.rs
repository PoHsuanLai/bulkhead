//! The allow-list network mode's filtering proxy, std only.
//!
//! - [`host`]: host names and the patterns a policy compares them with.
//! - [`policy`]: [`EgressPolicy`], the verdicts, and the address ranges a name must not lead to.
//! - [`request`]: the one request line the proxy understands, read with bounded sizes.
//! - [`resolve`]: name resolution behind a trait.
//! - [`proxy`]: the [`Proxy`] that listens on the unix socket and copies bytes.

pub mod host;
pub mod policy;
pub mod proxy;
pub mod request;
pub mod resolve;

pub use host::{Host, HostFault, HostPattern};
pub use policy::{DEFAULT_PORTS, EgressPolicy, PolicyFault, Ports, Refusal, special};
pub use proxy::{Entry, Gate, Journal, Outcome, Proxy, Silent};
pub use request::{BadRequest, Head, Request, Target, parse_head, read_head};
pub use resolve::{Resolver, SystemResolver};
