//! Host names as the proxy sees them: a validated, lower-case ASCII name or an address, and the
//! patterns a policy compares them with.

use std::fmt;
use std::net::IpAddr;

/// The longest host name kept, in bytes (the DNS limit).
const NAME_MAX: usize = 253;
/// The longest label.
const LABEL_MAX: usize = 63;

/// Why text is not a usable host or host pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostFault {
    /// Nothing there.
    #[error("the host is empty")]
    Empty,
    /// `*` alone: it would allow everything.
    #[error("a pattern of `*` alone allows every host")]
    BareStar,
    /// `*` anywhere but as the whole first label (`*.example.com`).
    #[error("`*` is allowed only as the whole first label, as in `*.example.com`")]
    StarNotLeading,
    /// A space or a control character.
    #[error("a host must not hold spaces or control characters")]
    Whitespace,
    /// Not ASCII. Internationalised names are out of scope; the caller sends the punycode form.
    #[error("a host must be ASCII (use the punycode form)")]
    NonAscii,
    /// A character a host name does not have.
    #[error("a host holds a character it cannot have")]
    BadChar,
    /// Two dots in a row, or a leading dot.
    #[error("a host must not have an empty label")]
    EmptyLabel,
    /// Longer than DNS allows.
    #[error("the host is too long")]
    TooLong,
    /// The last label is all digits, which a resolver may read as an address (`127.1`).
    #[error("the last label of a host must not be all digits")]
    Numeric,
}

/// A host in a request: a name or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A lower-case ASCII name, without a trailing dot.
    Name(String),
    /// An address literal (an IPv6 one without brackets).
    Addr(IpAddr),
}

/// Lower-cases `text`, drops one trailing dot and checks the labels.
fn name(text: &str) -> Result<String, HostFault> {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.strip_suffix('.').unwrap_or(&lower);
    if trimmed.is_empty() {
        return Err(HostFault::Empty);
    }
    if trimmed.len() > NAME_MAX {
        return Err(HostFault::TooLong);
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(HostFault::EmptyLabel);
        }
        if label.len() > LABEL_MAX {
            return Err(HostFault::TooLong);
        }
        let fine = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !fine {
            return Err(HostFault::BadChar);
        }
    }
    let last = trimmed.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HostFault::Numeric);
    }
    Ok(trimmed.to_owned())
}

/// The checks every host text passes first.
fn clean(text: &str) -> Result<(), HostFault> {
    if text.is_empty() {
        return Err(HostFault::Empty);
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(HostFault::Whitespace);
    }
    if !text.is_ascii() {
        return Err(HostFault::NonAscii);
    }
    Ok(())
}

/// An address literal in `text`, with or without the brackets an IPv6 literal has in a URL.
fn literal(text: &str) -> Option<IpAddr> {
    let bare = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    bare.parse::<IpAddr>().ok().map(|a| a.to_canonical())
}

impl Host {
    /// The host in `text`: an address literal or a name. Lower-cased, one trailing dot dropped.
    pub fn parse(text: &str) -> Result<Self, HostFault> {
        clean(text)?;
        match literal(text) {
            Some(addr) => Ok(Host::Addr(addr)),
            None => name(text).map(Host::Name),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::Addr(IpAddr::V6(a)) => write!(f, "[{a}]"),
            Host::Addr(a) => write!(f, "{a}"),
        }
    }
}

/// One policy entry: an exact host, every subdomain of a domain, or an exact address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// `api.example.com`.
    Exact(String),
    /// `*.example.com` (holds `example.com`): any name below it, never the domain itself.
    Subdomains(String),
    /// One address, which also lets it through the special-range check.
    Addr(IpAddr),
}

impl HostPattern {
    /// The entry in `text`. Case does not matter and one trailing dot is ignored.
    pub fn parse(text: &str) -> Result<Self, HostFault> {
        clean(text)?;
        if let Some(addr) = literal(text) {
            return Ok(HostPattern::Addr(addr));
        }
        if text == "*" || text == "*." {
            return Err(HostFault::BareStar);
        }
        match text.strip_prefix("*.") {
            Some(rest) if rest.contains('*') => Err(HostFault::StarNotLeading),
            Some(rest) => name(rest).map(HostPattern::Subdomains),
            None if text.contains('*') => Err(HostFault::StarNotLeading),
            None => name(text).map(HostPattern::Exact),
        }
    }

    /// Whether this entry names `host`.
    pub fn matches(&self, host: &Host) -> bool {
        match (self, host) {
            (HostPattern::Exact(want), Host::Name(got)) => want == got,
            (HostPattern::Subdomains(domain), Host::Name(got)) => got
                .strip_suffix(domain.as_str())
                .and_then(|front| front.strip_suffix('.'))
                .is_some_and(|front| !front.is_empty()),
            (HostPattern::Addr(want), Host::Addr(got)) => want == got,
            _ => false,
        }
    }

    /// Whether this entry is exactly the address `addr`.
    pub fn is_addr(&self, addr: IpAddr) -> bool {
        matches!(self, HostPattern::Addr(a) if *a == addr.to_canonical())
    }
}
