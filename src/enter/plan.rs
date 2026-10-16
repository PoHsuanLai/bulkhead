//! What the exec stage is told: the paths and the network rule, as words before a `--`, built by
//! the same code that builds the bubblewrap command line (`build`) and parsed strictly here.
//! `words` and `parse` are each other's inverse, so the two cannot drift.

use crate::{AbsPath, PathFault, RootState};
use serde::{Deserialize, Serialize};

const READ: &str = "--read";
const WRITE: &str = "--write";
const DEVICE: &str = "--device";
const NET_UNFILTERED: &str = "--net-unfiltered";
const NET_NONE: &str = "--net-none";
const NET_CONNECT: &str = "--net-connect";
const SEPARATOR: &str = "--";

/// How far Landlock confined the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LandlockLevel {
    /// Everything asked for is in force: files, and the network where a rule was asked for.
    Full,
    /// Files are restricted; the kernel's Landlock has no network rules (before ABI 4), so the
    /// network is held by the namespace and the proxy alone.
    FilesOnly,
    /// Landlock is not available here; bubblewrap and the syscall filter are all there is.
    None,
}

/// The first words of the line the exec stage writes to its standard error.
const REPORT: &str = "bulkhead-enter: landlock=";

impl LandlockLevel {
    /// The word for the level.
    pub fn word(self) -> &'static str {
        match self {
            LandlockLevel::Full => "full",
            LandlockLevel::FilesOnly => "files-only",
            LandlockLevel::None => "none",
        }
    }

    /// The one fixed-format line the exec stage writes to standard error before it starts the
    /// agent: `bulkhead-enter: landlock=<word>`.
    pub fn report_line(self) -> String {
        format!("{REPORT}{}", self.word())
    }

    /// The level in `line`, if it is exactly a report line (trailing newline allowed).
    pub fn from_report_line(line: &str) -> Option<Self> {
        let word = line.trim_end_matches(['\r', '\n']).strip_prefix(REPORT)?;
        [Self::Full, Self::FilesOnly, Self::None]
            .into_iter()
            .find(|level| level.word() == word)
    }
}

/// What Landlock does about TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetRule {
    /// No network rule: the host network was chosen.
    Unfiltered,
    /// No TCP connection at all, and no listening.
    NoTcp,
    /// Connections only to this loopback port, and no listening.
    ConnectTo(u16),
}

/// The paths and the network rule the exec stage applies to itself before it starts the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnterPlan {
    /// Read and execute. A path that does not exist is skipped (it narrows, never widens).
    pub read: Vec<AbsPath>,
    /// Read, write and execute: the workspace and the private scratch places.
    pub write: Vec<AbsPath>,
    /// Device directories: read, and write to what is there, no new files.
    pub device: Vec<AbsPath>,
    /// TCP.
    pub net: NetRule,
}

/// Why the exec stage's words were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnterFault {
    /// A word the stage does not know.
    #[error("unknown word {0:?}")]
    UnknownWord(String),
    /// A word that needs a value had none.
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    /// A value that is not an absolute path.
    #[error("not a usable path: {0}")]
    BadPath(PathFault),
    /// `/` itself: it would grant the whole file system.
    #[error("a path must not be /")]
    Root,
    /// A value that is not a port.
    #[error("not a port: {0:?}")]
    BadPort(String),
    /// No `--` between the words and the program.
    #[error("the words must end with --")]
    NoSeparator,
    /// No network word.
    #[error("a network word is required")]
    NoNet,
    /// More than one network word.
    #[error("only one network word is allowed")]
    TwoNets,
    /// Nothing to run after `--`.
    #[error("no program after --")]
    NoProgram,
}

impl EnterPlan {
    /// A plan with these parts.
    pub fn new(
        read: Vec<AbsPath>,
        write: Vec<AbsPath>,
        device: Vec<AbsPath>,
        net: NetRule,
    ) -> Self {
        Self {
            read,
            write,
            device,
            net,
        }
    }

    /// The words, ending with `--`: put the program and its arguments after them.
    pub fn words(&self) -> Vec<String> {
        let mut out = Vec::new();
        let lists = [
            (READ, &self.read),
            (WRITE, &self.write),
            (DEVICE, &self.device),
        ];
        for (word, paths) in lists {
            for path in paths {
                out.extend([word.to_owned(), path.as_str().to_owned()]);
            }
        }
        match self.net {
            NetRule::Unfiltered => out.push(NET_UNFILTERED.to_owned()),
            NetRule::NoTcp => out.push(NET_NONE.to_owned()),
            NetRule::ConnectTo(port) => out.extend([NET_CONNECT.to_owned(), port.to_string()]),
        }
        out.push(SEPARATOR.to_owned());
        out
    }

    /// The plan and the program words after the separator. Strict: an unknown word, a missing
    /// value, a bad path, two network words or none, no `--`, or no program is a fault.
    pub fn parse(
        args: impl IntoIterator<Item = String>,
    ) -> Result<(Self, Vec<String>), EnterFault> {
        let mut args = args.into_iter();
        let (mut read, mut write, mut device) = (Vec::new(), Vec::new(), Vec::new());
        let mut net: Option<NetRule> = None;
        loop {
            let word = args.next().ok_or(EnterFault::NoSeparator)?;
            let list = match word.as_str() {
                READ => Some((READ, &mut read)),
                WRITE => Some((WRITE, &mut write)),
                DEVICE => Some((DEVICE, &mut device)),
                _ => None,
            };
            if let Some((name, list)) = list {
                let value = args.next().ok_or(EnterFault::MissingValue(name))?;
                list.push(path(&value)?);
                continue;
            }
            let rule = match word.as_str() {
                SEPARATOR => break,
                NET_UNFILTERED => NetRule::Unfiltered,
                NET_NONE => NetRule::NoTcp,
                NET_CONNECT => {
                    let value = args.next().ok_or(EnterFault::MissingValue(NET_CONNECT))?;
                    NetRule::ConnectTo(port(&value)?)
                }
                _ => return Err(EnterFault::UnknownWord(word.clone())),
            };
            if net.replace(rule).is_some() {
                return Err(EnterFault::TwoNets);
            }
        }
        let program: Vec<String> = args.collect();
        if program.is_empty() {
            return Err(EnterFault::NoProgram);
        }
        let net = net.ok_or(EnterFault::NoNet)?;
        Ok((Self::new(read, write, device, net), program))
    }
}

fn path(text: &str) -> Result<AbsPath, EnterFault> {
    let path = AbsPath::parse(text).map_err(EnterFault::BadPath)?;
    match path.is_root() {
        RootState::Root => Err(EnterFault::Root),
        RootState::Below => Ok(path),
    }
}

fn port(text: &str) -> Result<u16, EnterFault> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    match text.parse::<u16>() {
        Ok(port) if digits && port != 0 => Ok(port),
        _ => Err(EnterFault::BadPort(text.to_owned())),
    }
}
