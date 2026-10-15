//! The hardening parts of a bubblewrap command line that do not depend on the run: how big the
//! scratch directories are. A `Profile` is plain data, so a test builds one and reads the
//! arguments.

use crate::AbsPath;
use crate::harden::{Bytes, OptDir};
use crate::root::Root;

/// What the shared confinement adds to the command line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    tmpfs: Option<Bytes>,
    seccomp: FilterFd,
    root: Root,
}

/// Whether the command line tells bubblewrap to read a seccomp filter from `FILTER_FD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FilterFd {
    #[default]
    Absent,
    Present,
}

/// The descriptor number bubblewrap reads the filter from. The launcher (`sh`) opens it.
pub(crate) const FILTER_FD: &str = "3";

impl Profile {
    /// Nothing added: scratch directories are as big as bubblewrap makes them.
    pub fn bare() -> Self {
        Self::default()
    }

    /// Scratch directories capped at `size` each.
    #[must_use]
    pub fn with_tmpfs_size(mut self, size: Bytes) -> Self {
        self.tmpfs = Some(size);
        self
    }

    /// `/opt` visible or not.
    #[must_use]
    pub fn with_opt(mut self, opt: OptDir) -> Self {
        self.root = self.root.with_opt(opt);
        self
    }

    /// One more host path visible read-only at the same path.
    #[must_use]
    pub fn with_extra_ro(mut self, path: AbsPath) -> Self {
        self.root = self.root.with_extra_ro(path);
        self
    }

    /// Covers the sensitive `/etc` paths (password hashes, sudoers, host keys, saved network
    /// credentials) that the host has.
    #[must_use]
    pub fn covering_host_secrets(self) -> Self {
        self.covering_secrets_where(|p| std::path::Path::new(p).exists())
    }

    /// Covers the sensitive `/etc` paths for which `exists` is true; the host's view is supplied
    /// by the caller, so a test can answer it.
    #[must_use]
    pub fn covering_secrets_where(mut self, exists: impl Fn(&str) -> bool) -> Self {
        self.root = self.root.covering_where(exists);
        self
    }

    /// The words that build the visible root.
    pub(crate) fn root(&self) -> Vec<String> {
        self.root.args()
    }

    /// Bubblewrap reads a seccomp filter from descriptor 3. Whoever starts the process must
    /// provide it (`BwrapSandbox` does); with this set and no filter, bubblewrap refuses to run.
    #[must_use]
    pub fn with_seccomp(mut self) -> Self {
        self.seccomp = FilterFd::Present;
        self
    }

    /// The `--seccomp` words, when the filter is on.
    pub(crate) fn seccomp(&self) -> Vec<String> {
        match self.seccomp {
            FilterFd::Present => vec!["--seccomp".to_owned(), FILTER_FD.to_owned()],
            FilterFd::Absent => Vec::new(),
        }
    }

    /// The writable in-memory scratch directories, each with the size cap: `/tmp`, `/var/tmp`
    /// and `/run`, with `/var` itself holding only `tmp` and a `run` link.
    pub(crate) fn scratch(&self) -> Vec<String> {
        let mut args = self.tmpfs("/tmp");
        args.extend(["--dir", "/var"].map(str::to_owned));
        args.extend(self.tmpfs("/var/tmp"));
        args.extend(["--symlink", "../run", "/var/run"].map(str::to_owned));
        args.extend(self.tmpfs("/run"));
        args
    }

    /// The words for one `--tmpfs dir`: the size cap first (it applies to the next tmpfs only).
    pub(crate) fn tmpfs(&self, dir: &str) -> Vec<String> {
        let mut words = Vec::new();
        if let Some(size) = self.tmpfs {
            words.extend(["--size".to_owned(), size.0.to_string()]);
        }
        words.extend(["--tmpfs".to_owned(), dir.to_owned()]);
        words
    }
}
