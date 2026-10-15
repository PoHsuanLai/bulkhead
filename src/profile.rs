//! The hardening parts of a bubblewrap command line that do not depend on the run: how big the
//! scratch directories are. A `Profile` is plain data, so a test builds one and reads the
//! arguments.

use crate::harden::Bytes;

/// What the shared confinement adds to the command line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    tmpfs: Option<Bytes>,
    seccomp: FilterFd,
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
