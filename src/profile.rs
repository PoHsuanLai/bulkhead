//! The hardening parts of a bubblewrap command line that do not depend on the run: how big the
//! scratch directories are. A `Profile` is plain data, so a test builds one and reads the
//! arguments.

use crate::harden::Bytes;

/// What the shared confinement adds to the command line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    tmpfs: Option<Bytes>,
}

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
