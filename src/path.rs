//! A host path that is absolute and normalised: the only kind of path the sandbox accepts.

use serde::{Deserialize, Serialize};

/// A directory (or file) as an absolute, normalised path: no `.` or `..` steps, no empty
/// components, no trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AbsPath(String);

/// Why text is not an absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathFault {
    /// It does not start with `/`.
    #[error("a path must be absolute")]
    NotAbsolute,
    /// It steps up with `..`, which could leave the sandbox's one writable place.
    #[error("a path must not step up with ..")]
    ParentStep,
    /// It holds a control character.
    #[error("a path must not hold control characters")]
    Control,
    /// It is not valid UTF-8, so it cannot be held as text.
    #[error("a path must be valid UTF-8")]
    NotUtf8,
}

/// Whether a path is `/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootState {
    /// It is `/`.
    Root,
    /// It is below `/`.
    Below,
}

impl AbsPath {
    /// `text` as an absolute path, `.` and doubled slashes folded away.
    pub fn parse(text: &str) -> Result<Self, PathFault> {
        if !text.starts_with('/') {
            return Err(PathFault::NotAbsolute);
        }
        if text.chars().any(char::is_control) {
            return Err(PathFault::Control);
        }
        let mut parts = Vec::new();
        for part in text.split('/') {
            match part {
                "" | "." => {}
                ".." => return Err(PathFault::ParentStep),
                other => parts.push(other),
            }
        }
        Ok(Self(format!("/{}", parts.join("/"))))
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is `/`.
    pub fn is_root(&self) -> RootState {
        if self.0 == "/" {
            RootState::Root
        } else {
            RootState::Below
        }
    }
}

impl TryFrom<String> for AbsPath {
    type Error = PathFault;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl TryFrom<&std::path::Path> for AbsPath {
    type Error = PathFault;

    /// Strict: a path that is not UTF-8 is a fault, never a lossy replacement that names a
    /// different file.
    fn try_from(path: &std::path::Path) -> Result<Self, Self::Error> {
        path.to_str()
            .ok_or(PathFault::NotUtf8)
            .and_then(Self::parse)
    }
}

impl From<AbsPath> for String {
    fn from(path: AbsPath) -> String {
        path.0
    }
}
