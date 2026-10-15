//! Descriptors the sandbox process would inherit.
//!
//! `std::process::Command` marks only the descriptors it opens itself close-on-exec; a descriptor
//! this process was handed or opened without `O_CLOEXEC` (socket activation, a key file opened by
//! C code) would be inherited by bubblewrap and from there by the command, which would hold it
//! open inside the sandbox. Without `unsafe` there is no way to close them in the child, so
//! the check is made in the parent, just before the spawn: where one is found, nothing starts.
//!
//! The requirement for callers: every descriptor above 2 must be close-on-exec by the time a
//! sandbox starts. Rust's std, tokio and zbus already do this.

use serde::{Deserialize, Serialize};

/// `O_CLOEXEC` in the octal `flags:` line of `/proc/self/fdinfo/N`.
const O_CLOEXEC: u32 = 0o2_000_000;

/// What to do when a descriptor above 2 would be inherited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InheritedFds {
    /// Refuse to start (`StartFault::InheritedFds`).
    #[default]
    Refuse,
    /// Start anyway, chosen by the person.
    Allow,
}

/// The `flags:` value of an fdinfo file's text.
fn flags(fdinfo: &str) -> Option<u32> {
    let line = fdinfo.lines().find_map(|l| l.strip_prefix("flags:"))?;
    u32::from_str_radix(line.trim(), 8).ok()
}

/// Whether a descriptor with this fdinfo text would survive an `exec`.
fn inheritable(fdinfo: &str) -> bool {
    flags(fdinfo).is_some_and(|f| f & O_CLOEXEC == 0)
}

/// The descriptors above 2 that are not close-on-exec. An error where `/proc` cannot be read, so
/// the caller can fail closed.
pub fn inherited_fds() -> std::io::Result<Vec<u32>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        let Some(fd) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if fd < 3 {
            continue;
        }
        // A descriptor closed since the listing (the directory's own, for one) is not there.
        let Ok(info) = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else {
            continue;
        };
        if inheritable(&info) {
            found.push(fd);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_descriptor_without_the_close_on_exec_flag_is_inheritable() {
        let rows = [
            ("pos:\t0\nflags:\t02000002\nmnt_id:\t5\n", false),
            ("pos:\t0\nflags:\t0100002\nmnt_id:\t5\n", true),
            ("no flags here\n", false),
        ];
        for (text, want) in rows {
            assert_eq!(inheritable(text), want, "{text:?}");
        }
    }
}
