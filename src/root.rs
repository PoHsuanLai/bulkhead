//! The root file system a sandbox sees: an allow-list, not the host's `/` with holes cut in it.
//!
//! Visible, read-only: `/usr`; the `/bin`, `/sbin` and `/lib*` directories or links where the
//! host has them; `/etc`; optionally `/opt`; and whatever extra paths the caller names. Fresh
//! and writable but in memory: `/tmp`, `/var/tmp`, `/run`. Not there at all: `/var` (apart from
//! those), `/home`, `/root`, `/mnt`, `/media`, `/srv`, `/sys`, `/boot`, `/run/user`. A working
//! directory or bind below one of the missing directories simply makes its parents.
//!
//! `/etc` is mostly harmless but holds a few secrets (password hashes, sudoers, host keys, saved
//! network credentials); those are covered by an empty file or directory when the host has them.

use crate::AbsPath;
use crate::harden::OptDir;

/// Host directories (or links) bound read-only at the same path when they exist.
const SYSTEM_DIRS: &[&str] = &["/bin", "/sbin", "/lib", "/lib32", "/lib64"];

/// What covers a sensitive path of `/etc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A file, covered by `/dev/null`.
    File,
    /// A directory, covered by an empty in-memory one.
    Dir,
}

/// Paths under `/etc` that are covered when present.
const SENSITIVE: &[(&str, Kind)] = &[
    ("/etc/shadow", Kind::File),
    ("/etc/shadow-", Kind::File),
    ("/etc/gshadow", Kind::File),
    ("/etc/gshadow-", Kind::File),
    ("/etc/sudoers", Kind::File),
    ("/etc/krb5.keytab", Kind::File),
    ("/etc/security/opasswd", Kind::File),
    ("/etc/sudoers.d", Kind::Dir),
    ("/etc/ssh", Kind::Dir),
    ("/etc/ssl/private", Kind::Dir),
    ("/etc/pki/tls/private", Kind::Dir),
    ("/etc/NetworkManager/system-connections", Kind::Dir),
    ("/etc/wireguard", Kind::Dir),
    ("/etc/openvpn", Kind::Dir),
    ("/etc/letsencrypt", Kind::Dir),
    ("/etc/credstore", Kind::Dir),
    ("/etc/credstore.encrypted", Kind::Dir),
];

/// The root of one sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Root {
    opt: OptDir,
    extra_ro: Vec<AbsPath>,
    covered: Vec<(&'static str, Kind)>,
}

impl Root {
    pub(crate) fn with_opt(mut self, opt: OptDir) -> Self {
        self.opt = opt;
        self
    }

    pub(crate) fn with_extra_ro(mut self, path: AbsPath) -> Self {
        self.extra_ro.push(path);
        self
    }

    /// Covers the sensitive `/etc` paths for which `exists` is true.
    pub(crate) fn covering_where(mut self, exists: impl Fn(&str) -> bool) -> Self {
        self.covered = SENSITIVE
            .iter()
            .copied()
            .filter(|(path, _)| exists(path))
            .collect();
        self
    }

    /// The bubblewrap words that build the visible part of the root.
    pub(crate) fn args(&self) -> Vec<String> {
        let mut args: Vec<String> = ["--ro-bind", "/usr", "/usr"].map(str::to_owned).to_vec();
        for dir in SYSTEM_DIRS {
            args.extend(["--ro-bind-try", dir, dir].map(str::to_owned));
        }
        args.extend(["--ro-bind-try", "/etc", "/etc"].map(str::to_owned));
        for (path, kind) in &self.covered {
            match kind {
                Kind::File => args.extend(["--ro-bind", "/dev/null", path].map(str::to_owned)),
                Kind::Dir => args.extend(["--tmpfs", path].map(str::to_owned)),
            }
        }
        if self.opt == OptDir::ReadOnly {
            args.extend(["--ro-bind-try", "/opt", "/opt"].map(str::to_owned));
        }
        for path in &self.extra_ro {
            let path = path.as_str();
            args.extend(["--ro-bind", path, path].map(str::to_owned));
        }
        args
    }
}
