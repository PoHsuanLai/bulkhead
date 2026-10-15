//! Why a user namespace was refused: the kernel switch, or the Ubuntu AppArmor restriction.
//!
//! Ubuntu 24.04 and later set `kernel.apparmor_restrict_unprivileged_userns=1`, which lets a
//! program make a user namespace only when its AppArmor profile allows `userns`. A stock
//! `bwrap` has no such profile, so it fails exactly as it does when namespaces are off, and the
//! remedy is different. This module only reads the switch; it never changes it.

use crate::CannotSandbox;
use std::path::Path;

/// Where the kernel exposes the switch.
pub const RESTRICT_USERNS: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// The reason a throwaway `bwrap` run failed, given the switch's text (`None`: no such file,
/// so this kernel has no AppArmor restriction). Pure.
pub fn namespaces_refused(switch: Option<&str>) -> CannotSandbox {
    match switch.map(str::trim) {
        Some("1") => CannotSandbox::RestrictedByAppArmor,
        _ => CannotSandbox::NamespacesDenied,
    }
}

/// `namespaces_refused` for the switch file at `path`; an unreadable file counts as missing.
pub fn refusal_at(path: &Path) -> CannotSandbox {
    namespaces_refused(std::fs::read_to_string(path).ok().as_deref())
}
