//! The part of the bubblewrap command line every sandbox here starts with: namespaces, no
//! capabilities, the host read-only, a fresh `/dev` and `/proc`, the emptied directories, and the
//! resolver files when the network is the host's. The terminal sandbox (`bwrap`) and the agent
//! sandbox (`agent`) both begin with exactly this, so a hardening flag added here reaches both.
//!
//! What follows it differs, and so does how the environment travels: the terminal sandbox puts
//! its allowlisted variables on the command line (`--clearenv`, then `--setenv`), where any
//! process of the user can read them in `/proc/*/cmdline`; the agent sandbox must not, so its
//! environment is set on the bubblewrap process itself (`env_clear`, then the variables) and
//! never in the arguments. The terminal's variables are a fixed allowlist with no secret in
//! it (`sandbox_env`), which is why `--setenv` is safe there and not for the agent.

use crate::net::resolver_binds;

/// Whether the sandbox shares the host's network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Share {
    /// A namespace of its own with no interface.
    Nothing,
    /// The host's network, and the resolver files it needs.
    HostNet,
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The shared arguments, hiding the `hidden` directories. Pure.
pub(crate) fn confinement(share: Share, hidden: &[&str]) -> Vec<String> {
    let mut args = words(&["--die-with-parent", "--new-session", "--unshare-all"]);
    if share == Share::HostNet {
        args.push("--share-net".to_owned());
    }
    args.extend(words(&[
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
    ]));
    for dir in hidden {
        args.extend(["--tmpfs".to_owned(), (*dir).to_owned()]);
    }
    if share == Share::HostNet {
        args.extend(resolver_binds());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prefix_drops_capabilities_and_empties_the_hidden_directories() {
        let args = confinement(Share::Nothing, &["/home", "/tmp"]);
        assert_eq!(
            &args[..3],
            ["--die-with-parent", "--new-session", "--unshare-all"]
        );
        assert!(args.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(args.windows(2).any(|w| w == ["--tmpfs", "/home"]));
        assert!(!args.contains(&"--share-net".to_owned()));
    }

    #[test]
    fn only_the_host_network_shares_the_net_namespace() {
        assert!(confinement(Share::HostNet, &[]).contains(&"--share-net".to_owned()));
    }
}
