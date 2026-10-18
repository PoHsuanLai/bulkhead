//! The part of the bubblewrap command line every sandbox here starts with: namespaces, no
//! capabilities, the allow-list root (`root`), a fresh `/dev` and `/proc`, the scratch
//! directories, and the resolver files when the network is the host's. The terminal sandbox (`bwrap`) and the agent
//! sandbox (`agent`) both begin with exactly this, so a hardening flag added here reaches both.
//!
//! What follows it differs, and so does how the environment travels: the terminal sandbox puts
//! its allowlisted variables on the command line (`--clearenv`, then `--setenv`), where any
//! process of the user can read them in `/proc/*/cmdline`; the agent sandbox must not, so its
//! environment is set on the bubblewrap process itself (`env_clear`, then the variables) and
//! never in the arguments. The terminal's variables are a fixed allowlist with no secret in
//! it (`sandbox_env`), which is why `--setenv` is safe there and not for the agent.

use crate::net::resolver_binds;
use crate::profile::Profile;
use crate::sandbox::Network;

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The shared arguments. Pure.
pub(crate) fn confinement(network: Network, profile: &Profile) -> Vec<String> {
    let mut args = words(&["--die-with-parent", "--new-session", "--unshare-all"]);
    if network == Network::Host {
        args.push("--share-net".to_owned());
    }
    args.extend(words(&["--cap-drop", "ALL"]));
    args.extend(profile.seccomp());
    args.extend(profile.root());
    args.extend(words(&["--dev", "/dev", "--proc", "/proc"]));
    args.extend(profile.scratch());
    if network == Network::Host {
        args.extend(resolver_binds());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both networks share the prefix (capabilities dropped, the allow-list root); only
    /// the host network adds `--share-net`. Each step names its network in the failure message.
    #[test]
    fn the_prefix_is_shared_and_only_the_host_network_shares_the_net_namespace() {
        let cases = [(Network::Off, false), (Network::Host, true)];
        for (network, shares_net) in cases {
            let args = confinement(network, &Profile::bare());
            assert_eq!(
                &args[..3],
                ["--die-with-parent", "--new-session", "--unshare-all"],
                "{network:?}: prefix"
            );
            assert!(
                args.windows(2).any(|w| w == ["--cap-drop", "ALL"]),
                "{network:?}: cap-drop"
            );
            assert!(
                args.windows(3).any(|w| w == ["--ro-bind", "/usr", "/usr"]),
                "{network:?}: /usr bound"
            );
            assert!(
                !args.iter().any(|a| a == "/home" || a == "/"),
                "{network:?}: no /home and no whole root"
            );
            assert_eq!(
                args.contains(&"--share-net".to_owned()),
                shares_net,
                "{network:?}: --share-net"
            );
        }
    }
}
