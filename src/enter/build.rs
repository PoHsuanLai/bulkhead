//! The exec stage's plan for one agent run, built from the same `AgentRun` and `Profile` that
//! `agent_bwrap_args` reads, so the bubblewrap mounts and the Landlock rules name the same places.

use super::plan::{EnterPlan, NetRule};
use crate::AbsPath;
use crate::agent::{Access, AgentRun};
use crate::net::AgentNet;
use crate::profile::Profile;

/// Places that are always fresh in-memory directories inside the sandbox and writable: the
/// agent's private scratch, home and shared memory. `/run` is not among them.
const SCRATCH: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];
/// Read only: the kernel's view of processes, which runtimes read.
const PROC: &str = "/proc";
/// Devices bubblewrap makes: read, and write to what is there.
const DEV: &str = "/dev";

fn fixed(paths: &[&str]) -> Vec<AbsPath> {
    paths
        .iter()
        .filter_map(|p| AbsPath::parse(p).ok())
        .collect()
}

/// The plan for `run`: read where the root and the read-only binds are, write only in the
/// workspace, the scratch places and the read-write binds, TCP as the network mode says.
pub(crate) fn plan_for(run: &AgentRun, profile: &Profile) -> EnterPlan {
    let mut read = profile.root_reads();
    read.extend(fixed(&[PROC]));
    let mut write = vec![run.cwd.clone()];
    write.extend(fixed(&SCRATCH));
    for bind in &run.binds {
        match bind.access {
            Access::ReadOnly => read.push(bind.path.clone()),
            Access::ReadWrite => write.push(bind.path.clone()),
        }
    }
    read.extend(run.overlays.iter().map(|o| o.to.clone()));
    let net = match &run.net {
        AgentNet::None => NetRule::NoTcp,
        AgentNet::Host => NetRule::Unfiltered,
        AgentNet::Endpoint(bind) | AgentNet::Allowlist(bind) => NetRule::ConnectTo(bind.port),
    };
    EnterPlan::new(read, write, fixed(&[DEV]), net)
}
