//! The real sandbox: bubblewrap (`bwrap`, LGPL) run as a separate process and never linked. It
//! builds the command line for one run and starts it; `bwrap_job` owns the running process.
//!
//! What a run gets: the host's file system read-only, a fresh `/dev` and `/proc`, empty in-memory
//! `/tmp`, `/run`, `/home`, `/root`, `/mnt` and the like (so home directories, the session bus
//! socket and other users' files are not there to read), the working directory bound writable and
//! nothing else writable, new user, pid, ipc, uts, cgroup and network namespaces (no interface at
//! all, not even loopback), no capabilities, a new session (its own process group), a cleared
//! environment, and death with its parent. With the host's network, the resolver files under `/run`
//! that `/etc/resolv.conf` may point at are bound back read-only (`RESOLVER_FILES`), or names would
//! not resolve. FINDINGS.md "Sandboxed shell" lists what that does not
//! stop.

use crate::bwrap_job::BwrapJob;
use crate::confinement::{Share, confinement};
use crate::sandbox::{Network, RunSpec, Sandbox, StartFault};
use crate::{AbsPath, CannotSandbox, RootState, SandboxState};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Directories that are emptied inside the sandbox when they exist on the host.
pub const HIDDEN: &[&str] = &[
    "/tmp", "/var/tmp", "/run", "/home", "/root", "/mnt", "/media", "/srv",
];

/// The `bwrap` arguments for `spec`, hiding the `hidden` directories. Pure.
///
/// The shared confinement comes first (`confinement`). The environment then travels as
/// `--setenv` words, readable in `/proc/*/cmdline`: safe only because `sandbox_env` is a fixed
/// allowlist with no secret. The agent sandbox passes its environment on the process instead.
pub fn bwrap_args(spec: &RunSpec, hidden: &[&str]) -> Vec<String> {
    let cwd = spec.cwd.as_str();
    let share = match spec.network {
        Network::Host => Share::HostNet,
        Network::Off => Share::Nothing,
    };
    let mut args = confinement(share, hidden);
    // The working directory goes in after the emptied directories, so it shows through them.
    args.extend(["--bind", cwd, cwd, "--chdir", cwd, "--clearenv"].map(str::to_owned));
    for var in &spec.env {
        args.extend(["--setenv".to_owned(), var.name.clone(), var.value.clone()]);
    }
    args.push("--".to_owned());
    args.extend(spec.argv.words().iter().cloned());
    args
}

/// The bubblewrap sandbox.
#[derive(Debug, Clone)]
pub struct BwrapSandbox {
    program: PathBuf,
}

impl BwrapSandbox {
    /// The `bwrap` program this sandbox runs.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Finds `bwrap` in the `:`-separated `path` and checks that the kernel lets it make the
    /// namespaces (one throwaway run). Reads no environment: the caller passes the search path.
    pub fn detect(path: &str) -> Result<Self, CannotSandbox> {
        if cfg!(not(unix)) {
            return Err(CannotSandbox::Unsupported);
        }
        let program = path
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| Path::new(d).join("bwrap"))
            .find(|p| p.is_file())
            .ok_or(CannotSandbox::NotInstalled)?;
        let probe = Command::new(&program)
            .args([
                "--ro-bind",
                "/",
                "/",
                "--unshare-all",
                "--die-with-parent",
                "--",
            ])
            .arg("true")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match probe {
            Ok(status) if status.success() => Ok(Self { program }),
            _ => Err(CannotSandbox::NamespacesDenied),
        }
    }
}

/// A working directory is usable when it is a real directory at least two levels down (never `/`,
/// never `/home` or `/tmp` themselves), so the writable place is a project and not a system root.
fn usable(cwd: &AbsPath) -> bool {
    let deep = cwd.as_str().matches('/').count() >= 2;
    cwd.is_root() == RootState::Below && deep && Path::new(cwd.as_str()).is_dir()
}

impl Sandbox for BwrapSandbox {
    type Job = BwrapJob;

    fn available(&self) -> SandboxState {
        SandboxState::Ready
    }

    fn check(&self, cwd: &AbsPath) -> SandboxState {
        if usable(cwd) {
            SandboxState::Ready
        } else {
            SandboxState::Cannot(CannotSandbox::BadWorkingDir)
        }
    }

    fn start(&self, spec: &RunSpec) -> Result<BwrapJob, StartFault> {
        if let SandboxState::Cannot(why) = self.check(&spec.cwd) {
            return Err(StartFault::Cannot(why));
        }
        let present: Vec<&str> = HIDDEN
            .iter()
            .copied()
            .filter(|d| Path::new(d).is_dir())
            .collect();
        let mut command = Command::new(&self.program);
        command
            .args(bwrap_args(spec, &present))
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        BwrapJob::spawn(command, spec.keep)
    }
}

/// What startup found: bubblewrap, or the reason there is none. A `Detected::Missing` starts
/// nothing, so a build that finds no sandbox runs no command.
#[derive(Debug, Clone)]
pub enum Detected {
    /// A working bubblewrap.
    Bwrap(BwrapSandbox),
    /// No usable sandbox, for this reason.
    Missing(CannotSandbox),
}

impl Detected {
    /// Looks for a sandbox in the `:`-separated `path`. Compiled but not run by the doc tests:
    /// it starts a real `bwrap`, which needs unprivileged user namespaces.
    ///
    /// ```no_run
    /// use bulkhead::{AbsPath, Argv, Detected, Launch, Shell};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let sandbox = Detected::probe("/usr/bin:/bin");
    /// let mut shell = Shell::new(sandbox);
    /// let argv = Argv::new("ls", &[]).ok_or("no program")?;
    /// let id = shell.create(&Launch::new(argv, AbsPath::parse("/home/u/project")?))?;
    /// println!("{:?}", shell.wait(id)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn probe(path: &str) -> Self {
        match BwrapSandbox::detect(path) {
            Ok(found) => Detected::Bwrap(found),
            Err(why) => Detected::Missing(why),
        }
    }
}

impl Sandbox for Detected {
    type Job = BwrapJob;

    fn available(&self) -> SandboxState {
        match self {
            Detected::Bwrap(b) => b.available(),
            Detected::Missing(why) => SandboxState::Cannot(*why),
        }
    }

    fn check(&self, cwd: &AbsPath) -> SandboxState {
        match self {
            Detected::Bwrap(b) => b.check(cwd),
            Detected::Missing(why) => SandboxState::Cannot(*why),
        }
    }

    fn start(&self, spec: &RunSpec) -> Result<BwrapJob, StartFault> {
        match self {
            Detected::Bwrap(b) => b.start(spec),
            Detected::Missing(why) => Err(StartFault::Cannot(*why)),
        }
    }
}
