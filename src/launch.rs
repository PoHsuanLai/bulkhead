//! How the bubblewrap process is started: directly, or through a small `sh` that applies
//! per-process limits and hands bubblewrap its seccomp filter, and, for cgroup limits, inside a
//! transient systemd user scope.
//!
//! Everything is a separate program (`systemd-run`, `sh`, `bwrap`) started with `std::process`;
//! this crate links nothing and has no `unsafe`. `systemd-run --scope` replaces itself with the
//! command after moving the process into the scope, so the child we hold is still the process
//! that becomes `bwrap`, and `bwrap_kill` works unchanged.
//!
//! Limits fail closed. A policy that asks for limits is resolved at startup by really applying
//! them once and reading them back; where that does not work, `resolve` is an error and no
//! sandbox exists.

use crate::AbsPath;
use crate::harden::{LimitPolicy, Limits};
use crate::sandbox::EnvVar;
use crate::state::CannotSandbox;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SH: &str = "/bin/sh";
const BASE_PATH: &str = "/usr/bin:/bin";

/// Run by `sh -c`: `$1` says where bubblewrap's seccomp filter comes from (`none`, `stdin`, or a
/// file path, which becomes fd 3), `$2` and `$3` are the CPU seconds and the address space in KiB
/// (`-` for none), the rest is the bubblewrap command. A limit that cannot be set stops here
/// with 125, before anything runs.
const SCRIPT: &str = r#"m=$1; cpu=$2; vm=$3; shift 3
[ "$cpu" = - ] || ulimit -t "$cpu" || exit 125
[ "$vm" = - ] || ulimit -v "$vm" || exit 125
case $m in
stdin) exec "$@" 3<&0 </dev/null ;;
none) exec "$@" ;;
*) exec "$@" 3<"$m" ;;
esac
exit 125"#;

/// The variables `systemd-run --user` needs to reach the user's manager.
const SESSION_VARS: &[&str] = &["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];

/// The caller's connection to its systemd user manager.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserSession {
    vars: Vec<(String, String)>,
}

impl UserSession {
    /// A session with exactly these variables.
    pub fn new(vars: Vec<(String, String)>) -> Self {
        Self { vars }
    }

    /// The session variables of this process. The only place the crate reads its environment.
    pub fn from_env() -> Self {
        let vars = SESSION_VARS
            .iter()
            .filter_map(|n| std::env::var(n).ok().map(|v| ((*n).to_owned(), v)))
            .collect();
        Self { vars }
    }
}

/// How limits are actually enforced by a started sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// A systemd user scope (cgroup).
    Cgroup,
    /// Per-process rlimits only.
    Rlimit,
    /// None, accepted by the person.
    Unlimited,
}

/// Where bubblewrap's seccomp filter comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Feed {
    /// No filter.
    NoFilter,
    /// The process's stdin holds it (stdin is then empty for the command).
    FromStdin,
    /// A file holds it.
    FromFile(AbsPath),
}

impl Feed {
    fn word(&self) -> String {
        match self {
            Feed::NoFilter => "none".to_owned(),
            Feed::FromStdin => "stdin".to_owned(),
            Feed::FromFile(path) => path.as_str().to_owned(),
        }
    }
}

/// The environment the started process gets.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Env<'a> {
    /// A fixed `PATH` only.
    Minimal,
    /// Exactly these variables (plus the session variables a scope needs).
    Exactly(&'a [EnvVar]),
}

#[derive(Debug, Clone)]
enum How {
    Scope {
        program: PathBuf,
        session: UserSession,
    },
    Rlimit,
    Nothing,
}

/// A resolved limit policy: what was checked to work, and the command it builds.
#[derive(Debug, Clone)]
pub(crate) struct Launcher {
    how: How,
    limits: Option<Limits>,
}

fn find(path: &str, name: &str) -> Option<PathBuf> {
    path.split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// Applies `limits` in a throwaway scope and reads the cgroup files back: systemd accepts
/// properties for controllers it has not been given, and then limits nothing.
fn scope_applies(program: &Path, session: &UserSession, limits: &Limits) -> bool {
    let read_back = r#"d=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup); echo "$(cat $d/memory.max) $(cat $d/pids.max)""#;
    let mut command = scope_command(program, session, limits);
    let out = command
        .args([SH, "-c", read_back])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let want = format!("{} {}", limits.memory.0, limits.pids);
    out.is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == want)
}

/// `systemd-run --user --scope` with the cgroup properties, ready for the program to run.
fn scope_command(program: &Path, session: &UserSession, limits: &Limits) -> Command {
    let mut command = Command::new(program);
    command
        .args(["--user", "--scope", "--quiet", "--collect"])
        .arg(format!("--property=MemoryMax={}", limits.memory.0))
        .arg("--property=MemorySwapMax=0")
        .arg(format!("--property=TasksMax={}", limits.pids))
        .arg("--")
        .env_clear()
        .env("PATH", BASE_PATH)
        .envs(session.vars.iter().map(|(k, v)| (k, v)));
    command
}

impl Launcher {
    /// Checks that `policy` can be applied here, using `systemd-run` found in `path`.
    pub(crate) fn resolve(
        path: &str,
        policy: &LimitPolicy,
        session: &UserSession,
    ) -> Result<Self, CannotSandbox> {
        match policy {
            LimitPolicy::Unlimited(_) => Ok(Self {
                how: How::Nothing,
                limits: None,
            }),
            LimitPolicy::Rlimit(limits) => {
                if !limits.usable() {
                    return Err(CannotSandbox::BadLimits);
                }
                if !Path::new(SH).is_file() {
                    return Err(CannotSandbox::LimitsUnavailable);
                }
                Ok(Self {
                    how: How::Rlimit,
                    limits: Some(limits.clone()),
                })
            }
            LimitPolicy::Cgroup(limits) => {
                if !limits.usable() {
                    return Err(CannotSandbox::BadLimits);
                }
                let program = find(path, "systemd-run").ok_or(CannotSandbox::LimitsUnavailable)?;
                if !Path::new(SH).is_file() || !scope_applies(&program, session, limits) {
                    return Err(CannotSandbox::LimitsUnavailable);
                }
                Ok(Self {
                    how: How::Scope {
                        program,
                        session: session.clone(),
                    },
                    limits: Some(limits.clone()),
                })
            }
        }
    }

    pub(crate) fn enforcement(&self) -> Enforcement {
        match self.how {
            How::Scope { .. } => Enforcement::Cgroup,
            How::Rlimit => Enforcement::Rlimit,
            How::Nothing => Enforcement::Unlimited,
        }
    }

    pub(crate) fn limits(&self) -> Option<&Limits> {
        self.limits.as_ref()
    }

    /// The `(cpu seconds, address space KiB)` words for the script; `-` where not set.
    fn rlimit_words(&self) -> (String, String) {
        let none = || "-".to_owned();
        match (&self.how, &self.limits) {
            (How::Scope { .. }, Some(l)) => (l.cpu_seconds.to_string(), none()),
            (How::Rlimit, Some(l)) => (l.cpu_seconds.to_string(), (l.memory.0 / 1024).to_string()),
            _ => (none(), none()),
        }
    }

    /// The command that starts `bwrap` with `args`, limited and fed as configured.
    pub(crate) fn command(
        &self,
        bwrap: &Path,
        args: &[String],
        feed: &Feed,
        env: Env<'_>,
    ) -> Command {
        let plain = matches!(self.how, How::Nothing) && *feed == Feed::NoFilter;
        let mut command = if plain {
            let mut c = Command::new(bwrap);
            c.args(args);
            c
        } else {
            let (cpu, vm) = self.rlimit_words();
            let mut c = match (&self.how, &self.limits) {
                (How::Scope { program, session }, Some(limits)) => {
                    let mut c = scope_command(program, session, limits);
                    c.arg(SH);
                    c
                }
                _ => Command::new(SH),
            };
            c.args(["-c", SCRIPT, "sh"])
                .arg(feed.word())
                .arg(cpu)
                .arg(vm)
                .arg(bwrap)
                .args(args);
            c
        };
        match env {
            Env::Minimal => {
                command.env_clear().env("PATH", BASE_PATH);
            }
            Env::Exactly(vars) => {
                command.env_clear();
                if let How::Scope { session, .. } = &self.how {
                    command.envs(session.vars.iter().map(|(k, v)| (k, v)));
                }
                command.envs(vars.iter().map(|v| (&v.name, &v.value)));
            }
        }
        if let (How::Scope { session, .. }, Env::Minimal) = (&self.how, env) {
            command.envs(session.vars.iter().map(|(k, v)| (k, v)));
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harden::{AcceptNoLimits, Bytes};

    fn words(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn args() -> Vec<String> {
        vec![
            "--unshare-all".to_owned(),
            "--".to_owned(),
            "true".to_owned(),
        ]
    }

    fn launcher(how: How, limits: Limits) -> Launcher {
        Launcher {
            how,
            limits: Some(limits),
        }
    }

    /// Each way of limiting builds its command; steps are named in the failure messages.
    #[test]
    fn the_command_follows_the_enforcement() {
        let bwrap = Path::new("/usr/bin/bwrap");
        let limits = Limits::default();

        let free = Launcher::resolve(
            "",
            &LimitPolicy::Unlimited(AcceptNoLimits),
            &UserSession::default(),
        )
        .expect("unlimited resolves anywhere");
        let c = free.command(bwrap, &args(), &Feed::NoFilter, Env::Minimal);
        assert_eq!(c.get_program(), "/usr/bin/bwrap", "step unlimited: direct");
        assert_eq!(words(&c), args(), "step unlimited: arguments untouched");

        let rl = launcher(How::Rlimit, limits.clone());
        let c = rl.command(bwrap, &args(), &Feed::FromStdin, Env::Minimal);
        assert_eq!(c.get_program(), SH, "step rlimit: through sh");
        let w = words(&c);
        assert_eq!(
            w[2..7],
            ["sh", "stdin", "900", "2097152", "/usr/bin/bwrap"],
            "step rlimit: cpu seconds and address space in KiB"
        );

        let scope = launcher(
            How::Scope {
                program: PathBuf::from("/usr/bin/systemd-run"),
                session: UserSession::default(),
            },
            limits,
        );
        let c = scope.command(bwrap, &args(), &Feed::NoFilter, Env::Minimal);
        let w = words(&c);
        for want in [
            "--user",
            "--scope",
            "--property=MemoryMax=2147483648",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=256",
        ] {
            assert!(w.iter().any(|a| a == want), "step scope: {want}");
        }
        let at = w.iter().position(|a| a == "--").expect("separator");
        assert_eq!(w[at + 1], SH, "step scope: sh runs inside the scope");
        assert_eq!(w[at + 5], "900", "step scope: cpu seconds still set");
        assert_eq!(w[at + 6], "-", "step scope: no address-space cap");
    }

    #[test]
    fn limits_that_are_not_usable_fail_closed_before_anything_runs() {
        let zero = |edit: fn(&mut Limits)| {
            let mut l = Limits::default();
            edit(&mut l);
            l
        };
        let bad = [
            zero(|l| l.pids = 0),
            zero(|l| l.cpu_seconds = 0),
            zero(|l| l.memory = Bytes(4097)),
            zero(|l| l.tmpfs = Bytes(0)),
        ];
        for limits in bad {
            for policy in [
                LimitPolicy::Cgroup(limits.clone()),
                LimitPolicy::Rlimit(limits.clone()),
            ] {
                let got = Launcher::resolve("/usr/bin", &policy, &UserSession::default());
                assert_eq!(got.err(), Some(CannotSandbox::BadLimits), "{policy:?}");
            }
        }
    }

    #[test]
    fn cgroup_limits_without_systemd_run_are_refused() {
        let got = Launcher::resolve(
            "/nonexistent-dir",
            &LimitPolicy::default(),
            &UserSession::default(),
        );
        assert_eq!(got.err(), Some(CannotSandbox::LimitsUnavailable));
    }
}
