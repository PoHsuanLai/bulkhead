//! The `Sandbox` seam: what the shell tool asks of whatever confines a command. Synchronous and
//! small on purpose: a job is polled, waited on and killed; nothing here names a runtime.

use crate::{AbsPath, SandboxState};

/// A command and its arguments: at least the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argv(Vec<String>);

impl Argv {
    /// The program and its arguments; none without a program.
    pub fn new(program: &str, args: &[String]) -> Option<Self> {
        if program.is_empty() || program.contains('\0') || args.iter().any(|a| a.contains('\0')) {
            return None;
        }
        let mut all = vec![program.to_owned()];
        all.extend(args.iter().cloned());
        Some(Self(all))
    }

    /// Every word, program first.
    pub fn words(&self) -> &[String] {
        &self.0
    }

    /// The words joined by single spaces: what a command prefix is compared with.
    pub fn line(&self) -> String {
        self.0.join(" ")
    }
}

/// One environment variable. Its value is never printed: `Debug` shows the name alone.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
}

impl std::fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EnvVar({}=<{} bytes>)", self.name, self.value.len())
    }
}

/// Whether the command may reach the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// No interface at all, not even loopback: the default, and the only one the terminal
    /// methods ask for.
    #[default]
    Off,
    /// The host's network. Nothing in this repo asks for it yet.
    Host,
}

/// How many bytes of output a job keeps (the tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteLimit(pub usize);

/// Everything a sandbox needs to run one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    /// The command.
    pub argv: Argv,
    /// The working directory, and the one place the command may write.
    pub cwd: AbsPath,
    /// The whole environment the command sees (already filtered); nothing else is inherited.
    pub env: Vec<EnvVar>,
    /// The network.
    pub network: Network,
    /// How much output to keep.
    pub keep: ByteLimit,
}

/// Whether captured output lost its beginning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// Everything the command wrote is here.
    Whole,
    /// The oldest bytes were dropped to stay within the limit.
    Head,
}

/// What a job has written so far (stdout and stderr in the order they arrived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The bytes kept.
    pub bytes: Vec<u8>,
    /// Whether any were dropped.
    pub cut: Cut,
}

/// How a job ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReport {
    /// It exited with this code.
    Code(u32),
    /// A signal ended it (`KILL`).
    Signal(String),
}

/// A command running in a sandbox. Dropping it kills it.
pub trait Job: Send + std::fmt::Debug {
    /// What it has written so far.
    fn output(&mut self) -> Captured;
    /// How it ended, if it has.
    fn exit(&mut self) -> Option<ExitReport>;
    /// Blocks until it ends.
    fn wait(&mut self) -> ExitReport;
    /// Kills it and everything it started. Safe to repeat.
    fn kill(&mut self);
}

/// Why a job did not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartFault {
    /// The sandbox cannot confine this command; nothing was run.
    #[error("cannot sandbox: {0}")]
    Cannot(crate::CannotSandbox),
    /// The sandbox program could not be started.
    #[error("the sandbox program did not start")]
    Spawn,
}

/// Something that confines commands. Closed set of implementations: `BwrapSandbox` and
/// `FakeSandbox`.
pub trait Sandbox: Send + std::fmt::Debug {
    /// What it runs.
    type Job: Job;

    /// Whether this sandbox can confine anything at all (the startup check).
    fn available(&self) -> SandboxState;

    /// Whether a command in `cwd` can run here.
    fn check(&self, cwd: &AbsPath) -> SandboxState;

    /// Starts the command, confined. Never runs it unconfined.
    fn start(&self, spec: &RunSpec) -> Result<Self::Job, StartFault>;
}

/// The signal name the reports use for a killed job.
pub const KILLED: &str = "KILL";
