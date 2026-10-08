//! `FakeSandbox`: records what it was asked to run and answers from a script. No process, no
//! clock. A test hands the sandbox to the shell tool and keeps a `Seen` handle to look at what
//! reached it.

use crate::output::Tail;
use crate::sandbox::{ByteLimit, Captured, ExitReport, Job, KILLED, RunSpec, Sandbox, StartFault};
use crate::{AbsPath, CannotSandbox, SandboxState};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

/// Whether a scripted job ends by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// It has already exited when started.
    Finishes,
    /// It runs until killed.
    UntilKilled,
}

/// What the next job does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// What it writes.
    pub output: Vec<u8>,
    /// How it ends.
    pub exit: ExitReport,
    /// Whether it ends by itself.
    pub lifetime: Lifetime,
}

impl Script {
    /// A job that wrote `output` and exited with `code`.
    pub fn done(output: &str, code: u32) -> Self {
        Self {
            output: output.as_bytes().to_vec(),
            exit: ExitReport::Code(code),
            lifetime: Lifetime::Finishes,
        }
    }

    /// A job that wrote `output` and keeps running.
    pub fn hangs(output: &str) -> Self {
        Self {
            output: output.as_bytes().to_vec(),
            exit: ExitReport::Signal(KILLED.to_owned()),
            lifetime: Lifetime::UntilKilled,
        }
    }
}

/// What happened to a started job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Still going.
    Running,
    /// Killed (by `kill`, or by being dropped).
    Killed,
}

/// What the fake has seen.
#[derive(Debug, Default)]
pub struct Log {
    /// Every command it was asked to run, in order.
    pub started: Vec<RunSpec>,
    /// What became of each, by index into `started`.
    pub fates: Vec<Fate>,
}

/// A shared view of the fake's log.
#[derive(Debug, Clone, Default)]
pub struct Seen(Arc<Mutex<Log>>);

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Seen {
    /// Every command the sandbox was asked to run.
    pub fn started(&self) -> Vec<RunSpec> {
        locked(&self.0).started.clone()
    }

    /// What became of each job.
    pub fn fates(&self) -> Vec<Fate> {
        locked(&self.0).fates.clone()
    }
}

/// The scripted sandbox.
#[derive(Debug)]
pub struct FakeSandbox {
    available: SandboxState,
    scripts: Mutex<VecDeque<Script>>,
    seen: Seen,
}

impl FakeSandbox {
    /// A sandbox that can run commands, answering from `scripts` in order.
    pub fn ready(scripts: Vec<Script>) -> (Self, Seen) {
        Self::with(SandboxState::Ready, scripts)
    }

    /// A sandbox that cannot confine anything, for this reason.
    pub fn withheld(why: CannotSandbox) -> (Self, Seen) {
        Self::with(SandboxState::Cannot(why), Vec::new())
    }

    fn with(available: SandboxState, scripts: Vec<Script>) -> (Self, Seen) {
        let seen = Seen::default();
        let fake = Self {
            available,
            scripts: Mutex::new(scripts.into()),
            seen: seen.clone(),
        };
        (fake, seen)
    }
}

/// A scripted job.
#[derive(Debug)]
pub struct FakeJob {
    tail: Tail,
    script: Script,
    index: usize,
    killed: bool,
    seen: Seen,
}

impl FakeJob {
    fn mark_killed(&mut self) {
        if !self.killed {
            self.killed = true;
            if let Some(fate) = locked(&self.seen.0).fates.get_mut(self.index) {
                *fate = Fate::Killed;
            }
        }
    }
}

impl Job for FakeJob {
    fn output(&mut self) -> Captured {
        self.tail.captured()
    }

    fn exit(&mut self) -> Option<ExitReport> {
        match (self.script.lifetime, self.killed) {
            (Lifetime::Finishes, _) => Some(self.script.exit.clone()),
            (Lifetime::UntilKilled, true) => Some(ExitReport::Signal(KILLED.to_owned())),
            (Lifetime::UntilKilled, false) => None,
        }
    }

    fn wait(&mut self) -> ExitReport {
        // A job that would run for ever is reported as killed: a test never hangs on the fake.
        self.exit()
            .unwrap_or_else(|| ExitReport::Signal(KILLED.to_owned()))
    }

    fn kill(&mut self) {
        self.mark_killed();
    }
}

impl Drop for FakeJob {
    fn drop(&mut self) {
        self.mark_killed();
    }
}

impl Sandbox for FakeSandbox {
    type Job = FakeJob;

    fn available(&self) -> SandboxState {
        self.available
    }

    fn check(&self, _cwd: &AbsPath) -> SandboxState {
        self.available
    }

    fn start(&self, spec: &RunSpec) -> Result<FakeJob, StartFault> {
        if let SandboxState::Cannot(why) = self.available {
            return Err(StartFault::Cannot(why));
        }
        let script = locked(&self.scripts)
            .pop_front()
            .unwrap_or_else(|| Script::done("", 0));
        let mut tail = Tail::new(ByteLimit(spec.keep.0));
        tail.push(&script.output);
        let index = {
            let mut log = locked(&self.seen.0);
            log.started.push(spec.clone());
            log.fates.push(Fate::Running);
            log.started.len() - 1
        };
        Ok(FakeJob {
            tail,
            script,
            index,
            killed: false,
            seen: self.seen.clone(),
        })
    }
}
