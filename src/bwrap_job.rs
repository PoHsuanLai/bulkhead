//! A running bubblewrap process: its output is read by one thread into a bounded tail, and
//! killing it (or dropping it) kills bubblewrap, whose pid namespace takes every descendant with
//! it.
//!
//! **Why `spawn` waits for the command to exist.** Bubblewrap is two processes: the one we start,
//! and the pid-1 of the new pid namespace it forks, which then forks the command. The inner one
//! arms `PR_SET_PDEATHSIG` (from `--die-with-parent`) only part-way through its setup. A SIGKILL
//! to the outer one before that leaves the inner one and the command alive and reparented, still
//! holding the output pipe, so a reader waiting for the pipe's end never returns (they even
//! ignore SIGTERM). The command is forked after the signal is armed, so `spawn` returns only once
//! the inner process has a child of its own (read from `/proc/<pid>/task/<pid>/children`), or
//! once bubblewrap has already ended. From then on killing the outer process takes everything.
//! `--info-fd` would say the same, but std can pass a child only stdin, stdout and stderr, and
//! each of those carries the command's own input or output. A process group does not help
//! either: `--new-session` puts the inner process in a session of its own. Where `/proc` has no
//! `children` file the wait is skipped, as it was before.

use crate::output::Tail;
use crate::sandbox::{ByteLimit, Captured, ExitReport, Job, KILLED, StartFault};
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often `spawn` looks for the command, and how many looks it gives it: setup takes
/// milliseconds, so the bound is only there so a broken `bwrap` cannot hold `spawn` forever.
const LOOK_EVERY: Duration = Duration::from_micros(200);
const LOOKS: u32 = 50_000;

/// The pids `pid` has forked, or `None` where the kernel does not list them.
fn children(pid: u32) -> Option<Vec<u32>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).ok()?;
    Some(
        text.split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect(),
    )
}

/// Whether the inner process has forked the command, which it does after arming its death
/// signal.
fn command_exists(outer: u32) -> Option<bool> {
    let inner = children(outer)?;
    Some(
        inner
            .iter()
            .any(|i| children(*i).is_some_and(|c| !c.is_empty())),
    )
}

/// Waits until a kill of `child` is safe: the command exists, or bubblewrap is already over.
fn until_killable(child: &mut Child) {
    for _ in 0..LOOKS {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        match command_exists(child.id()) {
            Some(false) => std::thread::sleep(LOOK_EVERY),
            Some(true) | None => return,
        }
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A started command.
#[derive(Debug)]
pub struct BwrapJob {
    child: Child,
    tail: Arc<Mutex<Tail>>,
    reader: Option<JoinHandle<()>>,
    ended: Option<ExitReport>,
}

#[cfg(unix)]
fn signal_name(status: &ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(9) => KILLED.to_owned(),
        Some(15) => "TERM".to_owned(),
        Some(2) => "INT".to_owned(),
        Some(n) => format!("SIG{n}"),
        None => KILLED.to_owned(),
    }
}

#[cfg(not(unix))]
fn signal_name(_: &ExitStatus) -> String {
    KILLED.to_owned()
}

fn report(status: &ExitStatus) -> ExitReport {
    match status.code().and_then(|c| u32::try_from(c).ok()) {
        Some(code) => ExitReport::Code(code),
        None => ExitReport::Signal(signal_name(status)),
    }
}

#[cfg(unix)]
fn own_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn own_group(_: &mut Command) {}

impl BwrapJob {
    /// Starts `command` with stdout and stderr on one pipe and no stdin.
    pub(crate) fn spawn(mut command: Command, keep: ByteLimit) -> Result<Self, StartFault> {
        let (mut reader, writer) = std::io::pipe().map_err(|_| StartFault::Spawn)?;
        let errors = writer.try_clone().map_err(|_| StartFault::Spawn)?;
        command.stdin(Stdio::null()).stdout(writer).stderr(errors);
        own_group(&mut command);
        let mut child = command.spawn().map_err(|_| StartFault::Spawn)?;
        // The command still holds the write ends; closing them lets the reader see the end.
        drop(command);
        until_killable(&mut child);
        let tail = Arc::new(Mutex::new(Tail::new(keep)));
        let sink = Arc::clone(&tail);
        let thread = std::thread::spawn(move || {
            let mut chunk = [0_u8; 8192];
            while let Ok(n) = reader.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                locked(&sink).push(&chunk[..n]);
            }
        });
        Ok(Self {
            child,
            tail,
            reader: Some(thread),
            ended: None,
        })
    }

    fn finish(&mut self, status: &ExitStatus) -> ExitReport {
        if let Some(thread) = self.reader.take() {
            let _ = thread.join();
        }
        let done = report(status);
        self.ended = Some(done.clone());
        done
    }
}

impl Job for BwrapJob {
    fn output(&mut self) -> Captured {
        locked(&self.tail).captured()
    }

    fn exit(&mut self) -> Option<ExitReport> {
        if self.ended.is_some() {
            return self.ended.clone();
        }
        match self.child.try_wait() {
            Ok(Some(status)) => Some(self.finish(&status)),
            _ => None,
        }
    }

    fn wait(&mut self) -> ExitReport {
        if let Some(done) = &self.ended {
            return done.clone();
        }
        match self.child.wait() {
            Ok(status) => self.finish(&status),
            Err(_) => ExitReport::Signal(KILLED.to_owned()),
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
    }
}

impl Drop for BwrapJob {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
