//! A running bubblewrap process: its output is read by one thread into a bounded tail, and
//! killing it (or dropping it) takes the whole sandbox with it (`bwrap_kill`).
//!
//! Waiting for the command to exist, then killing the outer process, was not enough: the outer
//! process may die before its child has armed `PR_SET_PDEATHSIG`, however long `spawn` waits for
//! some sign of progress, and a load spike can make that window long. So `spawn` waits for
//! nothing and `kill` does not rely on the death signal at all.

use crate::output::Tail;
use crate::sandbox::{ByteLimit, Captured, ExitReport, Job, KILLED, StartFault};
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

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
        let child = command.spawn().map_err(|_| StartFault::Spawn)?;
        // The command still holds the write ends; closing them lets the reader see the end.
        drop(command);
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
        crate::bwrap_kill::kill_all(&mut self.child);
    }
}

impl Drop for BwrapJob {
    fn drop(&mut self) {
        crate::bwrap_kill::kill_all(&mut self.child);
        let _ = self.child.wait();
    }
}
