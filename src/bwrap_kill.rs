//! Killing a bubblewrap sandbox so that nothing in it survives, whatever the machine's load.
//!
//! Bubblewrap is two processes: the one we start (the outer) and the pid 1 of the new pid
//! namespace it forks (the inner), which forks the command. `--die-with-parent` makes the inner
//! die with the outer, but the inner arms that death signal only part-way through its setup. A
//! SIGKILL to the outer before then leaves the inner and the command alive, reparented, holding
//! the output pipe. No amount of waiting after `spawn` closes that window for certain.
//!
//! The kernel does close it from the other side: when the pid 1 of a pid namespace dies, every
//! process in the namespace is killed with it. So the kill goes inner first:
//!
//! 1. SIGSTOP the outer and wait until it is stopped (or gone). A stopped process cannot fork,
//!    so the set of its children is now fixed.
//! 2. SIGKILL the outer's children, and their descendants, then the outer. The inner is the pid 1
//!    of the namespace, so its death ends the command; with no inner yet, killing the outer
//!    leaves nothing behind.
//!
//! The outer is our own unreaped child and its children cannot be reaped while it is stopped, so
//! no pid in the sequence can have been reused. Signals to processes other than our direct child
//! go through the `kill` program, as std offers no other way without `unsafe`. Where that fails,
//! or `/proc` lacks the `children` files, the kill falls back to killing the outer process only.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// How often, and how many times, the outer process is looked at while it stops. The bound only
/// keeps a process stuck in the kernel from holding the kill forever.
const LOOK_EVERY: Duration = Duration::from_micros(200);
const LOOKS: u32 = 100_000;

/// The pids `pid` has forked, or `None` where the kernel does not list them.
fn children(pid: u32) -> Option<Vec<u32>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).ok()?;
    Some(
        text.split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect(),
    )
}

/// Every descendant of `pid`, each before its own descendants.
fn descendants(pid: u32) -> Option<Vec<u32>> {
    let mut all = Vec::new();
    let mut next = children(pid)?;
    while let Some(p) = next.first().copied() {
        next.remove(0);
        all.push(p);
        // A descendant that has just died is simply not there any more.
        next.extend(children(p).unwrap_or_default());
    }
    Some(all)
}

/// The scheduling state letter of `pid` (`T` is stopped), or `None` where it is gone.
fn state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The state follows the command name, which is in parentheses and may hold anything.
    stat.rsplit_once(')')?.1.trim_start().chars().next()
}

/// Which signal to send.
#[derive(Debug, Clone, Copy)]
enum Signal {
    Stop,
    Kill,
}

impl Signal {
    fn flag(self) -> &'static str {
        match self {
            Signal::Stop => "-STOP",
            Signal::Kill => "-KILL",
        }
    }
}

/// Sends `signal` to `pids` with the `kill` program; whether it worked.
fn send(signal: Signal, pids: &[u32]) -> bool {
    Command::new("kill")
        .arg(signal.flag())
        .args(pids.iter().map(u32::to_string))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Waits (a counted number of looks) until `pid` is stopped or gone.
fn until_stopped(pid: u32) -> bool {
    for _ in 0..LOOKS {
        match state(pid) {
            Some('T' | 't' | 'Z' | 'X') | None => return true,
            Some(_) => std::thread::sleep(LOOK_EVERY),
        }
    }
    false
}

/// Kills the sandbox `child` leads, and reaps `child`.
pub(crate) fn kill_all(child: &mut Child) {
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    let outer = child.id();
    if send(Signal::Stop, &[outer]) && until_stopped(outer) {
        let mut victims = descendants(outer).unwrap_or_default();
        victims.push(outer);
        send(Signal::Kill, &victims);
    }
    let _ = child.kill();
}
