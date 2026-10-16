//! The exec stage inside the sandbox: a small program that bubblewrap runs as the agent's
//! command. It applies a Landlock ruleset to itself, reports the level it reached on standard
//! error in one fixed line (`bulkhead-enter: landlock=<word>`), and then replaces itself with
//! the agent. Landlock is a second layer behind bubblewrap and the syscall filter: bubblewrap
//! decides what is mounted, Landlock decides what the agent may do with it.
//!
//! - [`plan`]: the words the stage is given, built and parsed strictly, and [`LandlockLevel`].
//! - `build`: the plan for one `AgentRun`, from the same lists the bubblewrap arguments use.
//! - `apply`: the `landlock` calls (Linux, behind the `landlock` feature, so a crate that only
//!   builds the command line links no sandbox library).

mod build;
pub mod plan;

#[cfg(all(target_os = "linux", feature = "landlock"))]
mod apply;

pub(crate) use build::plan_for;
pub use plan::{EnterFault, EnterPlan, LandlockLevel, NetRule};

/// Where the exec stage appears inside the sandbox.
pub const INSIDE_ENTER: &str = "/run/bulkhead/enter";

#[cfg(all(target_os = "linux", feature = "landlock"))]
pub use apply::apply;

/// The exec stage's `main`, as a function so any binary can be it:
/// `NAME [--read P]... [--write P]... [--device P]... NETWORK -- PROGRAM [ARGS...]`.
/// Exits 2 on words it refuses, 3 when Landlock fails in a way that is not "not available", and
/// 127 when the program cannot be started.
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub fn enter_main(name: &str) -> std::process::ExitCode {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitCode};
    let Ok((plan, program)) = EnterPlan::parse(std::env::args().skip(1)) else {
        eprintln!(
            "usage: {name} [--read PATH]... [--write PATH]... [--device PATH]... \
             (--net-unfiltered | --net-none | --net-connect PORT) -- PROGRAM [ARGS]"
        );
        return ExitCode::from(2);
    };
    let level = match apply(&plan) {
        Ok(level) => level,
        Err(error) => {
            eprintln!("{name}: cannot apply Landlock: {error}");
            return ExitCode::from(3);
        }
    };
    eprintln!("{}", level.report_line());
    let error = Command::new(&program[0]).args(&program[1..]).exec();
    eprintln!("{name}: cannot run {}: {error}", program[0]);
    ExitCode::from(127)
}

/// The exec stage's `main` in a build that cannot apply Landlock: not Linux, or without the
/// `landlock` feature.
#[cfg(not(all(target_os = "linux", feature = "landlock")))]
pub fn enter_main(name: &str) -> std::process::ExitCode {
    eprintln!("{name} needs Linux and bulkhead's `landlock` feature");
    std::process::ExitCode::from(2)
}
