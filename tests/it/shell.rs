//! The terminal table over the fake sandbox: what reaches the sandbox, what is refused, and that
//! kill and release always work.

use bulkhead::fake::{FakeSandbox, Fate, Script};
use bulkhead::{AbsPath, CannotSandbox};
use bulkhead::{Argv, Cut, ExitReport, Launch, MAX_TERMINALS, Network, Shell, ShellFault};

fn launch(line: &[&str]) -> Launch {
    let words: Vec<String> = line.iter().map(|s| (*s).to_owned()).collect();
    Launch::new(
        Argv::new(&words[0], &words[1..]).expect("argv"),
        AbsPath::parse("/work/app").expect("cwd"),
    )
    .with_env(vec![
        ("API_TOKEN".to_owned(), "hunter2".to_owned()),
        ("LANG".to_owned(), "C".to_owned()),
    ])
}

#[test]
fn the_sandbox_gets_the_command_cwd_filtered_env_and_no_network() {
    let (sandbox, seen) = FakeSandbox::ready(vec![Script::done("ok\n", 0)]);
    let mut shell = Shell::new(sandbox);
    shell.create(&launch(&["cargo", "test"])).expect("created");
    let started = seen.started();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].argv.line(), "cargo test");
    assert_eq!(started[0].cwd.as_str(), "/work/app");
    assert_eq!(started[0].network, Network::Off);
    let names: Vec<&str> = started[0].env.iter().map(|v| v.name.as_str()).collect();
    assert!(!names.contains(&"API_TOKEN"));
    assert!(names.contains(&"LANG"));
}

#[test]
fn a_withheld_sandbox_refuses_and_runs_nothing() {
    for why in [CannotSandbox::NotInstalled, CannotSandbox::NamespacesDenied] {
        let (sandbox, seen) = FakeSandbox::withheld(why);
        let mut shell = Shell::new(sandbox);
        assert_eq!(
            shell.create(&launch(&["ls"])),
            Err(ShellFault::CannotSandbox(why))
        );
        assert!(seen.started().is_empty());
        assert_eq!(shell.open(), 0);
    }
}

#[test]
fn output_and_exit_come_back_redacted() {
    let (sandbox, _) = FakeSandbox::ready(vec![Script::done("TOKEN=abc\nfine\n", 3)]);
    let mut shell = Shell::new(sandbox);
    let id = shell.create(&launch(&["env"])).expect("created");
    let snap = shell.output(id).expect("output");
    assert_eq!(snap.shown.text, "TOKEN=[redacted]\nfine\n");
    assert_eq!(snap.exit, Some(ExitReport::Code(3)));
    assert_eq!(shell.wait(id), Ok(ExitReport::Code(3)));
}

#[test]
fn the_output_cap_keeps_the_tail() {
    let (sandbox, _) = FakeSandbox::ready(vec![Script::done("0123456789abcdef", 0)]);
    let mut shell = Shell::new(sandbox);
    let mut ask = launch(&["x"]);
    ask.limit = Some(6);
    let id = shell.create(&ask).expect("created");
    let snap = shell.output(id).expect("output");
    assert_eq!(snap.shown.text, "abcdef");
    assert_eq!(snap.shown.cut, Cut::Head);
}

#[test]
fn kill_keeps_the_terminal_and_release_frees_it_and_both_kill_the_job() {
    let (sandbox, seen) = FakeSandbox::ready(vec![Script::hangs("a"), Script::hangs("b")]);
    let mut shell = Shell::new(sandbox);
    let first = shell.create(&launch(&["sleep", "9"])).expect("created");
    let second = shell.create(&launch(&["sleep", "9"])).expect("created");
    assert_eq!(seen.fates(), [Fate::Running, Fate::Running]);
    assert_eq!(shell.output(first).expect("output").exit, None);

    shell.kill(first).expect("kill");
    assert_eq!(seen.fates()[0], Fate::Killed);
    let snap = shell.output(first).expect("still valid after kill");
    assert_eq!(snap.shown.text, "a");
    assert_eq!(snap.exit, Some(ExitReport::Signal("KILL".to_owned())));

    shell.release(second).expect("release");
    assert_eq!(seen.fates()[1], Fate::Killed);
    assert_eq!(shell.output(second), Err(ShellFault::NoSuchTerminal));
    assert_eq!(shell.release(second), Err(ShellFault::NoSuchTerminal));
}

#[test]
fn dropping_the_shell_kills_what_it_started() {
    let (sandbox, seen) = FakeSandbox::ready(vec![Script::hangs("")]);
    let mut shell = Shell::new(sandbox);
    shell.create(&launch(&["sleep", "9"])).expect("created");
    drop(shell);
    assert_eq!(seen.fates(), [Fate::Killed]);
}

#[test]
fn too_many_terminals_are_refused() {
    let (sandbox, _) = FakeSandbox::ready(Vec::new());
    let mut shell = Shell::new(sandbox);
    for _ in 0..MAX_TERMINALS {
        shell.create(&launch(&["true"])).expect("created");
    }
    assert_eq!(shell.create(&launch(&["true"])), Err(ShellFault::TooMany));
}
