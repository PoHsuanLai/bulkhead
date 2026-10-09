//! The real sandbox (bubblewrap). Each test skips, with a printed reason, where bwrap is missing
//! or the kernel refuses user namespaces (a locked-down build jail may). They use a scratch directory as
//! the working directory and never the real home.

use bulkhead::AbsPath;
use bulkhead::{Argv, BwrapSandbox, ExitReport, Launch, Shell};
use std::path::Path;

fn sandbox() -> Option<BwrapSandbox> {
    let path = std::env::var("PATH").unwrap_or_default();
    match BwrapSandbox::detect(&path) {
        Ok(s) => Some(s),
        Err(why) => {
            eprintln!("SKIP real sandbox test: {why}");
            None
        }
    }
}

fn launch(cwd: &Path, line: &[&str]) -> Launch {
    let words: Vec<String> = line.iter().map(|s| (*s).to_owned()).collect();
    Launch {
        argv: Argv::new(&words[0], &words[1..]).expect("argv"),
        cwd: AbsPath::parse(cwd.to_str().expect("utf8")).expect("abs"),
        // A secret the requester tries to pass, and a fake home: neither may arrive.
        env: vec![
            ("API_TOKEN".to_owned(), "hunter2-secret".to_owned()),
            ("HOME".to_owned(), "/home/scratch-secret".to_owned()),
        ],
        limit: None,
    }
}

/// Runs `sh -c script` in `cwd` and returns its output and exit.
fn run(shell: &mut Shell<BwrapSandbox>, cwd: &Path, script: &str) -> (String, ExitReport) {
    let id = shell
        .create(&launch(cwd, &["sh", "-c", script]))
        .expect("created");
    let exit = shell.wait(id).expect("wait");
    let text = shell.output(id).expect("output").shown.text;
    shell.release(id).expect("release");
    (text, exit)
}

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("scratch");
    let cwd = root.path().join("work/app");
    std::fs::create_dir_all(&cwd).expect("cwd");
    (root, cwd)
}

#[test]
fn a_write_inside_the_cwd_works_and_one_outside_fails() {
    let Some(sandbox) = sandbox() else { return };
    let (root, cwd) = scratch();
    let sibling = root.path().join("work/other");
    std::fs::create_dir_all(&sibling).expect("sibling");
    let mut shell = Shell::new(sandbox);

    let (out, exit) = run(&mut shell, &cwd, "echo hi > inside.txt && cat inside.txt");
    assert_eq!(exit, ExitReport::Code(0), "{out}");
    assert_eq!(out.trim(), "hi");
    assert_eq!(
        std::fs::read_to_string(cwd.join("inside.txt")).expect("written on the host"),
        "hi\n"
    );

    let outside = format!(
        "echo x > /usr/outside.txt; echo x > /etc/outside.txt; echo x > {}/outside.txt",
        sibling.display()
    );
    let (out, exit) = run(&mut shell, &cwd, &outside);
    assert_ne!(exit, ExitReport::Code(0), "the last write must fail: {out}");
    assert!(!sibling.join("outside.txt").exists());
    assert!(!Path::new("/usr/outside.txt").exists());
    assert!(!Path::new("/etc/outside.txt").exists());
}

#[test]
fn the_network_is_unreachable() {
    let Some(sandbox) = sandbox() else { return };
    if !Path::new("/usr/bin/bash").exists() && !Path::new("/bin/bash").exists() {
        eprintln!("SKIP network test: no bash to open /dev/tcp");
        return;
    }
    let (_root, cwd) = scratch();
    let mut shell = Shell::new(sandbox);
    // A listener on the host's loopback: the sandbox has its own loopback, so it cannot reach it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let script = format!("bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>&1");
    let (out, exit) = run(&mut shell, &cwd, &script);
    assert_ne!(
        exit,
        ExitReport::Code(0),
        "the host's loopback must be unreachable: {out}"
    );
    assert_eq!(
        listener.accept().map(|_| ()).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::WouldBlock),
        "the host's listener saw a connection"
    );
    // An address in the documentation range: there is no route out of the sandbox. Nothing is
    // sent; the connect fails in the sandbox's own routing table.
    let (out, exit) = run(
        &mut shell,
        &cwd,
        "bash -c 'exec 3<>/dev/tcp/192.0.2.1/80' 2>&1",
    );
    assert_ne!(exit, ExitReport::Code(0), "{out}");
    assert!(
        out.to_lowercase().contains("unreachable"),
        "expected a sandbox denial (unreachable), got: {out}"
    );
}

#[test]
fn the_environment_carries_no_secrets_and_a_fixed_home() {
    let Some(sandbox) = sandbox() else { return };
    let (_root, cwd) = scratch();
    let mut shell = Shell::new(sandbox);
    let (out, exit) = run(&mut shell, &cwd, "env; ls /home /root 2>&1");
    assert_eq!(exit, ExitReport::Code(0), "{out}");
    assert!(!out.contains("hunter2-secret"), "{out}");
    assert!(!out.contains("scratch-secret"), "{out}");
    assert!(out.contains("HOME=/tmp"), "{out}");
    let allowed = [
        "PATH", "HOME", "TMPDIR", "LANG", "TERM", "PWD", "SHLVL", "_", "OLDPWD",
    ];
    for line in out.lines().filter(|l| l.contains('=')) {
        let name = line.split('=').next().unwrap_or_default();
        assert!(allowed.contains(&name), "unexpected variable {name}");
    }
}

#[test]
fn kill_ends_a_long_command() {
    let Some(sandbox) = sandbox() else { return };
    let (_root, cwd) = scratch();
    let mut shell = Shell::new(sandbox);
    let id = shell
        .create(&launch(&cwd, &["sleep", "600"]))
        .expect("created");
    shell.kill(id).expect("kill");
    assert!(matches!(shell.wait(id), Ok(ExitReport::Signal(_))));
    shell.release(id).expect("release");
}

/// Why: a kill straight after `create` once reached the outer bubblewrap before the inner one had
/// armed its death signal, leaving the command alive and holding the output pipe. Counted polls,
/// no clock: every terminal must report its end.
#[test]
fn a_kill_straight_after_create_ends_everything() {
    let Some(sandbox) = sandbox() else { return };
    let (_root, cwd) = scratch();
    let mut shell = Shell::new(sandbox);
    for _ in 0..25 {
        let id = shell
            .create(&launch(&cwd, &["sleep", "600"]))
            .expect("created");
        shell.kill(id).expect("kill");
        let ended = (0..1_000_000).any(|_| shell.output(id).expect("output").exit.is_some());
        assert!(ended, "the killed command never reported an end");
        shell.release(id).expect("release");
    }
}

/// Why: the same race under load. Many threads create and kill at once, so the outer bubblewrap
/// is often killed while the inner one is still setting up. Counted polls, no clock; a command
/// that survives shows as a terminal that never reports its end.
#[test]
fn parallel_kills_straight_after_create_end_everything() {
    const THREADS: usize = 16;
    const ROUNDS: usize = 12;
    let Some(sandbox) = sandbox() else { return };
    let (_root, cwd) = scratch();
    let stuck: usize = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let sandbox = sandbox.clone();
                let cwd = cwd.clone();
                scope.spawn(move || {
                    let mut shell = Shell::new(sandbox);
                    (0..ROUNDS)
                        .filter(|_| {
                            let id = shell
                                .create(&launch(&cwd, &["sleep", "600"]))
                                .expect("created");
                            shell.kill(id).expect("kill");
                            let ended = (0..200_000)
                                .any(|_| shell.output(id).expect("output").exit.is_some());
                            // A survivor keeps the pipe open; its drop would block, so the
                            // test ends here and reports instead of releasing it.
                            if ended {
                                shell.release(id).expect("release");
                            }
                            !ended
                        })
                        .count()
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().expect("worker")).sum()
    });
    assert_eq!(stuck, 0, "commands survived a kill straight after create");
}

#[test]
fn a_cwd_that_is_not_a_directory_or_is_too_shallow_cannot_be_sandboxed() {
    let Some(sandbox) = sandbox() else { return };
    let mut shell = Shell::new(sandbox);
    for bad in ["/", "/home", "/does/not/exist/at/all"] {
        let ask = Launch {
            argv: Argv::new("ls", &[]).expect("argv"),
            cwd: AbsPath::parse(bad).expect("abs"),
            env: Vec::new(),
            limit: None,
        };
        assert!(
            matches!(
                shell.create(&ask),
                Err(bulkhead::ShellFault::CannotSandbox(_))
            ),
            "{bad}"
        );
    }
}
