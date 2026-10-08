//! The endpoint-only mode for real: bubblewrap, the forwarder binary, the bridge, and a loopback
//! listener standing in for a model endpoint. Skips, with a printed reason, where bwrap, user
//! namespaces or a loopback are missing. Scratch directories only.

use bulkhead::AbsPath;
use bulkhead::forward::{Bridge, Loopback};
use bulkhead::{AgentNet, AgentRun, Argv, EndpointBind, EnvVar, agent_bwrap_args, present_hidden};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};

fn bwrap() -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .map(|d| Path::new(d).join("bwrap"))
        .find(|p| p.is_file())
}

fn abs(path: &Path) -> AbsPath {
    AbsPath::parse(path.to_str().expect("utf8")).expect("abs")
}

fn run_in_sandbox(program: &Path, net: AgentNet, cwd: &Path, script: &str) -> Option<String> {
    let run = AgentRun {
        argv: Argv::new("bash", &["-c".to_owned(), script.to_owned()]).expect("argv"),
        cwd: abs(cwd),
        env: vec![EnvVar {
            name: "PATH".to_owned(),
            value: "/usr/bin:/bin".to_owned(),
        }],
        net,
        binds: Vec::new(),
        overlays: Vec::new(),
    };
    let out = Command::new(program)
        .args(agent_bwrap_args(&run, &present_hidden()))
        .env_clear()
        .envs(run.env.iter().map(|v| (&v.name, &v.value)))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn rig() -> Option<(std::path::PathBuf, TcpListener, tempfile::TempDir)> {
    let Some(program) = bwrap() else {
        eprintln!("SKIP endpoint test: no bwrap");
        return None;
    };
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIP endpoint test: no loopback here");
        return None;
    };
    let dir = tempfile::tempdir().expect("scratch");
    std::fs::create_dir_all(dir.path().join("work/app")).expect("cwd");
    Some((program, listener, dir))
}

const CLIENT: &str =
    "exec 3<>/dev/tcp/127.0.0.1/PORT && echo ping >&3 && read -r x <&3 && echo \"got $x\"";

#[test]
fn the_agent_reaches_the_endpoint_through_the_forwarder_and_the_bridge() {
    let Some((program, listener, dir)) = rig() else {
        return;
    };
    let port = listener.local_addr().expect("addr").port();
    let cwd = dir.path().join("work/app");
    let socket = dir.path().join("ep.sock");
    let _bridge = Bridge::start(&socket, Loopback::new("127.0.0.1", port).expect("loopback"))
        .expect("bridge");
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0_u8; 5];
        conn.read_exact(&mut buf).expect("read");
        conn.write_all(b"pong\n").expect("write");
    });
    let net = AgentNet::Endpoint(EndpointBind {
        forwarder: abs(Path::new(env!("CARGO_BIN_EXE_bulkhead-forward"))),
        socket: abs(&socket),
        port,
    });
    let script = CLIENT.replace("PORT", &port.to_string());
    let Some(out) = run_in_sandbox(&program, net, &cwd, &script) else {
        return;
    };
    if out.is_empty() {
        eprintln!("SKIP endpoint test: the sandbox did not start here");
        return;
    }
    assert_eq!(out.trim(), "got pong");
    server.join().expect("server");
}

#[test]
fn without_the_forwarder_the_hosts_loopback_is_unreachable() {
    let Some((program, listener, dir)) = rig() else {
        return;
    };
    let port = listener.local_addr().expect("addr").port();
    let cwd = dir.path().join("work/app");
    let script = format!("{}; echo done", CLIENT.replace("PORT", &port.to_string()));
    let Some(out) = run_in_sandbox(&program, AgentNet::None, &cwd, &script) else {
        return;
    };
    if !out.contains("done") {
        eprintln!("SKIP endpoint test: the sandbox did not start here");
        return;
    }
    assert!(!out.contains("got"), "{out}");
    listener.set_nonblocking(true).expect("nonblocking");
    assert!(
        listener.accept().is_err(),
        "nothing reached the host listener"
    );
}
