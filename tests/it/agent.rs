//! The agent process's bubblewrap arguments, as plain strings.

use bulkhead::AbsPath;
use bulkhead::{
    Access, AgentNet, AgentRun, Argv, Bind, ByteLimit, EndpointBind, EnvVar, INSIDE_FORWARDER,
    INSIDE_SOCKET, Network, NetworkMode, RESOLVER_FILES, RunSpec, agent_bwrap_args, bwrap_args,
};

fn abs(text: &str) -> AbsPath {
    AbsPath::parse(text).expect("abs")
}

fn run(net: AgentNet, binds: Vec<Bind>) -> AgentRun {
    let env = vec![EnvVar {
        name: "HOME".to_owned(),
        value: "/home/u".to_owned(),
    }];
    let argv = Argv::new("claude-agent-acp", &["--stdio".to_owned()]).expect("argv");
    binds.into_iter().fold(
        AgentRun::new(argv, abs("/work/project"), env, net),
        AgentRun::with_bind,
    )
}

fn has(args: &[String], seq: &[&str]) -> bool {
    args.windows(seq.len())
        .any(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

#[test]
fn with_no_network_the_namespace_is_new_and_nothing_is_shared() {
    let args = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &["/home", "/tmp"]);
    assert!(has(&args, &["--unshare-all"]));
    assert!(!args.iter().any(|a| a == "--share-net"));
    assert!(has(&args, &["--cap-drop", "ALL"]));
    // The environment is not in the arguments, so a key in it is not on a command line.
    assert!(!args.iter().any(|a| a == "--setenv" || a == "/home/u"));
    assert!(has(&args, &["--bind", "/work/project", "/work/project"]));
    assert!(has(&args, &["--tmpfs", "/home"]));
    assert_eq!(args.last().map(String::as_str), Some("--stdio"));
}

/// Only host mode shares the host network, and it binds back the resolver files. Steps:
/// "host shares the network", "host binds the resolver files", then the None run has neither.
#[test]
fn host_mode_shares_the_network_and_binds_back_only_the_resolver_files() {
    // /etc/resolv.conf is often a link into /run, which the sandbox empties: without these the
    // agent has the network but cannot resolve a name.
    let host = agent_bwrap_args(&run(AgentNet::Host, Vec::new()), &["/run"]);
    assert!(has(&host, &["--share-net"]), "step host shares the network");
    for file in RESOLVER_FILES {
        assert!(
            has(&host, &["--ro-bind-try", file, file]),
            "step host resolver binds: {file}"
        );
    }
    let tmpfs = host.iter().position(|a| a == "--tmpfs");
    let bind = host.iter().position(|a| a == "--ro-bind-try");
    assert!(
        tmpfs < bind,
        "step host binds: the binds come after /run is emptied"
    );
    let none = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &["/run"]);
    assert!(
        !none.iter().any(|a| a == "--share-net"),
        "step none: no shared network"
    );
    assert!(
        !none.iter().any(|a| a == "--ro-bind-try"),
        "step none: no resolver binds"
    );
}

#[test]
fn endpoint_only_starts_the_forwarder_first_and_binds_one_socket() {
    let bind = EndpointBind::new(
        abs("/opt/bulkhead/bulkhead-forward"),
        abs("/run/user/1000/bulkhead/ep.sock"),
        40123,
    );
    let args = agent_bwrap_args(&run(AgentNet::Endpoint(bind), Vec::new()), &[]);
    assert!(!args.iter().any(|a| a == "--share-net"));
    assert!(has(
        &args,
        &[
            "--ro-bind",
            "/opt/bulkhead/bulkhead-forward",
            INSIDE_FORWARDER
        ]
    ));
    assert!(has(
        &args,
        &["--bind", "/run/user/1000/bulkhead/ep.sock", INSIDE_SOCKET]
    ));
    let tail: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .skip_while(|a| *a != "--")
        .collect();
    assert_eq!(
        tail,
        [
            "--",
            INSIDE_FORWARDER,
            "run",
            "--listen",
            "127.0.0.1:40123",
            "--socket",
            INSIDE_SOCKET,
            "--",
            "claude-agent-acp",
            "--stdio"
        ]
    );
}

#[test]
fn extra_binds_come_after_the_emptied_directories_and_keep_their_access() {
    let binds = vec![
        Bind::new(abs("/home/u/.local/node"), Access::ReadOnly),
        Bind::new(abs("/home/u/.claude"), Access::ReadWrite),
    ];
    let args = agent_bwrap_args(&run(AgentNet::None, binds), &["/home"]);
    let at = |seq: &[&str]| {
        args.windows(seq.len())
            .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
            .expect("present")
    };
    let hide = at(&["--tmpfs", "/home"]);
    let ro = at(&["--ro-bind", "/home/u/.local/node", "/home/u/.local/node"]);
    let rw = at(&["--bind", "/home/u/.claude", "/home/u/.claude"]);
    assert!(hide < ro && ro < rw);
}

#[test]
fn a_mode_and_its_endpoint_must_agree() {
    let bind = EndpointBind::new(abs("/opt/f"), abs("/run/s"), 1);
    assert!(AgentNet::of(NetworkMode::EndpointOnly, None).is_err());
    assert!(AgentNet::of(NetworkMode::None, Some(bind.clone())).is_err());
    assert!(AgentNet::of(NetworkMode::Host, Some(bind.clone())).is_err());
    assert_eq!(
        AgentNet::of(NetworkMode::EndpointOnly, Some(bind))
            .expect("plan")
            .mode(),
        NetworkMode::EndpointOnly
    );
    assert_eq!(NetworkMode::default(), NetworkMode::None);
}

#[test]
fn a_command_with_the_host_network_resolves_names_too() {
    let spec = |network| {
        RunSpec::new(
            Argv::new("curl", &["example.org".to_owned()]).expect("argv"),
            abs("/work/project"),
            Vec::new(),
            network,
            ByteLimit(1024),
        )
    };
    let host = bwrap_args(&spec(Network::Host), &["/run"]);
    for file in RESOLVER_FILES {
        assert!(has(&host, &["--ro-bind-try", file, file]), "{file}");
    }
    let none = bwrap_args(&spec(Network::Off), &["/run"]);
    assert!(!none.iter().any(|a| a == "--ro-bind-try"));
}

#[test]
fn an_overlay_is_a_read_only_mount_of_another_file_after_the_binds() {
    let binds = vec![Bind::new(abs("/home/u/.gemini"), Access::ReadWrite)];
    let with = run(AgentNet::None, binds).with_overlay(bulkhead::Overlay::new(
        abs("/run/d/settings.json"),
        abs("/home/u/.gemini/antigravity-acp/settings.json"),
    ));
    let args = agent_bwrap_args(&with, &["/home"]);
    let at = |seq: &[&str]| {
        args.windows(seq.len())
            .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
            .expect("present")
    };
    let state = at(&["--bind", "/home/u/.gemini", "/home/u/.gemini"]);
    let over = at(&[
        "--ro-bind",
        "/run/d/settings.json",
        "/home/u/.gemini/antigravity-acp/settings.json",
    ]);
    assert!(state < over);
}

/// Why: the terminal sandbox and the agent sandbox must not drift apart on the hardening flags
/// (namespaces, capabilities, read-only root, emptied directories); both begin with one prefix.
#[test]
fn the_terminal_and_the_agent_sandbox_begin_with_the_same_confinement() {
    let spec = RunSpec::new(
        Argv::new("true", &[]).expect("argv"),
        abs("/work/project"),
        Vec::new(),
        Network::Off,
        ByteLimit(1024),
    );
    let terminal = bwrap_args(&spec, &["/run", "/home"]);
    let agent = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &["/run", "/home"]);
    let prefix = [
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/home",
    ];
    for args in [&terminal, &agent] {
        assert!(
            args.iter()
                .map(String::as_str)
                .take(prefix.len())
                .eq(prefix)
        );
    }
}
