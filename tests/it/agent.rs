//! The agent process's bubblewrap arguments, as plain strings.

use bulkhead::AbsPath;
use bulkhead::{
    Access, AgentNet, AgentRun, Argv, Bind, ByteLimit, EndpointBind, EnvVar, INSIDE_FORWARDER,
    INSIDE_SOCKET, Network, NetworkMode, Profile, RESOLVER_FILES, RunSpec, agent_bwrap_args,
    bwrap_args,
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
    let args = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &Profile::bare());
    assert!(has(&args, &["--unshare-all"]));
    assert!(!args.iter().any(|a| a == "--share-net"));
    assert!(has(&args, &["--cap-drop", "ALL"]));
    // The environment is not in the arguments, so a key in it is not on a command line.
    assert!(!args.iter().any(|a| a == "--setenv" || a == "/home/u"));
    assert!(has(&args, &["--bind", "/work/project", "/work/project"]));
    // The root is an allow-list: /usr is there, /home is not mentioned at all.
    assert!(has(&args, &["--ro-bind", "/usr", "/usr"]));
    assert!(!args.iter().any(|a| a == "/home" || a == "/"));
    assert_eq!(args.last().map(String::as_str), Some("--stdio"));
}

/// Only host mode shares the host network, and it binds back the resolver files. Steps:
/// "host shares the network", "host binds the resolver files", then the None run has neither.
#[test]
fn host_mode_shares_the_network_and_binds_back_only_the_resolver_files() {
    // /etc/resolv.conf is often a link into /run, which the sandbox empties: without these the
    // agent has the network but cannot resolve a name.
    let host = agent_bwrap_args(&run(AgentNet::Host, Vec::new()), &Profile::bare());
    assert!(has(&host, &["--share-net"]), "step host shares the network");
    for file in RESOLVER_FILES {
        assert!(
            has(&host, &["--ro-bind-try", file, file]),
            "step host resolver binds: {file}"
        );
    }
    let run_dir = host.windows(2).position(|w| w == ["--tmpfs", "/run"]);
    let bind = host
        .windows(3)
        .position(|w| w == ["--ro-bind-try", RESOLVER_FILES[0], RESOLVER_FILES[0]]);
    assert!(
        run_dir.is_some() && run_dir < bind,
        "step host binds: the binds come after /run is emptied"
    );
    let none = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &Profile::bare());
    assert!(
        !none.iter().any(|a| a == "--share-net"),
        "step none: no shared network"
    );
    assert!(
        !has(
            &none,
            &["--ro-bind-try", RESOLVER_FILES[0], RESOLVER_FILES[0]]
        ),
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
    let args = agent_bwrap_args(&run(AgentNet::Endpoint(bind), Vec::new()), &Profile::bare());
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
    let args = agent_bwrap_args(&run(AgentNet::None, binds), &Profile::bare());
    let at = |seq: &[&str]| {
        args.windows(seq.len())
            .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
            .expect("present")
    };
    let hide = at(&["--proc", "/proc"]);
    let ro = at(&["--ro-bind", "/home/u/.local/node", "/home/u/.local/node"]);
    let rw = at(&["--bind", "/home/u/.claude", "/home/u/.claude"]);
    assert!(hide < ro && ro < rw);
}

#[test]
fn a_mode_and_its_endpoint_must_agree() {
    let bind = EndpointBind::new(abs("/opt/f"), abs("/run/s"), 1);
    for mode in [NetworkMode::EndpointOnly, NetworkMode::Allowlist] {
        assert!(AgentNet::of(mode, None).is_err(), "{mode:?} needs a bind");
        let plan = AgentNet::of(mode, Some(bind.clone())).expect("plan");
        assert_eq!(plan.mode(), mode);
        assert_eq!(plan.port(), Some(1));
    }
    for mode in [NetworkMode::None, NetworkMode::Host] {
        assert!(
            AgentNet::of(mode, Some(bind.clone())).is_err(),
            "{mode:?} takes none"
        );
        assert_eq!(AgentNet::of(mode, None).expect("plan").mode(), mode);
    }
    assert_eq!(NetworkMode::default(), NetworkMode::None);
}

/// The allow-list mode is the endpoint-only wiring (same forwarder, same socket, own namespace)
/// plus the proxy variables, which replace anything the caller gave under those names; no other
/// mode adds any.
#[test]
fn the_allow_list_mode_wires_the_forwarder_and_sets_the_proxy_variables() {
    let bind = EndpointBind::new(abs("/opt/f"), abs("/run/s"), 3128);
    let only = run(AgentNet::Endpoint(bind.clone()), Vec::new());
    let list = run(AgentNet::Allowlist(bind.clone()), Vec::new());
    let profile = Profile::bare();
    assert_eq!(
        agent_bwrap_args(&only, &profile),
        agent_bwrap_args(&list, &profile)
    );
    assert!(
        !agent_bwrap_args(&list, &profile)
            .iter()
            .any(|a| a == "--share-net")
    );

    let given = vec![
        EnvVar {
            name: "HTTPS_PROXY".to_owned(),
            value: "http://elsewhere:1".to_owned(),
        },
        EnvVar {
            name: "HOME".to_owned(),
            value: "/home/u".to_owned(),
        },
    ];
    let argv = Argv::new("agent", &[]).expect("argv");
    let with = AgentRun::new(argv, abs("/work/project"), given, AgentNet::Allowlist(bind));
    let get = |name: &str| {
        let all: Vec<&EnvVar> = with.env.iter().filter(|v| v.name == name).collect();
        assert!(all.len() <= 1, "{name} once");
        all.first().map(|v| v.value.clone())
    };
    let url = Some("http://127.0.0.1:3128".to_owned());
    for name in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
        assert_eq!(get(name), url, "{name}");
    }
    for name in ["NO_PROXY", "no_proxy"] {
        assert_eq!(get(name), Some(String::new()), "{name}");
    }
    assert_eq!(
        get("HOME"),
        Some("/home/u".to_owned()),
        "other variables stay"
    );
    for net in [AgentNet::None, AgentNet::Host] {
        assert_eq!(net.proxy_env(), Vec::new(), "{net:?}");
    }
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
    let host = bwrap_args(&spec(Network::Host), &Profile::bare());
    for file in RESOLVER_FILES {
        assert!(has(&host, &["--ro-bind-try", file, file]), "{file}");
    }
    let none = bwrap_args(&spec(Network::Off), &Profile::bare());
    assert!(!has(
        &none,
        &["--ro-bind-try", RESOLVER_FILES[0], RESOLVER_FILES[0]]
    ));
}

#[test]
fn an_overlay_is_a_read_only_mount_of_another_file_after_the_binds() {
    let binds = vec![Bind::new(abs("/home/u/.gemini"), Access::ReadWrite)];
    let with = run(AgentNet::None, binds).with_overlay(bulkhead::Overlay::new(
        abs("/run/d/settings.json"),
        abs("/home/u/.gemini/antigravity-acp/settings.json"),
    ));
    let args = agent_bwrap_args(&with, &Profile::bare());
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
/// (namespaces, capabilities, the allow-list root); both begin with one prefix.
#[test]
fn the_terminal_and_the_agent_sandbox_begin_with_the_same_confinement() {
    let spec = RunSpec::new(
        Argv::new("true", &[]).expect("argv"),
        abs("/work/project"),
        Vec::new(),
        Network::Off,
        ByteLimit(1024),
    );
    let terminal = bwrap_args(&spec, &Profile::bare());
    let agent = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &Profile::bare());
    let prefix = [
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
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

/// Why: a scratch directory defaults to half of RAM, so each one needs its own size cap, and the
/// cap must come right before the `--tmpfs` it applies to.
#[test]
fn every_scratch_directory_gets_its_own_size_cap() {
    let profile = Profile::bare().with_tmpfs_size(bulkhead::Bytes::mib(8));
    let args = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &profile);
    for dir in ["/tmp", "/run"] {
        assert!(has(&args, &["--size", "8388608", "--tmpfs", dir]), "{dir}");
    }
}

/// Why: a protected path (a `.git` directory) must come after the writable workspace bind, or
/// the workspace would cover it. Steps: a real directory is bound read-only after the workspace,
/// a missing one and a symlink are skipped, and a path outside the workspace is refused.
#[test]
fn a_protected_path_is_bound_read_only_after_the_workspace() {
    let root = tempfile::tempdir().expect("scratch");
    let cwd = root.path().join("proj");
    std::fs::create_dir_all(cwd.join(".git")).expect("git dir");
    std::os::unix::fs::symlink("/etc", cwd.join("link")).expect("link");
    let cwd_text = cwd.to_str().expect("utf8");
    let inside = |name: &str| abs(&format!("{cwd_text}/{name}"));
    let base = AgentRun::new(
        Argv::new("agent", &[]).expect("argv"),
        abs(cwd_text),
        Vec::new(),
        AgentNet::None,
    );
    let with = base
        .clone()
        .with_protect(inside(".git"))
        .and_then(|r| r.with_protect(inside("missing")))
        .and_then(|r| r.with_protect(inside("link")))
        .expect("inside the workspace");
    let args = agent_bwrap_args(&with, &Profile::bare());
    let at = |seq: &[&str]| {
        args.windows(seq.len())
            .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
    };
    let git = format!("{cwd_text}/.git");
    let workspace = at(&["--bind", cwd_text, cwd_text]).expect("workspace");
    let protect = at(&["--ro-bind", &git, &git]).expect("step bound: .git");
    assert!(workspace < protect, "step order: after the workspace");
    assert_eq!(
        args.iter().filter(|a| a.starts_with(cwd_text)).count(),
        2 + 2 + 1,
        "step skipped: only the workspace, .git and --chdir show up"
    );
    for bad in [
        cwd_text.to_owned(),
        "/etc".to_owned(),
        format!("{cwd_text}x/y"),
    ] {
        assert_eq!(
            base.clone().with_protect(abs(&bad)).err(),
            Some(bulkhead::ProtectFault::OutsideCwd),
            "step refused: {bad}"
        );
    }
}

#[test]
fn the_seccomp_profile_hands_bubblewrap_descriptor_three() {
    let on = agent_bwrap_args(
        &run(AgentNet::None, Vec::new()),
        &Profile::bare().with_seccomp(),
    );
    assert!(has(&on, &["--seccomp", "3"]));
    let off = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &Profile::bare());
    assert!(!off.iter().any(|a| a == "--seccomp"));
}

/// Why: the root is an allow-list. Secrets under `/etc` are covered only where the host has them
/// (a bind over a missing path would fail), `/opt` is opt-in, and extra paths come last.
#[test]
fn the_root_is_an_allow_list_with_covered_secrets_and_an_escape_hatch() {
    let profile = Profile::bare()
        .covering_secrets_where(|p| p == "/etc/shadow" || p == "/etc/ssh")
        .with_opt(bulkhead::OptDir::ReadOnly)
        .with_extra_ro(abs("/nix"));
    let args = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &profile);
    for seq in [
        &["--ro-bind", "/usr", "/usr"][..],
        &["--ro-bind-try", "/etc", "/etc"],
        &["--ro-bind-try", "/lib64", "/lib64"],
        &["--ro-bind", "/dev/null", "/etc/shadow"],
        &["--tmpfs", "/etc/ssh"],
        &["--ro-bind-try", "/opt", "/opt"],
        &["--ro-bind", "/nix", "/nix"],
        &["--tmpfs", "/tmp"],
        &["--tmpfs", "/run"],
    ] {
        assert!(has(&args, seq), "{seq:?}");
    }
    assert!(!has(&args, &["--ro-bind", "/dev/null", "/etc/sudoers"]));
    for gone in [
        "/home", "/root", "/mnt", "/media", "/srv", "/boot", "/sys", "/var/lib",
    ] {
        assert!(!args.iter().any(|a| a == gone), "{gone}");
    }
    let bare = agent_bwrap_args(&run(AgentNet::None, Vec::new()), &Profile::bare());
    assert!(!has(&bare, &["--ro-bind-try", "/opt", "/opt"]));
}
