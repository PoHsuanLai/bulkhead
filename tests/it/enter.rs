//! The exec stage's words (built and parsed strictly), its report line, and how the bubblewrap
//! arguments carry it. Nothing here needs a kernel with Landlock.

use bulkhead::{
    AbsPath, Access, AgentNet, AgentRun, Argv, Bind, EndpointBind, EnterFault, EnterPlan, EnvVar,
    INSIDE_ENTER, INSIDE_FORWARDER, LandlockLevel, NetRule, Overlay, PathFault, Profile,
    agent_bwrap_args,
};

fn abs(text: &str) -> AbsPath {
    AbsPath::parse(text).expect("abs")
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| (*w).to_owned()).collect()
}

#[test]
fn the_words_round_trip_through_the_parser() {
    let plans = [
        EnterPlan::new(Vec::new(), Vec::new(), Vec::new(), NetRule::NoTcp),
        EnterPlan::new(
            vec![abs("/usr"), abs("/etc")],
            vec![abs("/work/project")],
            vec![abs("/dev")],
            NetRule::Unfiltered,
        ),
        EnterPlan::new(
            vec![abs("/usr")],
            vec![abs("/tmp"), abs("/var/tmp")],
            Vec::new(),
            NetRule::ConnectTo(40123),
        ),
    ];
    for plan in plans {
        let mut line = plan.words();
        assert_eq!(line.last().map(String::as_str), Some("--"), "{plan:?}");
        line.extend(words(&["agent", "--", "--net-none"]));
        let (back, program) = EnterPlan::parse(line).expect("parse");
        assert_eq!(back, plan);
        assert_eq!(program, words(&["agent", "--", "--net-none"]));
    }
}

#[test]
fn the_parser_refuses_what_it_does_not_know() {
    let bad = |w: &[&str], fault: EnterFault| (words(w), fault);
    let rows = [
        bad(
            &["--bogus", "--net-none", "--", "a"],
            EnterFault::UnknownWord("--bogus".into()),
        ),
        bad(&["--net-none", "a"], EnterFault::UnknownWord("a".into())),
        bad(&["--read"], EnterFault::MissingValue("--read")),
        bad(&["--write"], EnterFault::MissingValue("--write")),
        bad(&["--device"], EnterFault::MissingValue("--device")),
        bad(
            &["--net-connect"],
            EnterFault::MissingValue("--net-connect"),
        ),
        bad(
            &["--read", "relative", "--net-none", "--", "a"],
            EnterFault::BadPath(PathFault::NotAbsolute),
        ),
        bad(
            &["--write", "/a/../b", "--net-none", "--", "a"],
            EnterFault::BadPath(PathFault::ParentStep),
        ),
        bad(&["--read", "/", "--net-none", "--", "a"], EnterFault::Root),
        bad(&["--write", "/", "--net-none", "--", "a"], EnterFault::Root),
        bad(
            &["--device", "/.", "--net-none", "--", "a"],
            EnterFault::Root,
        ),
        bad(
            &["--net-connect", "0", "--", "a"],
            EnterFault::BadPort("0".into()),
        ),
        bad(
            &["--net-connect", "70000", "--", "a"],
            EnterFault::BadPort("70000".into()),
        ),
        bad(
            &["--net-connect", "+80", "--", "a"],
            EnterFault::BadPort("+80".into()),
        ),
        bad(
            &["--net-connect", "http", "--", "a"],
            EnterFault::BadPort("http".into()),
        ),
        bad(&[], EnterFault::NoSeparator),
        bad(&["--net-none"], EnterFault::NoSeparator),
        bad(&["--read", "/usr", "--net-none"], EnterFault::NoSeparator),
        bad(
            &["--net-none", "--net-unfiltered", "--", "a"],
            EnterFault::TwoNets,
        ),
        bad(
            &["--net-none", "--net-none", "--", "a"],
            EnterFault::TwoNets,
        ),
        bad(
            &["--net-none", "--net-connect", "80", "--", "a"],
            EnterFault::TwoNets,
        ),
        bad(&["--read", "/usr", "--", "a"], EnterFault::NoNet),
        bad(&["--net-none", "--"], EnterFault::NoProgram),
    ];
    for (line, fault) in rows {
        assert_eq!(EnterPlan::parse(line.clone()), Err(fault), "{line:?}");
    }
    let (plan, _) = EnterPlan::parse(words(&["--read", "/a//b/.", "--net-none", "--", "x"]))
        .expect("normalised");
    assert_eq!(plan.read, [abs("/a/b")]);
}

#[test]
fn the_report_line_names_the_level_and_nothing_else_is_one() {
    let rows = [
        (LandlockLevel::Full, "bulkhead-enter: landlock=full"),
        (
            LandlockLevel::FilesOnly,
            "bulkhead-enter: landlock=files-only",
        ),
        (LandlockLevel::None, "bulkhead-enter: landlock=none"),
    ];
    for (level, line) in rows {
        assert_eq!(level.report_line(), line);
        assert_eq!(LandlockLevel::from_report_line(line), Some(level));
        assert_eq!(
            LandlockLevel::from_report_line(&format!("{line}\n")),
            Some(level)
        );
    }
    for other in [
        "",
        "landlock=full",
        "bulkhead-enter: landlock=",
        "bulkhead-enter: landlock=partial",
        "bulkhead-enter: landlock=full extra",
        "xbulkhead-enter: landlock=full",
    ] {
        assert_eq!(LandlockLevel::from_report_line(other), None, "{other:?}");
    }
}

fn landlocked(net: AgentNet) -> AgentRun {
    let env = vec![EnvVar {
        name: "HOME".to_owned(),
        value: "/home/u".to_owned(),
    }];
    let argv = Argv::new("claude-agent-acp", &["--stdio".to_owned()]).expect("argv");
    AgentRun::new(argv, abs("/work/project"), env, net)
        .with_bind(Bind::new(abs("/home/u/.local/node"), Access::ReadOnly))
        .with_bind(Bind::new(abs("/home/u/.claude"), Access::ReadWrite))
        .with_overlay(Overlay::new(
            abs("/work/cfg/settings.json"),
            abs("/home/u/.claude/settings.json"),
        ))
        .with_landlock(abs("/opt/bulkhead/bulkhead-enter"))
}

fn has(args: &[String], seq: &[&str]) -> bool {
    args.windows(seq.len())
        .any(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

#[test]
fn the_exec_stage_starts_the_agent_and_its_plan_names_what_bubblewrap_mounts() {
    let bind = EndpointBind::new(
        abs("/opt/bulkhead/bulkhead-forward"),
        abs("/run/user/1000/bulkhead/ep.sock"),
        40123,
    );
    let modes = [
        (AgentNet::None, NetRule::NoTcp),
        (AgentNet::Host, NetRule::Unfiltered),
        (AgentNet::Endpoint(bind.clone()), NetRule::ConnectTo(40123)),
        (AgentNet::Allowlist(bind), NetRule::ConnectTo(40123)),
    ];
    for (net, want_net) in modes {
        let name = format!("{net:?}");
        let args = agent_bwrap_args(&landlocked(net.clone()), &Profile::bare());
        assert!(
            has(
                &args,
                &["--ro-bind", "/opt/bulkhead/bulkhead-enter", INSIDE_ENTER]
            ),
            "{name}: stage bound read-only"
        );
        // The last mention is the command; the first is the bind.
        let at = args.iter().rposition(|a| a == INSIDE_ENTER).expect("stage");
        let (plan, program) = EnterPlan::parse(args[at + 1..].to_vec()).expect("plan parses");
        assert_eq!(program, words(&["claude-agent-acp", "--stdio"]), "{name}");
        assert_eq!(plan.net, want_net, "{name}: network rule");
        assert_eq!(plan.device, [abs("/dev")], "{name}");
        assert_eq!(
            plan.write,
            [
                abs("/work/project"),
                abs("/tmp"),
                abs("/var/tmp"),
                abs("/dev/shm"),
                abs("/home/u/.claude")
            ],
            "{name}: writable places"
        );
        for path in [
            "/usr",
            "/etc",
            "/proc",
            "/home/u/.local/node",
            "/home/u/.claude/settings.json",
        ] {
            assert!(plan.read.contains(&abs(path)), "{name}: reads {path}");
        }
        // Every readable place is a read-only mount, and every writable one a writable mount or
        // fresh scratch: the plan cannot name what bubblewrap does not show.
        for path in plan.read.iter().filter(|p| p.as_str() != "/proc") {
            let p = path.as_str();
            let mounted = args
                .windows(3)
                .any(|w| matches!(w[0].as_str(), "--ro-bind" | "--ro-bind-try") && w[2] == p);
            assert!(mounted, "{name}: {p} is a read-only mount");
        }
        let scratch = ["/tmp", "/var/tmp", "/dev/shm"];
        for path in plan.write.iter().filter(|p| !scratch.contains(&p.as_str())) {
            let p = path.as_str();
            assert!(
                args.windows(3).any(|w| w[0] == "--bind" && w[2] == p),
                "{name}: {p} is a writable mount"
            );
        }
        // The forwarder starts first, then the stage, then the agent.
        match want_net {
            NetRule::ConnectTo(_) => {
                let f = args
                    .iter()
                    .rposition(|a| a == INSIDE_FORWARDER)
                    .expect("forwarder");
                assert!(f < at, "{name}: forwarder first");
            }
            _ => assert!(!args.iter().any(|a| a == INSIDE_FORWARDER), "{name}: none"),
        }
    }
}

#[test]
fn without_the_stage_nothing_changes() {
    let env = Vec::new();
    let argv = Argv::new("agent", &[]).expect("argv");
    let run = AgentRun::new(argv, abs("/work/project"), env, AgentNet::None);
    let args = agent_bwrap_args(&run, &Profile::bare());
    assert!(!args.iter().any(|a| a == INSIDE_ENTER));
    assert_eq!(args.last().map(String::as_str), Some("agent"));
}
