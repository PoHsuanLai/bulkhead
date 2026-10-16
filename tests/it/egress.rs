//! The egress policy and the filtering proxy: patterns, verdicts, request parsing as table rows,
//! and the proxy itself over a unix socket pair against a loopback listener, with names answered
//! by an injected resolver (no real DNS, no real network).

use bulkhead::egress::request::MAX_LINE;
use bulkhead::egress::{
    BadRequest, EgressPolicy, Entry, Gate, Host, HostFault, HostPattern, Journal, Outcome,
    PolicyFault, Ports, Refusal, Request, Resolver, Target, parse_head, read_head,
};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn pattern(text: &str) -> HostPattern {
    HostPattern::parse(text).expect("pattern")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn host(text: &str) -> Host {
    Host::parse(text).expect("host")
}

#[test]
fn patterns_parse_or_name_the_fault() {
    let ok = |text: &str, want: HostPattern| (text.to_owned(), Ok(want));
    let bad = |text: &str, fault: HostFault| (text.to_owned(), Err(fault));
    let long = format!("{}.com", "a".repeat(64));
    let rows = [
        ok(
            "api.example.com",
            HostPattern::Exact("api.example.com".into()),
        ),
        ok(
            "API.Example.COM.",
            HostPattern::Exact("api.example.com".into()),
        ),
        ok(
            "*.example.com",
            HostPattern::Subdomains("example.com".into()),
        ),
        ok(
            "*.Example.com.",
            HostPattern::Subdomains("example.com".into()),
        ),
        ok("192.0.2.7", HostPattern::Addr(ip("192.0.2.7"))),
        ok("[2001:db8::1]", HostPattern::Addr(ip("2001:db8::1"))),
        ok("::ffff:192.0.2.7", HostPattern::Addr(ip("192.0.2.7"))),
        bad("", HostFault::Empty),
        bad(".", HostFault::Empty),
        bad("*", HostFault::BareStar),
        bad("*.", HostFault::BareStar),
        bad("a*.example.com", HostFault::StarNotLeading),
        bad("foo.*.com", HostFault::StarNotLeading),
        bad("*.*.com", HostFault::StarNotLeading),
        bad("example.*", HostFault::StarNotLeading),
        bad("exa mple.com", HostFault::Whitespace),
        bad(" example.com", HostFault::Whitespace),
        bad("example.com\n", HostFault::Whitespace),
        bad("b\u{fc}cher.example", HostFault::NonAscii),
        bad("*.b\u{fc}cher.example", HostFault::NonAscii),
        bad("a..b", HostFault::EmptyLabel),
        bad(".example.com", HostFault::EmptyLabel),
        bad("exa/mple.com", HostFault::BadChar),
        bad("host:80", HostFault::BadChar),
        bad("example.123", HostFault::Numeric),
        bad("127.1", HostFault::Numeric),
        bad(&long, HostFault::TooLong),
    ];
    for (text, want) in rows {
        assert_eq!(HostPattern::parse(&text), want, "{text:?}");
    }
}

fn policy(allow: &[&str], deny: &[&str], ports: Ports) -> EgressPolicy {
    let list = |l: &[&str]| l.iter().map(|t| pattern(t)).collect();
    EgressPolicy::new(list(allow), list(deny), ports).expect("policy")
}

#[test]
fn a_policy_needs_an_allow_list_and_real_ports() {
    assert_eq!(
        EgressPolicy::new(Vec::new(), vec![pattern("a.example")], Ports::default()),
        Err(PolicyFault::NoAllow)
    );
    assert_eq!(Ports::new(Vec::new()), Err(PolicyFault::BadPorts));
    assert_eq!(Ports::new(vec![443, 0]), Err(PolicyFault::BadPorts));
    assert!(Ports::default().allows(443) && Ports::default().allows(80));
    assert!(!Ports::default().allows(22));
}

#[test]
fn verdicts_by_name_port_and_literal() {
    let p = policy(
        &[
            "api.example.com",
            "*.cdn.example.net",
            "*.evil.example.net",
            "203.0.113.9",
            "203.0.113.200",
        ],
        &["bad.cdn.example.net", "*.evil.example.net", "203.0.113.200"],
        Ports::default(),
    );
    let rows: Vec<(&str, u16, Result<(), Refusal>)> = vec![
        ("api.example.com", 443, Ok(())),
        ("api.example.com", 80, Ok(())),
        ("API.EXAMPLE.COM.", 443, Ok(())),
        ("api.example.com", 22, Err(Refusal::Port)),
        ("api.example.com", 8443, Err(Refusal::Port)),
        ("example.com", 443, Err(Refusal::NotListed)),
        ("www.api.example.com", 443, Err(Refusal::NotListed)),
        ("x.cdn.example.net", 443, Ok(())),
        ("a.b.cdn.example.net", 443, Ok(())),
        ("cdn.example.net", 443, Err(Refusal::NotListed)),
        ("xcdn.example.net", 443, Err(Refusal::NotListed)),
        ("bad.cdn.example.net", 443, Err(Refusal::Denied)),
        ("x.evil.example.net", 443, Err(Refusal::Denied)),
        ("203.0.113.9", 443, Ok(())),
        ("198.51.100.1", 443, Err(Refusal::NotListed)),
        ("[::1]", 443, Err(Refusal::NotListed)),
        ("127.0.0.1", 443, Err(Refusal::NotListed)),
        ("203.0.113.200", 443, Err(Refusal::Denied)),
        ("203.0.113.9", 22, Err(Refusal::Port)),
        ("::ffff:203.0.113.9", 443, Ok(())),
        ("localhost", 443, Err(Refusal::NotListed)),
        ("1.example.org", 443, Err(Refusal::NotListed)),
    ];
    for (name, port, want) in rows {
        assert_eq!(p.check(&host(name), port), want, "{name}:{port}");
    }
    let other = policy(&["a.example"], &[], Ports::new(vec![8443]).expect("ports"));
    assert_eq!(other.check(&host("a.example"), 8443), Ok(()));
    assert_eq!(other.check(&host("a.example"), 443), Err(Refusal::Port));
}

#[test]
fn addresses_in_special_ranges_are_refused_unless_listed_exactly() {
    let p = policy(
        &["api.example.com", "10.0.0.5", "fd00::5", "203.0.113.200"],
        &["203.0.113.200"],
        Ports::default(),
    );
    let special = [
        "127.0.0.1",
        "127.9.9.9",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "239.255.255.255",
        "255.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "240.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "febf::1",
        "fec0::1",
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
    ];
    for addr in special {
        assert_eq!(
            p.check_addr(ip(addr)),
            Err(Refusal::SpecialAddress),
            "{addr}"
        );
    }
    let fine = [
        "8.8.8.8",
        "1.1.1.1",
        "100.63.255.255",
        "100.128.0.1",
        "172.15.0.1",
        "172.32.0.1",
        "192.0.2.1",
        "2606:4700::1111",
        "::ffff:8.8.8.8",
        "10.0.0.5",
        "fd00::5",
        "::ffff:10.0.0.5",
    ];
    for addr in fine {
        assert_eq!(p.check_addr(ip(addr)), Ok(()), "{addr}");
    }
    assert_eq!(p.check_addr(ip("203.0.113.200")), Err(Refusal::Denied));
}

fn target(name: &str, port: u16) -> Target {
    Target {
        host: host(name),
        port,
    }
}

#[test]
fn request_heads_parse_or_name_the_fault() {
    let long = format!(
        "GET http://{}.example.com/ HTTP/1.1\r\n\r\n",
        "a".repeat(MAX_LINE)
    );
    let tunnel = |name, port| Ok(Request::Tunnel(target(name, port)));
    let relay = |name, port| Ok(Request::Relay(target(name, port)));
    let rows: Vec<(String, Result<Request, BadRequest>)> = vec![
        (
            "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n".into(),
            tunnel("api.example.com", 443),
        ),
        (
            "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n".into(),
            tunnel("2001:db8::1", 8443),
        ),
        (
            "GET http://API.example.com/a/b?c=d HTTP/1.1\r\nHost: api.example.com\r\n\r\n".into(),
            relay("api.example.com", 80),
        ),
        (
            "GET http://api.example.com:8080/ HTTP/1.1\r\n\r\n".into(),
            relay("api.example.com", 8080),
        ),
        (
            "POST HTTP://api.example.com HTTP/1.0\r\n\r\n".into(),
            relay("api.example.com", 80),
        ),
        (
            "GET http://[::1]/ HTTP/1.1\r\n\r\n".into(),
            relay("::1", 80),
        ),
        (
            "CONNECT api.example.com HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadPort),
        ),
        (
            "CONNECT api.example.com:0 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadPort),
        ),
        (
            "CONNECT api.example.com:99999 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadPort),
        ),
        (
            "CONNECT api.example.com:+80 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadPort),
        ),
        (
            "CONNECT api.example.com: HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadPort),
        ),
        (
            "CONNECT :443 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::NoHost),
        ),
        (
            "GET http:///x HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::NoHost),
        ),
        (
            "CONNECT ::1:443 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "CONNECT [::1]x HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "CONNECT [::1:443 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "CONNECT bad!host:443 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadHost(HostFault::BadChar)),
        ),
        (
            "CONNECT 127.1:80 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::BadHost(HostFault::Numeric)),
        ),
        (
            "GET /path HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::NotProxy),
        ),
        (
            "GET https://api.example.com/ HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::NotProxy),
        ),
        (
            "GET http://user@api.example.com/ HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::NotProxy),
        ),
        (
            "GET http://api.example.com/ HTTP/2\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "get http://api.example.com/ HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "GET http://api.example.com/\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        (
            "CONNECT a b:443 HTTP/1.1\r\n\r\n".into(),
            Err(BadRequest::Malformed),
        ),
        ("garbage\r\n\r\n".into(), Err(BadRequest::Malformed)),
        (String::new(), Err(BadRequest::Malformed)),
        (long, Err(BadRequest::TooLong)),
    ];
    for (head, want) in rows {
        let shown: String = head.chars().take(60).collect();
        assert_eq!(parse_head(head.as_bytes()), want, "{shown:?}");
    }
    assert_eq!(
        parse_head(b"GET \xff HTTP/1.1\r\n\r\n"),
        Err(BadRequest::Malformed)
    );
}

#[test]
fn reading_a_head_is_bounded_in_size_and_time() {
    // Early bytes after the blank line stay in `bytes`, past `end`.
    let (mut near, mut far) = UnixStream::pair().expect("pair");
    let text = "CONNECT h.example:443 HTTP/1.1\r\n\r\n";
    near.write_all(format!("{text}EARLY").as_bytes())
        .expect("write");
    let head = read_head(&mut far, Duration::from_secs(5)).expect("head");
    assert_eq!(&head.bytes[..head.end], text.as_bytes());
    assert!(b"EARLY".starts_with(&head.bytes[head.end..]));

    let (mut near, mut far) = UnixStream::pair().expect("pair");
    near.write_all(&vec![b'a'; MAX_LINE + 10]).expect("write");
    assert_eq!(
        read_head(&mut far, Duration::from_secs(5)),
        Err(BadRequest::TooLong)
    );

    let (mut near, mut far) = UnixStream::pair().expect("pair");
    let line = "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
    near.write_all(b"GET http://a.example/ HTTP/1.1\r\n")
        .expect("write");
    // One write: many small ones each cost a socket buffer slot and fill it before anyone reads.
    near.write_all(line.repeat(600).as_bytes()).expect("write");
    assert_eq!(
        read_head(&mut far, Duration::from_secs(5)),
        Err(BadRequest::TooLong)
    );

    let (near, mut far) = UnixStream::pair().expect("pair");
    drop(near);
    assert_eq!(
        read_head(&mut far, Duration::from_secs(5)),
        Err(BadRequest::Closed)
    );

    let (mut near, mut far) = UnixStream::pair().expect("pair");
    near.write_all(b"GET http://a").expect("write");
    drop(near);
    assert_eq!(
        read_head(&mut far, Duration::from_secs(5)),
        Err(BadRequest::Truncated)
    );

    let (mut near, mut far) = UnixStream::pair().expect("pair");
    near.write_all(b"GET http://a").expect("write");
    assert_eq!(
        read_head(&mut far, Duration::from_millis(150)),
        Err(BadRequest::Timeout)
    );
    drop(near);
}

/// Answers from a table and counts the lookups; a name not in it fails.
#[derive(Debug, Default)]
struct Table {
    rows: Vec<(&'static str, Vec<IpAddr>)>,
    calls: AtomicUsize,
}

impl Resolver for Table {
    fn resolve(&self, name: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.rows
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, a)| a.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
    }
}

#[derive(Debug, Default)]
struct Recorder(Mutex<Vec<Entry>>);

impl Journal for Recorder {
    fn record(&self, entry: &Entry) {
        self.0.lock().expect("lock").push(entry.clone());
    }
}

struct Rig {
    gate: Gate,
    table: Arc<Table>,
    journal: Arc<Recorder>,
}

fn rig(port: u16) -> Rig {
    let table = Arc::new(Table {
        rows: vec![
            ("files.example.test", vec![ip("127.0.0.1")]),
            ("rebind.example.test", vec![ip("10.0.0.9")]),
            ("mixed.example.test", vec![ip("8.8.8.8"), ip("10.0.0.9")]),
        ],
        calls: AtomicUsize::new(0),
    });
    let journal = Arc::new(Recorder::default());
    let allow = [
        "files.example.test",
        "rebind.example.test",
        "mixed.example.test",
        "gone.example.test",
        // The stand-in server lives on the loopback; only this exact address may be reached.
        "127.0.0.1",
    ];
    let p = policy(&allow, &[], Ports::new(vec![port]).expect("ports"));
    let gate = Gate::new(p, table.clone(), journal.clone());
    Rig {
        gate,
        table,
        journal,
    }
}

fn timed(stream: &UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
}

fn listener() -> Option<(TcpListener, u16)> {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIP egress proxy test: no loopback here");
        return None;
    };
    let port = listener.local_addr().expect("addr").port();
    Some((listener, port))
}

#[test]
fn a_connect_tunnel_reaches_the_resolved_address_and_carries_early_bytes() {
    let Some((server, port)) = listener() else {
        return;
    };
    let rig = rig(port);
    let echo = std::thread::spawn(move || {
        let (mut conn, _) = server.accept().expect("accept");
        let mut buf = [0_u8; 4];
        conn.read_exact(&mut buf).expect("read");
        conn.write_all(&buf).expect("echo");
    });
    let (mut near, far) = UnixStream::pair().expect("pair");
    timed(&near);
    let gate = rig.gate.clone();
    let worker = std::thread::spawn(move || gate.serve(far));
    near.write_all(format!("CONNECT files.example.test:{port} HTTP/1.1\r\n\r\nping").as_bytes())
        .expect("write");
    let want = "HTTP/1.1 200 Connection established\r\n\r\n";
    let mut got = vec![0_u8; want.len()];
    near.read_exact(&mut got).expect("established");
    assert_eq!(got, want.as_bytes());
    let mut echoed = [0_u8; 4];
    near.read_exact(&mut echoed).expect("echo");
    assert_eq!(&echoed, b"ping");
    drop(near);
    echo.join().expect("server");
    worker.join().expect("serve ends");
    assert_eq!(rig.table.calls.load(Ordering::SeqCst), 1, "resolved once");
    let entries = rig.journal.0.lock().expect("lock").clone();
    assert_eq!(
        entries,
        [Entry {
            target: Some(target("files.example.test", port)),
            outcome: Outcome::Tunnelled
        }]
    );
}

#[test]
fn a_plain_request_is_forwarded_unchanged() {
    let Some((server, port)) = listener() else {
        return;
    };
    let rig = rig(port);
    let request = format!(
        "GET http://files.example.test:{port}/x?y=1 HTTP/1.1\r\nHost: files.example.test\r\n\r\n"
    );
    let seen = std::thread::spawn(move || {
        let (mut conn, _) = server.accept().expect("accept");
        let mut got = Vec::new();
        let mut chunk = [0_u8; 256];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut chunk).expect("read");
            assert!(n > 0, "the request ended early");
            got.extend_from_slice(&chunk[..n]);
        }
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("reply");
        got
    });
    let (mut near, far) = UnixStream::pair().expect("pair");
    timed(&near);
    let gate = rig.gate.clone();
    let worker = std::thread::spawn(move || gate.serve(far));
    near.write_all(request.as_bytes()).expect("write");
    let mut reply = String::new();
    near.read_to_string(&mut reply).expect("reply");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply:?}");
    assert!(reply.ends_with("ok"));
    drop(near);
    assert_eq!(seen.join().expect("server"), request.as_bytes());
    worker.join().expect("serve ends");
    assert_eq!(rig.table.calls.load(Ordering::SeqCst), 1, "resolved once");
}

#[test]
fn refusals_answer_in_plain_text_and_never_connect() {
    // The listener is never accepted on: a connect that got through would still succeed in the
    // kernel's queue, so the journal is what proves the verdict.
    let Some((_server, port)) = listener() else {
        return;
    };
    let rig = rig(port);
    let rows: Vec<(String, &str, Option<&str>, Outcome)> = vec![
        (
            format!("CONNECT other.example.test:{port} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            Some("other.example.test"),
            Outcome::Refused(Refusal::NotListed),
        ),
        (
            "CONNECT files.example.test:22 HTTP/1.1\r\n\r\n".to_owned(),
            "HTTP/1.1 403 Forbidden",
            Some("files.example.test:22"),
            Outcome::Refused(Refusal::Port),
        ),
        (
            format!("CONNECT 10.0.0.1:{port} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            Some("10.0.0.1"),
            Outcome::Refused(Refusal::NotListed),
        ),
        (
            format!("CONNECT rebind.example.test:{port} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            Some("rebind.example.test"),
            Outcome::Refused(Refusal::SpecialAddress),
        ),
        (
            format!("GET http://mixed.example.test:{port}/ HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            Some("mixed.example.test"),
            Outcome::Refused(Refusal::SpecialAddress),
        ),
        (
            format!("CONNECT gone.example.test:{port} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 502 Bad Gateway",
            Some("gone.example.test"),
            Outcome::Unreachable,
        ),
        (
            "GET /path HTTP/1.1\r\n\r\n".to_owned(),
            "HTTP/1.1 400 Bad Request",
            None,
            Outcome::Malformed,
        ),
        (
            "garbage\r\n\r\n".to_owned(),
            "HTTP/1.1 400 Bad Request",
            None,
            Outcome::Malformed,
        ),
    ];
    let mut want_outcomes = Vec::new();
    for (request, status, names, outcome) in rows {
        let (mut near, far) = UnixStream::pair().expect("pair");
        timed(&near);
        let gate = rig.gate.clone();
        let worker = std::thread::spawn(move || gate.serve(far));
        near.write_all(request.as_bytes()).expect("write");
        let mut reply = String::new();
        near.read_to_string(&mut reply).expect("reply");
        worker.join().expect("serve ends");
        let first = request.lines().next().unwrap_or_default();
        assert!(reply.starts_with(status), "{first:?}: {reply:?}");
        let (_, body) = reply.split_once("\r\n\r\n").expect("body");
        if let Some(name) = names {
            assert!(body.contains(name), "{first:?}: {body:?}");
        }
        want_outcomes.push(outcome);
    }
    let got: Vec<Outcome> = rig
        .journal
        .0
        .lock()
        .expect("lock")
        .iter()
        .map(|e| e.outcome)
        .collect();
    assert_eq!(got, want_outcomes);
}
