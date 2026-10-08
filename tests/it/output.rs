//! Output is bounded and redacted; the environment is rebuilt from an allowlist.

use bulkhead::{ByteLimit, Captured, Cut, MASK, Tail, redact, sandbox_env, shown};

fn names(env: &[bulkhead::EnvVar]) -> Vec<&str> {
    env.iter().map(|v| v.name.as_str()).collect()
}

#[test]
fn secrets_are_masked_and_ordinary_text_is_not() {
    let table = [
        ("API_TOKEN=abc123 ok", "API_TOKEN=[redacted] ok"),
        ("password: hunter2", "password: [redacted]"),
        ("--password=hunter2 x", "--password=[redacted] x"),
        (
            "Authorization: Bearer abc.def.ghi",
            "Authorization: [redacted]",
        ),
        (
            "curl -H 'Authorization: Bearer abc123'",
            "curl -H 'Authorization: [redacted]",
        ),
        (
            "key ghp_0123456789abcdefghijABCDEFGHIJ end",
            "key [redacted] end",
        ),
        ("AKIAIOSFODNN7EXAMPLE", "[redacted]"),
        (
            "https://me:s3cret@example.org/repo.git",
            "https://me:[redacted]@example.org/repo.git",
        ),
        ("https://example.org/a:b", "https://example.org/a:b"),
        ("the author said hello", "the author said hello"),
        ("compiling some-crate v0.1.0", "compiling some-crate v0.1.0"),
    ];
    for (input, want) in table {
        let got = redact(input);
        // Quote characters trailing a masked word go with it.
        assert!(
            got == want || got.starts_with(want.trim_end_matches('\'')),
            "{input:?} -> {got:?}, wanted {want:?}"
        );
    }
}

#[test]
fn a_private_key_block_is_dropped() {
    let text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nafter";
    assert_eq!(redact(text), format!("before\n{MASK}\nafter"));
}

#[test]
fn a_jwt_is_masked() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
    assert_eq!(redact(&format!("t {jwt}")), format!("t {MASK}"));
}

#[test]
fn the_tail_keeps_the_last_bytes_and_says_it_cut() {
    let mut tail = Tail::new(ByteLimit(10));
    tail.push(b"abcde");
    assert_eq!(tail.captured().cut, Cut::Whole);
    tail.push(b"fghijklmno");
    let got = tail.captured();
    assert_eq!(got.bytes, b"fghijklmno");
    assert_eq!(got.cut, Cut::Head);
}

#[test]
fn the_cap_cuts_at_a_character_boundary_from_the_start() {
    let captured = Captured {
        bytes: "ééééé".as_bytes().to_vec(),
        cut: Cut::Whole,
    };
    let got = shown(&captured, ByteLimit(5));
    assert_eq!(got.text, "éé");
    assert_eq!(got.cut, Cut::Head);
    let whole = shown(&captured, ByteLimit(100));
    assert_eq!(whole.text, "ééééé");
    assert_eq!(whole.cut, Cut::Whole);
}

#[test]
fn invalid_utf8_becomes_replacement_characters() {
    let captured = Captured {
        bytes: vec![b'a', 0xff, b'b'],
        cut: Cut::Whole,
    };
    assert_eq!(shown(&captured, ByteLimit(100)).text, "a\u{fffd}b");
}

#[test]
fn only_allowlisted_variables_survive_and_path_and_home_are_fixed() {
    let asked: Vec<(String, String)> = [
        ("HOME", "/home/me"),
        ("PATH", "/home/me/bin"),
        ("API_TOKEN", "hunter2"),
        ("LD_PRELOAD", "/tmp/x.so"),
        ("LANG", "en_US.UTF-8"),
        ("LC_TIME", "de_DE.UTF-8"),
        ("NO_COLOR", "1"),
        ("BAD NAME", "x"),
        ("TERM", "xterm\n"),
    ]
    .map(|(a, b)| (a.to_owned(), b.to_owned()))
    .to_vec();
    let env = sandbox_env(&asked);
    let mut got = names(&env);
    got.sort_unstable();
    assert_eq!(
        got,
        [
            "HOME", "LANG", "LC_TIME", "NO_COLOR", "PATH", "TERM", "TMPDIR"
        ]
    );
    let value = |n: &str| env.iter().find(|v| v.name == n).map(|v| v.value.as_str());
    assert_eq!(value("HOME"), Some("/tmp"));
    assert_eq!(value("PATH"), Some("/usr/local/bin:/usr/bin:/bin"));
    assert_eq!(value("LANG"), Some("en_US.UTF-8"));
    assert_eq!(
        value("TERM"),
        Some("dumb"),
        "a value with a control character is dropped"
    );
    let shown = format!("{env:?}");
    assert!(!shown.contains("en_US"), "Debug never prints a value");
}
