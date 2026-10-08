//! The environment a sandboxed command sees: cleared, then rebuilt. A fixed base, plus the few
//! variables an agent may choose (locale, terminal type, colour switches). The host's own
//! environment is never read here, so a secret in it cannot reach a command; a variable an agent
//! sends that is not on the list is dropped, so it cannot smuggle one in.

use crate::sandbox::EnvVar;

/// `PATH` inside the sandbox: the read-only system directories only.
pub const SANDBOX_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Where `HOME` and `TMPDIR` point: a fresh in-memory directory the sandbox mounts.
pub const SANDBOX_HOME: &str = "/tmp";

/// Names an agent may set.
const ALLOWED: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "TERM",
    "TZ",
    "COLORTERM",
    "NO_COLOR",
    "CLICOLOR",
    "CI",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "CARGO_TERM_COLOR",
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
];

/// The longest value kept.
const VALUE_MAX: usize = 1024;

fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn allowed(name: &str) -> bool {
    name_ok(name) && (ALLOWED.contains(&name) || name.starts_with("LC_"))
}

fn var(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

/// The environment for a command, given the variables the requester asked for. Later duplicates
/// win; `PATH` and `HOME` are never the requester's.
pub fn sandbox_env(requested: &[(String, String)]) -> Vec<EnvVar> {
    let mut env = vec![
        var("PATH", SANDBOX_PATH),
        var("HOME", SANDBOX_HOME),
        var("TMPDIR", SANDBOX_HOME),
        var("LANG", "C.UTF-8"),
        var("TERM", "dumb"),
    ];
    for (name, value) in requested {
        let fine =
            allowed(name) && value.len() <= VALUE_MAX && !value.chars().any(char::is_control);
        if !fine {
            continue;
        }
        env.retain(|v| &v.name != name);
        env.push(var(name, value));
    }
    env
}

/// The names of the variables an agent asked for that were dropped, for the caller to show.
pub fn dropped(requested: &[(String, String)]) -> Vec<String> {
    requested
        .iter()
        .filter(|(n, v)| !(allowed(n) && v.len() <= VALUE_MAX && !v.chars().any(char::is_control)))
        .map(|(n, _)| n.clone())
        .collect()
}
