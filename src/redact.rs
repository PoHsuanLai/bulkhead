//! Redaction of obvious secrets from command output, a pure function. It is a net with large
//! holes, not a guarantee: it catches assignments to secret-looking names, well-known token
//! shapes, `Bearer` credentials, credentials inside URLs and in their query strings, `--password`
//! style flags, `name = value` with spaces, whole `Cookie:` lines, and private-key blocks (PGP
//! too). Not caught: short flags such as `-p x`, and secrets with no name or shape. The sandbox keeps
//! the environment and the home directory out of reach; this is the second line.

/// What replaces a secret.
pub const MASK: &str = "[redacted]";

/// Names whose values are secrets (matched on the lower-cased name).
const SECRET_NAMES: &[&str] = &[
    "secret",
    "token",
    "passwd",
    "password",
    "passphrase",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "private_key",
    "privatekey",
    "authorization",
    "cookie",
    "access_key",
];

/// Prefixes of well-known tokens, with the shortest length that counts.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk-", 20),
    ("sk_live_", 16),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 20),
    ("glpat-", 16),
    ("xoxb-", 16),
    ("xoxp-", 16),
    ("xoxa-", 16),
    ("AIza", 30),
    ("AKIA", 16),
];

fn secret_name(name: &str) -> bool {
    let lower = name
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .to_ascii_lowercase();
    !lower.is_empty() && SECRET_NAMES.iter().any(|s| lower.contains(s))
}

fn token_shaped(word: &str) -> bool {
    let w =
        word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.');
    let prefixed = TOKEN_PREFIXES
        .iter()
        .any(|(p, min)| w.starts_with(p) && w.len() >= *min);
    let jwt = w.starts_with("eyJ") && w.len() >= 30 && w.matches('.').count() == 2;
    prefixed || jwt
}

/// `scheme://user:pass@host` with the password masked.
fn url_password(word: &str) -> Option<String> {
    let (scheme, rest) = word.split_once("://")?;
    let (authority, tail) = rest
        .split_once('/')
        .map_or((rest, None), |(a, t)| (a, Some(t)));
    let (info, host) = authority.rsplit_once('@')?;
    let (user, _) = info.split_once(':')?;
    let tail = tail.map(|t| format!("/{t}")).unwrap_or_default();
    Some(format!("{scheme}://{user}:{MASK}@{host}{tail}"))
}

/// What the next word is, given the words before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Plain,
    /// The next word is a credential.
    SecretFollows,
    /// A secret-looking name with no separator: if `=` or `:` comes next, the word after that
    /// is the value (`password = x`).
    NameFollows,
    /// A `--password`-style flag: the next word is its value, unless it is itself a flag.
    FlagFollows,
    /// Every word to the end of the line (a `Cookie:` header holds many pairs).
    RestOfLine,
}

/// Authorization schemes: the scheme word stays, the credential after it is masked.
const AUTH_SCHEMES: &[&str] = &["bearer", "basic"];

/// `https://host/path?api_key=abc&x=1` with the values of secret-looking parameters masked.
fn query_secrets(w: &str) -> Option<String> {
    let (base, query) = w.split_once('?')?;
    let mut changed = false;
    let parts: Vec<String> = query
        .split('&')
        .map(|p| match p.split_once('=') {
            Some((name, value)) if secret_name(name) && !value.is_empty() => {
                changed = true;
                format!("{name}={MASK}")
            }
            _ => p.to_owned(),
        })
        .collect();
    changed.then(|| format!("{base}?{}", parts.join("&")))
}

fn word(w: &str, prev: Next) -> (String, Next) {
    match prev {
        Next::RestOfLine => return (MASK.to_owned(), Next::RestOfLine),
        Next::FlagFollows if !w.starts_with('-') => return (MASK.to_owned(), Next::Plain),
        Next::NameFollows if w == "=" || w == ":" => return (w.to_owned(), Next::SecretFollows),
        _ => {}
    }
    // Before the credential check, so `Authorization: Bearer <token>` masks the token, not the
    // scheme word.
    if AUTH_SCHEMES.iter().any(|s| w.eq_ignore_ascii_case(s)) {
        return (w.to_owned(), Next::SecretFollows);
    }
    if prev == Next::SecretFollows || token_shaped(w) {
        return (MASK.to_owned(), Next::Plain);
    }
    if let Some(masked) = url_password(w) {
        return (masked, Next::Plain);
    }
    if let Some(masked) = query_secrets(w) {
        return (masked, Next::Plain);
    }
    let split = w.find(['=', ':']).filter(|&i| i > 0);
    if let Some(i) = split {
        let (name, value) = (&w[..i], &w[i + 1..]);
        if secret_name(name) && !value.starts_with("//") {
            if value.is_empty() {
                let rest = name.to_ascii_lowercase().contains("cookie");
                let next = if rest {
                    Next::RestOfLine
                } else {
                    Next::SecretFollows
                };
                return (w.to_owned(), next);
            }
            return (format!("{}{}", &w[..=i], MASK), Next::Plain);
        }
    } else if secret_name(w) {
        let next = if w.starts_with('-') {
            Next::FlagFollows
        } else {
            Next::NameFollows
        };
        return (w.to_owned(), next);
    }
    (w.to_owned(), Next::Plain)
}

fn line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut next = Next::Plain;
    let mut rest = text;
    while !rest.is_empty() {
        let space = rest.starts_with(char::is_whitespace);
        let end = rest
            .find(|c: char| c.is_whitespace() != space)
            .unwrap_or(rest.len());
        let (run, tail) = rest.split_at(end);
        if space {
            out.push_str(run);
        } else {
            let (shown, after) = word(run, next);
            out.push_str(&shown);
            next = after;
        }
        rest = tail;
    }
    out
}

/// `text` with secrets masked. Private-key blocks are dropped to one masked line.
pub fn redact(text: &str) -> String {
    let mut out = Vec::new();
    let mut in_key = false;
    for l in text.split('\n') {
        if in_key {
            in_key = !l.contains("-----END ");
            continue;
        }
        if l.contains("-----BEGIN ") && l.contains("PRIVATE KEY") {
            in_key = !l.contains("-----END ");
            out.push(MASK.to_owned());
            continue;
        }
        out.push(line(l));
    }
    out.join("\n")
}
