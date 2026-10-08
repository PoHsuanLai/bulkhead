//! Redaction of obvious secrets from command output, a pure function. It is a net with large
//! holes, not a guarantee: it catches assignments to secret-looking names, well-known token
//! shapes, `Bearer` credentials, credentials inside URLs and private-key blocks. The sandbox keeps
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

/// What a word is, given the word before it.
enum Next {
    Plain,
    SecretFollows,
}

fn word(w: &str, after_credential: bool) -> (String, Next) {
    if after_credential || token_shaped(w) {
        return (MASK.to_owned(), Next::Plain);
    }
    if let Some(masked) = url_password(w) {
        return (masked, Next::Plain);
    }
    let split = w.find(['=', ':']).filter(|&i| i > 0);
    if let Some(i) = split {
        let (name, value) = (&w[..i], &w[i + 1..]);
        if secret_name(name) && !value.starts_with("//") {
            if value.is_empty() {
                return (w.to_owned(), Next::SecretFollows);
            }
            return (format!("{}{}", &w[..=i], MASK), Next::Plain);
        }
    }
    if w.eq_ignore_ascii_case("bearer") {
        return (w.to_owned(), Next::SecretFollows);
    }
    (w.to_owned(), Next::Plain)
}

fn line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut follows = false;
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
            let (shown, next) = word(run, follows);
            out.push_str(&shown);
            follows = matches!(next, Next::SecretFollows);
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
        if l.contains("-----BEGIN ") && l.contains("PRIVATE KEY-----") {
            in_key = !l.contains("-----END ");
            out.push(MASK.to_owned());
            continue;
        }
        out.push(line(l));
    }
    out.join("\n")
}
