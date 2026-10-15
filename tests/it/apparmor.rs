//! Why a refused user namespace is refused: the AppArmor switch, read from a scratch file.

use bulkhead::{CannotSandbox, namespaces_refused, refusal_at};

#[test]
fn the_switch_decides_the_reason() {
    let table = [
        (Some("1\n"), CannotSandbox::RestrictedByAppArmor),
        (Some("1"), CannotSandbox::RestrictedByAppArmor),
        (Some("0\n"), CannotSandbox::NamespacesDenied),
        (Some(""), CannotSandbox::NamespacesDenied),
        (Some("garbage"), CannotSandbox::NamespacesDenied),
        (None, CannotSandbox::NamespacesDenied),
    ];
    for (text, want) in table {
        assert_eq!(namespaces_refused(text), want, "switch {text:?}");
    }
}

#[test]
fn the_switch_file_is_read_from_the_path_given() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("restrict");
    assert_eq!(refusal_at(&file), CannotSandbox::NamespacesDenied);
    std::fs::write(&file, "1\n").expect("write");
    assert_eq!(refusal_at(&file), CannotSandbox::RestrictedByAppArmor);
    std::fs::write(&file, "0\n").expect("write");
    assert_eq!(refusal_at(&file), CannotSandbox::NamespacesDenied);
}

#[test]
fn the_apparmor_reason_says_what_to_do() {
    let words = CannotSandbox::RestrictedByAppArmor.to_string();
    assert!(words.contains("AppArmor"));
    assert!(words.contains("apparmor_restrict_unprivileged_userns"));
}
