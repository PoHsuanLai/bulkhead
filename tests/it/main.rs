mod agent;
mod endpoint;
mod forward;
mod output;
mod path;
mod real;
mod shell;

/// Include guard: cargo compiles only the files `mod` reaches. A file in `tests/` or `tests/it/`
/// that no `mod` names is silently never run, so this fails and names it.
#[test]
fn every_test_file_is_declared_here() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let declared = include_str!("main.rs");
    let is_rs = |p: &std::path::Path| p.is_file() && p.extension().is_some_and(|e| e == "rs");
    let mut missing: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&tests).expect("tests dir") {
        let path = entry.expect("entry").path();
        if is_rs(&path) {
            missing.push(format!(
                "tests/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }
    for entry in std::fs::read_dir(tests.join("it")).expect("tests/it dir") {
        let path = entry.expect("entry").path();
        if !is_rs(&path) {
            continue;
        }
        let stem = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if stem != "main" && !declared.contains(&format!("mod {stem};")) {
            missing.push(format!("tests/it/{stem}.rs"));
        }
    }
    assert!(
        missing.is_empty(),
        "not reached by a `mod` in tests/it/main.rs: {missing:?}"
    );
}
