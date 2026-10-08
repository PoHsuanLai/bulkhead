//! `AbsPath`: absolute, normalised, never stepping up.

use bulkhead::{AbsPath, PathFault, RootState};

#[test]
fn dots_and_doubled_slashes_fold_away() {
    let path = AbsPath::parse("/a//b/./c/").expect("path");
    assert_eq!(path.as_str(), "/a/b/c");
}

#[test]
fn relative_parent_and_control_are_refused() {
    assert_eq!(AbsPath::parse("a/b"), Err(PathFault::NotAbsolute));
    assert_eq!(AbsPath::parse("/a/../b"), Err(PathFault::ParentStep));
    assert_eq!(AbsPath::parse("/a\nb"), Err(PathFault::Control));
}

#[test]
fn only_slash_is_the_root() {
    assert_eq!(
        AbsPath::parse("/").expect("root").is_root(),
        RootState::Root
    );
    assert_eq!(AbsPath::parse("/a").expect("a").is_root(), RootState::Below);
}
