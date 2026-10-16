//! `bulkhead-enter [--read P]... [--write P]... [--device P]... NETWORK -- <program> [args...]`
//!
//! See [`bulkhead::enter::enter_main`].

fn main() -> std::process::ExitCode {
    bulkhead::enter::enter_main("bulkhead-enter")
}
