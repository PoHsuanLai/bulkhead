//! `bulkhead-forward run --listen 127.0.0.1:<port> --socket <path> -- <program> [args...]`
//!
//! See [`bulkhead::cli::forward_main`].

fn main() -> std::process::ExitCode {
    bulkhead::cli::forward_main("bulkhead-forward")
}
