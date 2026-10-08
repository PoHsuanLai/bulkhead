//! The forwarder program, as a function so any binary can be it:
//! `NAME run --listen 127.0.0.1:<port> --socket <path> -- <program> [args...]`.
//!
//! Started by the sandbox as its first process (endpoint-only mode): listens on the given
//! loopback address, hands each connection to the unix socket, and runs the program with this
//! process's own stdio. Exits with the program's exit code. std only; it reaches nothing but
//! that socket.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

#[cfg_attr(not(unix), allow(dead_code))]
struct Args {
    listen: String,
    socket: PathBuf,
    program: Vec<String>,
}

#[cfg_attr(not(unix), allow(dead_code))]
fn parse(mut args: impl Iterator<Item = String>) -> Option<Args> {
    if args.next().as_deref() != Some("run") {
        return None;
    }
    let (mut listen, mut socket) = (None, None);
    loop {
        match args.next()?.as_str() {
            "--listen" => listen = Some(args.next()?),
            "--socket" => socket = Some(PathBuf::from(args.next()?)),
            "--" => break,
            _ => return None,
        }
    }
    let program: Vec<String> = args.collect();
    (!program.is_empty()).then_some(Args {
        listen: listen?,
        socket: socket?,
        program,
    })
}

/// The forwarder's `main`, reading this process's arguments; `name` is how it calls itself in
/// messages.
#[cfg(not(unix))]
pub fn forward_main(name: &str) -> ExitCode {
    eprintln!("{name} runs where bubblewrap does: on Linux");
    ExitCode::from(2)
}

/// The forwarder's `main`, reading this process's arguments; `name` is how it calls itself in
/// messages.
#[cfg(unix)]
pub fn forward_main(name: &str) -> ExitCode {
    use std::net::TcpListener;
    let Some(args) = parse(std::env::args().skip(1)) else {
        eprintln!("usage: {name} run --listen ADDR --socket PATH -- PROGRAM [ARGS]");
        return ExitCode::from(2);
    };
    let Ok(listener) = TcpListener::bind(&args.listen) else {
        eprintln!("{name}: cannot listen on {}", args.listen);
        return ExitCode::from(3);
    };
    let socket = args.socket;
    std::thread::spawn(move || crate::forward::forward(&listener, &socket));
    let status = Command::new(&args.program[0])
        .args(&args.program[1..])
        .status();
    match status {
        Ok(s) => ExitCode::from(u8::try_from(s.code().unwrap_or(1)).unwrap_or(1)),
        Err(_) => ExitCode::from(127),
    }
}
