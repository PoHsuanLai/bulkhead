//! The forwarder and the bridge: bytes in, the same bytes out, to one destination only. They use
//! unix socket pairs, and the loopback only where it exists (a locked-down build jail may have none).

use bulkhead::forward::{Bridge, Loopback, splice};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;

#[test]
fn splice_copies_both_ways_and_passes_the_end() {
    let (mut near, a) = UnixStream::pair().expect("pair");
    let (b, mut far) = UnixStream::pair().expect("pair");
    let worker = std::thread::spawn(move || splice(a, b));
    near.write_all(b"request").expect("write");
    near.shutdown(std::net::Shutdown::Write).expect("shutdown");
    let mut got = String::new();
    far.read_to_string(&mut got).expect("read");
    assert_eq!(got, "request");
    far.write_all(b"reply").expect("write");
    far.shutdown(std::net::Shutdown::Write).expect("shutdown");
    let mut back = String::new();
    near.read_to_string(&mut back).expect("read");
    assert_eq!(back, "reply");
    worker.join().expect("splice ends");
}

#[test]
fn the_bridge_reaches_the_ipv4_loopback_and_nothing_else() {
    for host in [
        "localhost",
        "::1",
        "0.0.0.0",
        "192.168.1.1",
        "127.0.0.2",
        "example.org",
        "",
    ] {
        assert!(Loopback::new(host, 8080).is_err(), "{host:?}");
    }
    assert!(Loopback::new("127.0.0.1", 0).is_err());
    assert_eq!(Loopback::new("127.0.0.1", 8080).expect("ok").port(), 8080);
}

#[test]
fn a_connection_to_the_bridge_socket_reaches_the_loopback_listener() {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIP bridge test: no loopback here");
        return;
    };
    let port = listener.local_addr().expect("addr").port();
    let dir = tempfile::tempdir().expect("scratch");
    let socket = dir.path().join("ep.sock");
    let bridge = Bridge::start(&socket, Loopback::new("127.0.0.1", port).expect("loopback"))
        .expect("bridge");
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0_u8; 4];
        conn.read_exact(&mut buf).expect("read");
        conn.write_all(&buf).expect("echo");
    });
    let mut client = UnixStream::connect(&socket).expect("connect");
    client.write_all(b"ping").expect("write");
    let mut back = [0_u8; 4];
    client.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"ping");
    server.join().expect("server");
    drop(bridge);
    assert!(!socket.exists(), "the socket file goes with the bridge");
}
