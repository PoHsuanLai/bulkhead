//! The two ends of the endpoint-only network mode, std only. Inside the sandbox the forwarder
//! listens on a loopback port and hands each connection to one unix socket; outside, the bridge
//! listens on that socket and hands each connection to one loopback address. Both only copy
//! bytes; neither reads, logs or keeps them, and neither can be pointed anywhere else: the
//! forwarder's destination is a socket path, the bridge's a [`Loopback`].

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Connections served at once, per listener. A flood waits in the kernel's queue.
pub const MAX_LIVE: usize = 32;

/// A stream that can be copied in both directions at once.
pub trait Duplex: Read + Write + Send + Sized + 'static {
    /// A second handle on the same stream.
    fn dup(&self) -> io::Result<Self>;
    /// Tells the peer no more bytes are coming.
    fn finish(&self);
}

impl Duplex for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn finish(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

impl Duplex for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn finish(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

fn copy<A: Duplex, B: Duplex>(from: &mut A, to: &mut B) {
    let mut chunk = [0_u8; 16 * 1024];
    while let Ok(n) = from.read(&mut chunk) {
        if n == 0 || to.write_all(&chunk[..n]).is_err() {
            break;
        }
    }
    to.finish();
}

/// Copies `a` to `b` and `b` to `a` until both directions have ended.
pub fn splice<A: Duplex, B: Duplex>(a: A, b: B) {
    let (Ok(mut a_out), Ok(mut b_out)) = (a.dup(), b.dup()) else {
        return;
    };
    let (mut a_in, mut b_in) = (a, b);
    let back = std::thread::spawn(move || copy(&mut b_in, &mut a_out));
    copy(&mut a_in, &mut b_out);
    let _ = back.join();
}

/// A counter that keeps a listener from serving more than [`MAX_LIVE`] connections at once.
#[derive(Debug, Clone, Default)]
struct Live(Arc<AtomicUsize>);

impl Live {
    fn take(&self) -> Option<Held> {
        let before = self.0.fetch_add(1, Ordering::SeqCst);
        if before >= MAX_LIVE {
            self.0.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Held(self.0.clone()))
    }
}

struct Held(Arc<AtomicUsize>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Inside the sandbox: accepts on `listener` and splices each connection with a fresh connection
/// to the unix socket at `socket`. Runs until the listener fails (the process ends).
pub fn forward(listener: &TcpListener, socket: &Path) {
    let live = Live::default();
    for incoming in listener.incoming() {
        let Ok(client) = incoming else { continue };
        let Some(held) = live.take() else { continue };
        let Ok(upstream) = UnixStream::connect(socket) else {
            continue;
        };
        std::thread::spawn(move || {
            splice(client, upstream);
            drop(held);
        });
    }
}

/// The one address the bridge may reach: IPv4 loopback and a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loopback(SocketAddrV4);

/// A host that is not the IPv4 loopback address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the bridge reaches 127.0.0.1 and nothing else")]
pub struct NotLoopback;

impl Loopback {
    /// `host` and `port`, if the host is exactly `127.0.0.1`.
    pub fn new(host: &str, port: u16) -> Result<Self, NotLoopback> {
        match host.parse::<Ipv4Addr>() {
            Ok(ip) if ip == Ipv4Addr::LOCALHOST && port != 0 => {
                Ok(Self(SocketAddrV4::new(ip, port)))
            }
            _ => Err(NotLoopback),
        }
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.0.port()
    }
}

/// The host side: a unix socket whose every connection goes to one loopback address. Dropping it
/// stops accepting and removes the socket file.
#[derive(Debug)]
pub struct Bridge {
    path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Bridge {
    /// Listens on `path` (which must not exist) and bridges to `target`.
    pub fn start(path: &Path, target: Loopback) -> io::Result<Self> {
        let listener = UnixListener::bind(path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        // Detached: dropping the bridge wakes the thread and does not wait for it, so a bridge
        // dropped after its directory was removed cannot hang the caller.
        std::thread::spawn(move || {
            let live = Live::default();
            for incoming in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(client) = incoming else { continue };
                let Some(held) = live.take() else { continue };
                let Ok(upstream) = TcpStream::connect(SocketAddr::V4(target.0)) else {
                    continue;
                };
                std::thread::spawn(move || {
                    splice(client, upstream);
                    drop(held);
                });
            }
        });
        Ok(Self {
            path: path.to_owned(),
            stop,
        })
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // A connection wakes the blocked accept so the thread sees the flag.
        let _ = UnixStream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}
