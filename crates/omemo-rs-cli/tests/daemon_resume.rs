//! XEP-0198 stream resumption (P3-6).
//!
//! Inserts a TCP proxy between the daemon and ejabberd, drops
//! the proxied connections mid-conversation, and asserts that
//! after the daemon's tokio-xmpp worker reconnects (transparent
//! to the user-facing Stream) we observe a `reconnected`
//! event — proving the daemon stayed alive across a TCP-level
//! disconnect and the SM negotiation path actually fires.
//!
//! What the test does NOT assert:
//!   * `resumed: true` specifically. Whether SM resume succeeds
//!     depends on ejabberd's mod_stream_mgmt config and how
//!     long it holds the SmState. We accept either resume or
//!     fresh-bind here — both prove the daemon recovered.
//!
//! `#[ignore]` — needs the ejabberd fixture.

#![cfg(test)]

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const RUST_CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");

struct Daemon {
    child: Child,
    stdin: ChildStdin,
    events_rx: mpsc::Receiver<Value>,
}

impl Daemon {
    fn spawn(store_dir: &Path, jid: &str, password: &str, device_id: u32, server: &str) -> Self {
        let mut child = Command::new(RUST_CLI)
            .env("OMEMO_RS_STORE_DIR", store_dir)
            .args([
                "--jid",
                jid,
                "--password",
                password,
                "--insecure-tcp",
                server,
                "daemon",
                "--device-id",
                &device_id.to_string(),
                "--opk-count",
                "10",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<Value>();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if tx.send(v).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            stdin,
            events_rx: rx,
        }
    }
    fn shutdown(mut self) {
        let _ = self.stdin.write_all(b"{\"op\":\"shutdown\"}\n");
        drop(self.stdin);
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() > until => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => return,
            }
        }
    }
    fn expect(&self, name: &str, secs: u64) -> Value {
        let until = Instant::now() + Duration::from_secs(secs);
        loop {
            let r = until.saturating_duration_since(Instant::now());
            if r.is_zero() {
                panic!("timeout waiting for {name}");
            }
            match self.events_rx.recv_timeout(r) {
                Ok(v) => {
                    if v.get("event").and_then(|e| e.as_str()) == Some(name) {
                        return v;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("timeout waiting for {name}");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("channel closed before {name}");
                }
            }
        }
    }
}

/// Test-only TCP proxy. Always accepts new connections (so the
/// daemon's reconnect after a snap can re-traverse the proxy).
/// `snap()` shuts down every pump pair currently in flight.
struct TcpProxy {
    local: SocketAddr,
    pairs: Arc<Mutex<Vec<(std::net::TcpStream, std::net::TcpStream)>>>,
    accept_running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TcpProxy {
    fn start(local_port: u16, remote: &str) -> Self {
        let pairs: Arc<Mutex<Vec<(std::net::TcpStream, std::net::TcpStream)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let accept_running = Arc::new(AtomicBool::new(true));
        let local: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
        let listener = std::net::TcpListener::bind(local).expect("bind proxy");
        listener.set_nonblocking(true).unwrap();
        let remote = remote.to_string();
        let pairs_t = pairs.clone();
        let running = accept_running.clone();

        let handle = thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let server = match std::net::TcpStream::connect(&remote) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        // Track the pair so snap() can shutdown both halves
                        let client_for_pump = client.try_clone().unwrap();
                        let server_for_pump = server.try_clone().unwrap();
                        pairs_t.lock().unwrap().push((client, server));
                        thread::spawn(move || pump_one(client_for_pump, server_for_pump));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            local,
            pairs,
            accept_running,
            handle: Some(handle),
        }
    }
    fn local_addr(&self) -> String {
        self.local.to_string()
    }
    fn snap(&self) {
        let mut pairs = self.pairs.lock().unwrap();
        for (a, b) in pairs.drain(..) {
            let _ = a.shutdown(std::net::Shutdown::Both);
            let _ = b.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn pump_one(a: std::net::TcpStream, b: std::net::TcpStream) {
    let a_clone = a.try_clone().unwrap();
    let b_clone = b.try_clone().unwrap();
    let h1 = thread::spawn(move || one_way(a, b_clone));
    let h2 = thread::spawn(move || one_way(b, a_clone));
    let _ = h1.join();
    let _ = h2.join();
}

fn one_way(mut from: std::net::TcpStream, mut to: std::net::TcpStream) {
    use std::io::Read;
    let mut buf = [0u8; 4096];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.accept_running.store(false, Ordering::Relaxed);
        self.snap();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
#[ignore = "P3-6 stream resumption; requires the XMPP fixture"]
fn daemon_emits_reconnected_after_tcp_snap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proxy_port = pick_port();
    let proxy = TcpProxy::start(proxy_port, "127.0.0.1:5222");

    let alice = Daemon::spawn(
        &dir.path().join("a"),
        "resume_a@localhost",
        "resumeapass",
        96001,
        &proxy.local_addr(),
    );
    alice.expect("ready", 30);

    // Snap the existing TCP pair the daemon's xmpp worker is on.
    // The accept loop stays alive so the daemon's auto-reconnect
    // (with optional XEP-0198 resume) finds the proxy on the
    // next attempt.
    proxy.snap();

    // Wait up to 30s for the Reconnected event. The exact value
    // of `resumed` depends on ejabberd's mod_stream_mgmt and
    // how quickly the daemon reattaches; we accept either path.
    let until = Instant::now() + Duration::from_secs(30);
    let mut got: Option<Value> = None;
    while Instant::now() < until {
        let remaining = until.saturating_duration_since(Instant::now());
        if let Ok(ev) = alice.events_rx.recv_timeout(remaining) {
            if ev.get("event").and_then(|v| v.as_str()) == Some("reconnected") {
                got = Some(ev);
                break;
            }
        }
    }

    let ev = got.expect("daemon should emit `reconnected` after the TCP snap");
    let jid = ev
        .get("jid")
        .and_then(|v| v.as_str())
        .expect("reconnected.jid present");
    // tokio-xmpp's bound_jid is full (`bare/resource`); we just
    // care that the bare half matches our login JID.
    assert!(
        jid.starts_with("resume_a@localhost"),
        "expected reconnected.jid to start with `resume_a@localhost`; got: {jid}"
    );
    // resumed is a bool (either path is acceptable for this test)
    assert!(
        ev.get("resumed").and_then(|v| v.as_bool()).is_some(),
        "reconnected event should carry a boolean `resumed` field; got: {ev}"
    );

    alice.shutdown();
}

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}
