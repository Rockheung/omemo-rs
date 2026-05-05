//! Spawn `omemo-rs-cli daemon` as a child process and drive it
//! through its JSON Lines stdio protocol. Two scenarios:
//!
//! * `alice_send_bob_recv_via_daemon` — 1:1 OMEMO 2 round-trip.
//! * `three_way_muc_via_daemon`       — alice sends one MUC
//!   message; bob and carol both decrypt to the same body.
//!
//! Both are `#[ignore]` and require the ejabberd fixture to be up:
//!
//!     docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d
//!     cargo test -p omemo-rs-cli --test daemon -- --ignored
//!
//! Uses pre-registered `muc_a` / `muc_b` / `muc_c` accounts (same
//! group as the omemo-pep MUC integration tests) so it doesn't
//! collide with the cross-impl interop suite.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const RUST_CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");
const ROOM: &str = "daemon-it@conference.localhost";

struct Daemon {
    child: Child,
    stdin: ChildStdin,
    events_rx: mpsc::Receiver<Value>,
    log_path: std::path::PathBuf,
}

impl Daemon {
    fn spawn(store_dir: &Path, jid: &str, password: &str, device_id: u32) -> Self {
        std::fs::create_dir_all(store_dir).expect("create store dir");
        let log_path = store_dir.join(format!("{jid}.daemon.err.log"));
        let stderr_log = std::fs::File::create(&log_path).expect("stderr log");
        let mut child = Command::new(RUST_CLI)
            .env("OMEMO_RS_STORE_DIR", store_dir)
            .args([
                "--jid",
                jid,
                "--password",
                password,
                "--insecure-tcp",
                "127.0.0.1:5222",
                "daemon",
                "--device-id",
                &device_id.to_string(),
                "--opk-count",
                "20",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr_log)
            .spawn()
            .expect("spawn daemon");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel::<Value>();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { return };
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if tx.send(value).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            stdin,
            events_rx: rx,
            log_path,
        }
    }

    fn send(&mut self, cmd: Value) {
        let mut s = cmd.to_string();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).expect("write stdin");
        self.stdin.flush().expect("flush");
    }

    /// Wait up to `deadline_secs` for an event whose `event` field
    /// matches `name`. Returns the matching event or panics.
    fn expect_event(&self, name: &str, deadline_secs: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(deadline_secs);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!(
                    "timed out waiting for event '{name}' on daemon (log: {:?})",
                    self.log_path
                );
            }
            match self.events_rx.recv_timeout(remaining) {
                Ok(v) => {
                    if v.get("event").and_then(|e| e.as_str()) == Some(name) {
                        return v;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("timed out waiting for event '{name}' (log: {:?})", self.log_path);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("daemon stdout closed unexpectedly (log: {:?})", self.log_path);
                }
            }
        }
    }

    fn shutdown(mut self) {
        let _ = self.send_no_panic(serde_json::json!({"op":"shutdown"}));
        // Closing stdin gives the daemon's stdin_reader an EOF
        // signal even if the shutdown line never arrived (write
        // races). Drop it explicitly so the next steps don't have
        // to wait for the connection's async flush.
        drop(self.stdin);
        // Bound the wait — `client.send_end()` inside the daemon
        // can block on a slow ack from the server. 10s is plenty.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        return;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return,
            }
        }
    }

    fn send_no_panic(&mut self, cmd: Value) -> std::io::Result<()> {
        let mut s = cmd.to_string();
        s.push('\n');
        self.stdin.write_all(s.as_bytes())?;
        self.stdin.flush()
    }
}

fn pre_register(store_dir: &Path, jid: &str, password: &str, device_id: u32) {
    // One-shot daemon spawn just to install identity + publish PEP
    // bundles. Each test gets a fresh tempdir, so we always need to
    // run this once per JID.
    let d = Daemon::spawn(store_dir, jid, password, device_id);
    d.expect_event("ready", 30);
    d.shutdown();
}

#[test]
#[ignore = "Stage 9 daemon protocol; requires the XMPP fixture on 127.0.0.1:5222"]
fn alice_send_bob_recv_via_daemon() {
    let dir = tempfile::tempdir().expect("tempdir");
    let alice_dir = dir.path().join("alice");
    let bob_dir = dir.path().join("bob");
    pre_register(&alice_dir, "muc_a@localhost", "mucapass", 91001);
    pre_register(&bob_dir, "muc_b@localhost", "mucbpass", 91002);

    // Bob long-lived
    let bob = Daemon::spawn(&bob_dir, "muc_b@localhost", "mucbpass", 91002);
    bob.expect_event("ready", 30);

    // Alice sends one body, then exits
    let mut alice = Daemon::spawn(&alice_dir, "muc_a@localhost", "mucapass", 91001);
    alice.expect_event("ready", 30);
    alice.send(serde_json::json!({
        "op": "send",
        "peer": "muc_b@localhost",
        "device": 91002,
        "backend": "twomemo",
        "body": "hello bob from daemon-it",
        "id": "send-1"
    }));
    let sent = alice.expect_event("sent", 15);
    assert_eq!(sent.get("id").and_then(|v| v.as_str()), Some("send-1"));

    // Bob should receive the decrypted message
    let msg = bob.expect_event("message", 15);
    assert_eq!(
        msg.get("body").and_then(|v| v.as_str()),
        Some("hello bob from daemon-it")
    );
    assert_eq!(
        msg.get("from").and_then(|v| v.as_str()),
        Some("muc_a@localhost")
    );
    assert_eq!(msg.get("device").and_then(|v| v.as_u64()), Some(91001));

    alice.shutdown();
    bob.shutdown();
}

#[test]
#[ignore = "Stage 9 daemon protocol; requires the XMPP fixture on 127.0.0.1:5222"]
fn three_way_muc_via_daemon() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a_dir = dir.path().join("alice");
    let b_dir = dir.path().join("bob");
    let c_dir = dir.path().join("carol");
    pre_register(&a_dir, "muc_e@localhost", "mucepass", 92001);
    pre_register(&b_dir, "muc_f@localhost", "mucfpass", 92002);
    pre_register(&c_dir, "muc_g@localhost", "mucgpass", 92003);

    let mut bob = Daemon::spawn(&b_dir, "muc_f@localhost", "mucfpass", 92002);
    bob.expect_event("ready", 30);
    let mut carol = Daemon::spawn(&c_dir, "muc_g@localhost", "mucgpass", 92003);
    carol.expect_event("ready", 30);
    let mut alice = Daemon::spawn(&a_dir, "muc_e@localhost", "mucepass", 92001);
    alice.expect_event("ready", 30);

    let join = |d: &mut Daemon, nick: &str| {
        d.send(serde_json::json!({
            "op": "join_muc",
            "room": ROOM,
            "nick": nick,
            "id": format!("j-{nick}"),
        }));
        let joined = d.expect_event("muc_joined", 15);
        assert_eq!(
            joined.get("room").and_then(|v| v.as_str()),
            Some(ROOM)
        );
    };
    join(&mut bob, "bob");
    join(&mut carol, "carol");
    join(&mut alice, "alice");

    // Wait for alice to see both bob and carol enter (presence echo)
    let mut saw_bob = false;
    let mut saw_carol = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while !(saw_bob && saw_carol) && Instant::now() < deadline {
        let event = alice
            .events_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("alice event timeout");
        if event.get("event").and_then(|v| v.as_str()) == Some("muc_occupant_joined") {
            match event.get("nick").and_then(|v| v.as_str()) {
                Some("bob") => saw_bob = true,
                Some("carol") => saw_carol = true,
                _ => {}
            }
        }
    }
    assert!(saw_bob && saw_carol, "alice didn't see both occupants");

    // Snapshot occupant devicelists
    alice.send(serde_json::json!({"op":"refresh_muc","room":ROOM,"id":"r1"}));
    let refreshed = alice.expect_event("muc_refreshed", 15);
    let occupants = refreshed
        .get("occupants")
        .and_then(|v| v.as_array())
        .expect("occupants array");
    assert_eq!(occupants.len(), 2, "expected 2 occupants in refresh");

    alice.send(serde_json::json!({
        "op": "send_muc",
        "room": ROOM,
        "body": "hello room from daemon-it",
        "id": "g1",
    }));
    alice.expect_event("sent", 15);

    let bob_msg = bob.expect_event("muc_message", 20);
    assert_eq!(
        bob_msg.get("body").and_then(|v| v.as_str()),
        Some("hello room from daemon-it")
    );
    assert_eq!(
        bob_msg.get("from_real_jid").and_then(|v| v.as_str()),
        Some("muc_e@localhost")
    );
    let carol_msg = carol.expect_event("muc_message", 20);
    assert_eq!(
        carol_msg.get("body").and_then(|v| v.as_str()),
        Some("hello room from daemon-it")
    );

    alice.shutdown();
    bob.shutdown();
    carol.shutdown();
}
