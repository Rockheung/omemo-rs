//! OMEMO 0.3 MUC fan-out (P3-5).
//!
//! Three daemons join a MUC; alice sends an OMEMO 0.3 group
//! message; bob and carol receive + decrypt. Mirrors the
//! existing daemon.rs MUC test but pins the backend to oldmemo
//! on every send + refresh.
//!
//! `#[ignore]` — needs the ejabberd fixture.

#![cfg(test)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const RUST_CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");
const ROOM: &str = "muc-old@conference.localhost";

struct Daemon {
    child: Child,
    stdin: ChildStdin,
    events_rx: mpsc::Receiver<Value>,
}

impl Daemon {
    fn spawn(store_dir: &Path, jid: &str, password: &str, device_id: u32) -> Self {
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
    fn send(&mut self, cmd: Value) {
        let mut s = cmd.to_string();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
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
}

#[test]
#[ignore = "P3-5 OMEMO 0.3 MUC fan-out; requires the XMPP fixture"]
fn oldmemo_groupchat_fans_out_across_occupants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a_dir = dir.path().join("a");
    let b_dir = dir.path().join("b");
    let c_dir = dir.path().join("c");

    let mut bob = Daemon::spawn(&b_dir, "old_b@localhost", "oldbpass", 95002);
    bob.expect("ready", 30);
    let mut carol = Daemon::spawn(&c_dir, "old_c@localhost", "oldcpass", 95003);
    carol.expect("ready", 30);
    let mut alice = Daemon::spawn(&a_dir, "old_a@localhost", "oldapass", 95001);
    alice.expect("ready", 30);

    let join = |d: &mut Daemon, nick: &str| {
        d.send(serde_json::json!({
            "op": "join_muc",
            "room": ROOM,
            "nick": nick,
            "id": format!("j-{nick}"),
        }));
        let joined = d.expect("muc_joined", 15);
        assert_eq!(joined.get("room").and_then(|v| v.as_str()), Some(ROOM));
    };
    join(&mut bob, "bob");
    join(&mut carol, "carol");
    join(&mut alice, "alice");

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

    // Pin the backend to oldmemo for every step.
    alice.send(serde_json::json!({
        "op":"refresh_muc","room":ROOM,"backend":"oldmemo","id":"r1",
    }));
    let refreshed = alice.expect("muc_refreshed", 15);
    let occupants = refreshed
        .get("occupants")
        .and_then(|v| v.as_array())
        .expect("occupants array");
    assert_eq!(
        occupants.len(),
        2,
        "expected 2 occupants in refresh; got: {refreshed}"
    );

    alice.send(serde_json::json!({
        "op":"send_muc","room":ROOM,"body":"hello via oldmemo","backend":"oldmemo","id":"g1",
    }));
    let sent = alice.expect("sent", 15);
    assert_eq!(sent.get("backend").and_then(|v| v.as_str()), Some("oldmemo"));

    let bob_msg = bob.expect("muc_message", 20);
    assert_eq!(
        bob_msg.get("body").and_then(|v| v.as_str()),
        Some("hello via oldmemo")
    );
    assert_eq!(
        bob_msg.get("backend").and_then(|v| v.as_str()),
        Some("oldmemo"),
        "inbound MUC message should be tagged as oldmemo backend"
    );

    let carol_msg = carol.expect("muc_message", 20);
    assert_eq!(
        carol_msg.get("body").and_then(|v| v.as_str()),
        Some("hello via oldmemo")
    );

    alice.shutdown();
    bob.shutdown();
    carol.shutdown();
}
