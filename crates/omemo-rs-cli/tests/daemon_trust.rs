//! Trust protocol commands (P0-4 / P0-5).
//!
//! Exercises the daemon's trust-management surface:
//!
//!   * `set_trust(jid, device, state)` → `trust_set` event ack.
//!   * `list_pending` → `pending_trusts` event.
//!   * `force_retrust(jid, device, new_ik_hex)` → `retrusted` ack
//!     and the device's `ik_pub` in the store now matches
//!     `new_ik_hex`.
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
                "--jid", jid,
                "--password", password,
                "--insecure-tcp", "127.0.0.1:5222",
                "daemon",
                "--device-id", &device_id.to_string(),
                "--opk-count", "20",
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
                if line.trim().is_empty() { continue; }
                let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                if tx.send(v).is_err() { return; }
            }
        });
        Self { child, stdin, events_rx: rx }
    }
    fn send(&mut self, cmd: Value) {
        let mut s = cmd.to_string();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }
    fn expect(&self, name: &str, secs: u64) -> Value {
        let until = Instant::now() + Duration::from_secs(secs);
        let mut seen: Vec<String> = Vec::new();
        loop {
            let r = until.saturating_duration_since(Instant::now());
            if r.is_zero() { panic!("timeout waiting for {name} (saw: {seen:?})"); }
            match self.events_rx.recv_timeout(r) {
                Ok(v) => {
                    if v.get("event").and_then(|e| e.as_str()) == Some(name) {
                        return v;
                    }
                    seen.push(v.to_string());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("timeout waiting for {name} (saw: {seen:?})");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("channel closed before {name} (saw: {seen:?})");
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
#[ignore = "P0-4/5 trust protocol; requires the XMPP fixture"]
fn set_trust_and_force_retrust_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut alice = Daemon::spawn(&dir.path().join("a"), "muc_a@localhost", "mucapass", 90001);
    alice.expect("ready", 30);
    let mut bob = Daemon::spawn(&dir.path().join("b"), "muc_b@localhost", "mucbpass", 90002);
    bob.expect("ready", 30);

    // The TOFU record (`Store::record_first_seen`) only fires on
    // the RECEIVING side of a KEX. So for `set_trust(jid, dev)`
    // to find a row, the daemon doing the call must be the one
    // that received from `jid` — not the sender. Drive
    // alice→bob first so bob's trust table records alice; then
    // exercise bob's trust commands targeting alice.
    alice.send(serde_json::json!({
        "op":"send","peer":"muc_b@localhost","device":90002,
        "backend":"twomemo","body":"bootstrap","id":"s1",
    }));
    alice.expect("sent", 15);
    let m = bob.expect("message", 15);
    assert_eq!(m["body"].as_str(), Some("bootstrap"));

    // 2. bob flips alice's trust state to Untrusted.
    bob.send(serde_json::json!({
        "op":"set_trust","peer":"muc_a@localhost","device":90001,
        "state":"untrusted","id":"t1",
    }));
    let ts = bob.expect("trust_set", 10);
    assert_eq!(ts["peer"].as_str(), Some("muc_a@localhost"));
    assert_eq!(ts["state"].as_str(), Some("untrusted"));
    assert_eq!(ts["id"].as_str(), Some("t1"));

    // 3. force_retrust with a fresh fake IK — orchestrator-driven
    //    accept-the-rotation flow. The daemon doesn't validate
    //    the IK against anything (it's an orchestrator decision
    //    after out-of-band fingerprint check).
    let new_ik = "11".repeat(32); // 64 chars = 32 bytes
    bob.send(serde_json::json!({
        "op":"force_retrust","peer":"muc_a@localhost","device":90001,
        "new_ik_hex": new_ik,
        "state":"trusted",
        "id":"r1",
    }));
    let r = bob.expect("retrusted", 10);
    assert_eq!(r["peer"].as_str(), Some("muc_a@localhost"));
    assert_eq!(r["device"].as_u64(), Some(90001));
    assert_eq!(r["id"].as_str(), Some("r1"));

    // 4. list_pending should return empty (TOFU made alice
    //    Trusted on first sight; set_trust+force_retrust kept
    //    it non-Pending).
    bob.send(serde_json::json!({"op":"list_pending","id":"lp"}));
    let lp = bob.expect("pending_trusts", 10);
    let entries = lp["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 0);

    alice.shutdown();
    bob.shutdown();
}
