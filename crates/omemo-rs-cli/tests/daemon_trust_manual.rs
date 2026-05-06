//! Manual trust policy (P3-1).
//!
//! Spawns one daemon under `--trust-policy manual` and another
//! under default (TOFU). The manual-policy daemon should:
//!
//!   * Decrypt inbound bodies normally (KEX still completes).
//!   * After the KEX, emit a `pending_trust` event because the
//!     new device was recorded as `Pending` instead of `Trusted`.
//!   * Show the new device in `list_pending`.
//!   * After `set_trust(...,Trusted)`, the device drops out of
//!     `list_pending`.
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
    fn spawn(
        store_dir: &Path,
        jid: &str,
        password: &str,
        device_id: u32,
        trust_policy: &str,
    ) -> Self {
        let mut child = Command::new(RUST_CLI)
            .env("OMEMO_RS_STORE_DIR", store_dir)
            .args([
                "--jid",
                jid,
                "--password",
                password,
                "--insecure-tcp",
                "127.0.0.1:5222",
                "--trust-policy",
                trust_policy,
                "daemon",
                "--device-id",
                &device_id.to_string(),
                "--opk-count",
                "20",
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
        let mut seen: Vec<String> = Vec::new();
        loop {
            let r = until.saturating_duration_since(Instant::now());
            if r.is_zero() {
                panic!("timeout waiting for {name} (saw: {seen:?})");
            }
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
#[ignore = "P3-1 manual trust policy; requires the XMPP fixture"]
fn manual_policy_emits_pending_trust_then_clears_after_set_trust() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Bob runs under manual policy; alice is just a sender.
    let mut bob = Daemon::spawn(
        &dir.path().join("b"),
        "manual_b@localhost",
        "manualbpass",
        91002,
        "manual",
    );
    bob.expect("ready", 30);
    let mut alice = Daemon::spawn(
        &dir.path().join("a"),
        "manual_a@localhost",
        "manualapass",
        91001,
        "tofu",
    );
    alice.expect("ready", 30);

    // alice → bob KEX. Body should arrive at bob normally; in
    // addition bob should emit pending_trust because alice's
    // device is recorded as Pending (manual policy).
    alice.send(serde_json::json!({
        "op":"send","peer":"manual_b@localhost","device":91002,
        "backend":"twomemo","body":"first contact","id":"s1",
    }));
    alice.expect("sent", 15);

    let m = bob.expect("message", 15);
    assert_eq!(m["body"].as_str(), Some("first contact"));

    let pt = bob.expect("pending_trust", 5);
    assert_eq!(pt["peer"].as_str(), Some("manual_a@localhost"));
    assert_eq!(pt["device"].as_u64(), Some(91001));
    assert!(
        pt["ik_fingerprint"]
            .as_str()
            .map(|s| s.len() == 64)
            .unwrap_or(false),
        "ik_fingerprint should be 64-char hex"
    );

    // list_pending should now show alice/91001.
    bob.send(serde_json::json!({"op":"list_pending","id":"lp"}));
    let lp = bob.expect("pending_trusts", 10);
    let entries = lp["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "expected exactly one pending entry");
    assert_eq!(entries[0]["peer"].as_str(), Some("manual_a@localhost"));
    assert_eq!(entries[0]["device"].as_u64(), Some(91001));

    // Operator approves alice's device.
    bob.send(serde_json::json!({
        "op":"set_trust","peer":"manual_a@localhost","device":91001,
        "state":"trusted","id":"t1",
    }));
    let ts = bob.expect("trust_set", 10);
    assert_eq!(ts["state"].as_str(), Some("trusted"));

    // list_pending now empty.
    bob.send(serde_json::json!({"op":"list_pending","id":"lp2"}));
    let lp2 = bob.expect("pending_trusts", 10);
    assert_eq!(
        lp2["entries"].as_array().expect("entries").len(),
        0,
        "post-trust the queue should be empty"
    );

    alice.shutdown();
    bob.shutdown();
}
