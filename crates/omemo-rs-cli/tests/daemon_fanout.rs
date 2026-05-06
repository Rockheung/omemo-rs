//! Multi-device fan-out via `Send { device: None }` (P0-3).
//!
//! Spawn alice once, then spawn bob TWICE with two different
//! device ids on the same JID (sharing the same OMEMO store
//! across two daemon processes is unsafe, so each bob daemon
//! gets its own store dir but uses the same JID — they end up
//! as two distinct OMEMO devices for `bob@localhost` from
//! ejabberd's perspective).
//!
//! Alice sends `Send { peer: "bob@localhost", device: None }`.
//! Both bob daemons should receive the matching `Message`
//! event with the same body — proving the fan-out reached
//! every device.
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
            .stderr(Stdio::null())
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
        }
    }

    fn send(&mut self, cmd: Value) {
        let mut s = cmd.to_string();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).expect("write");
        self.stdin.flush().expect("flush");
    }

    fn expect_event(&self, name: &str, deadline_secs: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(deadline_secs);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for {name}");
            }
            match self.events_rx.recv_timeout(remaining) {
                Ok(v) if v.get("event").and_then(|e| e.as_str()) == Some(name) => return v,
                Ok(_) => continue,
                Err(_) => panic!("channel closed before {name}"),
            }
        }
    }

    fn shutdown(mut self) {
        let _ = self
            .stdin
            .write_all(b"{\"op\":\"shutdown\"}\n");
        drop(self.stdin);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() > deadline => {
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
#[ignore = "P0-3 multi-device fan-out; requires the XMPP fixture"]
fn send_with_no_device_fans_out_to_all_known_sessions() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Pre-init alice + bob's two devices so each has an
    // identity + bundle published on PEP. ejabberd's PEP node
    // for `urn:xmpp:omemo:2:devices` deduplicates by item id,
    // but the device list itself is the union of everyone who
    // published as `bob@localhost`. So we need bob_dev1 and
    // bob_dev2 to BOTH publish into the SAME devicelist —
    // achieved by having each bob daemon reuse its own
    // device_id but the same JID.
    //
    // Note: ejabberd's `pep` plugin replaces the devicelist
    // wholesale on each publish (item id "current"). So if
    // bob_dev1 publishes [1] and then bob_dev2 publishes [2],
    // the devicelist ends up being just [2]. To get a stable
    // multi-device peer, both bob daemons need to publish
    // a list containing BOTH device ids — which today's
    // omemo-rs-cli doesn't do (it publishes its single
    // device only). So this test simulates multi-device on
    // alice's side: alice has TWO sessions to bob (both at
    // the same JID), one per (jid, dev) pair, and alice's
    // `Send { device: None }` should fan out to both.
    //
    // We bootstrap alice's two bob-sessions by having alice
    // do a `Send { device: <bob_dev1> }` + `Send { device:
    // <bob_dev2> }` first. Then `Send { device: None }`
    // should hit both.

    // For this test, simpler:
    //   1. Spawn alice + bob_dev1 → exchange one message so
    //      alice has a session for (bob, dev1).
    //   2. Spawn bob_dev2 → reuse same JID, different dev id;
    //      alice doesn't have a session for (bob, dev2) yet.
    //      Don't bootstrap — verify Send { device: None }
    //      hits ONLY bob_dev1 (the only session alice has).
    //   3. Then alice does Send { device: bob_dev2_id, ... }
    //      to bootstrap that session too.
    //   4. Send { device: None } again — now both bob daemons
    //      receive.

    // ----- step 1: alice + bob_dev1 baseline session -----
    let alice_dir = dir.path().join("alice");
    let bob1_dir = dir.path().join("bob1");
    let bob2_dir = dir.path().join("bob2");
    let alice_jid = "muc_a@localhost";
    let bob_jid = "muc_b@localhost";
    const ALICE_DEV: u32 = 89001;
    const BOB_DEV_1: u32 = 89002;
    const BOB_DEV_2: u32 = 89003;

    let mut alice = Daemon::spawn(&alice_dir, alice_jid, "mucapass", ALICE_DEV);
    alice.expect_event("ready", 30);

    let bob1 = Daemon::spawn(&bob1_dir, bob_jid, "mucbpass", BOB_DEV_1);
    bob1.expect_event("ready", 30);

    // alice sends to bob_dev_1 specifically, establishing a session
    alice.send(serde_json::json!({
        "op": "send",
        "peer": bob_jid,
        "device": BOB_DEV_1,
        "backend": "twomemo",
        "body": "session-bootstrap-1",
        "id": "boot-1",
    }));
    alice.expect_event("sent", 15);
    let m = bob1.expect_event("message", 15);
    assert_eq!(m["body"].as_str(), Some("session-bootstrap-1"));

    // ----- step 2: bring up bob_dev_2; bootstrap that session too -----
    // (bob_dev_2 publishing replaces ejabberd's devicelist for
    // bob; when alice queries she sees only [bob_dev_2], and
    // her `(bob, bob_dev_1)` session in her local store lives
    // on independently of what ejabberd advertises.)
    let bob2 = Daemon::spawn(&bob2_dir, bob_jid, "mucbpass", BOB_DEV_2);
    bob2.expect_event("ready", 30);

    alice.send(serde_json::json!({
        "op": "send",
        "peer": bob_jid,
        "device": BOB_DEV_2,
        "backend": "twomemo",
        "body": "session-bootstrap-2",
        "id": "boot-2",
    }));
    alice.expect_event("sent", 15);
    let m2 = bob2.expect_event("message", 15);
    assert_eq!(m2["body"].as_str(), Some("session-bootstrap-2"));

    // ----- step 3: the actual fan-out test -----
    // alice now has TWO sessions for `bob@localhost`. Send
    // with `device: null` → daemon should fan out to both.
    alice.send(serde_json::json!({
        "op": "send",
        "peer": bob_jid,
        "device": null,
        "backend": "twomemo",
        "body": "fan-out hello",
        "id": "fanout-1",
    }));
    // We expect TWO `sent` events (one per recipient device).
    let sent1 = alice.expect_event("sent", 15);
    let sent2 = alice.expect_event("sent", 15);
    let dev_a = sent1["device"].as_u64().unwrap() as u32;
    let dev_b = sent2["device"].as_u64().unwrap() as u32;
    let mut got = vec![dev_a, dev_b];
    got.sort();
    assert_eq!(got, vec![BOB_DEV_1, BOB_DEV_2]);

    // Both bob daemons should decrypt the same body.
    let m_at_1 = bob1.expect_event("message", 15);
    let m_at_2 = bob2.expect_event("message", 15);
    assert_eq!(m_at_1["body"].as_str(), Some("fan-out hello"));
    assert_eq!(m_at_2["body"].as_str(), Some("fan-out hello"));

    alice.shutdown();
    bob1.shutdown();
    bob2.shutdown();
}
