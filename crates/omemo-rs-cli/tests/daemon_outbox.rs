//! In-flight outbox (P3-3).
//!
//! Goal: prove a daemon SIGKILL between `Send` accept and `sent`
//! emit replays the message on next startup. The trick is
//! catching the daemon mid-fan-out — too long and the daemon
//! finishes; too soon and the row never makes it onto the wire
//! at all (still useful, but not the scenario we want to assert).
//!
//! Strategy:
//!   1. spawn alice, bob; alice → bob initial KEX so bob is reachable.
//!   2. SIGSTOP alice (freezes mid-loop without losing the store
//!      file); insert a synthetic outbox row directly into
//!      alice's SQLite store using the same library code the
//!      daemon would use.
//!   3. SIGKILL alice without unblocking — the outbox row is now
//!      committed and a "send that never ran" exists for the
//!      next startup to see.
//!   4. Restart alice. After Ready, the daemon's `replay_outbox`
//!      drains the synthetic row and runs it through the normal
//!      Send path. Bob receives the body.
//!   5. The outbox is empty post-replay.
//!
//! `#[ignore]` — needs the ejabberd fixture.

#![cfg(test)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use omemo_session::{Backend, OutboxEntry, OutboxKind, Store};
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
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn kill_now(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
#[ignore = "P3-3 in-flight outbox; requires the XMPP fixture"]
fn outbox_row_replays_on_next_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().to_path_buf();
    let alice_db = store_dir.join("ob_a@localhost.db");

    // Round 1: alice & bob bootstrap so a session exists.
    let mut alice = Daemon::spawn(&store_dir, "ob_a@localhost", "obapass", 93001);
    alice.expect("ready", 30);
    let bob = Daemon::spawn(&store_dir, "ob_b@localhost", "obbpass", 93002);
    bob.expect("ready", 30);

    alice.send(serde_json::json!({
        "op":"send","peer":"ob_b@localhost","device":93002,
        "backend":"twomemo","body":"bootstrap","id":"s1",
    }));
    alice.expect("sent", 15);
    bob.expect("message", 15);

    // SIGSTOP alice so she can't drain the channel; we can then
    // mutate her sqlite store without races. SIGSTOP blocks the
    // process at a signal handler boundary — the file system is
    // free to write underneath.
    let alice_pid = alice.pid();
    sigstop(alice_pid);

    // Synthesise an outbox row that the *next* daemon process
    // will see and replay. We pre-create the row using
    // omemo-session directly, mirroring exactly what the daemon
    // would have done if it had crashed mid-Send.
    {
        let mut store = Store::open(&alice_db).expect("open store");
        let entry = OutboxEntry {
            rowid: None,
            kind: OutboxKind::Direct,
            peer: "ob_b@localhost".into(),
            device_id: Some(93002),
            backend: Backend::Twomemo,
            body: "replayed message".into(),
            request_id: Some("replay-1".into()),
            queued_at: 1,
        };
        store.enqueue_outbox(&entry).expect("enqueue");
        // Verify it's actually persisted.
        let pending = store.list_outbox().expect("list");
        assert_eq!(pending.len(), 1);
    }

    // Hard-kill alice (don't bother SIGCONT — the row is on disk).
    alice.kill_now();

    // Round 2: restart alice from the same store.
    let alice2 = Daemon::spawn(&store_dir, "ob_a@localhost", "obapass", 93001);
    alice2.expect("ready", 30);

    // The replayed Send should produce a `sent` event with the
    // original request id.
    let sent = alice2.expect("sent", 30);
    assert_eq!(sent["id"].as_str(), Some("replay-1"));
    assert_eq!(sent["peer"].as_str(), Some("ob_b@localhost"));
    assert_eq!(sent["device"].as_u64(), Some(93002));

    // Bob should receive the replayed body.
    let m = bob.expect("message", 15);
    assert_eq!(m["body"].as_str(), Some("replayed message"));

    // After successful replay, the outbox is empty.
    {
        let store = Store::open(&alice_db).expect("reopen");
        assert_eq!(store.list_outbox().unwrap().len(), 0);
    }

    alice2.shutdown();
    bob.shutdown();
}

fn sigstop(pid: u32) {
    // Best-effort — if pkill -STOP isn't available or pid is
    // gone, just continue; the test failure signal will surface
    // as a missing replay.
    let _ = std::process::Command::new("kill")
        .args(["-STOP", &pid.to_string()])
        .status();
}
