//! SPK rotation timer (P3-2).
//!
//! Spawns a daemon with `OMEMO_RS_SPK_ROTATION_SECS=2` so the
//! rotation interval ticks fast in CI. Records the SPK rowset
//! before and after the timer fires, and asserts:
//!
//!   * after rotation the active SPK (`replaced_at IS NULL`) has
//!     a new id (incremented from the previous one);
//!   * the previous SPK row still exists with `replaced_at`
//!     populated (peers in the middle of bootstrapping against
//!     the old `spk_id` can still complete their KEX).
//!
//! Reads the store directly via `Store::open` rather than going
//! through the daemon's stdio protocol — there is no `dump_spk`
//! command, and exposing one would be a wider surface change
//! than the test needs.
//!
//! `#[ignore]` — needs the ejabberd fixture (the daemon won't
//! reach Ready otherwise).

#![cfg(test)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use omemo_session::Store;
use serde_json::Value;

const RUST_CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");

struct Daemon {
    child: Child,
    stdin: ChildStdin,
    events_rx: mpsc::Receiver<Value>,
}

impl Daemon {
    fn spawn(store_dir: &Path, jid: &str, password: &str, device_id: u32, rotate_secs: u64) -> Self {
        let mut child = Command::new(RUST_CLI)
            .env("OMEMO_RS_STORE_DIR", store_dir)
            .env("OMEMO_RS_SPK_ROTATION_SECS", rotate_secs.to_string())
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
#[ignore = "P3-2 SPK rotation timer; requires the XMPP fixture"]
fn spk_rotates_on_timer_and_old_row_stays() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().to_path_buf();

    // Rotate every 2s so the test can observe a tick within
    // the harness budget.
    let alice = Daemon::spawn(
        &store_dir,
        "spk_a@localhost",
        "spkapass",
        92001,
        2,
    );
    alice.expect("ready", 30);

    // Wait for the 2s tick to fire and a republish to land. We
    // poll the store rather than synthesising an explicit
    // rotation event — the timer-driven path is what we want
    // to exercise.
    let store_path = store_dir.join("spk_a@localhost.db");
    let initial_id = wait_until_spk_id_at_least(&store_path, 2, Duration::from_secs(15))
        .expect("rotation didn't run within 15s");
    assert!(initial_id >= 2, "expected id ≥ 2 after first rotation");

    // Verify old (id = 1) row still exists with replaced_at populated.
    let store = Store::open(&store_path).expect("open store readonly");
    let old = store
        .get_spk(initial_id - 1)
        .expect("get_spk")
        .expect("predecessor SPK row missing");
    assert!(
        old.replaced_at.is_some(),
        "predecessor SPK should be marked replaced after rotation"
    );

    alice.shutdown();
}

fn wait_until_spk_id_at_least(
    store_path: &Path,
    min_id: u32,
    deadline: Duration,
) -> Option<u32> {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if let Ok(store) = Store::open(store_path) {
            if let Ok(Some(current)) = store.current_spk() {
                if current.id >= min_id {
                    return Some(current.id);
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    None
}
