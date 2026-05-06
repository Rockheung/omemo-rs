//! Prometheus exporter (P3-4).
//!
//! Spawns a daemon with `--metrics-bind 127.0.0.1:<port>`,
//! drives one alice→bob send, then scrapes `/metrics` from
//! both daemons and asserts the expected counters appear and
//! incremented.
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
        metrics_port: u16,
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
                "--metrics-bind",
                &format!("127.0.0.1:{metrics_port}"),
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

fn scrape(port: u16) -> String {
    use std::io::Read;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf
}

#[test]
#[ignore = "P3-4 metrics exporter; requires the XMPP fixture"]
fn metrics_endpoint_reflects_send_and_receive() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut alice = Daemon::spawn(
        &dir.path().join("a"),
        "metrics_a@localhost",
        "metricsapass",
        94001,
        9911,
    );
    alice.expect("ready", 30);
    let bob = Daemon::spawn(
        &dir.path().join("b"),
        "metrics_b@localhost",
        "metricsbpass",
        94002,
        9912,
    );
    bob.expect("ready", 30);

    alice.send(serde_json::json!({
        "op":"send","peer":"metrics_b@localhost","device":94002,
        "backend":"twomemo","body":"hello-metrics","id":"s1",
    }));
    alice.expect("sent", 15);
    bob.expect("message", 15);

    let alice_text = scrape(9911);
    let bob_text = scrape(9912);

    // Sent counter incremented for alice; received for bob.
    assert!(
        alice_text.contains(r#"omemo_sent_total{backend="twomemo"} 1"#),
        "alice metrics missing sent counter; got:\n{alice_text}"
    );
    assert!(
        bob_text.contains(r#"omemo_received_total{backend="twomemo"} 1"#),
        "bob metrics missing received counter; got:\n{bob_text}"
    );
    // OPK pool gauge populated (after the bundle health tick;
    // first tick in main_loop is consumed but the Send path
    // refills opportunistically and the tick runs at start +1m).
    // We just want the metric line registered, even if 0.
    assert!(
        alice_text.contains("omemo_opk_pool_size"),
        "alice metrics missing opk_pool_size gauge"
    );

    alice.shutdown();
    bob.shutdown();
}
