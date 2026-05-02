//! Stage 6 — cross-implementation OMEMO 2 interop tests.
//!
//! Spawns `omemo-rs-cli` (this binary) AND the Syndace reference
//! `python-omemo` stack via `interop_client.py`. Verifies both
//! directions decrypt the same body bytes.
//!
//! Marked `#[ignore]` — the workspace `cargo test` doesn't run it
//! automatically. Bring up Prosody and the Python venv first:
//!
//!     docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//!     test-vectors/.venv/bin/pip install slixmpp slixmpp-omemo lxml
//!     cargo test -p omemo-rs-cli --test python_interop -- --ignored
//!
//! The two scenarios use dedicated `pyint_a` / `pyint_b` Prosody
//! accounts (registered by the Dockerfile entrypoint) so they can
//! run in serial without colliding with the other ignored tests.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const RUST_CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the crate root; the repo root is two
    // levels up.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // .../crates
    p.pop(); // repo root
    p
}

fn python_bin() -> PathBuf {
    repo_root().join("test-vectors/.venv/bin/python")
}

fn interop_script() -> PathBuf {
    repo_root().join("test-vectors/integration/python-interop/interop_client.py")
}

fn rust_cli(store_dir: &Path, jid: &str, password: &str) -> Command {
    let mut c = Command::new(RUST_CLI);
    c.env("OMEMO_RS_STORE_DIR", store_dir).args([
        "--jid",
        jid,
        "--password",
        password,
        "--insecure-tcp",
        "127.0.0.1:5222",
    ]);
    c
}

fn py(data_dir: &Path, jid: &str, password: &str) -> Command {
    let mut c = Command::new(python_bin());
    c.arg(interop_script()).args([
        "--jid",
        jid,
        "--password",
        password,
        "--address",
        "127.0.0.1:5222",
        "--data-dir",
        data_dir.to_str().expect("utf-8 data dir"),
        "--timeout",
        "30",
        "-v",
    ]);
    c
}

/// Wait until `pred` returns true, polling `path` every 200ms. Panics
/// after `deadline_secs`.
fn poll_log_for<F: Fn(&str) -> bool>(path: &Path, pred: F, deadline_secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            if pred(&s) {
                return s;
            }
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for log predicate; current contents:\n{}",
                std::fs::read_to_string(path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "Stage 6 cross-impl interop; requires Prosody + python-interop venv"]
fn rust_send_python_recv_via_omemo2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path();
    let py_data_dir = store_dir.join("python");
    std::fs::create_dir_all(&py_data_dir).unwrap();

    // Initialise the rust sender.
    let init = rust_cli(store_dir, "pyint_a@localhost", "pyintapass")
        .args(["init", "--device-id", "1001", "--opk-count", "10"])
        .output()
        .expect("init rust");
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Start the python receiver. It logs `READY <device_id>` to its
    // stdout once its identity has been published, then waits for one
    // inbound encrypted message and exits.
    let py_log = store_dir.join("py-recv.log");
    let py_log_file = std::fs::File::create(&py_log).unwrap();
    let mut py_proc = py(&py_data_dir, "pyint_b@localhost", "pyintbpass")
        .arg("recv")
        .stdout(py_log_file.try_clone().unwrap())
        .stderr(py_log_file)
        .spawn()
        .expect("spawn python recv");

    // Wait until python publishes + signals READY.
    let log = poll_log_for(
        &py_log,
        |s| s.contains("\nREADY ") || s.starts_with("READY "),
        30,
    );
    let py_dev: u32 = log
        .lines()
        .find_map(|l| {
            l.strip_prefix("READY ")
                .map(str::trim)
                .and_then(|n| n.parse().ok())
        })
        .expect("READY <device_id> line");

    let body = "hello python from rust (interop test)";
    let send = rust_cli(store_dir, "pyint_a@localhost", "pyintapass")
        .args([
            "send",
            "--peer",
            "pyint_b@localhost",
            "--peer-device",
            &py_dev.to_string(),
            "--body",
            body,
        ])
        .output()
        .expect("rust send");
    assert!(
        send.status.success(),
        "rust send failed: {}\nstderr: {}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr),
    );

    // Wait for python to exit (it returns once it received one message).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = py_proc.try_wait().unwrap() {
            assert!(
                status.success(),
                "python recv exited non-zero: {status:?}\nlog:\n{}",
                std::fs::read_to_string(&py_log).unwrap_or_default()
            );
            break;
        }
        if Instant::now() > deadline {
            let _ = py_proc.kill();
            panic!(
                "python recv didn't exit within 30s; log:\n{}",
                std::fs::read_to_string(&py_log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let stdout = std::fs::read_to_string(&py_log).unwrap_or_default();
    assert!(
        stdout.contains(body),
        "python stdout doesn't contain body.\nbody: {body}\nstdout:\n{stdout}"
    );
}

#[test]
#[ignore = "Stage 6 cross-impl interop; requires Prosody + python-interop venv"]
fn python_send_rust_recv_via_omemo2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path();
    let py_data_dir = store_dir.join("python");
    std::fs::create_dir_all(&py_data_dir).unwrap();

    // Initialise the rust receiver — fixed device id so python's
    // bundle fetch gets a stable target.
    let init = rust_cli(store_dir, "pyint_b@localhost", "pyintbpass")
        .args(["init", "--device-id", "2002", "--opk-count", "10"])
        .output()
        .expect("init rust");
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Start rust recv first.
    let rust_log = store_dir.join("rust-recv.log");
    let rust_log_file = std::fs::File::create(&rust_log).unwrap();
    let mut rust_proc = rust_cli(store_dir, "pyint_b@localhost", "pyintbpass")
        .args(["recv", "--timeout", "60"])
        .stdout(rust_log_file.try_clone().unwrap())
        .stderr(rust_log_file)
        .spawn()
        .expect("spawn rust recv");

    // Give rust a moment to login + publish + subscribe.
    std::thread::sleep(Duration::from_secs(6));

    let body = "hello rust from python (interop test)";
    let send = py(&py_data_dir, "pyint_a@localhost", "pyintapass")
        .args(["send", "--peer", "pyint_b@localhost", "--body", body])
        .output()
        .expect("python send");
    assert!(
        send.status.success(),
        "python send failed: {}\nstderr: {}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr),
    );

    // Wait for rust to exit (recv returns after one message).
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = rust_proc.try_wait().unwrap() {
            assert!(
                status.success(),
                "rust recv exited non-zero: {status:?}\nlog:\n{}",
                std::fs::read_to_string(&rust_log).unwrap_or_default()
            );
            break;
        }
        if Instant::now() > deadline {
            let _ = rust_proc.kill();
            panic!(
                "rust recv didn't exit within 60s; log:\n{}",
                std::fs::read_to_string(&rust_log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let stdout = std::fs::read_to_string(&rust_log).unwrap_or_default();
    assert!(
        stdout.contains(body),
        "rust recv stdout doesn't contain body.\nbody: {body}\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("pyint_a@localhost/"),
        "rust recv stdout doesn't show python sender JID. stdout:\n{stdout}"
    );
}
