//! Integration test for the `omemo-rs-cli` binary itself —
//! exercises the same `init` / `send` / `recv` invocations the
//! README quickstart shows, against a local XMPP fixture. Catches CLI-
//! level regressions (arg parsing, store-path resolution, exit
//! codes, stdout format) that the lower-level `omemo-pep` tests
//! don't see.
//!
//!     docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d
//!     cargo test -p omemo-rs-cli -- --ignored
//!
//! Uses dedicated `cli_a` / `cli_b` pre-registered accounts
//! so the test can run in parallel with the other ignored
//! integration tests in the workspace.
//!
//! `env!("CARGO_BIN_EXE_omemo-rs-cli")` is set by Cargo for the
//! integration-test process, pointing at the freshly-built binary.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CLI: &str = env!("CARGO_BIN_EXE_omemo-rs-cli");

fn cli(store_dir: &std::path::Path, jid: &str, password: &str) -> Command {
    let mut c = Command::new(CLI);
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

fn run_init(store_dir: &std::path::Path, jid: &str, password: &str, device_id: u32) {
    let out = cli(store_dir, jid, password)
        .args([
            "init",
            "--device-id",
            &device_id.to_string(),
            "--opk-count",
            "10",
        ])
        .output()
        .expect("spawn init");
    assert!(
        out.status.success(),
        "init {jid} failed: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
#[ignore = "5-FU.4 CLI integration; requires the XMPP fixture on 127.0.0.1:5222"]
fn alice_send_bob_recv_via_cli_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path();

    run_init(store_dir, "cli_a@localhost", "cliapass", 1001);
    run_init(store_dir, "cli_b@localhost", "clibpass", 1002);

    // Spawn bob's `recv` first, then send. Capture stdout and read
    // it after the process exits — `recv` waits for one inbound
    // message and exits.
    let mut bob = cli(store_dir, "cli_b@localhost", "clibpass")
        .args(["recv", "--timeout", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn recv");

    // Give bob a moment to subscribe before alice sends.
    std::thread::sleep(Duration::from_secs(3));

    let body = "interop body via CLI";
    let send = cli(store_dir, "cli_a@localhost", "cliapass")
        .args([
            "send",
            "--peer",
            "cli_b@localhost",
            "--peer-device",
            "1002",
            "--body",
            body,
        ])
        .output()
        .expect("spawn send");
    assert!(
        send.status.success(),
        "send failed: {}\nstderr: {}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr),
    );

    // Wait for bob to exit (recv returns after one message). Bound
    // by `recv --timeout 30` plus a few seconds of slack.
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = bob.try_wait().expect("try_wait") {
            assert!(
                status.success(),
                "recv exited non-zero: {status:?}\nstderr: {}",
                {
                    let mut s = String::new();
                    bob.stderr.take().map(|mut e| e.read_to_string(&mut s));
                    s
                }
            );
            break;
        }
        if Instant::now() > deadline {
            let _ = bob.kill();
            panic!("bob recv did not exit within 45s");
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let mut bob_stdout = String::new();
    bob.stdout
        .take()
        .expect("stdout pipe")
        .read_to_string(&mut bob_stdout)
        .expect("read stdout");
    assert!(
        bob_stdout.contains(body),
        "bob recv stdout doesn't contain expected body.\n\
         expected substring: {body}\n\
         actual stdout: {bob_stdout}"
    );
    assert!(
        bob_stdout.contains("cli_a@localhost/1001"),
        "bob recv stdout doesn't show sender identity.\n\
         actual stdout: {bob_stdout}"
    );
}
