//! Stage 5.1 integration test — two clients join a MUC room on
//! `conference.localhost` and each one observes the other as an
//! occupant.
//!
//!     docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//!     cargo test -p omemo-pep --test muc -- --ignored
//!
//! Uses the `gate_a` / `gate_b` accounts (registered in the Prosody
//! Dockerfile alongside `alice` / `bob` / `charlie`).

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{connect_plaintext, BareJid, Event, MucRoom};
use tokio_xmpp::Stanza;
use xmpp_parsers::presence::Presence;

async fn await_online(client: &mut omemo_pep::Client) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = client.next().await {
            if matches!(event, Event::Online { .. }) {
                return;
            }
        }
        panic!("client stream ended without Online event (is Prosody running?)");
    })
    .await
    .expect("login timed out");
}

/// Drive `client` until `room.handle_presence` returns the matching
/// MucEvent, or until `Duration::from_secs(deadline_secs)` elapses.
/// Filters non-presence stanzas and `OutsideRoom` quietly. Returns the
/// matching event so callers can assert on its body.
/// Drain *both* streams concurrently into their respective rooms
/// until `done(alice_room, bob_room)` returns `true`. Polling both at
/// once is necessary because Prosody can broadcast bob's join to alice
/// at any point — if alice is idle inside a single-client pump, the
/// broadcast lands in tokio-xmpp's internal channel but our task is
/// not yielding to drain it.
async fn pump_two<F: Fn(&MucRoom, &MucRoom) -> bool>(
    alice: &mut omemo_pep::Client,
    alice_room: &mut MucRoom,
    bob: &mut omemo_pep::Client,
    bob_room: &mut MucRoom,
    deadline_secs: u64,
    done: F,
) {
    if done(alice_room, bob_room) {
        return;
    }
    tokio::time::timeout(Duration::from_secs(deadline_secs), async {
        loop {
            tokio::select! {
                ev = alice.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => {
                        let _ = alice_room.handle_presence(&p);
                    }
                    Some(_) => {}
                    None => panic!("alice stream ended"),
                },
                ev = bob.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => {
                        let _ = bob_room.handle_presence(&p);
                    }
                    Some(_) => {}
                    None => panic!("bob stream ended"),
                },
            }
            if done(alice_room, bob_room) {
                return;
            }
        }
    })
    .await
    .expect("pump_two: predicate not satisfied within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Stage 5.1; requires Prosody on 127.0.0.1:5222 with conference.localhost MUC"]
async fn two_clients_join_same_room_and_see_each_other() {
    let alice_jid = BareJid::from_str("gate_a@localhost").unwrap();
    let bob_jid = BareJid::from_str("gate_b@localhost").unwrap();
    let room_jid = BareJid::from_str("muc_5_1@conference.localhost").unwrap();

    let mut alice = connect_plaintext(alice_jid.clone(), "gateapass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "gatebpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;

    // RFC 6121 §4.2: each session MUST send initial `<presence/>` before
    // any directed presence (like a MUC join) is considered routable.
    alice
        .send_stanza(Presence::available().into())
        .await
        .expect("alice initial presence");
    bob.send_stanza(Presence::available().into())
        .await
        .expect("bob initial presence");

    let mut alice_room = MucRoom::new(room_jid.clone(), "alice_nick");
    let mut bob_room = MucRoom::new(room_jid.clone(), "bob_nick");

    // Alice joins first; ensure her self-presence lands.
    alice_room.send_join(&mut alice).await.expect("alice join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        10,
        |a, _| {
            a.occupants
                .get("alice_nick")
                .is_some_and(|o| o.real_jid.is_some())
        },
    )
    .await;
    assert_eq!(
        alice_room
            .occupants
            .get("alice_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("gate_a@localhost")
    );

    // Alice submits the muc#owner default-config form so the
    // freshly-created room unlocks for bob.
    alice_room
        .accept_default_config(&mut alice)
        .await
        .expect("alice accept default config");

    // Bob joins. We wait until BOTH rooms have BOTH occupants with
    // real JIDs — i.e. the broadcast has reached alice and the
    // history has reached bob.
    bob_room.send_join(&mut bob).await.expect("bob join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        15,
        |a, b| {
            let want =
                |r: &MucRoom, n: &str| r.occupants.get(n).is_some_and(|o| o.real_jid.is_some());
            want(a, "alice_nick")
                && want(a, "bob_nick")
                && want(b, "alice_nick")
                && want(b, "bob_nick")
        },
    )
    .await;
    assert_eq!(
        bob_room
            .occupants
            .get("alice_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("gate_a@localhost")
    );
    assert_eq!(
        alice_room
            .occupants
            .get("bob_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("gate_b@localhost")
    );

    // Bob leaves; alice eventually observes the occupant disappear.
    bob_room.send_leave(&mut bob).await.expect("bob leave");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        10,
        |a, _| !a.occupants.contains_key("bob_nick"),
    )
    .await;
    assert!(alice_room.occupants.contains_key("alice_nick"));

    alice.send_end().await.expect("alice send_end");
    bob.send_end().await.expect("bob send_end");
}
