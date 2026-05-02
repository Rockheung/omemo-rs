//! XEP-0045 Multi-User Chat support layered on `omemo-pep`'s transport.
//!
//! Stage 5.1 — basic join + occupant tracking. The room state is kept
//! in [`MucRoom`]; callers feed in incoming presence stanzas via
//! [`MucRoom::handle_presence`], which mutates the occupant table and
//! returns a [`MucEvent`] describing what changed.
//!
//! Encryption fan-out, device-list cache, and groupchat send/receive
//! are layered on top in subsequent sub-stages (see TODO.md Stage 5).

use std::collections::HashMap;
use std::str::FromStr;

use jid::{BareJid, FullJid, Jid, ResourcePart};
use thiserror::Error;
use tokio_xmpp::Client;
use xmpp_parsers::iq::Iq;
use xmpp_parsers::minidom::Element;
use xmpp_parsers::muc::user::{Affiliation, MucUser, Role, Status};
use xmpp_parsers::muc::Muc;
use xmpp_parsers::presence::{Presence, Type as PresenceType};

/// XML namespace of `<x xmlns='http://jabber.org/protocol/muc#user'>`,
/// the presence/message annotation Prosody (and every other MUC
/// service) sends to describe each occupant.
const MUC_USER_NS: &str = "http://jabber.org/protocol/muc#user";

#[derive(Debug, Error)]
pub enum MucError {
    #[error("MUC presence parse: {0}")]
    Parse(String),
    #[error("MUC presence has no <item> in <x xmlns='muc#user'>")]
    ItemMissing,
    #[error("could not build MUC nick resource: {0}")]
    Resource(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// One occupant of a MUC room as last reported by the server's
/// `<x xmlns='muc#user'>` presence annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct Occupant {
    /// The nickname (resource part of the room JID).
    pub nick: String,
    /// The occupant's real bare JID, if the room reveals it
    /// (`item.jid` populated). Anonymous rooms leave this `None` for
    /// everyone except the user themselves.
    pub real_jid: Option<BareJid>,
    pub affiliation: Affiliation,
    pub role: Role,
}

/// Outcome of processing one inbound presence stanza for a room.
///
/// `OutsideRoom` is the catch-all so callers can run a
/// `match room.handle_presence(&p)? { ... }` in a stream loop and
/// silently ignore stanzas that belong to other rooms or to non-MUC
/// state.
#[derive(Debug, Clone, PartialEq)]
pub enum MucEvent {
    OutsideRoom,
    /// Server confirmed our own join (status code 110, or `from` resource
    /// matches `our_nick`). The occupant entry now contains our `real_jid`
    /// (if non-anonymous), affiliation, and role.
    SelfJoined {
        occupant: Occupant,
    },
    OccupantJoined {
        occupant: Occupant,
    },
    OccupantLeft {
        nick: String,
    },
    SelfLeft,
}

/// Live state of one MUC room from this client's perspective.
///
/// `occupants` is keyed by nickname so callers can look up the real JID
/// associated with a `from='room@conf/nick'` message. Anonymous rooms
/// leave `Occupant::real_jid = None`; in that case the omemo fan-out
/// layer cannot identify recipients and must fall back to a UI prompt.
pub struct MucRoom {
    /// Bare JID of the room, e.g. `general@conference.localhost`.
    pub jid: BareJid,
    pub our_nick: String,
    pub occupants: HashMap<String, Occupant>,
}

impl MucRoom {
    pub fn new(room_jid: BareJid, our_nick: impl Into<String>) -> Self {
        Self {
            jid: room_jid,
            our_nick: our_nick.into(),
            occupants: HashMap::new(),
        }
    }

    fn full_jid_with_our_nick(&self) -> Result<FullJid, MucError> {
        let resource = ResourcePart::from_str(&self.our_nick)
            .map_err(|e| MucError::Resource(e.to_string()))?;
        Ok(self.jid.with_resource(&resource))
    }

    /// Send the join `<presence to='room@conf/nick'><x
    /// xmlns='http://jabber.org/protocol/muc'/></presence>`. The room
    /// is created on the server if it doesn't exist yet (subject to
    /// the MUC component's `restrict_room_creation` policy).
    pub async fn send_join(&self, client: &mut Client) -> Result<(), MucError> {
        let to = self.full_jid_with_our_nick()?;
        let mut presence = Presence::available().with_to(to);
        presence.payloads.push(Element::from(Muc::new()));
        client.send_stanza(presence.into()).await?;
        Ok(())
    }

    /// Send `<presence type='unavailable' to='room@conf/nick'/>` to
    /// leave the room. The server replies with our own `unavailable`
    /// presence and stops routing groupchat traffic.
    pub async fn send_leave(&self, client: &mut Client) -> Result<(), MucError> {
        let to = self.full_jid_with_our_nick()?;
        let presence = Presence::unavailable().with_to(to);
        client.send_stanza(presence.into()).await?;
        Ok(())
    }

    /// Accept the default room configuration (XEP-0045 §10.1.2). The
    /// MUC creator's first join produces a *locked* room: only the
    /// creator can enter until they submit a `muc#owner` config form.
    /// Sending an empty `<x type='submit'/>` accepts the server's
    /// defaults and unlocks the room so other occupants can join.
    ///
    /// Fire-and-forget: we do not wait for the iq-result. If the room
    /// rejects (e.g. caller is not actually owner), the server will
    /// emit an `<iq type='error'>` that callers can observe via the
    /// stream. For Stage 5 the gate test is deterministic and the
    /// caller is always the creator, so the error path is unreachable.
    pub async fn accept_default_config(&self, client: &mut Client) -> Result<(), MucError> {
        // OMEMO over MUC requires the room to be **non-anonymous** so
        // we can resolve each occupant's bare JID and fetch their
        // bundle. We therefore pin `muc#roomconfig_whois = anyone`
        // explicitly rather than accepting Prosody's semi-anonymous
        // default. (XEP-0045 §15.5.4.)
        //
        // minidom 0.18 requires NcName-typed attribute keys, which is
        // awkward through the builder API; round-tripping the form
        // through XML text is shorter and equally type-safe (the
        // resulting Element is checked at parse time).
        let xml = r#"<query xmlns="http://jabber.org/protocol/muc#owner">
            <x xmlns="jabber:x:data" type="submit">
                <field var="FORM_TYPE"><value>http://jabber.org/protocol/muc#roomconfig</value></field>
                <field var="muc#roomconfig_whois"><value>anyone</value></field>
            </x>
        </query>"#;
        let payload = Element::from_str(xml).map_err(|e| MucError::Parse(e.to_string()))?;
        let iq = Iq::Set {
            from: None,
            to: Some(Jid::from(self.jid.clone())),
            id: "muc-instant-config".to_owned(),
            payload,
        };
        client.send_stanza(iq.into()).await?;
        Ok(())
    }

    /// Update room state from one inbound `<presence>` stanza.
    ///
    /// Returns the classified [`MucEvent`]. Stanzas whose `from` is not
    /// addressed at this room (different bare, or no resource) yield
    /// [`MucEvent::OutsideRoom`] without mutation.
    pub fn handle_presence(&mut self, presence: &Presence) -> Result<MucEvent, MucError> {
        let Some(from) = &presence.from else {
            return Ok(MucEvent::OutsideRoom);
        };
        let from_full = match from.try_as_full() {
            Ok(f) => f,
            Err(_) => return Ok(MucEvent::OutsideRoom),
        };
        if from_full.to_bare() != self.jid {
            return Ok(MucEvent::OutsideRoom);
        }
        let nick = from_full.resource().as_str().to_string();
        let is_self_nick = nick == self.our_nick;

        if presence.type_ == PresenceType::Unavailable {
            self.occupants.remove(&nick);
            return Ok(if is_self_nick {
                MucEvent::SelfLeft
            } else {
                MucEvent::OccupantLeft { nick }
            });
        }

        let muc_user_elem = presence
            .payloads
            .iter()
            .find(|p| p.is("x", MUC_USER_NS))
            .cloned();
        let muc_user = match muc_user_elem {
            Some(elem) => MucUser::try_from(elem).map_err(|e| MucError::Parse(e.to_string()))?,
            // Some servers omit `<x xmlns='muc#user'>` for own-presence
            // echoes that confirm a state we already know. Treat as a
            // no-op rather than a parse error.
            None => return Ok(MucEvent::OutsideRoom),
        };
        let item = muc_user
            .items
            .into_iter()
            .next()
            .ok_or(MucError::ItemMissing)?;

        let occupant = Occupant {
            nick: nick.clone(),
            real_jid: item.jid.map(|j| j.into_bare()),
            affiliation: item.affiliation,
            role: item.role,
        };
        self.occupants.insert(nick.clone(), occupant.clone());

        let self_signaled = muc_user
            .status
            .iter()
            .any(|s| matches!(s, Status::SelfPresence));
        Ok(if is_self_nick || self_signaled {
            MucEvent::SelfJoined { occupant }
        } else {
            MucEvent::OccupantJoined { occupant }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use xmpp_parsers::minidom::Element;
    use xmpp_parsers::muc::user::{Affiliation, Role};

    fn presence_from_xml(xml: &str) -> Presence {
        let elem: Element = Element::from_str(xml).expect("element parse");
        Presence::try_from(elem).expect("presence parse")
    }

    #[test]
    fn outside_room_when_from_is_a_different_bare() {
        let mut room = MucRoom::new(
            BareJid::new("general@conference.localhost").unwrap(),
            "alice",
        );
        let p = presence_from_xml(
            "<presence from='other@conference.localhost/x' xmlns='jabber:client'>\
                <x xmlns='http://jabber.org/protocol/muc#user'>\
                    <item affiliation='owner' role='moderator'/>\
                </x>\
             </presence>",
        );
        assert_eq!(room.handle_presence(&p).unwrap(), MucEvent::OutsideRoom);
        assert!(room.occupants.is_empty());
    }

    #[test]
    fn self_join_recognised_via_status_110() {
        let mut room = MucRoom::new(
            BareJid::new("general@conference.localhost").unwrap(),
            "alice",
        );
        let p = presence_from_xml(
            "<presence from='general@conference.localhost/alice' xmlns='jabber:client'>\
                <x xmlns='http://jabber.org/protocol/muc#user'>\
                    <item affiliation='owner' role='moderator' \
                          jid='alice@localhost/laptop'/>\
                    <status code='110'/>\
                </x>\
             </presence>",
        );
        match room.handle_presence(&p).unwrap() {
            MucEvent::SelfJoined { occupant } => {
                assert_eq!(occupant.nick, "alice");
                assert_eq!(
                    occupant.real_jid.as_ref().map(|j| j.as_str()),
                    Some("alice@localhost")
                );
                assert_eq!(occupant.affiliation, Affiliation::Owner);
                assert_eq!(occupant.role, Role::Moderator);
            }
            other => panic!("expected SelfJoined, got {other:?}"),
        }
        assert_eq!(room.occupants.len(), 1);
    }

    #[test]
    fn other_occupant_joins_then_leaves() {
        let mut room = MucRoom::new(
            BareJid::new("general@conference.localhost").unwrap(),
            "alice",
        );
        let join = presence_from_xml(
            "<presence from='general@conference.localhost/bob' xmlns='jabber:client'>\
                <x xmlns='http://jabber.org/protocol/muc#user'>\
                    <item affiliation='member' role='participant' \
                          jid='bob@localhost/phone'/>\
                </x>\
             </presence>",
        );
        match room.handle_presence(&join).unwrap() {
            MucEvent::OccupantJoined { occupant } => {
                assert_eq!(occupant.nick, "bob");
                assert_eq!(
                    occupant.real_jid.as_ref().unwrap().as_str(),
                    "bob@localhost"
                );
                assert_eq!(occupant.affiliation, Affiliation::Member);
            }
            other => panic!("expected OccupantJoined, got {other:?}"),
        }
        assert!(room.occupants.contains_key("bob"));

        let leave = presence_from_xml(
            "<presence type='unavailable' \
                       from='general@conference.localhost/bob' xmlns='jabber:client'/>",
        );
        match room.handle_presence(&leave).unwrap() {
            MucEvent::OccupantLeft { nick } => assert_eq!(nick, "bob"),
            other => panic!("expected OccupantLeft, got {other:?}"),
        }
        assert!(!room.occupants.contains_key("bob"));
    }

    #[test]
    fn anonymous_room_leaves_real_jid_empty() {
        let mut room = MucRoom::new(BareJid::new("anon@conference.localhost").unwrap(), "alice");
        let p = presence_from_xml(
            "<presence from='anon@conference.localhost/bob' xmlns='jabber:client'>\
                <x xmlns='http://jabber.org/protocol/muc#user'>\
                    <item affiliation='none' role='visitor'/>\
                </x>\
             </presence>",
        );
        match room.handle_presence(&p).unwrap() {
            MucEvent::OccupantJoined { occupant } => {
                assert!(occupant.real_jid.is_none());
            }
            other => panic!("expected OccupantJoined, got {other:?}"),
        }
    }
}
