#!/usr/bin/env python3
"""
Stage 6 cross-implementation interop client: a minimal slixmpp +
python-omemo (Syndace `omemo` 2.x with the `twomemo` backend)
counterpart for `omemo-rs-cli`.

Two subcommands:

* ``send``  — connect, encrypt one body for the peer, send, exit.
* ``recv``  — connect, wait for one encrypted ``<message>`` from
              the peer, decrypt, print ``<bare>/<device>: <body>``
              to stdout, exit.

OMEMO data (identity, sessions, bundles) is stored in a JSON file
under ``--data-dir`` so a subsequent invocation against the same
account reuses keys.

This is reused by the Rust integration test
``tests/python_interop.rs`` to drive cross-impl OMEMO 2 traffic
between python-omemo (the Syndace reference) and omemo-rs.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import logging
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional


# Returned by `xep_0384.decrypt_message` when the underlying twomemo
# backend successfully decrypted but slixmpp-omemo doesn't unwrap
# the XEP-0420 envelope yet. The message looks like:
#   "SCE not supported yet. Plaintext: b'<envelope ...>...'"
# We parse the bytes-literal back out and walk the envelope ourselves.
SCE_NOT_SUPPORTED_PREFIX = "SCE not supported yet. Plaintext: "
SCE_NS = "{urn:xmpp:sce:1}"
CLIENT_NS = "{jabber:client}"


def unwrap_sce_envelope_from_error(err_text: str) -> Optional[str]:
    """If the NotImplementedError carries an SCE-envelope plaintext,
    parse the envelope and return the inner `<body>` text. Returns
    None if the format doesn't match."""
    if not err_text.startswith(SCE_NOT_SUPPORTED_PREFIX):
        return None
    bytes_repr = err_text.removeprefix(SCE_NOT_SUPPORTED_PREFIX)
    try:
        plaintext = ast.literal_eval(bytes_repr)
        if not isinstance(plaintext, (bytes, bytearray)):
            return None
        envelope = ET.fromstring(plaintext)
    except (ValueError, SyntaxError, ET.ParseError):
        return None
    body_elt = envelope.find(f"{SCE_NS}content/{CLIENT_NS}body")
    if body_elt is None:
        return None
    return body_elt.text or ""

from omemo.storage import Just, Maybe, Nothing, Storage
from omemo.types import DeviceInformation, JSONType
from slixmpp.clientxmpp import ClientXMPP
from slixmpp.jid import JID  # pylint: disable=no-name-in-module
from slixmpp.plugins import register_plugin  # type: ignore[attr-defined]
from slixmpp.stanza import Message
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.matcher import MatchXPath
from slixmpp_omemo import XEP_0384


log = logging.getLogger("omemo-interop")


class JsonStorage(Storage):
    """JSON-file backed Storage. Mirror of the example storage in
    slixmpp-omemo's repo, kept here so the script is self-contained."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path
        self._data: Dict[str, JSONType] = {}
        if path.exists():
            with open(path, encoding="utf8") as f:
                try:
                    self._data = json.load(f)
                except Exception:
                    pass

    def _flush(self) -> None:
        with open(self._path, "w", encoding="utf8") as f:
            json.dump(self._data, f)

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self._data:
            return Just(self._data[key])
        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self._data[key] = value
        self._flush()

    async def _delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._flush()

    @property
    def own_device_id_or_none(self) -> Optional[int]:
        v = self._data.get("/own_device_id")
        return v if isinstance(v, int) else None


class XEP_0384Impl(XEP_0384):
    """OMEMO plugin implementation with BTBV (blind trust on first
    use) — matches our omemo-rs ``TrustPolicy::Tofu``. Keeps the
    interop pair semantically equivalent on the trust side."""

    default_config = {
        "fallback_message": "This message is OMEMO encrypted.",
        "json_file_path": None,
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__storage: Storage  # set in plugin_init

    def plugin_init(self) -> None:
        if not self.json_file_path:
            raise RuntimeError("json_file_path required")
        self.__storage = JsonStorage(Path(self.json_file_path))
        super().plugin_init()

    @property
    def storage(self) -> Storage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        return True

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str],
    ) -> None:
        log.info("Blindly trusted: %s", blindly_trusted)

    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str],
    ) -> None:
        # BTBV enabled — should never reach here.
        log.warning("Manual trust requested for: %s", manually_trusted)


register_plugin(XEP_0384Impl)


class InteropClient(ClientXMPP):
    """One-shot send-or-receive XMPP client. Exits after the
    requested action completes (or hits its deadline)."""

    def __init__(
        self,
        jid: str,
        password: str,
        mode: str,
        peer: Optional[str],
        body: Optional[str],
        deadline_secs: int,
        backend: str = "twomemo",
    ) -> None:
        super().__init__(jid, password)
        self.mode = mode
        self.peer = peer
        self.body = body
        self.deadline_secs = deadline_secs
        self.backend = backend  # "twomemo" or "oldmemo"
        # Drives the single end-of-test event.
        self.done: asyncio.Event = asyncio.Event()
        # `recv` mode populates this with the recovered body so the
        # main coroutine can print + exit cleanly.
        self.received_body: Optional[str] = None
        self.received_from: Optional[str] = None

        self.add_event_handler("session_start", self.start)
        self.register_handler(CoroutineCallback(
            "Messages",
            MatchXPath(f"{{{self.default_ns}}}message"),
            self.message_handler,  # type: ignore[arg-type]
        ))

    async def start(self, _event: Any) -> None:
        self.send_presence()
        # Don't try to fetch a roster — Prosody-tests have no contacts
        # and the request just adds latency.
        # Wait for slixmpp-omemo to finish its initial publish round
        # (device list + bundle for both `urn:xmpp:omemo:2` and the
        # legacy `eu.siacs.conversations.axolotl` namespace). 5s is
        # enough on the localhost Prosody fixture; CI / production
        # would want a real "ready" event from the plugin.
        await asyncio.sleep(5.0)
        plugin: XEP_0384Impl = self["xep_0384"]
        storage = plugin.storage
        device_id: Optional[int] = None
        if isinstance(storage, JsonStorage):
            device_id = storage.own_device_id_or_none
        # READY line is consumed by the calling test to know it's
        # safe to send / fetch our bundle. STDERR-side logs and
        # other STDOUT can come and go around it; the consumer
        # only needs to grep for `^READY `.
        sys.stdout.write(f"READY {device_id if device_id is not None else 0}\n")
        sys.stdout.flush()

        if self.mode == "send":
            await self._send_once()

    async def _send_once(self) -> None:
        """Send one chat body in the configured backend.

        * `twomemo` (OMEMO 2) wraps the body in an XEP-0420 SCE
          envelope and bypasses `xep_0384.encrypt_message` because
          slixmpp-omemo 2.1.0's SCE encrypt path is unimplemented
          (it short-circuits on `urn:xmpp:omemo:2` — see the plugin
          source comment that ends `... IF I HAD ONE!!!`). We call
          `SessionManager.encrypt` directly with the envelope bytes.
        * `oldmemo` (OMEMO 0.3) uses raw body bytes (no SCE) — the
          path slixmpp-omemo natively supports — and lets the
          plugin's normal `encrypt_message` flow run.
        """

        import base64
        import os
        import xml.etree.ElementTree as ET_std
        from datetime import datetime, timezone

        import twomemo
        import twomemo.etree
        import oldmemo
        import oldmemo.etree

        # NOTE: Don't `ET_std.register_namespace("", twomemo_ns)` —
        # ET applies that registration globally, and slixmpp will
        # then start emitting the outer `<message>` with the
        # OMEMO 2 namespace as the default and `<message>` itself
        # under an `ns0:` prefix. Leaving the auto-`ns0:` on
        # `<encrypted>` is fine: omemo-rs uses minidom's
        # namespace-aware matching, so the prefix is invisible to
        # our parser.

        assert self.peer is not None and self.body is not None
        xep_0384: XEP_0384 = self["xep_0384"]

        await xep_0384.refresh_device_lists({JID(self.peer)})
        sm = await xep_0384.get_session_manager()

        if self.backend == "oldmemo":
            # OMEMO 0.3: raw body bytes, no SCE envelope. omemo-rs's
            # receive_followup_oldmemo / receive_first_message_oldmemo
            # consume the body bytes directly.
            plaintext = self.body.encode("utf-8")
            namespace = oldmemo.oldmemo.NAMESPACE
            omemo_messages, errs = await sm.encrypt(
                frozenset({self.peer}),
                {namespace: plaintext},
                backend_priority_order=[namespace],
                identifier=None,
            )
        else:
            # OMEMO 2 path — wrap in XEP-0420 SCE envelope.
            rpad = base64.b64encode(os.urandom(16)).decode()
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            body_escaped = (
                self.body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            envelope = (
                '<envelope xmlns="urn:xmpp:sce:1">'
                f'<content><body xmlns="jabber:client">{body_escaped}</body></content>'
                f"<rpad>{rpad}</rpad>"
                f'<time stamp="{ts}"/>'
                f'<to jid="{self.peer}"/>'
                f'<from jid="{self.boundjid.bare}"/>'
                "</envelope>"
            ).encode("utf-8")
            namespace = twomemo.twomemo.NAMESPACE
            omemo_messages, errs = await sm.encrypt(
                frozenset({self.peer}),
                {namespace: envelope},
                backend_priority_order=[namespace],
                identifier=None,
            )
        if errs:
            log.warning("non-critical encrypt errors: %s", errs)
        if not omemo_messages:
            log.error("session_manager.encrypt produced 0 messages — peer bundle missing?")
            self.done.set()
            return

        sent = 0
        for omemo_msg in omemo_messages.keys():
            if omemo_msg.namespace != namespace:
                continue
            if self.backend == "oldmemo":
                et_elt = oldmemo.etree.serialize_message(omemo_msg)
            else:
                et_elt = twomemo.etree.serialize_message(omemo_msg)
            msg = self.make_message(mto=JID(self.peer), mtype="chat")
            msg.xml.append(et_elt)
            msg.send()
            sent += 1
        log.info(
            "Sent %d byte body to %s in %d %s message(s)",
            len(self.body),
            self.peer,
            sent,
            self.backend,
        )
        # Let the wire flush before main() disconnects.
        await asyncio.sleep(2)
        self.done.set()

    async def message_handler(self, stanza: Message) -> None:
        if self.mode != "recv":
            return
        if stanza["type"] not in {"chat", "normal"}:
            return
        xep_0384: XEP_0384 = self["xep_0384"]
        namespace = xep_0384.is_encrypted(stanza)
        if namespace is None:
            return
        body: Optional[str] = None
        try:
            decrypted, _info = await xep_0384.decrypt_message(stanza)
            raw = decrypted["body"]
            if raw:
                body = str(raw)
        except NotImplementedError as e:
            # slixmpp-omemo doesn't unwrap XEP-0420 SCE envelopes for
            # the twomemo (urn:xmpp:omemo:2) namespace yet. The
            # plaintext bytes are leaked through the exception
            # message; we parse them ourselves so the cross-impl
            # round-trip can complete. (For OMEMO 0.3 there is no
            # SCE envelope, so this NotImplementedError path doesn't
            # fire — the regular decrypt branch above succeeds.)
            unwrapped = unwrap_sce_envelope_from_error(str(e))
            if unwrapped is not None:
                body = unwrapped
            else:
                log.warning("decrypt failed (no SCE envelope): %s", e)
        except Exception as e:
            log.warning("decrypt failed: %s", e)
        if body is None:
            return
        self.received_body = body
        self.received_from = str(stanza["from"])
        log.info("Received %s: %s", self.received_from, self.received_body)
        self.done.set()


def build_client(args: argparse.Namespace) -> InteropClient:
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    json_path = data_dir / f"{args.jid}.json"

    client = InteropClient(
        jid=args.jid,
        password=args.password,
        mode=args.mode,
        peer=getattr(args, "peer", None),
        body=getattr(args, "body", None),
        deadline_secs=args.timeout,
        backend=getattr(args, "backend", "twomemo"),
    )
    # Plaintext localhost only — match omemo-rs-cli's --insecure-tcp.
    # Slixmpp picks this up from the `address` keyword on connect.
    client.register_plugin("xep_0199")  # XMPP Ping
    client.register_plugin("xep_0380")  # Explicit Message Encryption
    client.register_plugin(
        "xep_0384",
        {"json_file_path": str(json_path)},
        module=sys.modules[__name__],
    )
    return client


async def amain(args: argparse.Namespace) -> int:
    client = build_client(args)

    host, port_s = args.address.rsplit(":", 1)
    port = int(port_s)

    # Localhost-integration Prosody serves a self-signed cert and
    # advertises STARTTLS. slixmpp 1.15's default ssl context
    # rejects the cert; for the test fixture we disable verification
    # entirely. (Production callers MUST verify; this is the
    # equivalent of omemo-rs-cli's --insecure-tcp.)
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.ssl_context = ctx

    client.connect(host=host, port=port)

    try:
        await asyncio.wait_for(client.done.wait(), timeout=args.timeout)
    except asyncio.TimeoutError:
        log.error("timed out after %ds", args.timeout)
        client.disconnect()
        return 2

    if args.mode == "recv":
        if client.received_body is None:
            log.error("recv exited without receiving a message")
            client.disconnect()
            return 3
        # stdout format mirrors omemo-rs-cli's recv: "<from>: <body>"
        sys.stdout.write(f"{client.received_from}: {client.received_body}\n")
        sys.stdout.flush()

    client.disconnect()
    # Give the disconnect a moment to flush.
    try:
        await asyncio.wait_for(client.disconnected, timeout=5)
    except (asyncio.TimeoutError, AttributeError):
        pass
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OMEMO 2 interop client (slixmpp + python-omemo)"
    )
    parser.add_argument("--jid", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--address",
        default="127.0.0.1:5222",
        help="host:port for plaintext XMPP (matches omemo-rs-cli --insecure-tcp)",
    )
    parser.add_argument(
        "--data-dir",
        default="./python-omemo-data",
        help="directory holding the per-account JSON storage",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="end-to-end deadline in seconds (login + send/recv)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable INFO logging"
    )
    parser.add_argument(
        "--backend",
        choices=["twomemo", "oldmemo"],
        default="twomemo",
        help="OMEMO wire-format backend (default: twomemo / OMEMO 2)",
    )

    sub = parser.add_subparsers(dest="mode", required=True)

    sub_send = sub.add_parser("send", help="send one body to a peer and exit")
    sub_send.add_argument("--peer", required=True)
    sub_send.add_argument("--body", required=True)

    sub.add_parser("recv", help="wait for one inbound encrypted message")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(name)s %(levelname)s: %(message)s",
    )

    rc = asyncio.run(amain(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
