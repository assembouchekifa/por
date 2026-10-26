"""Relay node (UML box: ``node``).

A node peels exactly one encrypted layer, forwards the rest to the next
hop, and remembers where the reply must go.  Every message gets a fresh
per-hop ``msg_id`` so ids cannot collide across circuits, and replies are
matched by that id rather than by connection order.
"""

import threading
import time

from . import protocol
from .config import DEFAULT
from .errors import CryptoError, ProtocolError
from .keys import Rsa
from .link import Link, connect
from .link_pool import LinkPool
from .pending import PendingTable
from .service import ServiceBase
from .wire import (
    b64,
    decode_json,
    new_id,
    parse_addr,
    require_int,
    require_str,
    unb64,
)

PENDING_TTL = DEFAULT.pending_ttl


class Node(ServiceBase):
    def __init__(
        self,
        node_id: str,
        host: str = "127.0.0.1",
        port: int = 9001,
        dir_host: str = "127.0.0.1",
        dir_port: int = 9000,
        keysize: int = None,
        *,
        settings=DEFAULT,
    ):
        super().__init__(host, port, settings=settings, name=f"node.{node_id}")
        self.node_id = node_id
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(settings.key_size if keysize is None else keysize)

        self._dir_link = None
        self._dir_lock = threading.Lock()
        self._links = LinkPool(
            f"{self._name}.peers",
            self._connect_peer,
            self._read_peer,
        )
        self._dest_links = LinkPool(
            f"{self._name}.dest",
            self._connect_dest,
            self._read_dest,
        )
        self._pending = PendingTable(
            ttl=settings.pending_ttl,
            max_entries=settings.max_pending,
        )

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        self._bind(self.host, self.port, backlog=16)
        try:
            self._register()
        except BaseException:
            super().stop()
            raise
        self._pending.clear()
        self._spawn(self._keepalive, name=f"{self._name}-keepalive")
        if background:
            self._spawn(self._accept_loop, name=f"{self._name}-accept")
        else:
            self._accept_loop()
        return self

    def stop(self) -> None:
        if self._running:
            try:
                self._query({"type": "unregister", "id": self.node_id})
            except (ConnectionError, OSError, ProtocolError):
                pass
        # Stop new work before tearing links down.  A keepalive thread may
        # be in the middle of a re-registration; _register() checks this
        # flag before publishing a new directory link.
        self._running = False
        self._stop.set()
        self._links.close_all()
        self._dest_links.close_all()
        with self._dir_lock:
            link, self._dir_link = self._dir_link, None
        if link is not None:
            link.close()
        super().stop()
        self._pending.clear()

    # -- directory ------------------------------------------------------
    def _connect_directory(self) -> Link:
        link = connect(
            self.dir_addr[0],
            self.dir_addr[1],
            timeout=self.settings.connect_timeout,
            max_frame_size=self.settings.max_frame_size,
        )
        link.settimeout(self.settings.query_timeout)
        return link

    def _register(self) -> None:
        link = connect(
            self.dir_addr[0],
            self.dir_addr[1],
            timeout=self.settings.connect_timeout,
            max_frame_size=self.settings.max_frame_size,
        )
        try:
            link.settimeout(self.settings.handshake_timeout)
            link.send({
                "type": "register",
                "version": protocol.PROTOCOL_VERSION,
                "id": self.node_id,
                "kind": "node",
                "host": self.host,
                "port": self.port,
                "public_key": self.rsa.export_public(),
            })
            protocol.prove_key(
                link.sock,
                self.rsa,
                max_frame_size=self.settings.max_frame_size,
            )
            reply = link.recv()
            if reply.get("type") != "ok":
                raise ConnectionError(
                    f"directory refused registration: {reply}"
                )
            link.settimeout(self.settings.query_timeout)
        except BaseException:
            link.close()
            raise

        if not self._running:
            link.close()
            raise ConnectionError("node is stopping")

        with self._dir_lock:
            old, self._dir_link = self._dir_link, link
        if old is not None and old is not link:
            old.close()
        self._log.info(
            "registered as %s at %s:%s", self.node_id, self.host, self.port
        )

    def _query(self, msg: dict) -> dict:
        """Send one request and read the answer atomically."""
        with self._dir_lock:
            link = self._dir_link
            if link is None:
                link = self._connect_directory()
                self._dir_link = link
            try:
                link.send(msg)
                return link.recv()
            except (ConnectionError, OSError, ProtocolError):
                if self._dir_link is link:
                    self._dir_link = None
                link.close()
                raise

    def get_client(self, peer_id: str):
        reply = self._query({"type": "get_client", "id": peer_id})
        if reply.get("type") == "error":
            raise ProtocolError(str(reply.get("error", "directory error")))
        if reply.get("type") != "client_data":
            raise ProtocolError(
                f"unexpected directory reply: {reply.get('type')!r}"
            )
        return reply.get("client")

    def _keepalive(self) -> None:
        while self._running:
            if self._stop.wait(self.settings.heartbeat_every):
                break
            try:
                reply = self._query({
                    "type": "heartbeat",
                    "id": self.node_id,
                })
            except (ConnectionError, OSError, ProtocolError):
                reply = None
            if reply is None or reply.get("type") != "ok":
                self._recover_directory()
            try:
                self._ping_links()
            except Exception:
                self._log.exception("link ping pass failed")
            self._pending.sweep()

    def _recover_directory(self) -> None:
        with self._dir_lock:
            link, self._dir_link = self._dir_link, None
        if link is not None:
            link.close()
        while self._running:
            try:
                self._register()
            except (ConnectionError, OSError, ProtocolError) as exc:
                self._log.warning("directory unavailable: %s", exc)
                if self._stop.wait(self.settings.recover_every):
                    return
                continue
            self._log.info("back with the directory: re-registered")
            return

    # -- incoming links -------------------------------------------------
    def _handle_link(self, link: Link) -> None:
        try:
            while self._running:
                msg = link.recv()
                kind = msg["type"]
                if kind == "forward":
                    self._handle_forward(msg, link)
                elif kind == "ping":
                    link.send({"type": "pong", "id": self.node_id})
                elif kind == "close":
                    break
                else:
                    raise ProtocolError(f"unexpected message type: {kind!r}")
        finally:
            self._pending.forget_link(link)

    def _handle_forward(self, msg: dict, back_link: Link) -> None:
        return_id = msg.get("msg_id")
        if return_id is None:
            return_id = new_id()
        else:
            return_id = require_str(msg, "msg_id", max_length=256)
        payload = unb64(require_str(msg, "payload"))
        inner = self.peel_layer(payload)

        reply_pub = inner.get("reply_pub")
        reply_key = None
        if reply_pub is not None:
            if not isinstance(reply_pub, str):
                raise ProtocolError("'reply_pub' must be a string")
            if len(reply_pub) > self.settings.max_public_key_length:
                raise ProtocolError("'reply_pub' is too long")
            reply_key = Rsa.import_public(reply_pub)

        final = inner.get("final", False)
        if not isinstance(final, bool):
            raise ProtocolError("'final' must be a boolean")

        if final:
            destination = require_str(
                inner,
                "next",
                max_length=self.settings.max_host_length + 8,
            )
            require_str(inner, "payload")
        else:
            next_id = require_str(
                inner, "next", max_length=self.settings.max_id_length
            )
            inner_payload = require_str(inner, "payload")

        hop_id = new_id()
        self._pending.remember(hop_id, back_link, reply_key, return_id)

        if final:
            self._log.info(
                "final layer -> deliver to %s (msg %s)",
                destination,
                hop_id[:8],
            )
            self._spawn(
                self._deliver_and_return,
                inner,
                hop_id,
                name=f"{self._name}-deliver",
            )
            return

        self._log.info(
            "peeled 1 layer -> next hop %s (msg %s)",
            next_id,
            hop_id[:8],
        )
        try:
            self.forward(next_id, inner_payload, hop_id)
        except (ConnectionError, OSError, ProtocolError) as exc:
            self._pending.forget(hop_id)
            self._log.warning(
                "cannot forward msg %s to %s: %s",
                hop_id[:8],
                next_id,
                exc,
            )

    # -- onion work -----------------------------------------------------
    def peel_layer(self, payload: bytes) -> dict:
        """Peel exactly one layer and return the inner envelope."""
        try:
            plain = self.rsa.decrypt_message(payload)
        except CryptoError as exc:
            raise ProtocolError(f"cannot peel layer: {exc}") from exc
        return decode_json(plain, "onion layer")

    def forward(self, next_id: str, payload_b64: str, msg_id: str) -> None:
        """Send to the next hop over its pooled link, retrying one dial."""
        last_error = None
        for attempt in (1, 2):
            link = None
            try:
                link = self._links.get(next_id)
                link.send({
                    "type": "forward",
                    "from": self.node_id,
                    "msg_id": msg_id,
                    "payload": payload_b64,
                })
                return
            except ProtocolError:
                raise
            except (ConnectionError, OSError) as exc:
                last_error = exc
                if link is not None:
                    self._links.drop(next_id, link)
                if attempt == 2:
                    raise
        raise last_error  # pragma: no cover - loop always returns/raises

    # -- pooled peer links ----------------------------------------------
    def _connect_peer(self, next_id: str) -> Link:
        entry = self.get_client(next_id)
        if entry is None:
            raise ConnectionError(
                f"unknown next hop {next_id!r} (not in directory)"
            )
        if entry.get("kind", "node") != "node":
            raise ProtocolError(f"next hop {next_id!r} is not a relay node")
        host = require_str(
            entry, "host", max_length=self.settings.max_host_length
        )
        port = require_int(entry, "port", min_value=1, max_value=65535)
        self._log.info("opening link to next hop %s (%s:%s)", next_id, host, port)
        return connect(
            host,
            port,
            timeout=self.settings.connect_timeout,
            max_frame_size=self.settings.max_frame_size,
        )

    def _read_peer(self, next_id: str, entry) -> None:
        while self._running:
            msg = entry.link.recv()
            kind = msg["type"]
            if kind == "reply":
                self._return_reply(msg)
            elif kind == "pong":
                entry.pong.set()
            else:
                raise ProtocolError(
                    f"unexpected message from peer {next_id}: {kind!r}"
                )

    def _ping_links(self) -> None:
        entries = self._links.snapshot()
        waiting = []
        for peer_id, entry in entries:
            if not self._running:
                return
            entry.pong.clear()
            try:
                entry.link.send({"type": "ping", "id": self.node_id})
            except (ConnectionError, OSError):
                self._links.drop(peer_id, entry.link)
                continue
            waiting.append((peer_id, entry))

        deadline = time.monotonic() + self.settings.link_ping_timeout
        for peer_id, entry in waiting:
            left = max(0.0, deadline - time.monotonic())
            if not entry.pong.wait(left):
                self._log.warning(
                    "peer %s missed its pong, dropping the link", peer_id
                )
                self._links.drop(peer_id, entry.link)

    # -- exit role ------------------------------------------------------
    def _connect_dest(self, dest: str) -> Link:
        host, port = parse_addr(dest)
        return connect(
            host,
            port,
            timeout=self.settings.connect_timeout,
            max_frame_size=self.settings.max_frame_size,
        )

    def _read_dest(self, dest: str, entry) -> None:
        while self._running:
            msg = entry.link.recv()
            if msg["type"] != "reply":
                raise ProtocolError(
                    f"unexpected message from destination {dest}: "
                    f"{msg['type']!r}"
                )
            msg_id = require_str(msg, "msg_id", max_length=256)
            text = msg.get("text", "")
            if not isinstance(text, str):
                raise ProtocolError("destination reply text must be a string")
            self._return_reply({
                "type": "reply",
                "msg_id": msg_id,
                "payload": b64(text.encode("utf-8")),
            })

    def _deliver_and_return(
        self,
        envelope: dict,
        hop_id: str,
    ) -> None:
        dest = require_str(
            envelope, "next", max_length=self.settings.max_host_length + 8
        )
        try:
            payload = unb64(require_str(envelope, "payload"))
            text = payload.decode("utf-8")
        except (ProtocolError, UnicodeDecodeError) as exc:
            self._pending.forget(hop_id)
            self._log.warning("cannot decode exit payload: %s", exc)
            return
        if len(text.encode("utf-8")) > self.settings.max_text_bytes:
            self._pending.forget(hop_id)
            self._log.warning("exit payload exceeds max_text_bytes")
            return

        deliver = {
            "type": "deliver",
            "msg_id": hop_id,
            "from": self.node_id,
            "text": text,
        }
        last_error = None
        for attempt in (1, 2):
            link = None
            try:
                link = self._dest_links.get(dest)
                link.send(deliver)
                self._log.info(
                    "exit delivered %d bytes to %s", len(payload), dest
                )
                return
            except ProtocolError as exc:
                last_error = exc
                if link is not None:
                    self._dest_links.drop(dest, link)
                if attempt == 2:
                    break
            except (ConnectionError, OSError) as exc:
                last_error = exc
                if link is not None:
                    self._dest_links.drop(dest, link)
                if attempt == 2:
                    break
        self._pending.forget(hop_id)
        self._log.warning(
            "exit delivery to %s failed: %s", dest, last_error
        )

    # -- reply routing --------------------------------------------------
    def _return_reply(self, msg: dict) -> None:
        msg_id = require_str(msg, "msg_id", max_length=256)
        payload_b64 = require_str(msg, "payload", allow_empty=True)
        pending = self._pending.pop(msg_id)
        if pending is None:
            return  # link died, reply too late, or duplicate
        blob = unb64(payload_b64)
        if pending.reply_key is not None:
            try:
                blob = self.rsa.encrypt_for(blob, pending.reply_key)
            except (ProtocolError, CryptoError) as exc:
                self._log.warning("cannot add reply layer: %s", exc)
                return
        try:
            pending.back_link.send({
                "type": "reply",
                "msg_id": pending.return_id,
                "payload": b64(blob),
            })
        except (ConnectionError, OSError, ProtocolError):
            return

    # -- compatibility / tests ------------------------------------------
    def _sweep_pending(self) -> int:
        return self._pending.sweep()

    def _get_link(self, next_id: str) -> Link:
        return self._links.get(next_id)

    def _drop_link(self, next_id: str, link: Link) -> None:
        self._links.drop(next_id, link)

    def _get_dest_link(self, dest: str) -> Link:
        return self._dest_links.get(dest)

    def _drop_dest_link(self, dest: str, link: Link) -> None:
        self._dest_links.drop(dest, link)
