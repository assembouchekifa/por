"""Por client sender (UML box: ``client``, the sending half).

The sender fetches node keys from the directory, builds an onion, and
uses one persistent TCP link to the entry node.  Replies are matched by
``msg_id`` and held in a condition-backed inbox; ``wait_reply`` never
does the old get/put spin.  ``receive`` is the continuous variant used by
chat, and ``send_message(..., chat=True)`` leases the reply route so the
destination can send more than one reply.
"""

import random
import threading
import time

from .config import DEFAULT
from .directory_client import DirectoryClient
from .errors import CryptoError, ProtocolError
from .keys import Rsa
from .link import Link, connect
from .log import get_logger
from .wire import (
    b64,
    encode_json,
    fmt_addr,
    new_id,
    parse_addr,
    require_int,
    require_str,
    unb64,
)


class Client:
    def __init__(
        self,
        dir_host: str = "127.0.0.1",
        dir_port: int = 9000,
        keysize: int = None,
        *,
        settings=DEFAULT,
    ):
        self.settings = settings
        self.dir_addr = (dir_host, dir_port)
        self._dir = DirectoryClient(dir_host, dir_port, settings)
        self.rsa = Rsa(settings.key_size if keysize is None else keysize)
        self._reply_pub = self.rsa.export_public()

        self.node_path = []
        self.rsa_of_nodes = {}
        self._entry_link = None
        self._link_lock = threading.Lock()
        self._path_ids = None
        self._hops = 2
        self._bad_nodes = set()

        self._inbox = []
        self._inbox_cv = threading.Condition()
        self._layers = {}
        self._layers_lock = threading.Lock()

        self._pong = threading.Event()
        self._running = False
        self._stop = threading.Event()
        self._reader = None
        self._keepalive = None
        self._log = get_logger("client")

    # -- directory ------------------------------------------------------
    def get_data_of_network(self):
        return self._dir.get_network()

    def get_client(self, client_id: str):
        return self._dir.get_client(client_id)

    def get_clients(self, client_ids) -> dict:
        return self._dir.get_clients(client_ids)

    # -- sender mode ----------------------------------------------------
    def calc_path(self, network, length: int):
        """Pick ``length`` random nodes, avoiding recently bad ones."""
        if isinstance(length, bool) or not isinstance(length, int):
            raise RuntimeError("path length must be an integer")
        if not 1 <= length <= self.settings.max_hops:
            raise RuntimeError(
                f"path length must be between 1 and {self.settings.max_hops}"
            )

        nodes = []
        seen = set()
        for entry in network:
            if not isinstance(entry, dict):
                continue
            node_id = entry.get("id")
            if isinstance(node_id, str) and node_id not in seen:
                seen.add(node_id)
                nodes.append(entry)

        good = [
            entry for entry in nodes
            if entry["id"] not in self._bad_nodes
        ]
        if len(good) < length:
            self._bad_nodes.clear()
            good = nodes
        if length > len(good):
            raise RuntimeError(
                f"path of {length} hops requested, "
                f"but network only has {len(good)} nodes"
            )
        return random.sample(good, length)

    def _node_key(self, entry):
        pem = entry.get("public_key")
        if not isinstance(pem, str) or not pem:
            raise RuntimeError(
                f"node {entry.get('id')} published no public key "
                f"in the directory"
            )
        return Rsa.import_public(pem)

    def _validate_path_entry(self, entry: dict) -> dict:
        node_id = require_str(
            entry, "id", max_length=self.settings.max_id_length
        )
        host = require_str(
            entry, "host", max_length=self.settings.max_host_length
        )
        port = require_int(entry, "port", min_value=1, max_value=65535)
        if entry.get("kind", "node") != "node":
            raise RuntimeError(f"{node_id!r} is not a relay node")
        if not isinstance(entry.get("public_key"), str):
            raise RuntimeError(f"node {node_id} has no public key")
        return {
            "id": node_id,
            "host": host,
            "port": port,
            "kind": "node",
            "public_key": entry["public_key"],
        }

    def init_connection(self, hops: int = 2, path=None):
        """Build a circuit and open the one persistent entry link."""
        if path:
            ids = [str(node_id).strip() for node_id in path]
            if not ids or any(not node_id for node_id in ids):
                raise RuntimeError("path must contain non-empty node ids")
            if len(set(ids)) != len(ids):
                raise RuntimeError("path contains duplicate node ids")
            if len(ids) > self.settings.max_hops:
                raise RuntimeError(
                    f"path is longer than {self.settings.max_hops} hops"
                )
            entries = self._dir.get_clients(ids)
            missing = [node_id for node_id in ids if node_id not in entries]
            if missing:
                raise RuntimeError(
                    f"unknown nodes: {', '.join(missing)}"
                )
            self.node_path = [
                self._validate_path_entry(entries[node_id])
                for node_id in ids
            ]
            self._hops = len(self.node_path)
        else:
            if isinstance(hops, bool) or not isinstance(hops, int):
                raise RuntimeError("hops must be an integer")
            if not 1 <= hops <= self.settings.max_hops:
                raise RuntimeError(
                    f"hops must be between 1 and {self.settings.max_hops}"
                )
            self.node_path = self.calc_path(
                self.get_data_of_network(), hops
            )
            self._hops = hops

        self.rsa_of_nodes = {
            entry["id"]: self._node_key(entry)
            for entry in self.node_path
        }
        self._path_ids = [entry["id"] for entry in self.node_path]

        self._drop_entry()  # a rebuild replaces the old entry link
        entry = self.node_path[0]
        sock_link = connect(
            entry["host"],
            entry["port"],
            timeout=self.settings.connect_timeout,
            max_frame_size=self.settings.max_frame_size,
        )
        with self._link_lock:
            self._entry_link = sock_link
        self._running = True
        self._stop.clear()
        self._pong.clear()

        self._reader = threading.Thread(
            target=self._read_loop,
            args=(sock_link,),
            daemon=True,
            name="por-client-reader",
        )
        self._reader.start()
        if self._keepalive is None or not self._keepalive.is_alive():
            self._keepalive = threading.Thread(
                target=self._ping_loop,
                daemon=True,
                name="por-client-keepalive",
            )
            self._keepalive.start()
        return self.node_path

    def _read_loop(self, link: Link) -> None:
        try:
            while self._running and self._entry_link is link:
                msg = link.recv()
                kind = msg["type"]
                if kind == "reply":
                    self._on_reply(msg)
                elif kind == "pong":
                    self._pong.set()
                else:
                    raise ProtocolError(
                        f"unexpected message from entry node: {kind!r}"
                    )
        except (ConnectionError, OSError, ProtocolError):
            pass
        except Exception:
            self._log.exception("reply reader failed")
        finally:
            with self._link_lock:
                if self._entry_link is link:
                    self._entry_link = None
            link.close()

    def _on_reply(self, msg: dict) -> None:
        """Strip one layer per hop and hand the text to the inbox."""
        try:
            msg_id = require_str(msg, "msg_id", max_length=256)
            with self._layers_lock:
                layer_entry = self._layers.get(msg_id)
                if layer_entry is None:
                    self._log.warning(
                        "dropping reply for unknown/expired msg %s",
                        msg_id[:8],
                    )
                    return
                layers, _created, chat = layer_entry
                if chat:
                    # A chat route may return many replies.  Refresh its
                    # idle timestamp instead of consuming the route.
                    self._layers[msg_id] = (
                        layers,
                        time.monotonic(),
                        True,
                    )
                else:
                    del self._layers[msg_id]
            blob = unb64(require_str(msg, "payload", allow_empty=True))
            for _ in range(layers):
                blob = self.rsa.decrypt_message(blob)
            text = blob.decode("utf-8")
        except (ProtocolError, CryptoError, UnicodeDecodeError) as exc:
            self._log.warning("dropping malformed reply: %s", exc)
            return
        self._put_reply(msg_id, text)

    def _build_onion(
        self,
        target_addr: str,
        text: str,
        *,
        chat: bool = False,
    ) -> dict:
        envelope = {
            "next": target_addr,
            "final": True,
            "reply_pub": self._reply_pub,
            "payload": b64(text.encode("utf-8")),
        }
        if chat:
            envelope["chat"] = True
        for node in reversed(self.node_path):
            blob = self.rsa.encrypt_for(
                encode_json(envelope),
                self.rsa_of_nodes[node["id"]],
            )
            envelope = {
                "next": node["id"],
                "reply_pub": self._reply_pub,
                "payload": b64(blob),
            }
            if chat:
                envelope["chat"] = True
        return envelope

    def send_message(
        self,
        text: str,
        target_addr: str,
        *,
        chat: bool = False,
    ) -> str:
        """Onion-encrypt ``text`` and push it through the persistent link.

        Pass ``chat=True`` to keep its reply route open so the destination
        can send more than one reply.  Every relay then uses the reusable
        reply route until the pending/layer TTL expires.
        """
        if not self.node_path:
            raise RuntimeError("call init_connection() before send_message()")
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not isinstance(chat, bool):
            raise TypeError("chat must be a boolean")
        text_bytes = text.encode("utf-8")
        if len(text_bytes) > self.settings.max_text_bytes:
            raise ValueError(
                f"message is larger than {self.settings.max_text_bytes} bytes"
            )
        target_host, target_port = parse_addr(target_addr)
        target = fmt_addr(target_host, target_port)
        self._prune_layers()

        msg_id = new_id()
        with self._layers_lock:
            while msg_id in self._layers:  # pragma: no cover
                msg_id = new_id()

        try:
            for attempt in (1, 2):
                if self._entry_link is None:
                    self._ensure_link()

                envelope = self._build_onion(target, text, chat=chat)
                with self._layers_lock:
                    self._layers[msg_id] = (
                        len(self.node_path),
                        time.monotonic(),
                        chat,
                    )

                with self._link_lock:
                    link = self._entry_link
                if link is None:
                    if attempt == 2:
                        raise ConnectionError("entry link is not available")
                    continue
                try:
                    link.send({
                        "type": "forward",
                        "from": "client",
                        "msg_id": msg_id,
                        "payload": envelope["payload"],
                    })
                    return msg_id
                except (ConnectionError, OSError):
                    if self.node_path:
                        self._bad_nodes.add(self.node_path[0]["id"])
                    self._drop_entry()
                    if attempt == 2:
                        raise
        except BaseException:
            with self._layers_lock:
                self._layers.pop(msg_id, None)
            raise
        raise RuntimeError("unreachable")  # pragma: no cover

    def wait_reply(self, timeout: float = 15.0, msg_id: str = None) -> str:
        """Wait for a reply, optionally for one specific ``msg_id``."""
        if not self.node_path:
            raise RuntimeError("call init_connection() before wait_reply()")
        deadline = (
            None if timeout is None
            else time.monotonic() + max(0.0, timeout)
        )
        with self._inbox_cv:
            while True:
                for index, (got_id, text) in enumerate(self._inbox):
                    if msg_id is None or got_id == msg_id:
                        del self._inbox[index]
                        self._prune_layers()
                        return text
                if deadline is None:
                    wait_for = None
                else:
                    wait_for = deadline - time.monotonic()
                    if wait_for <= 0:
                        self._prune_layers()
                        raise TimeoutError(
                            "no reply from the circuit"
                            + (f" for {msg_id}" if msg_id else "")
                        )
                self._inbox_cv.wait(wait_for)

    def receive(self, timeout: float = None) -> tuple:
        """Wait for and return any ``(msg_id, text)`` reply.

        This is the continuous counterpart to :meth:`wait_reply`; chat
        clients use it from a reader thread while the main thread sends.
        """
        if not self.node_path:
            raise RuntimeError("call init_connection() before receive()")
        deadline = (
            None if timeout is None
            else time.monotonic() + max(0.0, timeout)
        )
        with self._inbox_cv:
            while not self._inbox:
                if deadline is None:
                    wait_for = None
                else:
                    wait_for = deadline - time.monotonic()
                    if wait_for <= 0:
                        self._prune_layers()
                        raise TimeoutError("no reply from the circuit")
                self._inbox_cv.wait(wait_for)
            msg_id, text = self._inbox.pop(0)
        self._prune_layers()
        return msg_id, text

    def _put_reply(self, msg_id: str, text: str) -> None:
        with self._inbox_cv:
            self._inbox.append((msg_id, text))
            self._inbox_cv.notify_all()

    def _prune_layers(self) -> None:
        now = time.monotonic()
        with self._layers_lock:
            for msg_id, entry in list(self._layers.items()):
                if now - entry[1] > self.settings.layers_ttl:
                    del self._layers[msg_id]

    # -- keepalive ------------------------------------------------------
    def ping(self) -> bool:
        with self._link_lock:
            link = self._entry_link
        if link is None:
            return False
        self._pong.clear()
        try:
            link.send({"type": "ping", "id": "client"})
        except (ConnectionError, OSError):
            self._drop_entry()
            return False
        if not self._pong.wait(self.settings.link_ping_timeout):
            self._drop_entry()
            return False
        return True

    def _ping_loop(self) -> None:
        while self._running:
            if self._stop.wait(self.settings.link_ping_every):
                break
            if self._entry_link is not None and not self.ping():
                self._log.warning(
                    "entry node went quiet - circuit dropped, "
                    "next send rebuilds it"
                )
            self._prune_layers()

    def _ensure_link(self) -> None:
        """Re-open the circuit: same ids first, random if they are gone."""
        if self._path_ids:
            try:
                self.init_connection(hops=self._hops, path=self._path_ids)
                return
            except (RuntimeError, ConnectionError, OSError, ProtocolError) as exc:
                if self._path_ids:
                    self._bad_nodes.add(self._path_ids[0])
                self._log.warning(
                    "old circuit is gone (%s), picking a fresh one", exc
                )
        self.init_connection(hops=self._hops)

    def _drop_entry(self) -> None:
        with self._link_lock:
            link, self._entry_link = self._entry_link, None
        if link is not None:
            link.close()

    # -- helpers --------------------------------------------------------
    def close(self) -> None:
        self._running = False
        self._stop.set()
        self._drop_entry()
        for thread in (self._reader, self._keepalive):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=self.settings.stop_join_timeout)
        with self._layers_lock:
            self._layers.clear()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
