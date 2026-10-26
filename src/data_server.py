"""Directory authorities server (UML box: ``data server``).

The directory is a public phone-book.  Nodes register here and prove
ownership of their published key; the directory keeps no keypair of its
own and never sees message contents.
"""

import threading
import time

from . import protocol
from .config import DEFAULT
from .errors import ProtocolError
from .link import Link
from .service import ServiceBase
from .wire import require_int, require_list, require_str


class DataServer(ServiceBase):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        *,
        settings=DEFAULT,
    ):
        super().__init__(host, port, settings=settings, name="dir")
        self.dir_client = {}
        self._lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        self._bind(self.host, self.port, backlog=32)
        self._spawn(self._cleanup_loop, name="dir-cleanup")
        if background:
            self._spawn(self._accept_loop, name="dir-accept")
        else:
            self._accept_loop()
        return self

    def stop(self) -> None:
        with self._lock:
            self.dir_client.clear()
        super().stop()

    def _cleanup_loop(self) -> None:
        while self._running:
            if self._stop.wait(self.settings.cleanup_every):
                break
            self.cleanup_stale()

    # -- incoming connections ------------------------------------------
    def _handle_link(self, link: Link) -> None:
        try:
            while self._running:
                msg = link.recv()
                try:
                    reply = self._dispatch(msg, link)
                except ProtocolError as exc:
                    reply = {"type": "error", "error": str(exc)}
                except Exception:
                    self._log.exception("internal error while dispatching")
                    reply = {"type": "error", "error": "internal error"}
                if reply is None:
                    break
                link.send(reply)
        finally:
            with self._lock:
                for key, entry in list(self.dir_client.items()):
                    if entry["link"] is link:
                        del self.dir_client[key]

    # -- message router -------------------------------------------------
    def _dispatch(self, msg: dict, link: Link):
        kind = msg["type"]

        if kind == "register":
            return self._register(msg, link)

        if kind == "heartbeat":
            node_id = require_str(
                msg, "id", max_length=self.settings.max_id_length
            )
            with self._lock:
                entry = self.dir_client.get(node_id)
                if entry is None or entry["link"] is not link:
                    return {"type": "error", "error": "not registered"}
                entry["seen"] = time.monotonic()
            return {"type": "ok"}

        if kind == "get_data_of_network":
            with self._lock:
                nodes = [
                    self._public_entry(node_id, entry)
                    for node_id, entry in self.dir_client.items()
                    if entry["kind"] == "node"
                ]
            return {"type": "network_data", "nodes": nodes}

        if kind == "get_client":
            node_id = require_str(
                msg, "id", max_length=self.settings.max_id_length
            )
            return {"type": "client_data", "client": self.get_client(node_id)}

        if kind == "get_clients":
            ids = require_list(msg, "ids", max_length=1000)
            for node_id in ids:
                if not isinstance(node_id, str):
                    raise ProtocolError("'ids' must contain strings")
            with self._lock:
                clients = []
                for node_id in ids:
                    entry = self.dir_client.get(node_id)
                    if entry is not None:
                        clients.append(self._public_entry(node_id, entry))
            return {"type": "clients_data", "clients": clients}

        if kind == "unregister":
            node_id = require_str(
                msg, "id", max_length=self.settings.max_id_length
            )
            with self._lock:
                entry = self.dir_client.get(node_id)
                if entry is not None and entry["link"] is link:
                    del self.dir_client[node_id]
            return {"type": "ok"}

        raise ProtocolError(f"unknown message type: {kind!r}")

    def _register(self, msg: dict, link: Link) -> dict:
        version = msg.get("version", protocol.PROTOCOL_VERSION)
        if version != protocol.PROTOCOL_VERSION:
            raise ProtocolError(
                f"unsupported protocol version {version!r}; "
                f"this directory speaks version {protocol.PROTOCOL_VERSION}"
            )
        node_id = require_str(
            msg, "id", max_length=self.settings.max_id_length
        )
        host = require_str(
            msg, "host", max_length=self.settings.max_host_length
        )
        port = require_int(msg, "port", min_value=1, max_value=65535)
        kind = msg.get("kind", "node")
        if kind not in ("node", "client"):
            raise ProtocolError("'kind' must be 'node' or 'client'")
        public_key = require_str(
            msg,
            "public_key",
            max_length=self.settings.max_public_key_length,
        )

        old_timeout = link.sock.gettimeout()
        link.sock.settimeout(self.settings.handshake_timeout)
        try:
            protocol.test_key(
                link.sock,
                public_key,
                max_frame_size=self.settings.max_frame_size,
            )
        except ProtocolError as exc:
            return {"type": "error", "error": str(exc)}
        finally:
            try:
                link.sock.settimeout(old_timeout)
            except OSError:
                pass

        entry = {
            "host": host,
            "port": port,
            "kind": kind,
            "public_key": public_key,
            "link": link,
            "seen": time.monotonic(),
        }
        with self._lock:
            old = self.dir_client.get(node_id)
            self.dir_client[node_id] = entry
        if old is not None and old["link"] is not link:
            old["link"].close()
        return {"type": "ok"}

    # -- heartbeat cleanup ---------------------------------------------
    def cleanup_stale(self) -> int:
        now = time.monotonic()
        dropped = []
        with self._lock:
            for node_id, entry in list(self.dir_client.items()):
                if now - entry["seen"] > self.settings.stale_after:
                    del self.dir_client[node_id]
                    dropped.append((node_id, entry["link"]))
        for node_id, link in dropped:
            link.close()
            self._log.info(
                "dropped %s: no heartbeat for %ss",
                node_id,
                self.settings.stale_after,
            )
        return len(dropped)

    # -- UML API --------------------------------------------------------
    def get_client(self, client_id: str):
        with self._lock:
            entry = self.dir_client.get(client_id)
            if entry is None:
                return None
            return self._public_entry(client_id, entry)

    @staticmethod
    def _public_entry(node_id: str, entry: dict) -> dict:
        return {
            "id": node_id,
            "host": entry["host"],
            "port": entry["port"],
            "kind": entry["kind"],
            "public_key": entry["public_key"],
        }
