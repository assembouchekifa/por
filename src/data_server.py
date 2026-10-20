"""Directory authorities server (UML box: ``data server``).

Members from the design:
    - dir client  : socket   : live registry of nodes/clients (id -> entry)
    - getclient    -> get_client()

Nodes register here - and registration is the *only* place where keys are
tested: the directory challenges the node with a nonce encrypted under the
node's public key and drops anyone who cannot decrypt it.  The directory
owns no keypair of its own.

A live node keeps its entry fresh with a ``heartbeat`` every
:data:`protocol.HEARTBEAT_EVERY` seconds; :meth:`cleanup_stale` sweeps
entries every :data:`protocol.CLEANUP_EVERY` seconds and forgets anyone
silent for longer than :data:`protocol.STALE_AFTER`.  A dropped node that
comes back simply re-registers (its next heartbeat gets an ``error``
reply, which tells it to register again).
"""

import socket
import threading
import time

from . import protocol


class DataServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 9000):
        self.host = host
        self.port = port
        self.dir_client = {}  # id -> {"host", "port", "kind", "public_key", "sock", "seen"}
        self._lock = threading.Lock()
        self._server = None
        self._running = False
        self._stop = threading.Event()

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(32)
        self._server = srv
        self._running = True
        self._stop.clear()
        if background:
            threading.Thread(target=self._accept_loop, daemon=True).start()
            threading.Thread(target=self._cleanup_loop, daemon=True).start()
        else:
            # foreground: run the sweep next to the accept loop
            threading.Thread(target=self._cleanup_loop, daemon=True).start()
            self._accept_loop()
        return self

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        # tear down live links too, so registered nodes *notice* we are gone
        # (their next heartbeat fails -> they re-register when we come back)
        with self._lock:
            socks = list({entry["sock"] for entry in self.dir_client.values()})
            self.dir_client.clear()
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass
        if self._server is not None:
            # wake the blocked accept() before closing: a listener stuck in
            # accept() keeps the port bound, and the next bind() would fail
            # with "address already in use"
            try:
                socket.create_connection((self.host, self.port), timeout=1).close()
            except OSError:
                pass
            try:
                self._server.close()
            except OSError:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                sock, _addr = self._server.accept()
            except OSError:
                break
            if not self._running:  # the wake-up connection from stop()
                sock.close()
                break
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock):
        peer_id = None
        try:
            while True:
                msg = protocol.recv_msg(sock)
                if msg.get("type") == "register":
                    peer_id = msg["id"]
                reply = self._dispatch(msg, sock)
                if reply is None:
                    break
                protocol.send_msg(sock, reply)
        except (ConnectionError, OSError, protocol.ProtocolError):
            pass
        finally:
            # drop whoever registered on this socket
            with self._lock:
                for key, entry in list(self.dir_client.items()):
                    if entry.get("sock") is sock and (peer_id is None or key == peer_id):
                        del self.dir_client[key]
            sock.close()

    def _dispatch(self, msg, sock):
        kind = msg.get("type")

        if kind == "register":
            # the one and only key test: does the node really own the
            # private key of the public key it is registering with?
            try:
                protocol.test_key(sock, msg["public_key"])
            except protocol.ProtocolError as exc:
                return {"type": "error", "error": str(exc)}
            with self._lock:
                self.dir_client[msg["id"]] = {
                    "host": msg["host"],
                    "port": msg["port"],
                    "kind": msg.get("kind", "node"),
                    "public_key": msg["public_key"],
                    "sock": sock,
                    "seen": time.time(),
                }
            return {"type": "ok"}

        if kind == "heartbeat":  # keepalive from a registered node
            with self._lock:
                entry = self.dir_client.get(msg.get("id"))
                if entry is None:
                    # we swept it (or never saw it) -> tell the node so it
                    # knows to register again when it comes back
                    return {"type": "error", "error": "not registered"}
                entry["seen"] = time.time()
            return {"type": "ok"}

        if kind == "get_data_of_network":
            with self._lock:
                nodes = [
                    {k: v for k, v in entry.items() if k not in ("sock", "seen")}
                    | {"id": node_id}
                    for node_id, entry in self.dir_client.items()
                    if entry["kind"] == "node"
                ]
            return {"type": "network_data", "nodes": nodes}

        if kind == "get_client":
            return {"type": "client_data", "client": self.get_client(msg.get("id"))}

        if kind == "unregister":
            with self._lock:
                self.dir_client.pop(msg.get("id"), None)
            return {"type": "ok"}

        return {"type": "error", "error": f"unknown message type: {kind!r}"}

    # -- heartbeat cleanup ---------------------------------------------
    def _cleanup_loop(self):
        """Sweep stale entries every ``protocol.CLEANUP_EVERY`` seconds."""
        while self._running:
            if self._stop.wait(protocol.CLEANUP_EVERY):
                break
            self.cleanup_stale()

    def cleanup_stale(self) -> int:
        """Forget every node that has been silent for ``STALE_AFTER`` s.

        The entry goes away, its (still open) socket does not - if that
        node ever speaks again its heartbeat gets an ``error`` reply and
        it re-registers on a fresh connection.  Returns the drop count.
        """
        now = time.time()
        dropped = []
        with self._lock:
            for node_id, entry in list(self.dir_client.items()):
                if now - entry["seen"] > protocol.STALE_AFTER:
                    del self.dir_client[node_id]
                    dropped.append(node_id)
        for node_id in dropped:
            print(f"[dir] dropped {node_id}: no heartbeat for "
                  f"{protocol.STALE_AFTER}s", flush=True)
        return len(dropped)

    # -- UML API --------------------------------------------------------
    def get_client(self, client_id: str):
        """Public info about one registered node/client (or None)."""
        with self._lock:
            entry = self.dir_client.get(client_id)
            if entry is None:
                return None
            return {k: v for k, v in entry.items() if k not in ("sock", "seen")} | {"id": client_id}
