"""Directory authorities server (UML box: ``data server``).

Members from the design:
    - dir client  : socket   : live registry of nodes/clients (id -> entry)
    - getAllClient -> get_all_clients()
    - getclient    -> get_client()

Nodes register here and keep a light ``data`` keepalive; clients ask for
``get_data_of_network`` so they can calculate a path through the network.
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

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(32)
        self._server = srv
        self._running = True
        if background:
            threading.Thread(target=self._accept_loop, daemon=True).start()
        else:
            self._accept_loop()
        return self

    def stop(self) -> None:
        self._running = False
        if self._server is not None:
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

        if kind == "data":  # keepalive from a registered node
            with self._lock:
                entry = self.dir_client.get(msg.get("id"))
                if entry is not None:
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

        if kind == "get_all_clients":
            return {"type": "clients_data", "clients": self.get_all_clients()}

        if kind == "unregister":
            with self._lock:
                self.dir_client.pop(msg.get("id"), None)
            return {"type": "ok"}

        return {"type": "error", "error": f"unknown message type: {kind!r}"}

    # -- UML API --------------------------------------------------------
    def get_client(self, client_id: str):
        """Public info about one registered node/client (or None)."""
        with self._lock:
            entry = self.dir_client.get(client_id)
            if entry is None:
                return None
            return {k: v for k, v in entry.items() if k not in ("sock", "seen")} | {"id": client_id}

    def get_all_clients(self):
        """Public info about every registered node/client."""
        with self._lock:
            return [
                {k: v for k, v in entry.items() if k not in ("sock", "seen")} | {"id": cid}
                for cid, entry in self.dir_client.items()
            ]
