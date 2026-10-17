"""Por client (UML box: ``client``).

Two personalities live in this class:

* **server** - the hidden destination (e.g. server B).  It calls
  :meth:`listen` and has no idea who connects to it: it only reads the
  message the exit node delivers and replies on the same socket.
* **sender** - client A.  It fetches the network data from the directory
  authorities, calculates a circuit (:meth:`calc_path`) and pushes an
  onion-encrypted message into it.

Only the *exit* node ever learns the sender's ``reply_to`` address: it
sits inside the innermost RSA layer, so no intermediate hop (and not the
destination itself) can see it.  That is why only the exit node is able to
return the reply to client A.
"""

import json
import random
import socket

from . import protocol
from .rsa import Rsa


class Client:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.host = host
        self.port = port
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self.node_path = []        # ordered [{"id", "host", "port", ...}]
        self.rsa_of_nodes = {}     # node id -> public key
        self._hop_socks = {}       # node id -> live socket
        self._listener = None

    # -- server mode ----------------------------------------------------
    def listen(self, host: str = None, port: int = 0):
        """Start the plain TCP server used to receive messages.

        Returns the real ``(host, port)`` we bound (port 0 -> ephemeral).
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host or self.host, port))
        srv.listen(8)
        self._listener = srv
        self.host, self.port = self.local_addr
        return self.local_addr

    @property
    def local_addr(self):
        if self._listener is None:
            raise RuntimeError("call listen() first")
        host, port = self._listener.getsockname()[:2]
        return host, port

    def accept_connection(self, timeout: float = None):
        """Wait for the exit node to connect and return the socket."""
        if self._listener is None:
            raise RuntimeError("call listen() first")
        if timeout is not None:
            self._listener.settimeout(timeout)
        try:
            conn, _addr = self._listener.accept()
        finally:
            if timeout is not None:
                self._listener.settimeout(None)
        conn.settimeout(timeout)
        return conn

    def recv_message(self, conn):
        """Read one delivered message. Returns ``(text, sender)``."""
        msg = protocol.recv_msg(conn)
        if msg.get("type") != "deliver":
            raise protocol.ProtocolError(f"unexpected message: {msg.get('type')!r}")
        return msg.get("text", ""), msg.get("from")

    def reply(self, conn, text: str) -> None:
        """Answer on the connection the exit node opened to us."""
        protocol.send_msg(conn, {"type": "reply", "text": text})

    # -- directory ------------------------------------------------------
    def get_data_of_network(self):
        """Ask the directory authorities server for the network view."""
        with socket.create_connection(self.dir_addr) as sock:
            protocol.send_msg(sock, {"type": "get_data_of_network"})
            reply = protocol.recv_msg(sock)
        return reply.get("nodes", [])

    def get_client(self, client_id: str):
        with socket.create_connection(self.dir_addr) as sock:
            protocol.send_msg(sock, {"type": "get_client", "id": client_id})
            reply = protocol.recv_msg(sock)
        return reply.get("client")

    # -- sender mode ----------------------------------------------------
    def calc_path(self, network, length: int):
        """Pick ``length`` random nodes (the ``clac path`` loop in the diagram)."""
        if length > len(network):
            raise RuntimeError(f"path of {length} hops requested, "
                               f"but network only has {len(network)} nodes")
        return random.sample(network, length)

    def init_connecting(self, hops: int = 2, path=None):
        """Build the circuit: explicit ``path`` of node ids, or ``hops`` random.

        The last node of the circuit is the exit node.
        """
        if path:
            self.node_path = [self.get_client(node_id) for node_id in path]
            missing = [entry["id"] for entry in self.node_path if entry is None]
            if missing:
                raise RuntimeError(f"unknown nodes: {', '.join(missing)}")
        else:
            self.node_path = self.calc_path(self.get_data_of_network(), hops)

        for entry in self.node_path:
            sock = socket.create_connection((entry["host"], entry["port"]))
            _peer_id, peer_pem = protocol.handshake(sock, self.rsa)
            self.rsa_of_nodes[entry["id"]] = self.rsa.import_public(peer_pem)
            self._hop_socks[entry["id"]] = sock
        return self.node_path

    def send_message(self, text: str, target_addr: str, reply_to: str = None) -> None:
        """Onion-encrypt ``text`` for ``target_addr`` (the destination server).

        ``reply_to`` is our own ``ip:port``; it is sealed inside the layer
        only the exit node can open.
        """
        if not self.node_path:
            raise RuntimeError("call init_connecting() before send_message()")

        # innermost layer: everything the exit node needs, nobody else
        envelope = {"next": target_addr, "final": True,
                    "payload": protocol.b64(text.encode())}
        if reply_to:
            envelope["reply_to"] = reply_to

        # wrap one RSA layer per hop, exit first (encdata1L, then encdat2L, ...)
        for entry in reversed(self.node_path):
            blob = self.rsa.encrypt_message(json.dumps(envelope).encode(),
                                            self.rsa_of_nodes[entry["id"]])
            envelope = {"next": entry["id"], "payload": protocol.b64(blob)}

        first = self.node_path[0]
        protocol.send_msg(self._hop_socks[first["id"]],
                          {"type": "forward", "payload": envelope["payload"]})

    def wait_reply(self, timeout: float = 15.0) -> str:
        """Wait for the exit node to return the destination's answer."""
        conn = self.accept_connection(timeout=timeout)
        try:
            text, _sender = self.recv_message(conn)
            return text
        finally:
            conn.close()

    # -- helpers --------------------------------------------------------
    def close(self) -> None:
        for sock in self._hop_socks.values():
            try:
                sock.close()
            except OSError:
                pass
        self._hop_socks.clear()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
