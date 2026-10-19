"""Por client sender (UML box: ``client``, the sending half).

The destination half of the design (server B) lives alone in
:mod:`src.server` - this class only *sends*:

* it fetches the network data from the directory authorities
  (:meth:`get_data_of_network`), calculates a circuit (:meth:`calc_path`)
  and pushes an onion-encrypted message into it.

There is **no client handshake**.  The circuit's nodes are directory data
(host, port and every node's public key come from the directory), and the
client's own public key rides inside each onion layer as ``reply_pub`` -
that is how replies find their way back.  Only one socket is opened, to
the entry (start) node; every other hop is reached by the nodes
themselves.

The reply does not need an address: it rides the circuit back.  Each node
adds one encryption layer with the sender's public key as it hands the
reply to the previous hop, and the sender strips them all at the end.
Every node only ever knows the hop before it and the hop after it.
"""

import json
import random
import socket

from . import protocol
from .rsa import Rsa


class Client:
    def __init__(self, dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self.node_path = []        # ordered [{"id", "host", "port", ...}]
        self.rsa_of_nodes = {}     # node id -> public key
        self._entry_sock = None    # the one live socket: us -> entry node

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

    def _node_key(self, entry) -> "Rsa":
        """Public key of a node, straight from directory data (no handshake)."""
        pem = entry.get("public_key")
        if not pem:
            raise RuntimeError(f"node {entry['id']} published no public key "
                               f"in the directory")
        return self.rsa.import_public(pem)

    def init_connecting(self, hops: int = 2, path=None):
        """Build the circuit: explicit ``path`` of node ids, or ``hops`` random.

        The last node of the circuit is the exit node.  Nothing is
        negotiated on the wire: every node's address and public key comes
        from the directory, and the only connection we open is to the
        entry node - the client's key travels later, inside the onion.
        """
        if path:
            self.node_path = [self.get_client(node_id) for node_id in path]
            missing = [entry["id"] for entry in self.node_path if entry is None]
            if missing:
                raise RuntimeError(f"unknown nodes: {', '.join(missing)}")
        else:
            self.node_path = self.calc_path(self.get_data_of_network(), hops)

        self.rsa_of_nodes = {entry["id"]: self._node_key(entry)
                             for entry in self.node_path}

        entry = self.node_path[0]
        self._entry_sock = socket.create_connection((entry["host"], entry["port"]))
        return self.node_path

    def send_message(self, text: str, target_addr: str) -> None:
        """Onion-encrypt ``text`` for ``target_addr`` (the destination server).

        Every layer also carries our public key (``reply_pub``) so each node
        on the way back can add its own encryption for us.  The reply rides
        the circuit back, so no address of ours ever leaves this machine.
        """
        if not self.node_path:
            raise RuntimeError("call init_connecting() before send_message()")
        if self._entry_sock is None:
            raise RuntimeError("no entry connection - call init_connecting()")

        reply_pub = self.rsa.export_public()

        # innermost layer: everything the exit node needs, nobody else
        envelope = {"next": target_addr, "final": True, "reply_pub": reply_pub,
                    "payload": protocol.b64(text.encode())}

        # wrap one RSA layer per hop, exit first (encdata1L, then encdat2L, ...)
        for node in reversed(self.node_path):
            blob = self.rsa.encrypt_message(json.dumps(envelope).encode(),
                                            self.rsa_of_nodes[node["id"]])
            envelope = {"next": node["id"], "reply_pub": reply_pub,
                        "payload": protocol.b64(blob)}

        protocol.send_msg(self._entry_sock,
                          {"type": "forward", "from": "client",
                           "payload": envelope["payload"]})

    def wait_reply(self, timeout: float = 15.0) -> str:
        """Read the reply back from the entry node and strip every layer.

        One node added one encryption layer per hop on the way back, so we
        remove exactly ``len(node_path)`` layers with our private key.
        """
        if not self.node_path:
            raise RuntimeError("call init_connecting() before wait_reply()")
        if self._entry_sock is None:
            raise RuntimeError("no entry connection - call init_connecting()")

        sock = self._entry_sock
        if timeout is not None:
            sock.settimeout(timeout)

        msg = protocol.recv_msg(sock)
        if msg.get("type") != "reply":
            raise protocol.ProtocolError(f"unexpected message: {msg.get('type')!r}")

        blob = protocol.unb64(msg["payload"])
        for _ in range(len(self.node_path)):
            blob = self.rsa.decrypt_message(blob)
        return blob.decode()

    # -- helpers --------------------------------------------------------
    def close(self) -> None:
        if self._entry_sock is not None:
            try:
                self._entry_sock.close()
            except OSError:
                pass
            self._entry_sock = None
