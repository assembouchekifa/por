"""Por client sender (UML box: ``client``, the sending half).

The destination half of the design (server B) lives alone in
:mod:`src.server` - this class only *sends*:

* it fetches the network data from the directory authorities
  (:meth:`get_data_of_network`), calculates a circuit (:meth:`calc_path`)
  and pushes onion-encrypted messages into it.

There is **no client handshake**.  The circuit's nodes are directory data
(host, port and every node's public key come from the directory), and the
client's own public key rides inside each onion layer as ``reply_pub`` -
that is how replies come back.  Only one socket is opened, to the entry
(start) node; every other hop is reached by the nodes themselves.

The link is **persistent, chat style**: build the circuit once with
:meth:`init_connection`, then :meth:`send_message` as often as you like -
no new connection per message.  A background reader thread owns the entry
link, so replies arrive whenever they come back: they are matched by
``msg_id``, stripped of one RSA layer per hop and pushed into an inbox
that :meth:`wait_reply` drains.  A keepalive pings the entry node every
``protocol.LINK_PING_EVERY`` seconds; a dead circuit is rebuilt with the
same node ids on the next send.
"""

import json
import queue
import random
import socket
import threading
import time

from . import protocol
from .keys import Rsa


class Client:
    def __init__(self, dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self.node_path = []        # ordered [{"id", "host", "port", ...}]
        self.rsa_of_nodes = {}     # node id -> public key
        self._entry_link = None    # the one live link: us -> entry node
        self._path_ids = None      # circuit node ids, kept for rebuilds
        self._hops = 2             # circuit size, kept for rebuilds
        self._inbox = queue.Queue()  # (msg_id, text) replies, chat style
        self._layers = {}          # msg_id -> layers to strip on the way back
        self._bad_nodes = set()    # nodes a rebuild should avoid for now
        self._pong = threading.Event()
        self._running = False
        self._stop = threading.Event()
        self._reader = None
        self._keepalive = None

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
        """Pick ``length`` random nodes (the ``calc path`` loop in the diagram).

        Nodes that just failed are avoided; if too few are left, everyone
        is back in the pool (the directory may list a node for a while
        after it died, so "reachable" is only known by trying).
        """
        good = [entry for entry in network if entry["id"] not in self._bad_nodes]
        if len(good) < length:
            self._bad_nodes.clear()
            good = network
        if length > len(good):
            raise RuntimeError(f"path of {length} hops requested, "
                               f"but network only has {len(good)} nodes")
        return random.sample(good, length)

    def _node_key(self, entry) -> "Rsa":
        """Public key of a node, straight from directory data (no handshake)."""
        pem = entry.get("public_key")
        if not pem:
            raise RuntimeError(f"node {entry['id']} published no public key "
                               f"in the directory")
        return self.rsa.import_public(pem)

    def init_connection(self, hops: int = 2, path=None):
        """Build the circuit and open the one persistent link: explicit
        ``path`` of node ids, or ``hops`` random.

        The last node of the circuit is the exit node.  Nothing is
        negotiated on the wire: every node's address and public key comes
        from the directory, and the only connection we open is to the
        entry node - the client's key travels later, inside the onion.
        The circuit stays up for every later message (chat style).
        """
        if path:
            self.node_path = [self.get_client(node_id) for node_id in path]
            missing = [node_id for node_id, entry in zip(path, self.node_path)
                       if entry is None]
            if missing:
                raise RuntimeError(f"unknown nodes: {', '.join(missing)}")
        else:
            self.node_path = self.calc_path(self.get_data_of_network(), hops)

        self.rsa_of_nodes = {entry["id"]: self._node_key(entry)
                             for entry in self.node_path}
        self._path_ids = [entry["id"] for entry in self.node_path]
        self._hops = hops

        self._drop_entry()  # a re-build replaces the old entry link
        entry = self.node_path[0]
        sock = socket.create_connection((entry["host"], entry["port"]))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        link = protocol.Link(sock)
        self._entry_link = link
        self._running = True

        self._reader = threading.Thread(target=self._read_loop, args=(link,),
                                        daemon=True)
        self._reader.start()
        if self._keepalive is None:
            self._keepalive = threading.Thread(target=self._ping_loop,
                                               daemon=True)
            self._keepalive.start()
        return self.node_path

    def _read_loop(self, link: protocol.Link) -> None:
        """Own the entry link: replies -> inbox, pongs -> keepalive."""
        try:
            while self._running and self._entry_link is link:
                msg = link.recv()
                kind = msg.get("type")
                if kind == "reply":
                    self._on_reply(msg)
                elif kind == "pong":
                    self._pong.set()
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            if self._entry_link is link:
                self._entry_link = None  # next send rebuilds the circuit

    def _on_reply(self, msg: dict) -> None:
        """Strip one RSA layer per hop and hand the text to the inbox."""
        msg_id = msg.get("msg_id")
        blob = protocol.unb64(msg.get("payload", ""))
        for _ in range(self._layers.pop(msg_id, len(self.node_path))):
            blob = self.rsa.decrypt_message(blob)
        self._inbox.put((msg_id, blob.decode()))

    def send_message(self, text: str, target_addr: str) -> str:
        """Onion-encrypt ``text`` for ``target_addr`` (the destination server)
        and push it into the circuit - no new connection, the persistent
        entry link is reused.  Returns the ``msg_id`` the reply echoes.

        Every layer also carries our public key (``reply_pub``) so each node
        on the way back can add its own encryption for us.  The reply rides
        the circuit back, so no address of ours ever leaves this machine.
        A dead circuit is rebuilt with the same node ids and the message is
        retried once.
        """
        if not self.node_path:
            raise RuntimeError("call init_connection() before send_message()")

        reply_pub = self.rsa.export_public()
        msg_id = protocol.new_id()
        for attempt in (1, 2):
            if self._entry_link is None:
                self._ensure_link()
            envelope = {"next": target_addr, "final": True, "reply_pub": reply_pub,
                        "payload": protocol.b64(text.encode())}

            # wrap one RSA layer per hop, exit first (encdata1L, then encdat2L, ...)
            for node in reversed(self.node_path):
                blob = self.rsa.encrypt_for(json.dumps(envelope).encode(),
                                            self.rsa_of_nodes[node["id"]])
                envelope = {"next": node["id"], "reply_pub": reply_pub,
                            "payload": protocol.b64(blob)}

            self._layers[msg_id] = len(self.node_path)
            try:
                self._entry_link.send({"type": "forward", "from": "client",
                                       "msg_id": msg_id,
                                       "payload": envelope["payload"]})
                return msg_id
            except (ConnectionError, OSError):
                if self.node_path:  # the entry link died mid-chat
                    self._bad_nodes.add(self.node_path[0]["id"])
                self._drop_entry()
                if attempt == 2:
                    raise

    def wait_reply(self, timeout: float = 15.0, msg_id: str = None) -> str:
        """Pop the next reply off the inbox (chat style, non-blocking link).

        Replies arrive on the reader thread whenever they come back, so
        this only waits for one to show up - optionally a specific one.
        """
        if not self.node_path:
            raise RuntimeError("call init_connection() before wait_reply()")
        deadline = None if timeout is None else time.time() + timeout
        while True:
            left = None if deadline is None else deadline - time.time()
            if left is not None and left <= 0:
                raise TimeoutError(f"no reply from the circuit"
                                   + (f" for {msg_id}" if msg_id else ""))
            got_id, text = self._inbox.get(timeout=left)
            if msg_id is None or got_id == msg_id:
                return text
            # not the one we asked for - park it for the next wait_reply
            self._inbox.put((got_id, text))

    # -- keepalive ------------------------------------------------------
    def ping(self) -> bool:
        """Ping the entry node over the persistent link."""
        link = self._entry_link
        if link is None:
            return False
        self._pong.clear()
        try:
            link.send({"type": "ping", "id": "client"})
        except (ConnectionError, OSError):
            self._drop_entry()
            return False
        if not self._pong.wait(protocol.LINK_PING_TIMEOUT):
            self._drop_entry()
            return False
        return True

    def _ping_loop(self) -> None:
        """Ping the entry node every LINK_PING_EVERY seconds (chat keepalive)."""
        while self._running:
            if self._stop.wait(protocol.LINK_PING_EVERY):
                break
            if self._entry_link is not None and not self.ping():
                print("[sender] entry node went quiet - circuit dropped, "
                      "next send rebuilds it", flush=True)

    def _ensure_link(self) -> None:
        """Re-open the circuit: same node ids first, random if they are gone."""
        if self._path_ids:
            try:
                self.init_connection(hops=self._hops, path=self._path_ids)
                return
            except (RuntimeError, ConnectionError, OSError):
                # init_connection only ever dials the entry, so the entry
                # is the one that just refused us
                self._bad_nodes.add(self._path_ids[0])
                print("[sender] old circuit is gone, picking a fresh one",
                      flush=True)
        self.init_connection(hops=self._hops)

    def _drop_entry(self) -> None:
        link, self._entry_link = self._entry_link, None
        if link is not None:
            link.close()

    # -- helpers --------------------------------------------------------
    def close(self) -> None:
        self._running = False
        self._stop.set()
        self._drop_entry()
