"""Relay node (UML box: ``node``).

Members from the design:
    - rsa of clinet : public keys of the peers that talk to us - they
      travel inside the onion as ``reply_pub``, no key exchange needed
    - recvConneting -> gone: links are plain persistent TCP now, keys
      come from the directory (the node only proves its own key *to*
      the directory, once, at registration - see protocol.test_key/prove_key)
    - peel_layer    -> peel ONE rsa layer (the onion)
    - forward       -> hand the peeled layer to the next hop over the
      *pooled* link - one TCP connection per peer, reused for every
      message, instead of a fresh connection per packet

Every forward carries a ``msg_id``; the answer echoes it back.  A node
keeps a pending table (msg_id -> the link the packet came in on) and a
reader thread per pooled link, so replies are routed back the moment
they arrive - forwarding never blocks a link, and many messages can be
in flight over the same circuit at once (chat style).

A node registers itself on the directory authorities server (``heartbeat``
keepalive every ``protocol.HEARTBEAT_EVERY`` seconds), accepts circuits
and peels one RSA layer per hop.  Every node only knows the hop it
received a packet from and the hop it forwards to.  The **exit** node
(last hop) is the only one that meets the destination; it keeps a pooled
link per destination, and each reply on the way back gets one more
encryption layer for the original sender.  Nothing knows the sender's
address.

If the directory drops this node (missed heartbeats) or disappears, the
keepalive loop notices and **re-registers** as soon as it can reach the
directory again - a dead node coming back simply registers anew.  Pooled
peer links are pinged every ``protocol.LINK_PING_EVERY`` seconds and
dropped when silent, so a dead neighbour is replaced instead of hanging
the next message.
"""

import json
import socket
import threading
import time

from . import protocol
from .keys import Rsa

PENDING_TTL = 300  # seconds a reply may take before its pending entry is dropped


class Node:
    def __init__(self, node_id: str, host: str = "127.0.0.1", port: int = 9001,
                 dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self._lock = threading.Lock()          # guards the directory link
        self._server = None
        self._dir_link = None
        self._running = False
        self._stop = threading.Event()
        # pooled links: peer id -> Link (with its pong event), and
        # destination "host:port" -> Link; both guarded by _links_lock
        self._links = {}
        self._pong = {}
        self._dest_links = {}
        self._links_lock = threading.Lock()
        # msg_id -> (back Link, reply_pub, seen-at); guarded by _pending_lock
        self._pending = {}
        self._pending_lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        self._server = srv
        self._running = True
        self._stop.clear()

        self._register()
        threading.Thread(target=self._keepalive, daemon=True).start()

        if background:
            threading.Thread(target=self._accept_loop, daemon=True).start()
        else:
            self._accept_loop()
        return self

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        try:
            self._query({"type": "unregister", "id": self.node_id})
        except (ConnectionError, OSError):
            pass
        with self._links_lock:
            links = list(self._links.values()) + list(self._dest_links.values())
            self._links.clear()
            self._pong.clear()
            self._dest_links.clear()
        for link in links:
            link.close()
        if self._dir_link is not None:
            self._dir_link.close()
            self._dir_link = None
        if self._server is not None:
            # wake the blocked accept() first, otherwise the listener keeps
            # this port bound and a later start() would fail to rebind
            try:
                socket.create_connection((self.host, self.port), timeout=1).close()
            except OSError:
                pass
            try:
                self._server.close()
            except OSError:
                pass

    def _register(self):
        """Announce ourselves and prove we own the key we publish.

        The directory answers the key test with ``ok`` - it keeps no key
        of its own, it only checked ours (protocol.prove_key).
        """
        sock = socket.create_connection(self.dir_addr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        link = protocol.Link(sock)
        try:
            link.send({
                "type": "register", "id": self.node_id, "kind": "node",
                "host": self.host, "port": self.port,
                "public_key": self.rsa.export_public()})
            protocol.prove_key(sock, self.rsa)
            reply = link.recv()
        except BaseException:
            link.close()
            raise
        if reply.get("type") != "ok":
            link.close()
            raise ConnectionError(f"directory refused registration: {reply}")
        with self._lock:
            old, self._dir_link = self._dir_link, link
        if old is not None and old is not link:
            old.close()

    def _keepalive(self):
        """Heartbeat the directory, then ping the pooled peer links.

        The directory stops listing us if we stay silent for too long and
        answers our next heartbeat with ``error: not registered`` - that,
        or a dead connection, sends us straight back through _register().
        """
        while self._running:
            if self._stop.wait(protocol.HEARTBEAT_EVERY):
                break
            try:
                reply = self._query({"type": "heartbeat", "id": self.node_id})
            except (ConnectionError, OSError):
                reply = None
            if reply is None or reply.get("type") != "ok":
                self._recover_directory()
            self._ping_links()
            self._sweep_pending()

    def _recover_directory(self) -> None:
        """Drop the broken link and re-register until the directory answers."""
        with self._lock:
            link, self._dir_link = self._dir_link, None
        if link is not None:
            link.close()
        while self._running:
            try:
                self._register()
            except (ConnectionError, OSError, protocol.ProtocolError):
                if self._stop.wait(5):
                    return
                continue
            print(f"[node {self.node_id}] back with the directory: "
                  f"re-registered", flush=True)
            return

    def _query(self, msg: dict) -> dict:
        """Send one request to the directory server and read the answer.

        The send/receive pair is atomic: the keepalive thread and the
        serve threads share one link, and interleaving a heartbeat
        between a get_client and its answer would mismatch them.
        """
        with self._lock:
            link = self._dir_link
            if link is None:
                sock = socket.create_connection(self.dir_addr)
                sock.settimeout(10)  # a silent directory must not hang us
                link = protocol.Link(sock)
                self._dir_link = link
            link.send(msg)
            return link.recv()

    def get_client(self, peer_id: str):
        """Ask the directory server about one peer (UML ``getclient``)."""
        reply = self._query({"type": "get_client", "id": peer_id})
        return reply.get("client")

    # -- incoming links -------------------------------------------------
    def _accept_loop(self):
        while self._running:
            try:
                sock, _addr = self._server.accept()
            except OSError:
                break
            if not self._running:  # the wake-up connection from stop()
                sock.close()
                break
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock):
        """Serve one persistent link: previous hop (or the client) -> forward.

        No handshake happens here - whoever we are talking to is known
        only from what the packet itself carries (``from``), and the only
        key in play is the sender's ``reply_pub`` from the onion layers.
        Forwards are handed to the pooled next-hop link and this loop
        keeps reading; the reply travels back later, matched by msg_id.
        """
        link = protocol.Link(sock)
        try:
            while True:
                msg = link.recv()
                kind = msg.get("type")
                if kind == "forward":
                    msg_id = msg.get("msg_id") or protocol.new_id()
                    prev = msg.get("from", "someone")
                    inner = self.peel_layer(protocol.unb64(msg["payload"]))
                    self._remember_pending(msg_id, link, inner.get("reply_pub"))
                    if inner.get("final"):
                        print(f"[node {self.node_id}] packet arrived: final layer "
                              f"(exit) -> deliver to {inner['next']}", flush=True)
                        threading.Thread(target=self._deliver_and_return,
                                         args=(inner, msg_id, link, prev),
                                         daemon=True).start()
                    else:
                        print(f"[node {self.node_id}] packet arrived: peeled 1 RSA "
                              f"layer -> next hop {inner['next']}", flush=True)
                        # not the exit: we only see the next hop, nothing else
                        self.forward(inner["next"], inner["payload"], msg_id)
                elif kind == "ping":
                    link.send({"type": "pong", "id": self.node_id})
                elif kind == "close":
                    break
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            self._forget_pending(back_link=link)
            link.close()

    # -- pooled outgoing links ------------------------------------------
    def _get_link(self, next_id: str) -> protocol.Link:
        """Persistent link to a peer node - opened once, then reused."""
        with self._links_lock:
            link = self._links.get(next_id)
        if link is not None:
            return link

        entry = self.get_client(next_id)  # address from the directory
        if entry is None:
            raise ConnectionError(f"unknown next hop {next_id!r} (not in directory)")
        print(f"[node {self.node_id}] opening link to next hop {next_id} "
              f"({entry['host']}:{entry['port']})", flush=True)
        sock = socket.create_connection((entry["host"], entry["port"]))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        link = protocol.Link(sock)
        pong = threading.Event()
        with self._links_lock:
            existing = self._links.get(next_id)
            if existing is not None:  # another thread won the race
                link.close()
                return existing
            self._links[next_id] = link
            self._pong[next_id] = pong
        threading.Thread(target=self._link_reader, args=(next_id, link, pong),
                         daemon=True).start()
        return link

    def _link_reader(self, next_id: str, link: protocol.Link, pong) -> None:
        """Read one pooled link forever: replies and pongs."""
        try:
            while self._running:
                msg = link.recv()
                kind = msg.get("type")
                if kind == "reply":
                    self._return_reply(msg)
                elif kind == "pong":
                    pong.set()
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            self._drop_link(next_id, link)

    def _drop_link(self, next_id: str, link: protocol.Link) -> None:
        with self._links_lock:
            if self._links.get(next_id) is link:
                del self._links[next_id]
                self._pong.pop(next_id, None)
        link.close()

    def _ping_links(self) -> None:
        """Ping every pooled peer link; drop the ones that stay silent."""
        with self._links_lock:
            peer_ids = list(self._links)
        for peer_id in peer_ids:
            with self._links_lock:
                link, pong = self._links.get(peer_id), self._pong.get(peer_id)
            if link is None or not self._running:
                continue
            pong.clear()
            try:
                link.send({"type": "ping", "id": self.node_id})
            except (ConnectionError, OSError):
                self._drop_link(peer_id, link)
                continue
            if not pong.wait(protocol.LINK_PING_TIMEOUT):
                print(f"[node {self.node_id}] peer {peer_id} missed its pong, "
                      f"dropping the link", flush=True)
                self._drop_link(peer_id, link)

    # -- outgoing traffic -----------------------------------------------
    def peel_layer(self, payload: bytes) -> dict:
        """Peel exactly one RSA layer and return the inner envelope."""
        plain = self.rsa.decrypt_message(payload)
        return json.loads(plain.decode())

    def forward(self, next_id: str, payload_b64: str, msg_id: str) -> None:
        """Hand ``payload`` to the next hop over the pooled link.

        Non-blocking on purpose: the reply is routed back by msg_id when
        it arrives (see _link_reader), so one link serves many messages.
        A broken pooled link is dropped and retried once, transparently.
        """
        for attempt in (1, 2):
            link = self._get_link(next_id)
            try:
                link.send({"type": "forward", "from": self.node_id,
                           "msg_id": msg_id, "payload": payload_b64})
                return
            except (ConnectionError, OSError):
                self._drop_link(next_id, link)
                if attempt == 2:
                    raise

    def _deliver_and_return(self, envelope: dict, msg_id: str,
                            back_link: protocol.Link, prev_hop: str) -> None:
        """Exit-node role: deliver on the pooled destination link.

        We only know the previous hop, so server B's answer simply goes
        back there with one encryption layer for the original sender on
        top - whenever it arrives (matched by msg_id, see _dest_reader).
        """
        dest = envelope["next"]
        dest_host, dest_port = protocol.parse_addr(dest)
        text = protocol.unb64(envelope["payload"]).decode()

        deliver = {"type": "deliver", "msg_id": msg_id,
                   "from": self.node_id, "text": text}
        for attempt in (1, 2):
            link = self._get_dest_link(dest)
            try:
                link.send(deliver)
                break
            except (ConnectionError, OSError):
                self._drop_dest_link(dest, link)
                if attempt == 2:
                    raise
        print(f"[node {self.node_id}] exit delivered {text!r} to "
              f"{dest_host}:{dest_port}, answer comes back on the same link",
              flush=True)

    # -- pooled destination links (exit role) ---------------------------
    def _get_dest_link(self, dest: str) -> protocol.Link:
        """Persistent link to a destination server - opened once, reused."""
        with self._links_lock:
            link = self._dest_links.get(dest)
        if link is not None:
            return link
        host, port = protocol.parse_addr(dest)
        sock = socket.create_connection((host, port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        link = protocol.Link(sock)
        with self._links_lock:
            existing = self._dest_links.get(dest)
            if existing is not None:  # another thread won the race
                link.close()
                return existing
            self._dest_links[dest] = link
        threading.Thread(target=self._dest_reader, args=(dest, link),
                         daemon=True).start()
        return link

    def _dest_reader(self, dest: str, link: protocol.Link) -> None:
        """Read one pooled destination link forever; route answers back.

        Server B answers in plain text (``text``), the circuit speaks
        base64 payloads - translate on the way in, then route by msg_id.
        """
        try:
            while self._running:
                msg = link.recv()
                if msg.get("type") == "reply":
                    self._return_reply({"type": "reply",
                                        "msg_id": msg.get("msg_id"),
                                        "payload": protocol.b64(
                                            msg.get("text", "").encode())})
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            self._drop_dest_link(dest, link)

    def _drop_dest_link(self, dest: str, link: protocol.Link) -> None:
        with self._links_lock:
            if self._dest_links.get(dest) is link:
                del self._dest_links[dest]
        link.close()

    # -- pending table (msg_id -> the link the packet came in on) -------
    def _remember_pending(self, msg_id: str, back_link: protocol.Link,
                          reply_pub) -> None:
        with self._pending_lock:
            self._pending[msg_id] = (back_link, reply_pub, time.time())

    def _forget_pending(self, back_link=None, msg_id: str = None) -> None:
        with self._pending_lock:
            if msg_id is not None:
                self._pending.pop(msg_id, None)
            if back_link is not None:
                for key, (link, _pub, _seen) in list(self._pending.items()):
                    if link is back_link:
                        del self._pending[key]

    def _sweep_pending(self) -> None:
        """Drop pending entries whose reply never came (client went away)."""
        now = time.time()
        with self._pending_lock:
            for msg_id, (_link, _pub, seen) in list(self._pending.items()):
                if now - seen > PENDING_TTL:
                    del self._pending[msg_id]

    def _return_reply(self, msg: dict) -> None:
        """A reply arrived on a pooled link: add our layer, send it back."""
        msg_id = msg.get("msg_id")
        with self._pending_lock:
            pending = self._pending.pop(msg_id, None)
        if pending is None:
            return  # the incoming link died, or the reply came too late
        back_link, reply_pub, _seen = pending
        self._send_reply_back(back_link, msg.get("payload", ""), reply_pub,
                              msg_id)
    def _send_reply_back(self, back_link: protocol.Link, payload_b64: str,
                         reply_pub, msg_id: str) -> None:
        """Add one layer with the sender's public key and hand it backwards."""
        blob = protocol.unb64(payload_b64)
        if reply_pub:
            blob = self.rsa.encrypt_for(blob, self.rsa.import_public(reply_pub))
        try:
            back_link.send({"type": "reply", "msg_id": msg_id,
                            "payload": protocol.b64(blob)})
        except (ConnectionError, OSError):
            return  # previous hop is gone; nothing to do
        print(f"[node {self.node_id}] reply layer added -> routed back "
              f"(msg_id {str(msg_id)[:8]})", flush=True)
