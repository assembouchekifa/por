"""Relay node (UML box: ``node``).

Members from the design:
    - rsa of clinet : public keys of the peers that talk to us
    - recvConneting -> gone: links are plain TCP now, keys come from the
      directory (the node only proves its own key *to* the directory,
      once, at registration - see protocol.test_key/prove_key)
    - recvMessage   -> recv_message()    : peel ONE rsa layer (the onion)
    - sendMessage   -> send_message()    : forward the peeled layer

A node registers itself on the directory authorities server (``heartbeat``
keepalive every ``protocol.HEARTBEAT_EVERY`` seconds), accepts circuits
and peels one RSA layer per hop.  Node-to-node links carry no handshake:
addresses and public keys are directory data, and the sender's public key
travels inside every onion layer (``reply_pub``) so replies can be
encrypted back.  Every node only knows the hop it received a packet from
and the hop it forwards to.  The **exit** node (last hop) is the only one
that meets the destination; it sends the answer back to the previous hop,
and each node on the way adds one more encryption layer for the original
sender.  Nothing knows the sender's address.

If the directory drops this node (missed heartbeats) or disappears, the
keepalive loop notices and **re-registers** as soon as it can reach the
directory again - a dead node coming back simply registers anew.
"""

import json
import socket
import threading

from . import protocol
from .rsa import Rsa


class Node:
    def __init__(self, node_id: str, host: str = "127.0.0.1", port: int = 9001,
                 dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self._lock = threading.Lock()
        self._server = None
        self._dir_sock = None
        self._running = False
        self._stop = threading.Event()

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        if self._dir_sock is not None:
            try:
                self._dir_sock.close()
            except OSError:
                pass
            self._dir_sock = None
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
        try:
            protocol.send_msg(sock, {
                "type": "register", "id": self.node_id, "kind": "node",
                "host": self.host, "port": self.port,
                "public_key": self.rsa.export_public()})
            protocol.prove_key(sock, self.rsa)
            reply = protocol.recv_msg(sock)
        except BaseException:
            sock.close()
            raise
        if reply.get("type") != "ok":
            sock.close()
            raise ConnectionError(f"directory refused registration: {reply}")
        with self._lock:
            old, self._dir_sock = self._dir_sock, sock
        if old is not None and old is not sock:
            try:
                old.close()
            except OSError:
                pass

    def _keepalive(self):
        """Heartbeat the directory; re-register the moment we are cut off.

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

    def _recover_directory(self) -> None:
        """Drop the broken link and re-register until the directory answers."""
        with self._lock:
            sock, self._dir_sock = self._dir_sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
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
        """Send one request to the directory server and read the answer."""
        with self._lock:
            sock = self._dir_sock
        if sock is None:
            sock = socket.create_connection(self.dir_addr)
            with self._lock:
                self._dir_sock = sock
        protocol.send_msg(sock, msg)
        return protocol.recv_msg(sock)

    def get_client(self, peer_id: str):
        """Ask the directory server about one peer (UML ``getclient``)."""
        reply = self._query({"type": "get_client", "id": peer_id})
        return reply.get("client")

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
        """Serve one plain link: previous hop (or the client) -> forward.

        No handshake happens here - whoever we are talking to is known
        only from what the packet itself carries (``from``), and the only
        key in play is the sender's ``reply_pub`` from the onion layers.
        """
        try:
            while True:
                msg = protocol.recv_msg(sock)
                kind = msg.get("type")
                if kind == "forward":
                    prev = msg.get("from", "someone")
                    inner = self.recv_message(protocol.unb64(msg["payload"]))
                    if inner.get("final"):
                        print(f"[node {self.node_id}] packet arrived: final layer "
                              f"(exit) -> deliver to {inner['next']}", flush=True)
                        self.exit_and_return(inner, sock, prev)
                    else:
                        print(f"[node {self.node_id}] packet arrived: peeled 1 RSA "
                              f"layer -> next hop {inner['next']}", flush=True)
                        # not the exit: we only see the next hop, nothing else
                        reply = self.send_message(inner["next"],
                                                  protocol.unb64(inner["payload"]))
                        self._send_reply_back(sock, reply["payload"],
                                              inner.get("reply_pub"), prev)
                elif kind == "ping":
                    protocol.send_msg(sock, {"type": "pong", "id": self.node_id})
                elif kind == "close":
                    break
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            sock.close()

    # -- UML API --------------------------------------------------------
    def recv_message(self, payload: bytes) -> dict:
        """Peel exactly one RSA layer and return the inner envelope."""
        plain = self.rsa.decrypt_message(payload)
        return json.loads(plain.decode())

    def send_message(self, next_id: str, payload: bytes) -> dict:
        """Forward ``payload`` to the next hop and wait for the reply back.

        A fresh link is opened per forward so a circuit's reply always comes
        back on the connection this node is watching.  Only this node's
        neighbour is involved; nothing else about the path is known here.
        """
        sock = self._open_link(next_id)
        try:
            protocol.send_msg(sock, {"type": "forward", "from": self.node_id,
                                     "payload": protocol.b64(payload)})
            reply = protocol.recv_msg(sock)
        finally:
            sock.close()
        if reply.get("type") != "reply":
            raise protocol.ProtocolError(
                f"expected reply from next hop {next_id!r}, got {reply.get('type')!r}")
        return reply

    def exit_and_return(self, envelope: dict, back_sock, prev_hop: str) -> bool:
        """Exit-node role: deliver the message, then send the reply back.

        We only know the previous hop, so the reply simply goes back there
        with one encryption layer for the original sender on top.
        """
        dest_host, dest_port = protocol.parse_addr(envelope["next"])
        text = protocol.unb64(envelope["payload"]).decode()

        with socket.create_connection((dest_host, dest_port)) as dest:
            protocol.send_msg(dest, {"type": "deliver", "text": text})
            reply = protocol.recv_msg(dest)
        if reply.get("type") != "reply":
            raise protocol.ProtocolError(f"destination did not reply: {reply!r}")
        reply_text = reply.get("text", "")
        print(f"[node {self.node_id}] exit delivered {text!r} to "
              f"{dest_host}:{dest_port}, got {reply_text!r} back", flush=True)

        self._send_reply_back(back_sock, protocol.b64(reply_text.encode()),
                              envelope.get("reply_pub"), prev_hop)
        return True

    # -- helpers --------------------------------------------------------
    def _send_reply_back(self, back_sock, payload_b64: str, reply_pub,
                         prev_hop: str) -> None:
        """Add one layer with the sender's public key and hand it backwards."""
        blob = protocol.unb64(payload_b64)
        if reply_pub:
            blob = self.rsa.encrypt_message(blob, self.rsa.import_public(reply_pub))
        protocol.send_msg(back_sock, {"type": "reply", "payload": protocol.b64(blob)})
        print(f"[node {self.node_id}] reply layer added -> "
              f"back to previous hop {prev_hop}", flush=True)

    def _open_link(self, next_id: str) -> socket.socket:
        """Plain TCP link to the next hop - address from the directory.

        No handshake: the onion layer for that hop was already encrypted
        for it by whoever built the circuit, and our reply layer only
        needs the sender's ``reply_pub`` which travels in the envelope.
        """
        entry = self.get_client(next_id)
        if entry is None:
            raise ConnectionError(f"unknown next hop {next_id!r} (not in directory)")
        print(f"[node {self.node_id}] opening link to next hop {next_id} "
              f"({entry['host']}:{entry['port']})", flush=True)
        return socket.create_connection((entry["host"], entry["port"]))
