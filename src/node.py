"""Relay node (UML box: ``node``).

Members from the design:
    - rsa of clinet : public keys of the peers that talk to us
    - recvConneting -> recv_connecting() : accept a peer + RSA handshake
    - recvMessage   -> recv_message()    : peel ONE rsa layer (the onion)
    - sendMessage   -> send_message()    : forward the peeled layer

A node registers itself on the directory authorities server (``data``
keepalive), accepts circuits and peels one RSA layer per hop.  Every node
only knows the hop it received a packet from and the hop it forwards to.
The **exit** node (last hop) is the only one that meets the destination;
it sends the answer back to the previous hop, and each node on the way
adds one more encryption layer for the original sender.  Nothing knows the
sender's address.
"""

import json
import os
import socket
import threading
import time

from . import protocol
from .rsa import Rsa


class Node:
    def __init__(self, node_id: str, host: str = "127.0.0.1", port: int = 7001,
                 dir_host: str = "127.0.0.1", dir_port: int = 9000,
                 keysize: int = 2048):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.dir_addr = (dir_host, dir_port)
        self.rsa = Rsa(keysize)
        self.links = {}  # peer id -> live socket (handshaked)
        self._lock = threading.Lock()
        self._server = None
        self._dir_sock = None
        self._running = False

    # -- lifecycle ------------------------------------------------------
    def start(self, background: bool = True):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        self._server = srv
        self._running = True

        self._register()
        threading.Thread(target=self._keepalive, daemon=True).start()

        if background:
            threading.Thread(target=self._accept_loop, daemon=True).start()
        else:
            self._accept_loop()
        return self

    def stop(self) -> None:
        self._running = False
        try:
            self._query({"type": "unregister", "id": self.node_id})
        except (ConnectionError, OSError):
            pass
        if self._dir_sock is not None:
            try:
                self._dir_sock.close()
            except OSError:
                pass
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass

    def _register(self):
        self._dir_sock = socket.create_connection(self.dir_addr)
        reply = self._query({"type": "register", "id": self.node_id, "kind": "node",
                             "host": self.host, "port": self.port,
                             "public_key": self.rsa.export_public()})
        if reply.get("type") != "ok":
            raise ConnectionError(f"directory refused registration: {reply}")

    def _keepalive(self):
        while self._running:
            time.sleep(5)
            if not self._running:
                break
            try:
                self._query({"type": "data", "id": self.node_id})
            except (ConnectionError, OSError):
                break

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
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock):
        peer_id = None
        try:
            peer_id = self.recv_connecting(sock)
            print(f"[node {self.node_id}] peer connected: {peer_id}", flush=True)
            while True:
                msg = protocol.recv_msg(sock)
                kind = msg.get("type")
                if kind == "forward":
                    inner = self.recv_message(protocol.unb64(msg["payload"]))
                    if inner.get("final"):
                        print(f"[node {self.node_id}] packet arrived: final layer "
                              f"(exit) -> deliver to {inner['next']}", flush=True)
                        self.exit_and_return(inner, sock, peer_id)
                    else:
                        print(f"[node {self.node_id}] packet arrived: peeled 1 RSA "
                              f"layer -> next hop {inner['next']}", flush=True)
                        # not the exit: we only see the next hop, nothing else
                        reply = self.send_message(inner["next"],
                                                  protocol.unb64(inner["payload"]))
                        self._send_reply_back(sock, reply["payload"],
                                              inner.get("reply_pub"), peer_id)
                elif kind == "ping":
                    protocol.send_msg(sock, {"type": "pong", "id": self.node_id})
                elif kind == "close":
                    break
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError, ValueError):
            pass
        finally:
            if peer_id is not None:
                with self._lock:
                    if self.links.get(peer_id) is sock:
                        del self.links[peer_id]
            sock.close()

    # -- UML API --------------------------------------------------------
    def recv_connecting(self, sock) -> str:
        """Responder side of the RSA handshake. Returns the peer id."""
        hello = protocol.recv_msg(sock)
        if hello.get("type") != "handshake":
            raise protocol.ProtocolError(f"expected handshake, got {hello.get('type')!r}")

        peer_pub = self.rsa.import_public(hello["public_key"])
        nonce = os.urandom(16)
        protocol.send_msg(sock, {
            "type": "handshake_ok",
            "id": self.node_id,
            "public_key": self.rsa.export_public(),
            "enc": protocol.b64(self.rsa.encrypt_message(nonce, peer_pub)),
        })

        done = protocol.recv_msg(sock)
        if done.get("type") != "handshake_done":
            raise protocol.ProtocolError(f"expected handshake_done, got {done.get('type')!r}")
        # done["dec"] is our nonce echoed back -> proves the peer could read it
        if protocol.unb64(done["dec"]) != nonce:
            raise protocol.ProtocolError("handshake failed: peer does not own its private key")

        # decrypting done["enc"] only works with our private key -> proof
        proof = self.rsa.decrypt_message(protocol.unb64(done["enc"]))
        protocol.send_msg(sock, {"type": "handshake_result",
                                 "dec": protocol.b64(proof)})

        peer_id = hello.get("id")
        if not peer_id:
            # anonymous client: identify it by where it connected from
            host, port = sock.getpeername()[:2]
            peer_id = f"peer:{protocol.fmt_addr(host, port)}"
        self.rsa.remember_node(peer_id, hello["public_key"])
        with self._lock:
            self.links[peer_id] = sock
        return peer_id

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
        entry = self.get_client(next_id)
        if entry is None:
            raise ConnectionError(f"unknown next hop {next_id!r} (not in directory)")
        print(f"[node {self.node_id}] opening link to next hop {next_id} "
              f"({entry['host']}:{entry['port']})", flush=True)
        sock = socket.create_connection((entry["host"], entry["port"]))
        protocol.handshake(sock, self.rsa, self.node_id)
        return sock
