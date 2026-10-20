"""Shared wire protocol for Por.

Every message is a JSON object framed with a 4-byte big-endian length
prefix and sent over a plain Linux TCP socket wrapped in a :class:`Link`.

Links are **persistent**: one TCP connection per peer is opened on first
use and reused for every later message (chat style), instead of dialling
a new connection per packet.  Every request carries a random ``msg_id``
and the answer echoes it back, so many messages can be in flight over the
same link and replies are matched by id - not by "whichever socket the
answer happened to arrive on".

Key ownership is a one-way RSA test, run only between a node and the
directory authorities server when the node registers:

    node       -> directory : {"type": "register",        "id", "host", "port", "public_key"}
    directory  -> node      : {"type": "challenge",       "enc"}
    node       -> directory : {"type": "challenge_reply", "dec"}
    directory  -> node      : {"type": "ok"}

``enc`` is a random nonce encrypted with the node's public key, ``dec``
is that nonce decrypted back.  Only the owner of the private key can
produce ``dec``, so the directory learns the registered public key is
real without ever owning a keypair itself.

Nothing else on the wire handshakes: nodes fetch each other's public keys
from the directory, the client puts its own public key (``reply_pub``)
inside every onion layer so replies can come back, and the exit node
talks to the destination server in plain text.
"""

import base64
import json
import os
import socket
import struct
import threading
import uuid

from .keys import Rsa

MAX_MSG_SIZE = 64 * 1024 * 1024  # 64 MiB safety cap

# -- keepalive cadence -------------------------------------------------
# a live node pings the directory this often...
HEARTBEAT_EVERY = 60      # seconds between node -> directory heartbeats
# ...and the directory sweeps entries this often, dropping anything that
# missed ~1.5 heartbeats (so a healthy node is never swept by accident).
CLEANUP_EVERY = 90        # seconds between stale-entry sweeps
STALE_AFTER = 90          # seconds without a heartbeat -> node is dropped
# pooled peer links (client -> entry, node -> node, exit -> destination)
# are pinged this often so a dead link is noticed before it is used.
LINK_PING_EVERY = 30      # seconds between link pings
LINK_PING_TIMEOUT = 5.0   # seconds to wait for a pong before dropping


class ProtocolError(Exception):
    """Raised when a peer sends something that is not valid protocol."""


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def fmt_addr(host: str, port: int) -> str:
    return f"{host}:{port}"


def parse_addr(addr: str):
    """Parse ``"ip:port"`` into ``(host, port)``."""
    host, _, port = str(addr).rpartition(":")
    if not host or not port.isdigit():
        raise ProtocolError(f"bad address {addr!r}, expected ip:port")
    return host, int(port)


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        data += chunk
    return data


def send_msg(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_msg(sock: socket.socket) -> dict:
    (size,) = struct.unpack(">I", recv_exact(sock, 4))
    if size > MAX_MSG_SIZE:
        raise ProtocolError(f"message too large: {size} bytes")
    return json.loads(recv_exact(sock, size).decode())


def new_id() -> str:
    """Fresh correlation id for one request/reply pair."""
    return uuid.uuid4().hex


class Link:
    """One persistent TCP link: a socket plus a write lock.

    Reading and writing are independent (TCP is full duplex), but two
    threads must never *write* at the same time - otherwise their frames
    interleave on the wire.  The lock serializes writers; readers are
    expected to live in a single thread per link.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._write_lock = threading.Lock()

    def send(self, obj: dict) -> None:
        with self._write_lock:
            send_msg(self.sock, obj)

    def recv(self) -> dict:
        return recv_msg(self.sock)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __repr__(self):  # pragma: no cover - debugging aid
        try:
            peer = "%s:%s" % self.sock.getpeername()[:2]
        except OSError:
            peer = "closed"
        return f"<Link {peer}>"


# -- key ownership test (node <-> directory only) ----------------------
def test_key(sock: socket.socket, public_pem) -> bytes:
    """Directory side of the key test: challenge + verify, no keypair here.

    Encrypts a random nonce with ``public_pem`` and expects it back in
    plaintext.  The directory never creates a public/private key of its
    own - it only *tests* that the node owns the private key of the
    public key it sent.  Returns the nonce that was proven, raises
    :class:`ProtocolError` if the peer fails the test.
    """
    pub = Rsa.import_public(public_pem)
    nonce = os.urandom(16)
    send_msg(sock, {"type": "challenge",
                    "enc": b64(Rsa.encrypt_for(nonce, pub))})

    reply = recv_msg(sock)
    if reply.get("type") != "challenge_reply":
        raise ProtocolError(f"expected challenge_reply, "
                            f"got {reply.get('type')!r}")
    try:
        proven = unb64(reply["dec"])
    except (KeyError, ValueError, TypeError) as exc:  # missing/garbage answer
        raise ProtocolError(f"bad key test reply: {exc}")
    if proven != nonce:
        raise ProtocolError("key test failed: peer does not own its private key")
    return nonce


def prove_key(sock: socket.socket, rsa_obj) -> bytes:
    """Node side of the key test: answer the directory's challenge.

    This response used to live inside the node; it is a protocol
    exchange, so it belongs here.  Returns the decrypted nonce.
    """
    if not isinstance(rsa_obj, Rsa):  # pragma: no cover - sanity check
        raise TypeError("rsa_obj must be a src.keys.Rsa instance")

    challenge = recv_msg(sock)
    if challenge.get("type") != "challenge":
        raise ProtocolError(f"expected challenge, got {challenge.get('type')!r}")

    try:
        nonce = rsa_obj.decrypt_message(unb64(challenge["enc"]))
    except (ValueError, KeyError, TypeError) as exc:
        raise ProtocolError(f"bad challenge: {exc}")
    except Exception as exc:  # rsa.lib DecryptionError etc. -> protocol level
        raise ProtocolError(f"cannot answer challenge: {exc}")
    send_msg(sock, {"type": "challenge_reply", "dec": b64(nonce)})
    return nonce
