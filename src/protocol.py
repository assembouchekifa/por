"""Shared wire protocol for Por.

Every message is a JSON object framed with a 4-byte big-endian length
prefix and sent over a plain Linux TCP socket.

The handshake is a standard RSA challenge/response:

    initiator -> responder : {"type": "handshake",     "id", "public_key"}
    responder -> initiator : {"type": "handshake_ok",  "id", "public_key", "enc"}
    initiator -> responder : {"type": "handshake_done", "dec", "enc"}
    responder -> initiator : {"type": "handshake_result", "dec"}

``enc`` is a random nonce encrypted with the peer's public key, ``dec`` is
that nonce decrypted back.  Only the owner of the private key can produce
``dec``, so both sides end up trusting each other's public key.
"""

import base64
import json
import os
import socket
import struct

MAX_MSG_SIZE = 64 * 1024 * 1024  # 64 MiB safety cap


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


def handshake(sock: socket.socket, rsa_obj, my_id: str = None):
    """Run the initiator (client) side of the RSA handshake.

    ``my_id`` is optional: clients are anonymous and send no id, nodes do.
    Returns ``(peer_id, peer_public_key_pem)``.
    """
    from .rsa import Rsa  # local import to avoid a cycle at module load

    if not isinstance(rsa_obj, Rsa):  # pragma: no cover - sanity check
        raise TypeError("rsa_obj must be a src.rsa.Rsa instance")

    send_msg(sock, {"type": "handshake", "id": my_id,
                    "public_key": rsa_obj.export_public()})

    reply = recv_msg(sock)
    if reply.get("type") != "handshake_ok":
        raise ProtocolError(f"expected handshake_ok, got {reply.get('type')!r}")
    peer_id = reply["id"]
    peer_pub = rsa_obj.import_public(reply["public_key"])

    # prove we can read what was encrypted for us, then challenge the peer
    nonce_back = rsa_obj.decrypt_message(unb64(reply["enc"]))
    my_nonce = os.urandom(16)
    send_msg(sock, {"type": "handshake_done",
                    "dec": b64(nonce_back),
                    "enc": b64(rsa_obj.encrypt_message(my_nonce, peer_pub))})

    result = recv_msg(sock)
    if result.get("type") != "handshake_result":
        raise ProtocolError(f"expected handshake_result, got {result.get('type')!r}")
    if unb64(result["dec"]) != my_nonce:
        raise ProtocolError("handshake failed: peer does not own its private key")

    rsa_obj.remember_node(peer_id, reply["public_key"])
    return peer_id, reply["public_key"]
