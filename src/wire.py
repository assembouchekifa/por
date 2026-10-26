"""Wire format: length-framed JSON over TCP, plus validation helpers.

Every frame is::

    +----------------+---------------------------+
    | 4 bytes length | JSON object, UTF-8 bytes  |
    | big-endian int | ("type" is required)      |
    +----------------+---------------------------+

The helpers here deliberately turn every malformed input into
:class:`ProtocolError` so the connection loops only have to handle one
exception family.
"""

import base64
import binascii
import json
import socket
import struct
import uuid

from .config import DEFAULT
from .errors import ProtocolError

_HEADER = struct.Struct(">I")


# -- base64 -------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text) -> bytes:
    """Decode a base64 field, rejecting garbage instead of guessing."""
    if not isinstance(text, str):
        raise ProtocolError(f"expected base64 text, got {type(text).__name__}")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ProtocolError(f"invalid base64 field: {exc}") from exc


# -- addresses ----------------------------------------------------------
def fmt_addr(host: str, port: int) -> str:
    return f"{host}:{port}"


def parse_addr(addr) -> tuple:
    """Parse ``"host:port"`` into ``(host, port)``."""
    host, _, port_text = str(addr).rpartition(":")
    if not host or not port_text.isdigit():
        raise ProtocolError(f"bad address {addr!r}, expected host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ProtocolError(f"bad port {port!r} in address {addr!r}")
    return host, port


# -- bytes / JSON -------------------------------------------------------
def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes, without O(n^2) bytes concatenation."""
    if size < 0:
        raise ValueError("size must not be negative")
    buf = bytearray(size)
    view = memoryview(buf)
    received = 0
    while received < size:
        try:
            chunk = sock.recv_into(view[received:], size - received)
        except InterruptedError:
            continue
        if chunk == 0:
            raise ConnectionError("connection closed while reading")
        received += chunk
    return bytes(buf)


def encode_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_json(data: bytes, what: str = "payload") -> dict:
    try:
        text = data.decode("utf-8")
        obj = json.loads(text)
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"{what} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        # Do not include the document/snippet in the exception text: a
        # malformed frame may still contain user plaintext.
        raise ProtocolError(f"invalid JSON in {what}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(f"{what} must be a JSON object")
    return obj


def send_msg(sock: socket.socket, obj: dict, max_frame_size: int = None) -> None:
    if not isinstance(obj, dict):
        raise ProtocolError("outgoing message must be a dict")
    limit = DEFAULT.max_frame_size if max_frame_size is None else max_frame_size
    payload = encode_json(obj)
    if len(payload) > limit:
        raise ProtocolError(f"message too large: {len(payload)} bytes")
    sock.sendall(_HEADER.pack(len(payload)) + payload)


def recv_msg(sock: socket.socket, max_frame_size: int = None) -> dict:
    limit = DEFAULT.max_frame_size if max_frame_size is None else max_frame_size
    raw_size = recv_exact(sock, _HEADER.size)
    (size,) = _HEADER.unpack(raw_size)
    if size <= 0:
        raise ProtocolError("empty message frame")
    if size > limit:
        raise ProtocolError(f"message too large: {size} bytes")
    body = recv_exact(sock, size)
    msg = decode_json(body, "frame")
    msg_type = msg.get("type")
    if not isinstance(msg_type, str) or not msg_type:
        raise ProtocolError("message is missing a string 'type'")
    return msg


def new_id() -> str:
    """Fresh correlation id for one request/reply pair."""
    return uuid.uuid4().hex


# -- field validation ---------------------------------------------------
def require_dict_field(msg: dict, field: str) -> dict:
    value = msg.get(field)
    if not isinstance(value, dict):
        raise ProtocolError(f"field {field!r} must be an object")
    return value


def require_str(
    msg: dict,
    field: str,
    *,
    max_length: int = None,
    allow_empty: bool = False,
) -> str:
    value = msg.get(field)
    if not isinstance(value, str):
        raise ProtocolError(f"field {field!r} must be a string")
    if not allow_empty and not value:
        raise ProtocolError(f"field {field!r} must not be empty")
    if max_length is not None and len(value) > max_length:
        raise ProtocolError(f"field {field!r} is too long")
    return value


def optional_str(msg: dict, field: str, *, max_length: int = None) -> str:
    value = msg.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ProtocolError(f"field {field!r} must be a string")
    if max_length is not None and len(value) > max_length:
        raise ProtocolError(f"field {field!r} is too long")
    return value


def require_int(
    msg: dict,
    field: str,
    *,
    min_value: int = None,
    max_value: int = None,
) -> int:
    value = msg.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"field {field!r} must be an integer")
    if min_value is not None and value < min_value:
        raise ProtocolError(f"field {field!r} is too small")
    if max_value is not None and value > max_value:
        raise ProtocolError(f"field {field!r} is too large")
    return value


def require_list(msg: dict, field: str, *, max_length: int = None) -> list:
    value = msg.get(field)
    if not isinstance(value, list):
        raise ProtocolError(f"field {field!r} must be a list")
    if max_length is not None and len(value) > max_length:
        raise ProtocolError(f"field {field!r} has too many entries")
    return value
