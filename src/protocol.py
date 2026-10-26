"""Public wire-protocol facade.

The implementation is split into :mod:`src.wire` (framing/validation),
:mod:`src.link` (persistent links) and :mod:`src.errors` (exceptions).
This module keeps the historical import surface used by the rest of the
project and implements the one-off key-ownership test.
"""

import hmac
import os

from .config import DEFAULT
from .errors import CryptoError, PorError, ProtocolError
from .keys import Rsa
from .link import Link, connect, set_keepalive
from .wire import (
    b64,
    decode_json,
    encode_json,
    fmt_addr,
    new_id,
    optional_str,
    parse_addr,
    recv_exact,
    recv_msg,
    require_dict_field,
    require_int,
    require_list,
    require_str,
    send_msg,
    unb64,
)

# Protocol version is bumped when the on-the-wire crypto/layer format
# changes.  All components in this repository speak version 2.
PROTOCOL_VERSION = 2

MAX_MSG_SIZE = DEFAULT.max_frame_size

HEARTBEAT_EVERY = DEFAULT.heartbeat_every
CLEANUP_EVERY = DEFAULT.cleanup_every
STALE_AFTER = DEFAULT.stale_after
LINK_PING_EVERY = DEFAULT.link_ping_every
LINK_PING_TIMEOUT = DEFAULT.link_ping_timeout


# -- key ownership test (node <-> directory only) ----------------------
def test_key(sock, public_pem, max_frame_size: int = None) -> bytes:
    """Directory side: challenge the node and verify its private key."""
    try:
        pub = Rsa.import_public(public_pem)
        nonce = os.urandom(16)
        send_msg(
            sock,
            {"type": "challenge", "enc": b64(Rsa.encrypt_for(nonce, pub))},
            max_frame_size,
        )
        reply = recv_msg(sock, max_frame_size)
    except ProtocolError:
        raise
    except Exception as exc:
        raise ProtocolError(f"key test failed: {exc}") from exc

    if reply.get("type") != "challenge_reply":
        raise ProtocolError(
            f"expected challenge_reply, got {reply.get('type')!r}"
        )
    try:
        proven = unb64(reply["dec"])
    except (KeyError, ProtocolError) as exc:
        raise ProtocolError(f"bad key test reply: {exc}") from exc
    if not hmac.compare_digest(proven, nonce):
        raise ProtocolError(
            "key test failed: peer does not own its private key"
        )
    return nonce


def prove_key(sock, rsa_obj, max_frame_size: int = None) -> bytes:
    """Node side: answer the directory's key-ownership challenge."""
    if not isinstance(rsa_obj, Rsa):
        raise TypeError("rsa_obj must be a src.keys.Rsa instance")

    try:
        challenge = recv_msg(sock, max_frame_size)
    except ProtocolError:
        raise
    except Exception as exc:
        raise ProtocolError(f"cannot read key challenge: {exc}") from exc

    if challenge.get("type") != "challenge":
        raise ProtocolError(
            f"expected challenge, got {challenge.get('type')!r}"
        )
    try:
        nonce = rsa_obj.decrypt_message(unb64(challenge["enc"]))
    except CryptoError as exc:
        raise ProtocolError(f"cannot answer challenge: {exc}") from exc
    except (KeyError, ProtocolError) as exc:
        raise ProtocolError(f"bad challenge: {exc}") from exc
    send_msg(
        sock,
        {"type": "challenge_reply", "dec": b64(nonce)},
        max_frame_size,
    )
    return nonce


__all__ = [
    "CLEANUP_EVERY",
    "CryptoError",
    "HEARTBEAT_EVERY",
    "LINK_PING_EVERY",
    "LINK_PING_TIMEOUT",
    "Link",
    "MAX_MSG_SIZE",
    "PROTOCOL_VERSION",
    "PorError",
    "ProtocolError",
    "Rsa",
    "STALE_AFTER",
    "b64",
    "connect",
    "decode_json",
    "encode_json",
    "fmt_addr",
    "new_id",
    "optional_str",
    "parse_addr",
    "prove_key",
    "recv_exact",
    "recv_msg",
    "require_dict_field",
    "require_int",
    "require_list",
    "require_str",
    "send_msg",
    "set_keepalive",
    "test_key",
    "unb64",
]
