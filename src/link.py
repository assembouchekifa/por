"""Persistent TCP link wrapper and connection helpers."""

import socket
import threading

from .errors import ProtocolError
from .wire import recv_msg, send_msg


def set_keepalive(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def connect(
    host: str,
    port: int,
    *,
    timeout: float = None,
    keepalive: bool = True,
    max_frame_size: int = None,
) -> "Link":
    """Dial a TCP peer with a bounded connect time, then block normally."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(None)
    if keepalive:
        set_keepalive(sock)
    return Link(sock, max_frame_size=max_frame_size)


class Link:
    """One persistent TCP link: a socket plus a write lock.

    TCP is full duplex, so reading and writing are independent.  Several
    threads may write to one link (forward + reply + ping), and their
    frames must never interleave; ``_write_lock`` serializes writers.
    Each link still has exactly one reader thread by design.
    """

    def __init__(self, sock: socket.socket, max_frame_size: int = None):
        self.sock = sock
        self.max_frame_size = max_frame_size
        self._write_lock = threading.Lock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def send(self, obj: dict) -> None:
        if self._closed:
            raise ConnectionError("link is closed")
        with self._write_lock:
            if self._closed:
                raise ConnectionError("link is closed")
            try:
                send_msg(self.sock, obj, self.max_frame_size)
            except ProtocolError:
                raise
            except OSError as exc:
                raise ConnectionError(str(exc)) from exc

    def recv(self) -> dict:
        if self._closed:
            raise ConnectionError("link is closed")
        try:
            return recv_msg(self.sock, self.max_frame_size)
        except ProtocolError:
            raise
        except OSError as exc:
            raise ConnectionError(str(exc)) from exc

    def settimeout(self, timeout: float) -> None:
        self.sock.settimeout(timeout)

    def close(self) -> None:
        self._closed = True
        # shutdown() is what actually wakes a thread blocked in recv() on
        # Linux; close() alone can leave that thread waiting for data.
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Link":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> None:  # pragma: no cover - debugging aid
        try:
            peer = "%s:%s" % self.sock.getpeername()[:2]
        except OSError:
            peer = "closed"
        return f"<Link {peer}>"
