"""Por destination server (UML box: the hidden half of ``client``).

Server B is a plain, keyless TCP endpoint.  It never dials anyone, has no
directory identity, and only sees the exit node that delivered the text.
Connections are persistent: one link per exit node, many messages.
"""

import threading
import time

from .config import DEFAULT
from .errors import ProtocolError
from .link import Link, set_keepalive
from .service import ServiceBase
from .wire import optional_str, require_str


class ServerSession:
    """One accepted destination link that may send many replies.

    The exit node pools one link per destination address, so this object
    remembers the most recent route id seen on that link.  A chat writer
    thread can call :meth:`send` at any time after the first delivery.
    """

    def __init__(self, server, link: Link):
        self._server = server
        self._link = link
        self._route_id = None
        self._route_lock = threading.Lock()
        self._ready = threading.Event()
        self._closed = threading.Event()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and not self.closed

    @property
    def route_id(self):
        with self._route_lock:
            return self._route_id

    def _set_route(self, msg_id: str) -> None:
        with self._route_lock:
            self._route_id = msg_id
        self._ready.set()

    def wait_ready(self, timeout: float = None) -> bool:
        """Wait until the first delivered message created a reply route."""
        deadline = (
            None if timeout is None
            else time.monotonic() + max(0.0, timeout)
        )
        while not self._closed.is_set():
            if deadline is None:
                wait_for = None
            else:
                wait_for = deadline - time.monotonic()
                if wait_for <= 0:
                    return False
            if self._ready.wait(wait_for):
                return not self._closed.is_set()
        return False

    def send(self, text: str, msg_id: str = None, timeout: float = None) -> None:
        """Send a reply on the most recent route, or an explicit route."""
        if not isinstance(text, str):
            raise TypeError("chat text must be a string")
        if self._closed.is_set():
            raise ConnectionError("chat session is closed")
        if msg_id is None:
            if not self.wait_ready(timeout):
                if self._closed.is_set():
                    raise ConnectionError("chat session is closed")
                raise TimeoutError("no chat route is ready yet")
            with self._route_lock:
                msg_id = self._route_id
        if not isinstance(msg_id, str) or not msg_id:
            raise RuntimeError("chat route is not ready")
        self._server.reply(self._link, text, msg_id)

    def close(self) -> None:
        self._closed.set()
        self._ready.set()


class Server(ServiceBase):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        settings=DEFAULT,
    ):
        super().__init__(host, port, settings=settings, name="destination")
        self._handler = None
        self._chat_handler = None
        self._on_open = None

    # -- lifecycle ------------------------------------------------------
    def listen(self, host: str = None, port: int = 0):
        """Bind the plain TCP listener and return the real address."""
        return self._bind(host, port, backlog=8)

    @property
    def local_addr(self):
        if self._listener is None:
            raise RuntimeError("call listen() first")
        host, port = self._listener.getsockname()[:2]
        return host, port

    def accept_connection(self, timeout: float = None) -> Link:
        """Wait for one exit node and return the raw link (manual mode)."""
        if self._listener is None:
            raise RuntimeError("call listen() first")
        if timeout is not None:
            self._listener.settimeout(timeout)
        try:
            conn, _addr = self._listener.accept()
        finally:
            if timeout is not None:
                self._listener.settimeout(None)
        conn.settimeout(timeout)
        set_keepalive(conn)
        return Link(conn, self.settings.max_frame_size)

    def serve(self, handler, background: bool = True):
        """Accept forever; one thread per exit link."""
        if self._listener is None:
            raise RuntimeError("call listen() first")
        self._handler = handler
        self._chat_handler = None
        self._on_open = None
        if background:
            self._spawn(self._accept_loop, name="destination-accept")
        else:
            self._accept_loop()
        return self

    def serve_chat(
        self,
        handler,
        *,
        on_open=None,
        background: bool = True,
    ):
        """Serve interactive chat sessions.

        ``handler(session, text)`` is called for every delivery.  ``session``
        is a :class:`ServerSession`; it may send any number of replies, and
        ``on_open(session)`` runs once per accepted exit link so a demo can
        start its stdin reader.
        """
        if self._listener is None:
            raise RuntimeError("call listen() first")
        self._chat_handler = handler
        self._on_open = on_open
        self._handler = None
        if background:
            self._spawn(self._accept_loop, name="destination-accept")
        else:
            self._accept_loop()
        return self

    def close(self) -> None:
        super().stop()

    # -- incoming links -------------------------------------------------
    def _handle_link(self, link: Link) -> None:
        if self._chat_handler is not None:
            self._handle_chat_link(link)
            return
        if self._handler is None:
            raise RuntimeError("serve() was not called")
        while self._running:
            msg_id, text, _sender = self.recv_message(link)
            try:
                reply = self._handler(text)
            except Exception:
                self._log.exception("destination handler failed")
                reply = None
            if reply is not None:
                if not isinstance(reply, str):
                    self._log.warning(
                        "destination handler returned %s, not a string",
                        type(reply).__name__,
                    )
                    reply = str(reply)
                self.reply(link, reply, msg_id)

    def _handle_chat_link(self, link: Link) -> None:
        session = ServerSession(self, link)
        try:
            if self._on_open is not None:
                self._on_open(session)
            while self._running:
                msg_id, text, _sender = self.recv_message(link)
                session._set_route(msg_id)
                try:
                    reply = self._chat_handler(session, text)
                except Exception:
                    self._log.exception("destination chat handler failed")
                    reply = None
                if reply is not None:
                    if not isinstance(reply, str):
                        self._log.warning(
                            "destination chat handler returned %s, "
                            "not a string",
                            type(reply).__name__,
                        )
                        reply = str(reply)
                    try:
                        session.send(reply, msg_id=msg_id)
                    except (ConnectionError, OSError, TimeoutError):
                        self._log.warning("chat reply could not be sent")
                        break
        finally:
            session.close()

    # -- plain exchange -------------------------------------------------
    def recv_message(self, link: Link) -> tuple:
        """Read one delivered message. Returns ``(msg_id, text, sender)``."""
        msg = link.recv()
        if msg["type"] != "deliver":
            raise ProtocolError(
                f"unexpected message: {msg['type']!r}"
            )
        msg_id = require_str(msg, "msg_id", max_length=256)
        text = msg.get("text", "")
        if not isinstance(text, str):
            raise ProtocolError("'text' must be a string")
        sender = optional_str(
            msg, "from", max_length=self.settings.max_id_length
        )
        if len(text.encode("utf-8")) > self.settings.max_text_bytes:
            raise ProtocolError("delivered text is too large")
        return msg_id, text, sender

    def reply(self, link: Link, text: str, msg_id: str = None) -> None:
        if not isinstance(text, str):
            raise TypeError("reply text must be a string")
        if len(text.encode("utf-8")) > self.settings.max_text_bytes:
            self._log.warning("reply exceeds max_text_bytes; dropping it")
            return
        link.send({"type": "reply", "msg_id": msg_id, "text": text})
