"""Por destination server (UML box: the hidden half of ``client``).

Server B is a plain, keyless TCP endpoint.  It never dials anyone, has no
directory identity, and only sees the exit node that delivered the text.
Connections are persistent: one link per exit node, many messages.
"""

from .config import DEFAULT
from .errors import ProtocolError
from .link import Link, set_keepalive
from .service import ServiceBase
from .wire import optional_str, require_str


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
        if background:
            self._spawn(self._accept_loop, name="destination-accept")
        else:
            self._accept_loop()
        return self

    def close(self) -> None:
        super().stop()

    # -- incoming links -------------------------------------------------
    def _handle_link(self, link: Link) -> None:
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
