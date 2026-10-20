"""Por destination server (UML box: the hidden half of ``client``, server B).

This is the *server alone*: the plain TCP endpoint an exit node delivers
to.  It has:

* no id, no directory registration, no circuit;
* no RSA keypair at all - nothing here is encrypted, the exit node just
  hands over the text and reads the answer on the same socket;
* no idea who is talking to it: the sender's address never leaves the
  sender's machine, only the message does.

Connections are **persistent** (chat style): the exit node keeps one
connection per destination and reuses it for every message, so
:meth:`serve` accepts once per exit node and then reads ``deliver``
messages forever on that same link.  Each ``deliver`` carries a
``msg_id`` that the reply echoes back, so messages and answers are
matched by id, not by connection order.

Split out of :class:`src.client.Client` so the client (sender) and the
server (destination) each stand alone.
"""

import socket
import threading

from . import protocol


class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._listener = None
        self._running = False

    # -- lifecycle ------------------------------------------------------
    def listen(self, host: str = None, port: int = 0):
        """Start the plain TCP server used to receive messages.

        Returns the real ``(host, port)`` we bound (port 0 -> ephemeral).
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        srv.bind((host or self.host, port))
        srv.listen(8)
        self._listener = srv
        self._running = True
        self.host, self.port = self.local_addr
        return self.local_addr

    @property
    def local_addr(self):
        if self._listener is None:
            raise RuntimeError("call listen() first")
        host, port = self._listener.getsockname()[:2]
        return host, port

    def accept_connection(self, timeout: float = None):
        """Wait for an exit node to connect and return the link."""
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
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        return protocol.Link(conn)

    def serve(self, handler, background: bool = True):
        """Accept forever; one thread per exit link, messages stay open.

        ``handler(text)`` is called for every delivered message and its
        return value is sent back as the reply (``None`` = no reply).
        """
        if self._listener is None:
            raise RuntimeError("call listen() first")
        if background:
            threading.Thread(target=self._accept_loop, args=(handler,),
                             daemon=True).start()
        else:
            self._accept_loop(handler)
        return self

    def _accept_loop(self, handler):
        while self._running:
            try:
                link = self.accept_connection()
            except OSError:
                break
            threading.Thread(target=self._serve_link, args=(link, handler),
                             daemon=True).start()

    def _serve_link(self, link: protocol.Link, handler) -> None:
        try:
            while self._running:
                msg_id, text, _sender = self.recv_message(link)
                reply = handler(text)
                if reply is not None:
                    self.reply(link, reply, msg_id)
        except (ConnectionError, OSError, protocol.ProtocolError, KeyError):
            pass
        finally:
            link.close()

    # -- plain exchange -------------------------------------------------
    def recv_message(self, link) -> tuple:
        """Read one delivered message. Returns ``(msg_id, text, sender)``."""
        msg = link.recv()
        if msg.get("type") != "deliver":
            raise protocol.ProtocolError(f"unexpected message: {msg.get('type')!r}")
        return msg.get("msg_id"), msg.get("text", ""), msg.get("from")

    def reply(self, link, text: str, msg_id: str = None) -> None:
        """Answer on the link the exit node opened to us, echoing its id."""
        link.send({"type": "reply", "msg_id": msg_id, "text": text})

    def close(self) -> None:
        self._running = False
        if self._listener is not None:
            try:
                # wake a blocked accept() before closing the listener
                socket.create_connection(self.local_addr, timeout=1).close()
            except OSError:
                pass
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
