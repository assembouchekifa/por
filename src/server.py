"""Por destination server (UML box: the hidden half of ``client``, server B).

This is the *server alone*: the plain TCP endpoint an exit node delivers
to.  It has:

* no id, no directory registration, no circuit;
* no RSA keypair at all - nothing here is encrypted, the exit node just
  hands over the text and reads the answer on the same socket;
* no idea who is talking to it: the sender's address never leaves the
  sender's machine, only the message does.

Split out of :class:`src.client.Client` so the client (sender) and the
server (destination) each stand alone.
"""

import socket

from . import protocol


class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._listener = None

    # -- lifecycle ------------------------------------------------------
    def listen(self, host: str = None, port: int = 0):
        """Start the plain TCP server used to receive messages.

        Returns the real ``(host, port)`` we bound (port 0 -> ephemeral).
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host or self.host, port))
        srv.listen(8)
        self._listener = srv
        self.host, self.port = self.local_addr
        return self.local_addr

    @property
    def local_addr(self):
        if self._listener is None:
            raise RuntimeError("call listen() first")
        host, port = self._listener.getsockname()[:2]
        return host, port

    def accept_connection(self, timeout: float = None):
        """Wait for the exit node to connect and return the socket."""
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
        return conn

    # -- plain exchange -------------------------------------------------
    def recv_message(self, conn):
        """Read one delivered message. Returns ``(text, sender)``."""
        msg = protocol.recv_msg(conn)
        if msg.get("type") != "deliver":
            raise protocol.ProtocolError(f"unexpected message: {msg.get('type')!r}")
        return msg.get("text", ""), msg.get("from")

    def reply(self, conn, text: str) -> None:
        """Answer on the connection the exit node opened to us."""
        protocol.send_msg(conn, {"type": "reply", "text": text})

    def close(self) -> None:
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
