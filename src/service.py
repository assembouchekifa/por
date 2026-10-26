"""Shared TCP service lifecycle.

Directory, relay node and destination server all used to duplicate the
same accept-loop / wake-up / close-the-listener / join-the-threads code.
This base class centralizes it and tracks every accepted connection so a
clean ``stop()`` really closes them.
"""

import socket
import threading

from .config import DEFAULT
from .errors import PorError, ProtocolError
from .link import Link, set_keepalive
from .log import get_logger


class ServiceBase:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        settings=DEFAULT,
        name: str = "service",
    ):
        self.host = host
        self.port = port
        self.settings = settings
        self._name = name
        self._listener = None
        self._running = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections = set()
        self._conn_lock = threading.Lock()
        self._threads = set()
        self._thread_lock = threading.Lock()
        self._log = get_logger(name)

    @property
    def running(self) -> bool:
        return self._running

    # -- listener -------------------------------------------------------
    def _bind(
        self,
        host: str = None,
        port: int = None,
        *,
        backlog: int = None,
    ) -> tuple:
        if self._listener is not None:
            raise RuntimeError("service is already listening")
        bind_host = self.host if host is None else host
        bind_port = self.port if port is None else port
        if bind_port is None:
            bind_port = 0

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((bind_host, bind_port))
            srv.listen(backlog if backlog is not None else self.settings.backlog)
        except BaseException:
            srv.close()
            raise
        self._listener = srv
        self.host, self.port = srv.getsockname()[:2]
        self._running = True
        self._stop.clear()
        return self.host, self.port

    def _accept_loop(self) -> None:
        while self._running:
            listener = self._listener
            if listener is None:
                break
            try:
                sock, _addr = listener.accept()
            except OSError:
                break
            if not self._running:
                sock.close()
                break
            set_keepalive(sock)
            link = Link(sock, self.settings.max_frame_size)
            self._track(link)
            self._spawn(
                self._serve_connection,
                link,
                name=f"{self._name}-conn",
            )

    def _serve_connection(self, link: Link) -> None:
        try:
            self._handle_link(link)
        except (ConnectionError, OSError, ProtocolError):
            pass
        except PorError as exc:
            self._log.warning("connection error: %s", exc)
        except Exception:  # never let one peer kill the process
            self._log.exception("unexpected error while serving a connection")
        finally:
            self._untrack(link)
            link.close()

    def _handle_link(self, link: Link) -> None:
        raise NotImplementedError

    # -- connection tracking -------------------------------------------
    def _track(self, link: Link) -> None:
        with self._conn_lock:
            self._connections.add(link)

    def _untrack(self, link: Link) -> None:
        with self._conn_lock:
            self._connections.discard(link)

    def _close_connections(self) -> None:
        with self._conn_lock:
            links = list(self._connections)
            self._connections.clear()
        for link in links:
            link.close()

    # -- threads --------------------------------------------------------
    def _spawn(self, target, *args, name: str = None) -> threading.Thread:
        thread = threading.Thread(
            target=self._thread_main,
            args=(target, args),
            daemon=True,
            name=name or f"{self._name}-thread",
        )
        with self._thread_lock:
            self._threads.add(thread)
        thread.start()
        return thread

    def _thread_main(self, target, args) -> None:
        current = threading.current_thread()
        try:
            target(*args)
        except Exception:  # defensive: background work must not vanish silently
            self._log.exception("unexpected error in %s", current.name)
        finally:
            with self._thread_lock:
                self._threads.discard(current)

    def _join_threads(self) -> None:
        current = threading.current_thread()
        with self._thread_lock:
            threads = list(self._threads)
        for thread in threads:
            if thread is current:
                continue
            thread.join(timeout=self.settings.stop_join_timeout)

    # -- shutdown -------------------------------------------------------
    def _wake_and_close(self, listener: socket.socket) -> None:
        try:
            host, port = listener.getsockname()[:2]
        except OSError:
            host = port = None
        if host in ("", "0.0.0.0"):
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        if host is not None and port:
            try:
                socket.create_connection(
                    (host, port), timeout=self.settings.stop_wake_timeout
                ).close()
            except OSError:
                pass
        try:
            listener.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        self._close_connections()
        with self._lock:
            listener, self._listener = self._listener, None
        if listener is not None:
            self._wake_and_close(listener)
        self._join_threads()
