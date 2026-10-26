"""Generic pool of pooled persistent links.

A relay uses this twice: once for peer nodes (keyed by node id) and once
for destination servers (keyed by ``host:port``).  Each entry has one
reader thread and a pong event; dropping an entry closes the link and
lets the next send dial a fresh connection.
"""

import threading
from dataclasses import dataclass, field

from .errors import PorError, ProtocolError
from .link import Link
from .log import get_logger


@dataclass
class PoolEntry:
    link: Link
    pong: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread = None


class LinkPool:
    def __init__(self, name: str, connect_fn, reader_fn):
        self._name = name
        self._connect = connect_fn
        self._reader = reader_fn
        self._entries = {}
        self._lock = threading.Lock()
        self._log = get_logger(name)

    def get(self, key: str) -> Link:
        with self._lock:
            entry = self._entries.get(key)
        if entry is not None:
            return entry.link

        link = self._connect(key)
        entry = PoolEntry(link)
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:  # another thread won the race
                link.close()
                return existing.link
            self._entries[key] = entry

        thread = threading.Thread(
            target=self._reader_main,
            args=(key, entry),
            daemon=True,
            name=f"{self._name}-{key}",
        )
        entry.thread = thread
        thread.start()
        return link

    def entry(self, key: str) -> PoolEntry:
        with self._lock:
            return self._entries.get(key)

    def snapshot(self) -> list:
        with self._lock:
            return list(self._entries.items())

    def keys(self) -> list:
        with self._lock:
            return list(self._entries)

    def drop(self, key: str, link: Link) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry.link is link:
                del self._entries[key]
        link.close()

    def close_all(self) -> None:
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            entry.link.close()
        for entry in entries:
            thread = entry.thread
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=1.0)

    def _reader_main(self, key: str, entry: PoolEntry) -> None:
        try:
            self._reader(key, entry)
        except (ConnectionError, OSError, ProtocolError):
            pass
        except PorError as exc:
            self._log.warning("pool reader for %s: %s", key, exc)
        except Exception:
            self._log.exception("unexpected error in pool reader for %s", key)
        finally:
            self.drop(key, entry.link)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
