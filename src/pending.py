"""Reply-routing table used by relay nodes.

A node remembers ``hop_id -> (incoming link, sender public key, return id)``
for every forwarded message.  Replies come back on the pooled link and
are matched by ``hop_id``.  The table has a TTL and a hard size cap.
"""

import threading
import time
from dataclasses import dataclass

from .config import DEFAULT
from .errors import ProtocolError
from .link import Link


@dataclass(frozen=True)
class PendingEntry:
    back_link: Link
    reply_key: object
    return_id: str
    created: float


class PendingTable:
    def __init__(self, ttl: float = DEFAULT.pending_ttl,
                 max_entries: int = DEFAULT.max_pending):
        self._ttl = ttl
        self._max_entries = max_entries
        self._entries = {}
        self._lock = threading.Lock()

    def remember(
        self,
        hop_id: str,
        back_link: Link,
        reply_key,
        return_id: str,
    ) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._entries) >= self._max_entries:
                self._sweep_locked(now)
                if len(self._entries) >= self._max_entries:
                    raise ProtocolError("reply routing table is full")
            self._entries[hop_id] = PendingEntry(
                back_link=back_link,
                reply_key=reply_key,
                return_id=return_id,
                created=now,
            )

    def pop(self, hop_id: str):
        with self._lock:
            return self._entries.pop(hop_id, None)

    def forget(self, hop_id: str) -> None:
        with self._lock:
            self._entries.pop(hop_id, None)

    def forget_link(self, link: Link) -> None:
        with self._lock:
            for key, entry in list(self._entries.items()):
                if entry.back_link is link:
                    del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def sweep(self, now: float = None) -> int:
        with self._lock:
            return self._sweep_locked(time.monotonic() if now is None else now)

    def _sweep_locked(self, now: float) -> int:
        stale = [
            key for key, entry in self._entries.items()
            if now - entry.created > self._ttl
        ]
        for key in stale:
            del self._entries[key]
        return len(stale)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
