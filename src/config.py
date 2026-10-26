"""Central configuration for Por.

Every timing constant, limit and default lives here so the roles do not
carry their own copies of the same magic numbers.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime settings shared by all roles.

    The defaults match the values that used to be scattered across
    ``protocol.py`` and ``demo/config.py``.  Tests and demos may create a
    modified copy (for example with very short heartbeat intervals).
    """

    host: str = "127.0.0.1"
    dir_port: int = 9000
    key_size: int = 2048

    # network timeouts (seconds)
    connect_timeout: float = 5.0
    query_timeout: float = 10.0
    handshake_timeout: float = 10.0
    stop_wake_timeout: float = 1.0
    stop_join_timeout: float = 1.0

    # directory liveness
    heartbeat_every: float = 60.0
    cleanup_every: float = 90.0
    stale_after: float = 90.0
    recover_every: float = 5.0

    # link keepalive
    link_ping_every: float = 30.0
    link_ping_timeout: float = 5.0

    # reply routing / client bookkeeping
    pending_ttl: float = 300.0
    layers_ttl: float = 330.0

    # limits (bytes / entries / hops)
    max_frame_size: int = 16 * 1024 * 1024
    max_text_bytes: int = 1024 * 1024
    max_pending: int = 10_000
    max_hops: int = 8
    max_id_length: int = 128
    max_host_length: int = 255
    max_public_key_length: int = 16_384

    # listener backlog defaults
    backlog: int = 32


DEFAULT = Settings()
