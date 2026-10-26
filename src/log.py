"""Logging setup for Por.

Library modules only emit messages through :mod:`logging`; the demo
scripts decide where those messages go.  Payload contents are never
logged by the library by default (a privacy tool should not write every
message to stdout/disk).
"""

import logging
import sys

_ROOT = "por"

# Library default: discard records unless the embedding application (or a
# demo script via configure_logging()) installs a real handler.  This also
# stops Python's lastResort handler from printing warnings to stderr.
logging.getLogger(_ROOT).addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``por`` namespace."""
    if name.startswith(_ROOT + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT}.{name}")


def configure_logging(level: int = logging.INFO, stream=None) -> None:
    """Configure Por's logger for the demo/CLI scripts."""
    logger = logging.getLogger(_ROOT)
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def set_level(level: int) -> None:
    logging.getLogger(_ROOT).setLevel(level)
