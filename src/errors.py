"""Por exception hierarchy."""


class PorError(Exception):
    """Base class for all Por-specific errors."""


class ProtocolError(PorError):
    """A peer sent something that is not valid Por protocol."""


class CryptoError(ProtocolError):
    """A key or encrypted blob could not be processed."""
