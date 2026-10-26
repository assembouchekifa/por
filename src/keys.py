"""RSA + AES-GCM helper for Por (UML box: ``rsa``).

The original implementation encrypted the entire payload with chunked
RSA PKCS#1 v1.5.  That is both very slow (pure-Python RSA private-key
operations) and unauthenticated.  A layer is now sealed with a fresh
AES-256-GCM key and only that short key is wrapped with RSA-OAEP:

    b"POR1" | uint16 wrapped-key length | wrapped key | 12-byte nonce | ciphertext

One RSA operation per layer, independent of message size.  Legacy
chunked RSA ciphertext is still accepted by :meth:`decrypt_message` so
old in-flight data does not turn into a confusing crash.
"""

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CryptoError, ProtocolError

_MAGIC = b"POR1"
_KEY_LEN = 32
_NONCE_LEN = 12
_AAD = b"por-layers-v1"
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
_LEGACY_PADDING = padding.PKCS1v15()


class Rsa:
    def __init__(self, keysize: int = 2048):
        if keysize < 1024:
            raise ValueError("RSA key size must be at least 1024 bits")
        self.keysize = keysize
        self.private_key = None
        self.public_key = None
        self.generate()

    # -- keys -----------------------------------------------------------
    def generate(self):
        self.private_key = _rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keysize,
        )
        self.public_key = self.private_key.public_key()
        return self

    @property
    def block_size(self) -> int:
        """Size in bytes of one RSA block (kept for compatibility)."""
        return self.keysize // 8

    def export_public(self) -> str:
        """Public key as SubjectPublicKeyInfo PEM text."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @staticmethod
    def import_public(pem):
        """Import a peer's public key from PEM text or bytes."""
        if isinstance(pem, _rsa.RSAPublicKey):
            return pem
        if isinstance(pem, str):
            pem = pem.encode("ascii")
        if not isinstance(pem, (bytes, bytearray)):
            raise ProtocolError("public key must be PEM text or bytes")
        try:
            key = serialization.load_pem_public_key(bytes(pem))
        except Exception as exc:
            raise ProtocolError(f"invalid public key: {exc}") from exc
        if not isinstance(key, _rsa.RSAPublicKey):
            raise ProtocolError("public key is not an RSA key")
        return key

    # -- messages -------------------------------------------------------
    @staticmethod
    def encrypt_for(data, pubkey) -> bytes:
        """Seal ``data`` for ``pubkey`` with AES-GCM + RSA-OAEP."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be str or bytes")
        if not isinstance(pubkey, _rsa.RSAPublicKey):
            raise ProtocolError("encrypt_for() needs an RSA public key")

        key = AESGCM.generate_key(bit_length=_KEY_LEN * 8)
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = AESGCM(key).encrypt(nonce, bytes(data), _AAD)
        try:
            wrapped = pubkey.encrypt(key, _OAEP)
        except Exception as exc:  # invalid key size, etc.
            raise CryptoError(f"cannot wrap layer key: {exc}") from exc
        if len(wrapped) > 0xFFFF:
            raise CryptoError("wrapped key is too large")
        return (
            _MAGIC
            + struct.pack(">H", len(wrapped))
            + wrapped
            + nonce
            + ciphertext
        )

    def decrypt_message(self, cipher: bytes) -> bytes:
        """Open one layer produced by :meth:`encrypt_for`."""
        if not isinstance(cipher, (bytes, bytearray)):
            raise CryptoError("ciphertext must be bytes")
        cipher = bytes(cipher)
        if not cipher:
            return b""
        if cipher.startswith(_MAGIC):
            return self._decrypt_hybrid(cipher)
        return self._decrypt_legacy(cipher)

    def _decrypt_hybrid(self, cipher: bytes) -> bytes:
        header = len(_MAGIC) + 2
        if len(cipher) < header + _NONCE_LEN:
            raise CryptoError("truncated encrypted layer")
        (wrapped_len,) = struct.unpack(">H", cipher[len(_MAGIC):header])
        end = header + wrapped_len
        if wrapped_len <= 0 or len(cipher) < end + _NONCE_LEN:
            raise CryptoError("truncated encrypted layer")
        wrapped = cipher[header:end]
        nonce = cipher[end:end + _NONCE_LEN]
        ciphertext = cipher[end + _NONCE_LEN:]
        if self.private_key is None:
            raise CryptoError("no private key available")

        try:
            key = self.private_key.decrypt(wrapped, _OAEP)
        except Exception as exc:
            raise CryptoError(f"cannot unwrap layer key: {exc}") from exc
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, _AAD)
        except InvalidTag as exc:
            raise CryptoError("layer authentication failed") from exc
        except Exception as exc:
            raise CryptoError(f"cannot open encrypted layer: {exc}") from exc

    def _decrypt_legacy(self, cipher: bytes) -> bytes:
        """Accept the old chunked RSA PKCS#1 v1.5 format."""
        block = self.block_size
        if block <= 0 or len(cipher) % block != 0:
            raise CryptoError("invalid encrypted layer length")
        if self.private_key is None:
            raise CryptoError("no private key available")
        out = bytearray()
        for offset in range(0, len(cipher), block):
            chunk = cipher[offset:offset + block]
            try:
                out += self.private_key.decrypt(chunk, _LEGACY_PADDING)
            except Exception as exc:
                raise CryptoError(f"cannot decrypt legacy layer: {exc}") from exc
        return bytes(out)
