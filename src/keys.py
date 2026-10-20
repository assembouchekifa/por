"""RSA helper for Por (UML box: ``rsa``).

Members from the design:
    - private_key : private key
    - public_key  : public key
    - encMessge   -> encrypt_for()
    - decryptMessage -> decrypt_message()

Standard RSA can only encrypt ``(keysize / 8) - 11`` bytes per block, so
messages are chunked and every chunk becomes one full-size cipher block.
"""

import rsa as _rsa


class Rsa:
    def __init__(self, keysize: int = 2048):
        self.keysize = keysize
        self.private_key = None
        self.public_key = None
        self.generate()

    # -- keys -----------------------------------------------------------
    def generate(self):
        self.public_key, self.private_key = _rsa.newkeys(self.keysize)
        return self

    @property
    def block_size(self) -> int:
        """Size in bytes of one encrypted block."""
        return self.keysize // 8

    def export_public(self) -> str:
        """Public key as PKCS#1 PEM text (safe to share over the wire)."""
        return self.public_key.save_pkcs1().decode()

    @staticmethod
    def import_public(pem):
        if isinstance(pem, str):
            pem = pem.encode()
        return _rsa.PublicKey.load_pkcs1(pem)

    # -- messages -------------------------------------------------------
    @staticmethod
    def encrypt_for(data, pubkey) -> bytes:
        """Encrypt ``data`` (str or bytes) with ``pubkey``, chunked.

        Needs no keypair of its own, so anyone who only *holds* a peer's
        public key (e.g. the directory server testing a node, or a hop
        adding its reply layer) can use it.
        """
        if isinstance(data, str):
            data = data.encode()
        if not data:
            return b""
        block = (pubkey.n.bit_length() + 7) // 8
        chunk = block - 11  # PKCS#1 overhead
        out = bytearray()
        for i in range(0, len(data), chunk):
            out += _rsa.encrypt(data[i:i + chunk], pubkey)
        return bytes(out)

    def decrypt_message(self, cipher: bytes) -> bytes:
        """Decrypt what :meth:`encrypt_for` produced, using ``private_key``."""
        if not cipher:
            return b""
        out = bytearray()
        for i in range(0, len(cipher), self.block_size):
            out += _rsa.decrypt(cipher[i:i + self.block_size], self.private_key)
        return bytes(out)
