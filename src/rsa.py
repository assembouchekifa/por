"""RSA helper for Por (UML box: ``rsa``).

Members from the design:
    - prive      : private key
    - public     : public key
    - node public: known public keys of peers (nodes)
    - encMessge  -> encrypt_message()
    - decryptMessage -> decrypt_message()

Standard RSA can only encrypt ``(keysize / 8) - 11`` bytes per block, so
messages are chunked and every chunk becomes one full-size cipher block.
"""

import rsa as _rsa


class Rsa:
    def __init__(self, keysize: int = 2048):
        self.keysize = keysize
        self.prive = None
        self.public = None
        self.node_public = {}  # peer id -> rsa.PublicKey
        self.generate()

    # -- keys -----------------------------------------------------------
    def generate(self):
        self.public, self.prive = _rsa.newkeys(self.keysize)
        return self

    @property
    def block_size(self) -> int:
        """Size in bytes of one encrypted block."""
        return self.keysize // 8

    @property
    def chunk_size(self) -> int:
        """Max plaintext bytes that fit in one block (PKCS#1 overhead = 11)."""
        return self.block_size - 11

    def export_public(self) -> str:
        """Public key as PKCS#1 PEM text (safe to share over the wire)."""
        return self.public.save_pkcs1().decode()

    @staticmethod
    def import_public(pem):
        if isinstance(pem, str):
            pem = pem.encode()
        return _rsa.PublicKey.load_pkcs1(pem)

    def remember_node(self, node_id: str, pem) -> None:
        self.node_public[node_id] = self.import_public(pem)

    # -- messages -------------------------------------------------------
    @staticmethod
    def encrypt_for(data, pubkey) -> bytes:
        """Encrypt ``data`` (str or bytes) with ``pubkey``, chunked.

        Needs no keypair of its own, so anyone who only *holds* a peer's
        public key (e.g. the directory server testing a node) can use it.
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

    def encrypt_message(self, data, pubkey) -> bytes:
        """Encrypt ``data`` (str or bytes) with ``pubkey``, chunked."""
        return self.encrypt_for(data, pubkey)

    def decrypt_message(self, cipher: bytes) -> bytes:
        """Decrypt what :meth:`encrypt_message` produced, using ``prive``."""
        if not cipher:
            return b""
        out = bytearray()
        for i in range(0, len(cipher), self.block_size):
            out += _rsa.decrypt(cipher[i:i + self.block_size], self.prive)
        return bytes(out)
