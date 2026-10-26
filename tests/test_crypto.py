import socket
import threading
import unittest

from src import protocol
from src.errors import CryptoError, ProtocolError
from src.keys import Rsa


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = Rsa(2048)

    def test_roundtrip_sizes(self):
        for size in (0, 1, 100, 10_000, 1_000_000):
            data = b"x" * size
            sealed = Rsa.encrypt_for(data, self.rsa.public_key)
            self.assertEqual(self.rsa.decrypt_message(sealed), data)

    def test_unicode_string(self):
        data = "hello \u2603"
        sealed = Rsa.encrypt_for(data, self.rsa.public_key)
        self.assertEqual(self.rsa.decrypt_message(sealed), data.encode())

    def test_wrong_private_key(self):
        other = Rsa(2048)
        sealed = Rsa.encrypt_for(b"secret", self.rsa.public_key)
        with self.assertRaises(CryptoError):
            other.decrypt_message(sealed)

    def test_tampering_is_detected(self):
        sealed = bytearray(Rsa.encrypt_for(b"secret", self.rsa.public_key))
        sealed[-1] ^= 1
        with self.assertRaises(CryptoError):
            self.rsa.decrypt_message(bytes(sealed))

    def test_export_import_public(self):
        pem = self.rsa.export_public()
        imported = Rsa.import_public(pem)
        sealed = Rsa.encrypt_for(b"hello", imported)
        self.assertEqual(self.rsa.decrypt_message(sealed), b"hello")

    def test_bad_public_key(self):
        with self.assertRaises(ProtocolError):
            Rsa.import_public("not a key")
        with self.assertRaises(ProtocolError):
            Rsa.import_public(123)

    def test_legacy_chunked_rsa_is_still_readable(self):
        from cryptography.hazmat.primitives.asymmetric import padding

        data = b"legacy message " * 100
        block = self.rsa.block_size
        chunk = block - 11
        cipher = b"".join(
            self.rsa.public_key.encrypt(
                data[offset:offset + chunk], padding.PKCS1v15()
            )
            for offset in range(0, len(data), chunk)
        )
        self.assertEqual(self.rsa.decrypt_message(cipher), data)

    def test_key_ownership_exchange(self):
        left, right = socket.socketpair()
        left.settimeout(2)
        right.settimeout(2)
        errors = []

        def directory_side():
            try:
                nonce = protocol.test_key(left, self.rsa.export_public())
                self.assertEqual(len(nonce), 16)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        thread = threading.Thread(target=directory_side)
        thread.start()
        try:
            protocol.prove_key(right, self.rsa)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
