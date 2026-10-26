import socket
import struct
import threading
import unittest

from src import wire
from src.errors import ProtocolError


def socket_pair():
    left, right = socket.socketpair()
    left.settimeout(2)
    right.settimeout(2)
    return left, right


class WireTests(unittest.TestCase):
    def test_roundtrip(self):
        left, right = socket_pair()
        try:
            payload = {"type": "hello", "text": "unicode snowman \u2603"}
            wire.send_msg(left, payload)
            self.assertEqual(wire.recv_msg(right), payload)
        finally:
            left.close()
            right.close()

    def test_partial_frame(self):
        left, right = socket_pair()
        try:
            payload = {"type": "hello", "text": "x" * 1000}
            encoded = wire.encode_json(payload)
            frame = struct.pack(">I", len(encoded)) + encoded

            def dribble():
                for index in range(0, len(frame), 7):
                    left.sendall(frame[index:index + 7])

            thread = threading.Thread(target=dribble)
            thread.start()
            self.assertEqual(wire.recv_msg(right), payload)
            thread.join()
        finally:
            left.close()
            right.close()

    def test_zero_length_frame_rejected(self):
        left, right = socket_pair()
        try:
            left.sendall(struct.pack(">I", 0))
            with self.assertRaises(ProtocolError):
                wire.recv_msg(right)
        finally:
            left.close()
            right.close()

    def test_oversized_frame_rejected_before_body(self):
        left, right = socket_pair()
        try:
            left.sendall(struct.pack(">I", 100))
            with self.assertRaises(ProtocolError):
                wire.recv_msg(right, max_frame_size=10)
        finally:
            left.close()
            right.close()

    def test_malformed_json_rejected(self):
        left, right = socket_pair()
        try:
            body = b"not json"
            left.sendall(struct.pack(">I", len(body)) + body)
            with self.assertRaises(ProtocolError):
                wire.recv_msg(right)
        finally:
            left.close()
            right.close()

    def test_non_object_json_rejected(self):
        left, right = socket_pair()
        try:
            body = b'["not", "an", "object"]'
            left.sendall(struct.pack(">I", len(body)) + body)
            with self.assertRaises(ProtocolError):
                wire.recv_msg(right)
        finally:
            left.close()
            right.close()

    def test_missing_type_rejected(self):
        left, right = socket_pair()
        try:
            wire.send_msg(left, {"text": "no type"})
            with self.assertRaises(ProtocolError):
                wire.recv_msg(right)
        finally:
            left.close()
            right.close()

    def test_closed_socket_raises_connection_error(self):
        left, right = socket_pair()
        left.close()
        try:
            with self.assertRaises(ConnectionError):
                wire.recv_exact(right, 4)
        finally:
            right.close()

    def test_b64_rejects_garbage(self):
        with self.assertRaises(ProtocolError):
            wire.unb64("not base64!")
        with self.assertRaises(ProtocolError):
            wire.unb64(123)

    def test_parse_addr(self):
        self.assertEqual(wire.parse_addr("127.0.0.1:9000"), ("127.0.0.1", 9000))
        for bad in ("127.0.0.1", ":9000", "127.0.0.1:0", "127.0.0.1:70000",
                    "127.0.0.1:notaport", None):
            with self.assertRaises(ProtocolError, msg=bad):
                wire.parse_addr(bad)

    def test_require_helpers(self):
        msg = {"id": "x", "port": 1, "items": []}
        self.assertEqual(wire.require_str(msg, "id"), "x")
        self.assertEqual(wire.require_int(msg, "port", min_value=1), 1)
        self.assertEqual(wire.require_list(msg, "items"), [])
        with self.assertRaises(ProtocolError):
            wire.require_str(msg, "missing")
        with self.assertRaises(ProtocolError):
            wire.require_int({"port": True}, "port")


if __name__ == "__main__":
    unittest.main()
