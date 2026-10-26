import socket
import unittest

from src.config import Settings
from src.errors import ProtocolError
from src.link import Link
from src.node import Node
from src.pending import PendingTable
from src.server import Server
from src import wire


class FailureTests(unittest.TestCase):
    def test_peel_layer_rejects_garbage_without_crashing(self):
        node = Node(
            "bad-layer",
            "127.0.0.1",
            0,
            "127.0.0.1",
            1,
            keysize=1024,
            settings=Settings(key_size=1024),
        )
        with self.assertRaises(ProtocolError):
            node.peel_layer(b"this is not an encrypted layer")

    def test_exit_delivery_failure_clears_pending_entry(self):
        node = Node(
            "dead-dest",
            "127.0.0.1",
            0,
            "127.0.0.1",
            1,
            keysize=1024,
            settings=Settings(key_size=1024, connect_timeout=0.2),
        )
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
        finally:
            probe.close()
        back_link = Link(socket.socket(), max_frame_size=1024 * 1024)
        try:
            node._pending.remember("hop", back_link, None, "return")
            node._deliver_and_return(
                {
                    "next": f"127.0.0.1:{dead_port}",
                    "payload": "aGVsbG8=",  # b"hello"
                },
                "hop",
            )
            self.assertEqual(len(node._pending), 0)
        finally:
            back_link.close()
            node._dest_links.close_all()

    def test_server_rejects_non_deliver_message(self):
        server = Server("127.0.0.1", 0, settings=Settings(key_size=1024))
        left, right = socket.socketpair()
        try:
            link = Link(left, max_frame_size=1024 * 1024)
            wire.send_msg(
                right,
                {"type": "reply", "msg_id": "id", "text": "not a deliver"},
                max_frame_size=1024 * 1024,
            )
            with self.assertRaises(ProtocolError):
                server.recv_message(link)
        finally:
            left.close()
            right.close()

    def test_pending_table_ttl_and_link_cleanup(self):
        table = PendingTable(ttl=-1.0, max_entries=2)
        link = Link(socket.socket())
        try:
            table.remember("one", link, None, "return-one")
            table.remember("two", link, None, "return-two")
            self.assertEqual(len(table), 2)
            self.assertGreaterEqual(table.sweep(), 2)
            table.remember("three", link, None, "return-three")
            table.forget_link(link)
            self.assertEqual(len(table), 0)
        finally:
            link.close()

    def test_chat_pending_entry_survives_repeated_replies(self):
        table = PendingTable(ttl=60.0, max_entries=4)
        link = Link(socket.socket())
        try:
            table.remember("chat", link, None, "return-chat", chat=True)
            first = table.claim("chat")
            second = table.claim("chat")
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertGreaterEqual(second.created, first.created)
            self.assertEqual(len(table), 1)

            table.remember("one-shot", link, None, "return-one")
            self.assertIsNotNone(table.claim("one-shot"))
            self.assertIsNone(table.claim("one-shot"))
            self.assertEqual(len(table), 1)
        finally:
            link.close()


if __name__ == "__main__":
    unittest.main()
