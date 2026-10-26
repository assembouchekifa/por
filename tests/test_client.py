import socket
import time
import unittest
from unittest import mock

from src.client import Client
from src.config import Settings
from src.link import Link


class ClientInboxTests(unittest.TestCase):
    def setUp(self):
        self.client = Client(settings=Settings(key_size=1024))
        self.client.node_path = [{"id": "node1"}]

    def tearDown(self):
        self.client.close()

    def test_timeout_raises_timeout_error(self):
        with self.assertRaises(TimeoutError):
            self.client.wait_reply(timeout=0.05)

    def test_buffered_reply_with_zero_timeout(self):
        self.client._put_reply("abc", "hello")
        self.assertEqual(
            self.client.wait_reply(timeout=0, msg_id="abc"), "hello"
        )

    def test_unmatched_reply_does_not_spin_or_disappear(self):
        self.client._put_reply("other", "not mine")
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.client.wait_reply(timeout=0.1, msg_id="mine")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0)
        self.assertEqual(
            self.client.wait_reply(timeout=0, msg_id="other"), "not mine"
        )

    def test_matching_reply_leaves_other_replies(self):
        self.client._put_reply("other", "other text")
        self.client._put_reply("mine", "mine text")
        self.assertEqual(
            self.client.wait_reply(timeout=0, msg_id="mine"), "mine text"
        )
        self.assertEqual(
            self.client.wait_reply(timeout=0, msg_id="other"), "other text"
        )

    def test_unknown_reply_is_dropped(self):
        self.client._on_reply({"msg_id": "unknown", "payload": "AAAA"})
        with self.assertRaises(TimeoutError):
            self.client.wait_reply(timeout=0.01)

    def test_layer_entries_are_pruned(self):
        self.client.settings = Settings(key_size=1024, layers_ttl=0)
        self.client._layers["old"] = (2, time.monotonic() - 1)
        self.client._prune_layers()
        self.assertNotIn("old", self.client._layers)


class ClientCircuitTests(unittest.TestCase):
    def test_explicit_path_sets_hop_count_to_path_length(self):
        client = Client(settings=Settings(key_size=1024))
        entries = {
            node_id: {
                "id": node_id,
                "host": "127.0.0.1",
                "port": 7000 + index,
                "kind": "node",
                "public_key": client.rsa.export_public(),
            }
            for index, node_id in enumerate(("a", "b", "c"))
        }
        client._dir = mock.Mock()
        client._dir.get_clients.return_value = entries

        left, right = socket.socketpair()
        left.settimeout(2)
        right.settimeout(2)
        try:
            with mock.patch(
                "src.client.connect",
                return_value=Link(left, max_frame_size=1024 * 1024),
            ):
                path = client.init_connection(
                    hops=1, path=["a", "b", "c"]
                )
            self.assertEqual([entry["id"] for entry in path], ["a", "b", "c"])
            self.assertEqual(client._hops, 3)
            self.assertEqual(client._path_ids, ["a", "b", "c"])
        finally:
            client.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
