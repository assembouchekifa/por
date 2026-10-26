import unittest

from src import protocol
from src.config import Settings
from src.data_server import DataServer
from src.directory_client import DirectoryClient
from src.keys import Rsa
from src.link import connect


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            key_size=1024,
            connect_timeout=1.0,
            query_timeout=1.0,
            handshake_timeout=1.0,
            cleanup_every=0.05,
            stale_after=2.0,
            max_frame_size=1024 * 1024,
        )
        self.server = DataServer("127.0.0.1", 0, settings=self.settings)
        self.server.start(background=True)
        self.dir = DirectoryClient(
            "127.0.0.1", self.server.port, self.settings
        )
        self.links = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for link in self.links:
            link.close()
        self.server.stop()

    def register(self, node_id="n1", kind="node", port=7001, rsa_obj=None):
        rsa_obj = rsa_obj or Rsa(1024)
        link = connect(
            "127.0.0.1",
            self.server.port,
            timeout=1.0,
            max_frame_size=self.settings.max_frame_size,
        )
        self.links.append(link)
        link.send({
            "type": "register",
            "id": node_id,
            "kind": kind,
            "host": "127.0.0.1",
            "port": port,
            "public_key": rsa_obj.export_public(),
        })
        protocol.prove_key(
            link.sock, rsa_obj, max_frame_size=self.settings.max_frame_size
        )
        reply = link.recv()
        self.assertEqual(reply["type"], "ok")
        return link, rsa_obj

    def test_register_heartbeat_and_lookup(self):
        link, _rsa = self.register()
        nodes = self.dir.get_network()
        self.assertEqual([node["id"] for node in nodes], ["n1"])
        self.assertEqual(nodes[0]["port"], 7001)
        self.assertNotIn("link", nodes[0])

        link.send({"type": "heartbeat", "id": "n1"})
        self.assertEqual(link.recv()["type"], "ok")

        client = self.dir.get_client("n1")
        self.assertEqual(client["id"], "n1")
        self.assertEqual(client["host"], "127.0.0.1")

        batch = self.dir.get_clients(["n1", "missing"])
        self.assertEqual(list(batch), ["n1"])

    def test_client_kind_is_not_in_network_data(self):
        self.register("node1", kind="node")
        self.register("client1", kind="client", port=8000)
        ids = {node["id"] for node in self.dir.get_network()}
        self.assertEqual(ids, {"node1"})

    def test_malformed_register_returns_error_and_keeps_connection(self):
        link = connect(
            "127.0.0.1",
            self.server.port,
            timeout=1.0,
            max_frame_size=self.settings.max_frame_size,
        )
        self.links.append(link)
        link.send({"type": "register", "id": "bad"})
        reply = link.recv()
        self.assertEqual(reply["type"], "error")
        self.assertIn("host", reply["error"])

        rsa_obj = Rsa(1024)
        link.send({
            "type": "register",
            "id": "good",
            "host": "127.0.0.1",
            "port": 7002,
            "public_key": rsa_obj.export_public(),
        })
        protocol.prove_key(
            link.sock, rsa_obj, max_frame_size=self.settings.max_frame_size
        )
        self.assertEqual(link.recv()["type"], "ok")

    def test_heartbeat_from_wrong_link_is_rejected(self):
        self.register("n1")
        link = connect(
            "127.0.0.1",
            self.server.port,
            timeout=1.0,
            max_frame_size=self.settings.max_frame_size,
        )
        self.links.append(link)
        link.send({"type": "heartbeat", "id": "n1"})
        reply = link.recv()
        self.assertEqual(reply["type"], "error")
        self.assertIn("not registered", reply["error"])

    def test_stale_entry_is_dropped_and_link_closed(self):
        link, _rsa = self.register("n1")
        with self.server._lock:
            self.server.dir_client["n1"]["seen"] -= 10
        self.assertEqual(self.server.cleanup_stale(), 1)
        self.assertIsNone(self.dir.get_client("n1"))
        with self.assertRaises((ConnectionError, OSError)):
            link.recv()

    def test_re_register_same_id_replaces_old_link(self):
        old_link, rsa_obj = self.register("n1", port=7001)
        new_link, _ = self.register("n1", port=7001, rsa_obj=rsa_obj)
        self.assertEqual(self.dir.get_client("n1")["port"], 7001)
        with self.assertRaises((ConnectionError, OSError)):
            old_link.recv()
        new_link.send({"type": "heartbeat", "id": "n1"})
        self.assertEqual(new_link.recv()["type"], "ok")

    def test_unknown_message_returns_error(self):
        link, _ = self.register()
        link.send({"type": "nonsense"})
        reply = link.recv()
        self.assertEqual(reply["type"], "error")
        self.assertIn("unknown", reply["error"])

    def test_invalid_json_does_not_kill_directory(self):
        link = connect(
            "127.0.0.1",
            self.server.port,
            timeout=1.0,
            max_frame_size=self.settings.max_frame_size,
        )
        self.links.append(link)
        link.sock.sendall((4).to_bytes(4, "big") + b"nope")
        with self.assertRaises((ConnectionError, OSError)):
            link.recv()
        # The listener is still alive and can answer a fresh query.
        self.assertEqual(self.dir.get_network(), [])


if __name__ == "__main__":
    unittest.main()
