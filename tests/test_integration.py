import socket
import time
import unittest

from src.client import Client
from src.config import Settings
from src.data_server import DataServer
from src.directory_client import DirectoryClient
from src.link import connect
from src.node import Node
from src.server import Server


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_until(predicate, timeout: float = 5.0, message: str = "timed out"):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # directory may still be starting
            last_error = exc
        time.sleep(0.05)
    raise AssertionError(f"{message}; last error: {last_error!r}")


class FullCircuitTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            key_size=1024,
            connect_timeout=2.0,
            query_timeout=2.0,
            handshake_timeout=2.0,
            heartbeat_every=0.2,
            cleanup_every=0.2,
            stale_after=5.0,
            recover_every=0.1,
            link_ping_every=0.2,
            link_ping_timeout=0.5,
            pending_ttl=5.0,
            layers_ttl=5.0,
            max_frame_size=1024 * 1024,
            max_text_bytes=100_000,
        )
        self.dir = DataServer("127.0.0.1", 0, settings=self.settings)
        self.dir.start(background=True)
        self.dir_client = DirectoryClient(
            "127.0.0.1", self.dir.port, self.settings
        )

        self.nodes = []
        for index in range(1, 4):
            node = Node(
                f"n{index}",
                "127.0.0.1",
                0,
                "127.0.0.1",
                self.dir.port,
                keysize=1024,
                settings=self.settings,
            )
            node.start(background=True)
            self.nodes.append(node)

        wait_until(
            lambda: len(self.dir_client.get_network()) == 3,
            message="nodes did not register",
        )

        self.server = Server("127.0.0.1", 0, settings=self.settings)
        self.server.listen()
        self.server.serve(
            lambda text: f"echo:{text}",
            background=True,
        )
        self.server_addr = self.server.local_addr

        self.client = Client(
            "127.0.0.1",
            self.dir.port,
            keysize=1024,
            settings=self.settings,
        )
        self.client.init_connection(hops=2)

    def tearDown(self):
        try:
            self.client.close()
        finally:
            try:
                self.server.close()
            finally:
                for node in self.nodes:
                    node.stop()
                self.dir.stop()

    def test_two_messages_round_trip_on_one_circuit(self):
        address = f"{self.server_addr[0]}:{self.server_addr[1]}"
        entry_link = self.client._entry_link
        for text in ("hi", "still here"):
            msg_id = self.client.send_message(text, address)
            self.assertEqual(
                self.client.wait_reply(timeout=5.0, msg_id=msg_id),
                f"echo:{text}",
            )
            self.assertIs(self.client._entry_link, entry_link)

    def test_chat_server_sends_multiple_replies_on_one_route(self):
        def handler(session, text):
            session.send(f"first:{text}")
            session.send(f"second:{text}")

        chat_server = Server("127.0.0.1", 0, settings=self.settings)
        chat_server.listen()
        chat_server.serve_chat(handler, background=True)
        self.addCleanup(chat_server.close)
        address = "%s:%s" % chat_server.local_addr

        self.client.send_message("hello", address, chat=True)
        replies = [self.client.receive(timeout=5.0) for _ in range(2)]
        self.assertEqual(
            [text for _msg_id, text in replies],
            ["first:hello", "second:hello"],
        )

        # The same route must still work for a later chat turn.
        self.client.send_message("again", address, chat=True)
        replies = [self.client.receive(timeout=5.0) for _ in range(2)]
        self.assertEqual(
            [text for _msg_id, text in replies],
            ["first:again", "second:again"],
        )

    def test_chat_server_can_send_after_handler_returns(self):
        sessions = []

        def on_open(session):
            sessions.append(session)

        def handler(session, text):
            return None

        chat_server = Server("127.0.0.1", 0, settings=self.settings)
        chat_server.listen()
        chat_server.serve_chat(
            handler,
            on_open=on_open,
            background=True,
        )
        self.addCleanup(chat_server.close)
        address = "%s:%s" % chat_server.local_addr

        self.client.send_message("open", address, chat=True)
        wait_until(
            lambda: bool(sessions) and sessions[0].ready,
            message="chat session did not become ready",
        )
        sessions[0].send("delayed reply")
        _msg_id, text = self.client.receive(timeout=5.0)
        self.assertEqual(text, "delayed reply")

    def test_unreachable_destination_times_out_then_circuit_still_works(self):
        address = f"{self.server_addr[0]}:{self.server_addr[1]}"
        dead = f"127.0.0.1:{free_port()}"
        self.client.send_message("into the void", dead)
        with self.assertRaises(TimeoutError):
            self.client.wait_reply(timeout=0.4)

        msg_id = self.client.send_message("after the miss", address)
        self.assertEqual(
            self.client.wait_reply(timeout=5.0, msg_id=msg_id),
            "echo:after the miss",
        )

    def test_nodes_reregister_after_directory_restart(self):
        port = self.dir.port
        self.dir.stop()

        replacement = DataServer("127.0.0.1", port, settings=self.settings)
        replacement.start(background=True)
        self.addCleanup(replacement.stop)
        probe = DirectoryClient("127.0.0.1", port, self.settings)
        wait_until(
            lambda: len(probe.get_network()) == 3,
            timeout=6.0,
            message="nodes did not re-register after directory restart",
        )

    def test_malformed_peer_does_not_kill_a_node(self):
        entry = self.client.node_path[0]
        link = connect(
            "127.0.0.1",
            entry["port"],
            timeout=2.0,
            max_frame_size=self.settings.max_frame_size,
        )
        try:
            link.send({
                "type": "forward",
                "from": "attacker",
                "msg_id": "bad",
                "payload": "not-base64!",
            })
            with self.assertRaises((ConnectionError, OSError)):
                link.recv()
        finally:
            link.close()

        address = f"{self.server_addr[0]}:{self.server_addr[1]}"
        msg_id = self.client.send_message("node is fine", address)
        self.assertEqual(
            self.client.wait_reply(timeout=5.0, msg_id=msg_id),
            "echo:node is fine",
        )


if __name__ == "__main__":
    unittest.main()
