"""Small client for the directory authorities server."""

from .config import DEFAULT
from .errors import ProtocolError
from .link import connect
from .wire import require_list


class DirectoryClient:
    """One-shot directory queries (fresh short-lived TCP connection)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9000,
                 settings=DEFAULT):
        self.host = host
        self.port = port
        self.settings = settings

    def _request(self, msg: dict) -> dict:
        link = connect(
            self.host,
            self.port,
            timeout=self.settings.connect_timeout,
            keepalive=False,
            max_frame_size=self.settings.max_frame_size,
        )
        try:
            link.settimeout(self.settings.query_timeout)
            link.send(msg)
            reply = link.recv()
        finally:
            link.close()
        if reply.get("type") == "error":
            raise ProtocolError(str(reply.get("error", "directory error")))
        return reply

    def get_network(self) -> list:
        reply = self._request({"type": "get_data_of_network"})
        if reply.get("type") != "network_data":
            raise ProtocolError(f"unexpected directory reply: {reply.get('type')!r}")
        nodes = require_list(reply, "nodes", max_length=100_000)
        for entry in nodes:
            if not isinstance(entry, dict):
                raise ProtocolError("directory returned a non-object node entry")
        return nodes

    def get_client(self, node_id: str):
        reply = self._request({"type": "get_client", "id": node_id})
        if reply.get("type") != "client_data":
            raise ProtocolError(f"unexpected directory reply: {reply.get('type')!r}")
        client = reply.get("client")
        if client is not None and not isinstance(client, dict):
            raise ProtocolError("directory returned a non-object client entry")
        return client

    def get_clients(self, node_ids) -> dict:
        ids = list(node_ids)
        try:
            reply = self._request({"type": "get_clients", "ids": ids})
        except ProtocolError:
            # An older directory answers "unknown message": fall back to
            # one lookup per id instead of failing the whole circuit.
            return {node_id: self.get_client(node_id) for node_id in ids}
        if reply.get("type") != "clients_data":
            return {node_id: self.get_client(node_id) for node_id in ids}
        clients = require_list(reply, "clients", max_length=len(ids))
        result = {}
        for entry in clients:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise ProtocolError("directory returned a malformed client entry")
            result[entry["id"]] = entry
        return result
