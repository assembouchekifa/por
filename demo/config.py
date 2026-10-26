"""Shared defaults for the demo scripts."""

from src.config import DEFAULT

HOST = DEFAULT.host
DIR_PORT = DEFAULT.dir_port
KEY_SIZE = DEFAULT.key_size

# Demo-specific topology.
NODES = {"node1": 7001, "node2": 7002, "node3": 7003}

# circuit length used only when --via is missing (random nodes)
CIRCUIT_HOPS = 2

# default listening port of server B
B_PORT = 8000
