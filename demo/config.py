"""Shared defaults for the demo scripts."""

HOST = "127.0.0.1"
DIR_PORT = 9000
NODES = {"node1": 7001, "node2": 7002, "node3": 7003}
KEY_SIZE = 2048

# circuit length used only when --via is missing (random nodes)
CIRCUIT_HOPS = 2

# default listening port of server B
B_PORT = 8000
