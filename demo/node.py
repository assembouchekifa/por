#!/usr/bin/env python3
"""Por relay node script.

Registers with the directory (proving the published public key), then
heartbeats every 60s - if the directory drops it or restarts, the node
re-registers on its own.

Usage:
    .venv/bin/python demo/node.py --id node1 [--port PORT]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from src.log import configure_logging
from src.node import Node


def main() -> None:
    parser = argparse.ArgumentParser(description="Por relay node")
    parser.add_argument("--id", default="node1", help="node id (must be unique)")
    parser.add_argument("--port", type=int, default=None,
                        help="listen port (default: from demo config)")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--dir-host", default=config.HOST)
    parser.add_argument("--dir-port", type=int, default=config.DIR_PORT)
    args = parser.parse_args()

    port = args.port if args.port is not None else config.NODES.get(args.id, 7001)
    configure_logging()

    node = Node(args.id, args.host, port, args.dir_host, args.dir_port,
                keysize=config.KEY_SIZE)
    print(f"[node {args.id}] starting on {args.host}:{port}, "
          f"directory {args.dir_host}:{args.dir_port}", flush=True)
    try:
        node.start(background=False)
    except KeyboardInterrupt:
        print(f"\n[node {args.id}] stopped", flush=True)
    finally:
        node.stop()


if __name__ == "__main__":
    main()
