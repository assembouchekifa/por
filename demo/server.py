#!/usr/bin/env python3
"""Directory authorities server script.

Nodes register here and prove they own the public key they publish; a
stale sweep drops anyone silent for too long (nodes heartbeat every 60s).

Usage:
    .venv/bin/python demo/server.py [--host HOST] [--port PORT]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from src.data_server import DataServer
from src.log import configure_logging


def main() -> None:
    parser = argparse.ArgumentParser(description="Por directory authorities server")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.DIR_PORT)
    args = parser.parse_args()

    configure_logging()
    server = DataServer(args.host, args.port)
    print(f"[server] directory authorities listening on {args.host}:{args.port}",
          flush=True)
    try:
        server.start(background=False)
    except KeyboardInterrupt:
        print("\n[server] stopped", flush=True)
    finally:
        server.stop()


if __name__ == "__main__":
    main()
