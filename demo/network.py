#!/usr/bin/env python3
"""Start the Por directory and relay nodes and keep them running.

This is the infrastructure half of the interactive chat demo.  Start it in
one terminal, then run server B and client A in two other terminals:

    .venv/bin/python demo/network.py

    # terminal 2
    .venv/bin/python demo/client.py --server --chat --port 8000

    # terminal 3
    .venv/bin/python demo/client.py --chat \
        --to 127.0.0.1:8000 --via node1,node3,node2
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(DEMO_DIR))

import config
from run_all import _stop_all, spawn, wait_nodes, wait_port


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Start the Por directory and relay nodes for chat demos."
    )
    parser.parse_args()

    procs = []
    try:
        print("=== directory authorities server ===", flush=True)
        procs.append(spawn("demo/server.py"))
        wait_port(config.DIR_PORT)

        print("\n=== relay nodes ===", flush=True)
        for node_id, port in config.NODES.items():
            procs.append(
                spawn(
                    "demo/node.py",
                    "--id",
                    node_id,
                    "--port",
                    str(port),
                )
            )
        wait_nodes(len(config.NODES))

        print(
            "\nnetwork ready. Leave this terminal running and use:\n"
            "  server B: .venv/bin/python demo/client.py --server --chat "
            "--port 8000\n"
            "  client A: .venv/bin/python demo/client.py --chat "
            "--to 127.0.0.1:8000 --via node1,node3,node2\n"
            "\nCtrl-C stops the directory and relay nodes.",
            flush=True,
        )
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[network] stopping", flush=True)
    except Exception as exc:
        print(f"\n[network] failed: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        _stop_all(procs)
        print("[network] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
