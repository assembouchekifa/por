#!/usr/bin/env python3
"""Run the whole Por demo with one command.

    directory authorities server
    3 relay nodes (node1, node2, node3)
    server B listening (it never learns who talks to it)
    client A builds ONE circuit node1 -> node3 -> node2 (exit)
    client A sends two messages over the SAME link
    server B's replies ride the same circuit back, A strips the layers

Usage:
    .venv/bin/python demo/run_all.py [--via node1,node3,node2] [--timeout 60]
"""

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(DEMO_DIR))

import config
from src.directory_client import DirectoryClient
from src.errors import ProtocolError

PYTHON = sys.executable
DEFAULT_VIA = "node1,node3,node2"
B_ADDR = f"{config.HOST}:{config.B_PORT}"


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((config.HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"port {port} never came up")


def wait_nodes(count: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    probe = DirectoryClient(config.HOST, config.DIR_PORT)
    while time.monotonic() < deadline:
        try:
            if len(probe.get_network()) >= count:
                return
        except (OSError, ProtocolError, TimeoutError):
            pass
        time.sleep(0.2)
    raise TimeoutError(f"directory never listed {count} nodes")


def spawn(*args) -> subprocess.Popen:
    return subprocess.Popen([PYTHON, "-u", *args], cwd=ROOT)


def _stop_all(procs) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Por full demo")
    parser.add_argument("--via", default=DEFAULT_VIA,
                        help="circuit node ids, last one is the exit")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="seconds allowed for the sender")
    args = parser.parse_args()

    procs = []
    try:
        print("=== 1. directory authorities server ===", flush=True)
        procs.append(spawn("demo/server.py"))
        wait_port(config.DIR_PORT)

        print("\n=== 2. relay nodes ===", flush=True)
        for node_id, port in config.NODES.items():
            procs.append(spawn("demo/node.py", "--id", node_id, "--port", str(port)))
        wait_nodes(len(config.NODES))

        print("\n=== 3. server B (listening, hidden from the network) ===", flush=True)
        procs.append(spawn("demo/client.py", "--server",
                           "--port", str(config.B_PORT)))
        wait_port(config.B_PORT)

        print(f"\n=== 4. client A sends two messages through {args.via} ===",
              flush=True)
        sender = spawn("demo/client.py", "--send", "hi",
                       "--send", "same circuit, still here",
                       "--to", B_ADDR, "--via", args.via)
        procs.append(sender)
        returncode = sender.wait(timeout=args.timeout)
        if returncode != 0:
            raise RuntimeError(f"sender exited with status {returncode}")

        print("\n=== done: both replies came back through the same circuit "
              "and the same connection, A stripped all layers ===", flush=True)
        time.sleep(0.5)
        return 0
    except Exception as exc:
        print(f"\ndemo failed: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        _stop_all(procs)
        print("\ndemo finished - all processes stopped", flush=True)


if __name__ == "__main__":
    sys.exit(main())
