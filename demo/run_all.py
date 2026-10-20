#!/usr/bin/env python3
"""Run the whole Por demo with one command:

    directory authorities server
    3 relay nodes (node1, node2, node3)
    server B listening (it never learns who talks to it)
    client A builds ONE circuit node1 -> node3 -> node2 (exit)
    client A sends "hi", then "still here" over the SAME link
    server B's replies ride the same circuit back, A strips the layers

Usage:
    .venv/bin/python demo/run_all.py [--via node1,node3,node2]
"""

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config
from src.client import Client

PYTHON = sys.executable
DEFAULT_VIA = "node1,node3,node2"
B_ADDR = f"{config.HOST}:{config.B_PORT}"


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((config.HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"port {port} never came up")


def wait_nodes(count: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    probe = Client(dir_host=config.HOST, dir_port=config.DIR_PORT)
    while time.time() < deadline:
        try:
            if len(probe.get_data_of_network()) >= count:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"directory never listed {count} nodes")


def spawn(*args) -> subprocess.Popen:
    return subprocess.Popen([PYTHON, *args], cwd=ROOT)


def main() -> None:
    parser = argparse.ArgumentParser(description="Por full demo")
    parser.add_argument("--via", default=DEFAULT_VIA,
                        help="circuit node ids, last one is the exit")
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
        sender.wait(timeout=60)

        print("\n=== done: both replies came back through the same circuit "
              "and the same connection, A stripped all layers ===", flush=True)
        time.sleep(0.5)
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("\ndemo finished - all processes stopped", flush=True)


if __name__ == "__main__":
    main()
