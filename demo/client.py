#!/usr/bin/env python3
"""Por client script - hidden server, or sender.

Server mode (server B, no keys, no id, knows nothing about who connects):
    .venv/bin/python demo/client.py --server --port 8000

Sender mode (client A, circuit + persistent reply listener):
    .venv/bin/python demo/client.py --send hi --send "still here" \
        --to 127.0.0.1:8000 --via node1,node3,node2

Drop --via and the client picks --hops random nodes from the directory.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from src.client import Client
from src.log import configure_logging
from src.protocol import fmt_addr, parse_addr
from src.server import Server


def run_server(args) -> None:
    server = Server(config.HOST, args.port)
    host, port = server.listen(config.HOST, args.port)
    print(f"[server] listening on {fmt_addr(host, port)} "
          f"(no id, no keys, no circuit, no idea who will connect)", flush=True)

    def handler(text: str) -> str:
        print(f"[server] received from exit node: {text!r}", flush=True)
        print(f"[server] replied: {args.reply!r}", flush=True)
        return args.reply

    try:
        server.serve(handler, background=False)
    except KeyboardInterrupt:
        print("\n[server] stopped", flush=True)
    finally:
        server.close()


def run_sender(args) -> None:
    sender = Client(dir_host=args.dir_host, dir_port=args.dir_port,
                    keysize=config.KEY_SIZE)

    try:
        path = ([node_id.strip() for node_id in args.via.split(",")]
                if args.via else None)
        circuit = sender.init_connection(hops=args.hops, path=path)
        route = " -> ".join(entry["id"] for entry in circuit)
        print(f"[sender] circuit ready: {route} (exit: {circuit[-1]['id']}), "
              f"one persistent link, keys from the directory, no handshake",
              flush=True)

        for text in args.send:
            msg_id = sender.send_message(text, args.to)
            print(f"[sender] sent to {args.to}: {text!r} (msg_id {msg_id[:8]}, "
                  f"no address of ours left this machine)", flush=True)
            reply = sender.wait_reply(timeout=args.timeout, msg_id=msg_id)
            print(f"[sender] stripped {len(circuit)} layers -> "
                  f"reply from destination: {reply!r}", flush=True)
        print(f"[sender] {len(args.send)} message(s) on the same circuit "
              f"and the same connection", flush=True)
    except KeyboardInterrupt:
        print("\n[sender] stopped", flush=True)
    finally:
        sender.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Por client (anonymous)")
    parser.add_argument("--dir-host", default=config.HOST)
    parser.add_argument("--dir-port", type=int, default=config.DIR_PORT)

    parser.add_argument("--server", action="store_true",
                        help="run as a plain, keyless destination server (server B)")
    parser.add_argument("--port", type=int, default=config.B_PORT,
                        help="port to listen on in --server mode")
    parser.add_argument("--reply", default="hello",
                        help="fixed reply sent back by --server mode")

    parser.add_argument("--send", default=None, action="append", metavar="TEXT",
                        help="send this message (sender mode); repeat the flag "
                             "to send several over the same circuit")
    parser.add_argument("--to", default=None, metavar="IP:PORT",
                        help="destination server address for --send")
    parser.add_argument("--via", default=None,
                        help="comma separated node ids forming the circuit, "
                             "e.g. node1,node3,node2 (last one is the exit)")
    parser.add_argument("--hops", type=int, default=config.CIRCUIT_HOPS,
                        help="random circuit length when --via is not given")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="seconds to wait for each reply")
    args = parser.parse_args()

    configure_logging()
    if args.server:
        run_server(args)
        return

    args.send = args.send or ["hi"]
    if not args.to:
        parser.error("sender mode requires --to IP:PORT")
    parse_addr(args.to)  # fail fast on a bad address
    run_sender(args)


if __name__ == "__main__":
    main()
