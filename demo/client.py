#!/usr/bin/env python3
"""Por client script - hidden server, or sender.

Server mode (server B, no keys, no id, knows nothing about who connects):
    .venv/bin/python demo/client.py --server --port 8000

Sender mode (client A, circuit + persistent reply listener):
    .venv/bin/python demo/client.py --send hi --send "still here" \
        --to 127.0.0.1:8000 --via node1,node3,node2

Interactive chat (both sides type lines):
    .venv/bin/python demo/client.py --server --chat --port 8000
    .venv/bin/python demo/client.py --chat --to 127.0.0.1:8000 \
        --via node1,node3,node2

Drop --via and the client picks --hops random nodes from the directory.
"""

import argparse
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from src.client import Client
from src.errors import ProtocolError
from src.log import configure_logging
from src.protocol import fmt_addr, parse_addr
from src.server import Server


def run_server(args) -> None:
    server = Server(config.HOST, args.port)
    host, port = server.listen(config.HOST, args.port)
    print(f"[server] listening on {fmt_addr(host, port)} "
          f"(no id, no keys, no circuit, no idea who will connect)", flush=True)

    if args.chat:
        print_lock = threading.Lock()

        def chat_print(text: str) -> None:
            with print_lock:
                print(text, flush=True)

        def on_open(session) -> None:
            chat_print("[server] chat route accepted; waiting for the first "
                       "client line")

            def read_stdin() -> None:
                if not session.wait_ready():
                    return
                chat_print("[server] route ready - type a line and press "
                           "Enter (Ctrl-D exits)")
                while not session.closed:
                    line = sys.stdin.readline()
                    if not line:
                        chat_print("[server] input closed; stopping")
                        server.close()
                        break
                    text = line.rstrip("\n")
                    if not text:
                        continue
                    try:
                        session.send(text)
                    except (ConnectionError, OSError, TimeoutError) as exc:
                        with print_lock:
                            print(f"[server] send failed: {exc}",
                                  file=sys.stderr, flush=True)
                        break

            threading.Thread(
                target=read_stdin,
                daemon=True,
                name="por-server-chat-stdin",
            ).start()

        def chat_handler(session, text: str) -> None:
            chat_print(f"[client] {text}")

        try:
            server.serve_chat(
                chat_handler,
                on_open=on_open,
                background=False,
            )
        except KeyboardInterrupt:
            print("\n[server] stopped", flush=True)
        finally:
            server.close()
        return

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


def run_chat(sender: Client, args) -> None:
    """Read stdin, send every line through the circuit, print replies."""
    stop = threading.Event()

    def receive_loop() -> None:
        while not stop.is_set():
            try:
                _msg_id, text = sender.receive(timeout=0.5)
            except TimeoutError:
                continue
            except (ConnectionError, OSError, RuntimeError) as exc:
                print(f"[sender] receive loop stopped: {exc}",
                      file=sys.stderr, flush=True)
                break
            print(f"[server] {text}", flush=True)

    reader = threading.Thread(
        target=receive_loop,
        daemon=True,
        name="por-client-chat-receive",
    )
    reader.start()
    print("[sender] chat mode: type a line and press Enter "
          "(Ctrl-D exits)", flush=True)
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            text = line.rstrip("\n")
            if not text:
                continue
            try:
                sender.send_message(text, args.to, chat=True)
            except (ConnectionError, OSError, ProtocolError, ValueError) as exc:
                print(f"[sender] send failed: {exc}",
                      file=sys.stderr, flush=True)
                break
    finally:
        stop.set()
        reader.join(timeout=1.0)


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

        if args.chat:
            run_chat(sender, args)
            return

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
                        help="fixed reply sent back by --server mode "
                             "(non-chat)")
    parser.add_argument("--chat", action="store_true",
                        help="interactive chat: read lines from stdin and "
                             "send each one through the circuit")

    parser.add_argument("--send", default=None, action="append", metavar="TEXT",
                        help="send this message (sender mode); repeat the flag "
                             "to send several over the same circuit")
    parser.add_argument("--to", default=None, metavar="IP:PORT",
                        help="destination server address for --send/--chat")
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

    if not args.to:
        parser.error("sender mode requires --to IP:PORT")
    parse_addr(args.to)  # fail fast on a bad address
    if args.chat and args.send:
        parser.error("--chat reads from stdin and cannot be combined with --send")
    if not args.chat:
        args.send = args.send or ["hi"]
    run_sender(args)


if __name__ == "__main__":
    main()
