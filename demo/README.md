# Por demo

One command runs the whole architecture from `architecture.md`:

```
.venv/bin/python demo/run_all.py
```

That starts the directory authorities server, three relay nodes, server B
and then client A pushes `hi` through `node1 -> node3 -> node2`.  node2 is
the **exit** node, so it is the only one that learns client A's reply
address and can return server B's `hello`.

Use `--via` to pick any circuit, the number of nodes is up to you (the last
one is the exit):

```
.venv/bin/python demo/run_all.py --via node2,node1
```

## Run the pieces yourself

Terminal 1 - directory authorities server:

```
.venv/bin/python demo/server.py
```

Terminal 2..n - relay nodes:

```
.venv/bin/python demo/node.py --id node1 --port 7001
.venv/bin/python demo/node.py --id node2 --port 7002
.venv/bin/python demo/node.py --id node3 --port 7003
```

Terminal - server B.  It is a plain TCP server: it has no id, no circuit,
and does not know who is connecting or where the message came from.

```
.venv/bin/python demo/client.py --server --port 8000
```

Terminal - client A sends and waits for the reply:

```
.venv/bin/python demo/client.py --send hi \
    --to 127.0.0.1:8000 --via node1,node3,node2
```

Clients have no `--id`: only nodes are identified (their id is what they
register with `server.py`).  `--to` is the destination **ip:port** (server
B).  Leave `--via` out and client A picks `--hops` random nodes from the
network data instead (2 by default).

## How the reply comes back

`client A` seals its own `ip:port` as `reply_to` inside the innermost RSA
layer, the one only the exit node can open.  The exit node delivers the
message to server B, reads server B's `hello` on that same socket, and —
being the only node that knows the address — connects back to client A.
