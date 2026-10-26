# Por demo

One command runs the whole architecture:

```bash
.venv/bin/python demo/run_all.py
```

That starts the directory authorities server, three relay nodes, server B,
and client A. Client A builds **one circuit** `node1 -> node3 -> node2` and
pushes two messages through it: `hi`, then `same circuit, still here`.
node2 is the **exit** node, so it is the only relay that learns client A's
reply address and can return server B's answers.

Use `--via` to pick any circuit (the last node is the exit):

```bash
.venv/bin/python demo/run_all.py --via node2,node1
```

## Run the pieces yourself

Terminal 1 - directory authorities server:

```bash
.venv/bin/python demo/server.py
```

Terminal 2..n - relay nodes:

```bash
.venv/bin/python demo/node.py --id node1 --port 7001
.venv/bin/python demo/node.py --id node2 --port 7002
.venv/bin/python demo/node.py --id node3 --port 7003
```

Terminal - server B. It is a plain TCP server: no id, no keys, no circuit,
and no idea who is connecting or where the message came from.

```bash
.venv/bin/python demo/client.py --server --port 8000
```

Terminal - client A. Repeat `--send` to push several messages through the
same circuit; the connection stays open:

```bash
.venv/bin/python demo/client.py --send hi --send "and again" \
    --to 127.0.0.1:8000 --via node1,node3,node2
```

Clients have no `--id`: only nodes are identified (their id is what they
register with `server.py`). `--to` is the destination **ip:port** (server B).
Leave `--via` out and client A picks `--hops` random nodes from the network
data instead (2 by default).

## Persistent links, not one connection per message

Every link is opened once and reused:

* client A opens one connection to the entry node and keeps it for every
  later message - `init_connection()` once, `send_message()` as often as you
  like;
* each node keeps a pooled connection per neighbour (`node -> node`), so a
  hop does not dial TCP again for every packet;
* the exit node keeps a pooled connection per destination server, and server
  B keeps one per exit node.

Every forward carries a fresh random **per-hop `msg_id`**. A relay remembers
`hop_id -> (incoming link, reply key, previous hop's id, expiry)`, so replies
are routed back the moment they arrive and many messages can be in flight
over the same circuit at once. Nothing is matched by "whichever socket the
answer happened to land on". The pending table has a TTL and a size cap.

A background reader thread owns each link, which is what makes the chat work:
replies show up whenever they come back and are pushed into a client inbox
instead of blocking the sender. `wait_reply()` uses a condition variable and
raises `TimeoutError`, so it does not spin.

Keepalive: client A pings the entry node every **30 seconds**, and every node
pings its pooled neighbours the same way. A link that misses its pong is
dropped; the next send rebuilds the circuit (the same node ids first, random
ones if they are gone). Nodes heartbeat the directory every **60 seconds**;
the directory drops silent entries after **90 seconds** and the node
re-registers automatically.

## Keys, heartbeats, no handshakes

There is exactly **one** key test in the whole network: when a node
registers, the directory encrypts a random nonce with the node's public key
and expects it back decrypted. The directory keeps no keypair of its own - it
only checks that the node really owns the key it published, and refuses the
registration otherwise.

Nothing else handshakes. Nodes fetch each other's address **and public key**
from the directory and open plain TCP links; client A gets every node's public
key the same way; server B has no keys at all.

## How the reply comes back

`client A` puts its public key (`reply_pub`) in every onion layer. The exit
node delivers the message to server B, reads server B's answer, seals it for
A, and hands it to the previous hop. Each relay adds one layer and passes it
back, until the entry node hands it to A. Every node only knows the hop before
it and the hop after it.

The crypto is hybrid: each layer is AES-256-GCM encrypted and only the short
session key is wrapped with RSA-OAEP. That is one RSA operation per layer (fast
regardless of message size) and GCM detects tampering. `client A` strips one
layer per hop (`N` nodes -> `N` layers) with its private key and reads the
message.

## Tests

From the repository root:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
