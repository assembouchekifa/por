# Por

Por is a small, readable Tor-like messaging network written in Python. It
builds an onion circuit through relay nodes, sends an encrypted message to a
plain TCP destination server, and routes the reply back through the same
circuit. It is a learning/demo project, **not** a replacement for Tor.

## What it does

- The **directory** keeps a public phone-book of relay nodes. Nodes prove they
  own the public key they publish.
- A **client** builds a circuit (for example `node1 -> node3 -> node2`) and
  wraps the message in one onion layer per hop.
- Each **relay node** peels exactly one layer, forwards the rest, and remembers
  where the reply belongs.
- The **exit node** delivers plaintext to a keyless destination server and
  carries the reply back.
- The client strips one reply layer per hop.
- In **chat mode**, one reply route can stay open so the server can send
  several messages while the client sends more lines.

Everything is persistent-link based: one client link, pooled node links and a
pooled destination link per exit. Many messages can share the same circuit.

Full protocol, API, lifecycle, and troubleshooting documentation:
[`document.md`](document.md).

## Requirements

- Python 3.10+
- `cryptography` (see `requirements.txt`)

## Install

```bash
git clone <repo-url> por
cd por
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run the full demo

```bash
.venv/bin/python demo/run_all.py
```

That starts the directory, three relay nodes, server B (the hidden
destination), and client A. Client A sends two messages through one circuit
and one TCP connection, and prints the replies after removing all layers.

Choose a different circuit (the last node is the exit):

```bash
.venv/bin/python demo/run_all.py --via node2,node1
```

## Interactive chat

The chat demo is netcat-like: type a line, press Enter, and it goes through the
onion circuit. The other side can type and send at the same time.

Start the directory and relay nodes in terminal 1:

```bash
.venv/bin/python demo/network.py
```

Start server B in terminal 2:

```bash
.venv/bin/python demo/client.py --server --chat --port 8000
```

Start client A in terminal 3:

```bash
.venv/bin/python demo/client.py --chat \
    --to 127.0.0.1:8000 --via node1,node3,node2
```

Type in either terminal:

```text
[client] hello through the nodes
[server] hi, I got it
[server] here is a second message on the same route
```

Notes:

- Every client line creates a reply route. The first one is what enables
  server input; server input always uses the most recent route. Input typed
  before the first client message is only sent after that message arrives.
- The route stays alive while messages flow. After about five minutes of
  complete silence the pending/layer TTL expires; the next client line creates
  a fresh route.
- This minimal chat mode assumes one client per exit-to-destination link. The
  exit pools one link per destination address, so two simultaneous chat
  clients using the same exit and destination would share the same server-side
  "latest route." Clients using different exits get separate destination
  links.
- The CLI is netcat-like, but raw `nc` will not work because Por uses
  4-byte-length-prefixed JSON frames, not plain lines.

## Run the pieces yourself

Terminal 1:

```bash
.venv/bin/python demo/server.py
```

Terminals 2-4:

```bash
.venv/bin/python demo/node.py --id node1 --port 7001
.venv/bin/python demo/node.py --id node2 --port 7002
.venv/bin/python demo/node.py --id node3 --port 7003
```

Terminal 5 - destination server B:

```bash
.venv/bin/python demo/client.py --server --port 8000
```

Terminal 6 - sender A:

```bash
.venv/bin/python demo/client.py \
    --send hi --send "still here" \
    --to 127.0.0.1:8000 --via node1,node3,node2
```

Leave out `--via` and the client picks `--hops` random nodes from the
directory (default 2).

## How the protocol works

### Framing

Every frame is a 4-byte big-endian length followed by one UTF-8 JSON object.
A malformed frame, an oversized frame, or a missing `type` becomes a
`ProtocolError`; the role closes that connection instead of leaking a raw
`JSONDecodeError` or `KeyError`.

### Onion layers

For a final destination `host:port`, the innermost envelope contains:

```json
{"next": "127.0.0.1:8000", "final": true,
 "reply_pub": "<client public key>", "payload": "<base64 text>"}
```

Each node wraps the JSON envelope once with the next node's public key. A
relay peels one layer and either forwards the rest or, for the final layer,
delivers the text.

### Crypto

Each layer uses hybrid encryption: a fresh AES-256-GCM key encrypts the layer,
and RSA-OAEP (SHA-256) wraps only that key. This is one RSA operation per
layer instead of chunking the entire payload through RSA. GCM also detects
tampering. Legacy chunked RSA ciphertext is still readable for compatibility.

The directory's registration challenge uses the same hybrid path: the
directory sends a random nonce encrypted with the node's public key, and the
node must send the nonce back. The directory keeps no keypair.

### Reply routing

Every forwarded message gets a fresh random `msg_id` **per hop**. A node
stores:

```text
hop_id -> (incoming link, client reply key, previous hop's id, expiry, chat)
```

The reply returns on the pooled peer link, is matched by `hop_id`, gets one
new encryption layer, and is sent back to the incoming link. The client
matches the reply against the original `msg_id` and strips `len(circuit)`
layers. Expired pending entries are swept; the routing table has a hard size
cap.

Normal messages are one-shot: the first matching reply consumes the pending
entry at every hop and the client consumes its layer bookkeeping. A msg sent
with `chat=True` is different: relays lease the route and refresh its idle
time on every reply, so the destination can keep sending. The client keeps its
layer entry until the chat route expires. Replies still use hybrid
RSA-OAEP + AES-256-GCM at every hop.

### Liveness

- Nodes heartbeat the directory every 60 seconds.
- The directory drops entries silent for 90 seconds and closes their links; an
  evicted or restarted node re-registers automatically.
- Client and node links are pinged every 30 seconds and dropped after a missed
  pong. The next send rebuilds the circuit.
- `wait_reply()` uses a condition variable, not the old get/put spin loop, and
  raises `TimeoutError`. `receive()` is the continuous variant used by chat
  clients.

## Tests

The test suite uses the standard library `unittest`:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Covered areas include framing/validation, hybrid crypto and legacy
ciphertext, reply inbox behavior, explicit-path hop counts, directory
registration/heartbeats/cleanup, full three-process circuit integration,
multi-reply chat routes, malformed peers, and exit-delivery failures.

## Project layout

```text
src/
  config.py           shared Settings/defaults
  errors.py           PorError / ProtocolError / CryptoError
  log.py              logging + NullHandler default
  wire.py             framing, JSON, base64, validation helpers
  link.py             Link wrapper, connect(), keepalive
  service.py          shared accept/stop/thread lifecycle
  keys.py             hybrid RSA-OAEP + AES-256-GCM
  protocol.py         public protocol facade + key ownership test
  directory_client.py one-shot directory queries
  link_pool.py        pooled links + reader threads + pong events
  pending.py          per-hop reply routing table
  data_server.py      directory authorities server
  node.py             relay node + exit role
  client.py           sender/inbox/reply decryption
  server.py           plain destination server B
demo/
  server.py           directory process
  node.py             relay process
  client.py           server B / sender / chat CLI
  network.py          start directory + relays and keep them running
  run_all.py          one-command end-to-end demo
document.md           full protocol/API/lifecycle documentation
tests/                unittest suite
```

## Security limitations

Por demonstrates the shape of an onion network; it is not hardened for real
anonymity. In particular:

- The directory is a central point of trust and sees registrations and query
  timing.
- There is no cover traffic, padding, batching, or timing obfuscation, so
  traffic analysis is possible.
- Links are plain TCP; there is no link encryption or forward secrecy.
- The exit node and destination see the message and the destination address in
  plaintext, exactly as with Tor exit traffic.
- A single malicious relay can delay or drop traffic.
- Chat mode keeps a reply route open for its TTL; a malicious destination can
  send repeated replies on that route until it expires.
- The minimal chat demo has no per-conversation session id, so it assumes one
  chat client per exit-to-destination link.
- RSA keys are generated per process and are not persisted.

Use it to learn, not to protect a real identity.

## Author

**7aydara** - GitHub: `@bouchekifaassem`
