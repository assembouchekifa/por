# Por — full documentation

Por is a small, readable Tor-like messaging network written in Python. It
builds an onion circuit through relay nodes, sends an encrypted message to a
plain TCP destination server, and routes the reply back through the same
circuit. It is a learning/demo project, **not** a replacement for Tor.

This document covers the current implementation. The original design notes in
`structur.md` and `architecture.md` are historical references.

---

## 1. Quick start

```bash
git clone <repo-url> por
cd por
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python demo/run_all.py
```

Run the test suite:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Requirements:

- Python 3.10+
- `cryptography>=42` (installed from `requirements.txt`)

---

## 2. What the network does

The demo has five roles:

| Role | Code | Responsibility |
|---|---|---|
| Directory authorities server | `src/data_server.py` → `DataServer` | Public phone-book of relay nodes; verifies key ownership |
| Relay node | `src/node.py` → `Node` | Peels one onion layer, forwards the rest, routes replies |
| Sender | `src/client.py` → `Client` | Builds circuits/onions, sends messages, opens replies |
| Destination server | `src/server.py` → `Server` | Plain TCP endpoint; has no id, keys, or circuit |
| Crypto helper | `src/keys.py` → `Rsa` | Hybrid RSA-OAEP + AES-256-GCM layer sealing |

A typical circuit:

```text
client A  ->  node1  ->  node3  ->  node2 (exit)  ->  server B
          <-         <-         <-                 <-
```

- Client A knows the full circuit.
- node1 knows A and node3.
- node3 knows node1 and node2.
- node2 (the exit) knows node3 and server B.
- Server B only sees the exit node.

The reply rides the circuit backwards:

```text
server B reply -> node2 -> node3 -> node1 -> client A
```

Each relay adds one encryption layer on the way back; only client A can remove
all layers.

---

## 3. Project layout

```text
src/
  config.py           shared Settings/defaults
  errors.py           PorError / ProtocolError / CryptoError
  log.py              logging setup; library default is silent
  wire.py             framing, JSON, base64, validation helpers
  link.py             Link wrapper, connect(), TCP keepalive
  service.py          shared accept loop, thread tracking, clean stop
  keys.py             hybrid RSA-OAEP + AES-256-GCM
  protocol.py         public protocol facade + key ownership test
  directory_client.py one-shot directory queries
  link_pool.py        pooled links, reader threads, pong events
  pending.py          bounded per-hop reply routing table
  data_server.py      directory authorities server
  node.py             relay node + exit role
  client.py           sender, inbox, reply decryption
  server.py           plain destination server B
demo/
  config.py           demo topology/defaults
  server.py           directory process
  node.py             relay process
  client.py           server B / sender CLI
  run_all.py          one-command end-to-end demo
tests/
  test_wire.py
  test_crypto.py
  test_client.py
  test_directory.py
  test_failures.py
  test_integration.py
```

---

## 4. Wire format

Every TCP message is one frame:

```text
+----------------+---------------------------+
| 4-byte length  | UTF-8 JSON object         |
| big-endian     | must contain "type"       |
+----------------+---------------------------+
```

Defaults and hard limits are in `src/config.py`:

| Setting | Default |
|---|---:|
| `max_frame_size` | 16 MiB |
| `max_text_bytes` | 1 MiB |
| `max_hops` | 8 |
| `max_pending` | 10,000 |
| `connect_timeout` | 5 s |
| `query_timeout` | 10 s |
| `handshake_timeout` | 10 s |
| `heartbeat_every` | 60 s |
| `cleanup_every` | 90 s |
| `stale_after` | 90 s |
| `link_ping_every` | 30 s |
| `link_ping_timeout` | 5 s |
| `pending_ttl` | 300 s |
| `layers_ttl` | 330 s |

Malformed frames, oversized frames, invalid base64, and missing required fields
raise `ProtocolError`. A peer that sends one has its connection closed; one bad
peer cannot kill a process.

All roles use `src/wire.py` for framing and `src/link.py` for persistent links.
A `Link` serializes writers with a lock and is read by one background thread.

---

## 5. Directory protocol

The directory is a public phone-book. It stores a node's id, host, port, kind,
public key, and last heartbeat. It has no keypair of its own and never sees
message payloads.

### Registration and key proof

```text
node      -> directory : register {version, id, kind, host, port, public_key}
directory -> node      : challenge {enc}
node      -> directory : challenge_reply {dec}
directory -> node      : ok | error
```

`enc` is a random nonce encrypted for the node's published public key.
`dec` is that nonce decrypted back. Only the owner of the matching private key
can answer, so the directory verifies key ownership without keeping a keypair.
A successful registration means the directory will list the node in network
data.

Other directory messages:

| Message | Direction | Purpose |
|---|---|---|
| `heartbeat {id}` | node → directory | Keep registration alive |
| `get_data_of_network` | client/node → directory | List relay nodes only |
| `network_data {nodes}` | directory → client/node | Relay node entries |
| `get_client {id}` | client/node → directory | Look up one node/client |
| `client_data {client}` | directory → client/node | One entry or `null` |
| `get_clients {ids}` | client → directory | Batch lookup |
| `clients_data {clients}` | directory → client | Batch result |
| `unregister {id}` | node → directory | Remove registration |
| `ok` / `error` | directory → peer | Result |

`get_data_of_network` intentionally excludes entries whose `kind` is `client`.
A node can still be looked up directly by id.

### Registration validation

The directory validates:

- protocol version
- non-empty id, host, and public key
- port in `1..65535`
- kind is `node` or `client`
- public key size and ownership

A malformed registration receives an error and the connection remains usable.
A stale registration is removed after `stale_after` seconds without a
heartbeat; the directory closes that link, and the node automatically
re-registers.

---

## 6. Circuits and onion layers

For a destination `host:port`, the innermost envelope is:

```json
{
  "next": "127.0.0.1:8000",
  "final": true,
  "reply_pub": "<client public key PEM>",
  "payload": "<base64 text>"
}
```

Starting from the innermost envelope, the client wraps it once per node in
reverse path order. Each wrapped layer contains:

```json
{
  "next": "node3",
  "reply_pub": "<client public key PEM>",
  "payload": "<base64 encrypted bytes>"
}
```

The outer layer's `next` is the entry node. A relay peels exactly one layer and
then either:

- forwards `payload` to `next` (`final` absent/false), or
- delivers the plaintext to `next` (`final: true`).

Client A sends the outer payload to the entry node:

```json
{
  "type": "forward",
  "from": "client",
  "msg_id": "<original client id>",
  "payload": "<base64 outer layer>"
}
```

Relays forward with:

```json
{
  "type": "forward",
  "from": "<current node id>",
  "msg_id": "<per-hop id>",
  "payload": "<base64 rest of onion>"
}
```

The exit node opens a connection to the destination server and sends:

```json
{
  "type": "deliver",
  "msg_id": "<exit per-hop id>",
  "from": "<exit node id>",
  "text": "<plaintext>"
}
```

Server B answers on the same link:

```json
{
  "type": "reply",
  "msg_id": "<exit per-hop id>",
  "text": "<reply text>"
}
```

`msg_id` is regenerated at every hop. A node stores a mapping from its new
`hop_id` to:

- the incoming link that must receive the reply,
- the client's reply public key,
- the previous hop's id (which becomes the outgoing `msg_id`),
- a creation timestamp.

This means the original client id is never reused across the whole route, and
two circuits cannot accidentally match each other's replies.

---

## 7. Crypto

Each onion layer is sealed with hybrid encryption:

```text
b"POR1" | uint16 wrapped-key length | wrapped key | 12-byte nonce | ciphertext
```

- AES-256-GCM encrypts the layer payload.
- A fresh random AES key is generated per layer.
- RSA-OAEP with SHA-256 wraps only the AES key.
- The GCM authentication tag is part of the ciphertext.
- AAD is the constant `por-layers-v1`.

This gives one RSA operation per layer, instead of chunking the entire message
through RSA. It also authenticates each layer, so tampering is rejected.

Legacy ciphertext from the old chunked RSA PKCS#1 v1.5 format is still accepted
by `Rsa.decrypt_message()` for compatibility. New messages always use the
hybrid format.

The directory key test uses the same hybrid helper: the nonce is small, sealed
for the node's public key, and returned decrypted.

Measured on the current development machine:

```text
1 KB layer:   ~0.3 ms encrypt, ~0.7 ms decrypt
1 MB layer:   ~0.8 ms encrypt, ~1.2 ms decrypt
```

Hardware and Python version affect these numbers.

---

## 8. Reply routing

Reply processing is symmetric with the forward path:

1. Server B sends a reply to the exit node on the link the exit opened.
2. The exit node pops its pending entry for that `hop_id`.
3. The exit adds one encryption layer using the client's `reply_pub`.
4. It sends `{"type": "reply", "msg_id": previous_id, "payload": ...}` over the
   incoming link.
5. Every relay repeats: pop pending, add one layer, send backwards.
6. The entry node sends the final layer to client A using the client's original
   `msg_id`.
7. Client A pops the layer count, decrypts once per hop, and puts the text in
   its inbox.

The pending table:

- expires entries after `pending_ttl`
- has a hard `max_pending` cap
- is cleaned when an incoming link closes
- is cleared on shutdown

Client layer bookkeeping is similarly pruned after `layers_ttl`, on send, on
reply, and when waiting times out. A reply for an unknown or expired id is
dropped instead of crashing the reader.

---

## 9. Liveness and connection lifecycle

### Directory

- A node sends `heartbeat` every 60 seconds.
- The directory sweeps every 90 seconds.
- An entry silent for more than 90 seconds is removed and its link is closed.
- The node notices the closed link or `not registered` reply, then reconnects
  and registers again.

### Pooled links

- Client A keeps one persistent link to the entry node.
- Each relay keeps a pooled link per next-hop relay.
- The exit keeps a pooled link per destination address.
- Server B keeps one link per exit node.

Client and relay peer links are pinged every 30 seconds and dropped after a
missed pong. The next send rebuilds the circuit, trying the same node ids first
and random nodes if they are gone.

### Shutdown

All services use `src/service.py`:

- stop accepting new connections
- close tracked connections
- wake the accept loop
- close the listener
- join background threads with a bounded timeout

`Link.close()` calls `shutdown(SHUT_RDWR)` before `close()` so a thread blocked
in `recv()` is woken reliably.

### Client inbox

`Client.wait_reply()` uses a condition variable:

- waits until a matching reply exists or the timeout expires
- returns `TimeoutError` on timeout
- leaves other replies in the inbox
- does not spin on get/put

Default timeout is 15 seconds. Pass `msg_id=` to wait for a specific send.

---

## 10. Client API

```python
from src.client import Client
from src.config import Settings

settings = Settings()
client = Client("127.0.0.1", 9000, settings=settings)

# Random 2-hop circuit.
client.init_connection(hops=2)

# Or force a circuit; the last node is the exit.
client.init_connection(path=["node1", "node3", "node2"])

msg_id = client.send_message("hello", "127.0.0.1:8000")
reply = client.wait_reply(timeout=15, msg_id=msg_id)

client.close()
```

Useful public methods:

| Method | Purpose |
|---|---|
| `get_data_of_network()` | List relay nodes from the directory |
| `get_client(id)` | Look up one entry |
| `get_clients(ids)` | Batch lookup |
| `calc_path(network, length)` | Pick a random path |
| `init_connection(hops=2, path=None)` | Build a circuit and open the entry link |
| `send_message(text, target_addr)` | Build an onion and send it |
| `wait_reply(timeout=15, msg_id=None)` | Wait for a reply |
| `ping()` | Ping the entry link |
| `close()` | Close the circuit and background threads |

`target_addr` must be `"host:port"`.

---

## 11. Demo commands

Full demo:

```bash
.venv/bin/python demo/run_all.py
```

Pick a circuit:

```bash
.venv/bin/python demo/run_all.py --via node2,node1
```

Manual processes:

```bash
# directory
.venv/bin/python demo/server.py

# relays
.venv/bin/python demo/node.py --id node1 --port 7001
.venv/bin/python demo/node.py --id node2 --port 7002
.venv/bin/python demo/node.py --id node3 --port 7003

# destination server B
.venv/bin/python demo/client.py --server --port 8000

# sender A
.venv/bin/python demo/client.py \
    --send hi --send "still here" \
    --to 127.0.0.1:8000 --via node1,node3,node2
```

Use `--help` on any demo script for its options.

Demo defaults live in `demo/config.py` and follow `src/config.py` for host,
directory port, and key size.

---

## 12. Testing

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The suite covers:

- frame round-trips, partial reads, oversized/zero/malformed frames
- base64 and field validation
- hybrid crypto round-trips, tampering, wrong keys, legacy RSA
- key ownership exchange
- client timeout behavior and inbox matching
- explicit-path hop counts
- directory registration, heartbeat, batch lookup, stale cleanup
- directory restart and automatic re-registration
- full client → relay → exit → destination → reply circuit
- unreachable destinations
- malformed peers and delivery failures
- pending-table TTL and link cleanup

Optional static check if `pyflakes` is installed:

```bash
.venv/bin/python -m pyflakes src demo tests
```

---

## 13. Security limitations

Por demonstrates the shape of an onion network. It is not hardened for real
anonymity.

- The directory is a central point of trust and sees registrations and query
  timing.
- There is no cover traffic, padding, batching, or timing obfuscation.
- Links are plain TCP; there is no link encryption or forward secrecy.
- The exit node and destination see the message and destination address in
  plaintext.
- A single malicious relay can delay, drop, or observe traffic it handles.
- RSA keys are generated per process and are not persisted.
- There is no directory authentication or consensus.
- There is no protection against a global traffic observer.

Use it to learn, not to protect a real identity.

---

## 14. Troubleshooting

### `ModuleNotFoundError: cryptography`

Install dependencies inside the virtual environment:

```bash
.venv/bin/pip install -r requirements.txt
```

### Nodes never appear in the directory

Check that:

- `demo/server.py` is running on the expected directory port
- each node points at the same directory host/port
- node ports are free
- the node logs show a successful registration

### Sender times out

Common causes:

- destination server is not listening
- the exit node cannot connect to the destination
- a relay died and the circuit has not been rebuilt yet
- a message was sent to a closed destination port

If the entry link is down, the next send rebuilds the circuit. Replies that
arrive after a `wait_reply()` timeout are still accepted until the layer TTL
expires, so a second `wait_reply()` can consume them.

### Port already in use

The demo uses ports `9000` (directory), `7001`–`7003` (nodes), and `8000`
(server B). Stop the old demo processes or choose other ports with the CLI
flags.

### Logs are quiet

The library installs a `NullHandler` by default. Demo scripts call
`configure_logging()` to print logs. Embedding applications can configure the
`por` logger themselves.

---

## 15. Current public modules

| Module | Main API |
|---|---|
| `src.client` | `Client` |
| `src.node` | `Node` |
| `src.data_server` | `DataServer` |
| `src.server` | `Server` |
| `src.keys` | `Rsa` |
| `src.protocol` | framing helpers, `test_key`, `prove_key`, protocol constants |
| `src.config` | `Settings`, `DEFAULT` |
| `src.errors` | `PorError`, `ProtocolError`, `CryptoError` |
| `src.directory_client` | `DirectoryClient` |
| `src.link` | `Link`, `connect` |
| `src.wire` | frame/JSON/validation helpers |
| `src.log` | `configure_logging`, `get_logger` |

All roles in this repository speak protocol version `2`.
