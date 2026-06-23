# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

---

## Core Concepts

**Identity** is a keypair derived deterministically from a username and passphrase. The same credentials always produce the same identity. There is no registration, no server-side account, and no recovery mechanism beyond the credentials themselves.

**Contacts** are identified by their publicId — a short hash of their encryption public key. Adding a contact requires their shareable address, exchanged out-of-band (QR code, copy-paste).

**Relays** are WebSocket servers that route packets between clients. A relay has no knowledge of message contents. Clients choose which relay to use. Relays are interoperable — clients on different relays communicate directly.

**Authentication** gates both sending and receiving. A client must prove possession of their encryption key before the relay accepts any messages from them or registers them for inbound routing. The from field of any app:message must match an identity already proven on that socket.
When connecting to a foreign relay to send, the client runs the same challenge-response handshake before any messages are transmitted. The queue is held until auth completes, then flushed.
---

## Identity and Key Derivation

### 256-bit (primary)

All keys are derived deterministically from `(username, passphrase)`:

```
masterSecret = PBKDF2(
  password   = passphrase,
  salt       = SHA-256("meshchat-v1:" + username.toLowerCase().trim()),
  iterations = 100000,
  hash       = SHA-256,
  bits       = 256
)
```

Three keys are expanded from the master secret via HKDF-SHA-256:

| Label | Use |
|---|---|
| `meshchat-v1:encryption` | AES-256-GCM message encryption |
| `meshchat-v1:backup`     | AES-256-GCM backup file encryption |
| `meshchat-v1:signing`    | Ed25519 signing seed |

### PublicId

A stable identifier for routing and contact lookup, identical formula for both bit widths:

```
publicId = base64url( SHA-256(encryptionKey)[0:12] )
```

The server derives publicId from the presented enc key during auth and never trusts a client-supplied ID claim.

---

## Shareable Address

Everything needed to reach someone, encoded as a single dot-separated string:

```
<encKey_b64>.<signPublicKey_b64>.<relayWss_b64>
```

All three segments are base64url encoded. The third segment is `btoa(wssUrl)` — standard base64 of the relay WebSocket URL. It is optional but included when sharing via QR code or copy-paste, bootstrapping direct relay connectivity on first contact.

Implementations must decode the third segment with `atob()` before use. Segments beyond the third must be ignored for forward compatibility.

## Relay Authentication

Authentication happens on connect, before routing or buffer delivery. The protocol is a simple challenge-response proving possession of the enc key. It gates *receiving* only — fire-and-forget sending requires no auth.

### Sequence

```
client → server:  auth_init      { enc_key: [...bytes], bits: 256 }
server → client:  auth_challenge { bits: 256, iv: [...], data: [...] }
client → server:  auth_proof     { nonce: [...bytes] }
server → client:  auth_ok        { public_id: "..." }
             or:  auth_fail      { reason: "..." }
```

1. Client sends enc key bytes and bit width
2. Server encrypts a random 32-byte nonce with the presented key (AES-GCM) and sends it back
3. Client decrypts and returns the nonce plaintext
4. Server verifies, derives publicId from the enc key, registers the socket, flushes buffer
5. Client proceeds with `get_relay_info`, presence polling, and normal operation

The server never trusts the client's claimed publicId — it derives it authoritatively from the presented enc key.

### Cross-relay connections

When a client opens a connection to a foreign relay to deliver a message, it does **not** send `auth_init` — the connection is outbound and send-only. No identity is registered on the foreign relay. Only the home relay authenticates the client.

### Auth failure

On `auth_fail` the client does not retry immediately — the socket `onclose` handler drives reconnect with the normal backoff. Reason codes: `bad_init`, `bad_key_length`, `timeout`, `proof_invalid`, `not_authenticated`.

### Security properties

- Proves possession of the enc key without revealing any secret
- The enc key is already public by design (shared in the shareable address) — presenting it to the server is not a privacy concern
- Replay attacks are prevented by the random nonce
- Buffer hijacking, ID spoofing, and fake presence are all closed by this mechanism
- A server stores the enc key in process memory during auth only; admin policy governs any persistence

---

## Encryption

**Message encryption** uses the recipient's encryption key (AES-256-GCM):
```
ciphertext = AES-GCM(
  key  = recipient.encryptionKey,
  iv   = random 12 bytes,
  data = JSON(payload)
)
wire = { v: 1, iv: [...], data: [...] }
```

**Message signing** uses the sender's Ed25519 signing key (256-bit):
```
sig = Ed25519.sign(JSON(wire), sender.signingKeySeed)       // 256-bit
```

The recipient verifies the signature against the sender's signing public key (known from the shareable address). Invalid signatures are flagged but not dropped — the message is displayed with a warning.

**Backup encryption** uses the backup key (separate from the message encryption key):
```
ciphertext = AES-256-GCM(key = backupKey, iv = random, data = gzip(JSON(contacts)))
```

---

## Message Payload

The plaintext payload (before encryption) for a text message:

```json
{
  "id":    "<uuid>",
  "type":  "text",
  "text":  "hello",
  "ts":    1234567890123,
  "relay": { "wss": "wss://sender.example.com/ws/" }
}
```

The `relay` field carries the sender's current relay WSS URL. Recipients update their routing table for the sender on every message received. This is how relay information propagates passively through the network.

**Other payload types:** `audio`, `image`, `reaction`. Audio and image carry `data` (base64) and `mimeType`. Reactions carry `targetId` and `emoji`.

---

## Transport and Routing

### Routing Rule

Every outbound message is sent to the **contact's relay WSS** — never to the sender's own relay, never based on online presence.

Priority:
1. `contact.lastRelay` known and differs from sender's relay → open or reuse connection to their relay
2. `contact.lastRelay` is the same as sender's relay → send via main signal connection
3. No `lastRelay` known → send via main signal connection (last resort)

`state.online` / `seen` signals are **UI only** (the green dot). They have no effect on routing decisions.

### Relay Connections

When sending to a contact on a different relay:

- A WebSocket connection is opened to their relay WSS
- **No `auth_init` is sent** — the connection is send-only, never registered as a recipient on that relay
- Messages are sent immediately; pre-open messages are queued and flushed on `onopen`
- A 30-second idle timer closes the connection after the last outbound message
- Timer resets on every outbound message; protocol traffic does not reset it
- Connections are keyed by hostname — one connection serves all contacts on the same relay
- On connection failure or timeout (5s), queued messages fall back to the main signal connection

### Offline Delivery

If a contact is not connected to their relay when the message arrives, the relay buffers the message to disk:

```
relay_buf/
  <recipientPublicId>/
    <timestamp>_<uuid>.json
```

On reconnect and successful auth, the relay flushes all buffered packets oldest-first and deletes them on successful delivery. Unauthenticated connections never receive buffered messages.

**Per-recipient limits** (configurable via environment):
- `BUF_MAX_MSGS` — maximum buffered packets (default 100, drops oldest)
- `BUF_MAX_MB`  — maximum total size in MB (default 10, drops new)
- `BUF_MAX_AGE` — expiry in seconds (default 86400 = 24h, swept periodically)

---

## Signal Server Protocol

### Client → Server
| Type | Fields | Auth required | Description |
|---|---|---|---|
| `sig:auth_init`        | `enc_key`, `bits`               | no  | Begin challenge-response |
| `sig:auth_proof`       | `nonce`                         | no  | Return decrypted nonce |
| `sig:announce`         | `ids[]`                         | no  | Check local presence of up to 10 IDs |
| `app:message`          | `from`, `to`, `blob`, `sig`     | yes | Deliver message — `from` must match authed identity on this socket |
| `app:sync`             | `from`, `to`, `msgs[]`, `reply` | no  | Manual sync exchange |
| `sync:backup_offer`    | `from`, `to`, `size`            | no  | Offer backup blob to peer |
| `sync:backup_accept`   | `from`, `to`                    | no  | Accept a backup offer |
| `sync:backup_push`     | `from`, `to`, `blob`            | no  | Push backup blob to peer |
| `sync:restore_req`     | `from`, `to`, `blob`            | no  | Request peer send their stored backup |
| `sync:restore_ack`     | `from`, `to`                    | no  | Acknowledge restore request |
| `sync:restore_push`    | `from`, `to`, `blob`            | no  | Push stored backup to requester |
| `sync:token_req`       | `from`, `to`                    | no  | Request a contact token |
| `sync:token_resp`      | `from`, `to`, `token`           | no  | Deliver a contact token |
| `sig:relay_req`        | —                               | yes | Request relay's own WSS URL |
| `sig:ping`             | —                               | yes | Keepalive |

### Server → Client
| Type | Fields | Description |
|---|---|---|
| `sig:auth_challenge` | `bits`, `iv`, `data` | Encrypted nonce for client to decrypt |
| `sig:auth_ok`        | `public_id`          | Auth succeeded, routing active |
| `sig:auth_fail`      | `reason`             | Auth failed or unauthed packet dropped |
| `sig:relay_info`     | `wss`                | Relay's own WSS URL |
| `sig:seen`           | `id`                 | A queried ID is locally connected |
| `sig:pong`           | —                    | Keepalive response |
| `error`              | `reason`             | Protocol error (e.g. rate limited, not_authenticated) |

### Notes
- `app:message` is the only type that requires auth AND validates `from` ∈ `client_ids` on the socket.
  All other types that require auth (`sig:relay_req`, `sig:ping`) only require the socket to be authed,
  not a matching `from`.
- Sync and backup types are intentionally unauthenticated — they are e2e encrypted and
  routed by the server without inspection.
- When connecting to a foreign relay to send, the client runs the same challenge-response
  handshake before transmitting. The outbound queue is held until auth completes.
- `sig:announce` is unauthenticated to allow presence probing before auth completes.


---

## Peer Backup Protocol

Contacts back each other up automatically. The backup blob is the sender's encrypted contact store — encrypted with the backup key, unreadable to the peer storing it. 

**Distribution:**
1. After saving contacts, sender broadcasts `backup_offer { size }` to all reachable contacts
2. Recipient replies `backup_accept`
3. Sender pushes `backup_push { blob }`
4. Recipient stores blob locally; serves it back on `restore_push`

Self-sync (same identity on multiple devices) skips the offer/accept handshake.

**Restore handshake** (fires on connect for all known contacts):
1. Client sends `push_restore_request` to each contact
2. Contact replies `push_restore_ack`
3. Contact sends `restore_push` containing the stored backup for the requester
4. Requester decrypts and merges into local state

A 5-minute cooldown per contact prevents restore flooding. The `seen` presence signal also triggers a restore request, subject to the same cooldown.

---

## Message Merging

All message stores use last-write-wins merge by message ID:

```javascript
function mergeMessages(a, b) {
  const byId = {};
  for (const m of [...a, ...b]) if (m.id) byId[m.id] = m;
  return Object.values(byId).sort((x, y) => x.ts - y.ts);
}
```

Reactions use a stable derived ID (`SHA-256("reaction:" + myId + ":" + targetMsgId)`) so a user's reaction to a given message always has the same ID — naturally replacing rather than duplicating on merge.

---

## Online Presence

`announce` queries the **local relay only**. The relay can only report on clients currently authenticated and connected to it — it has no knowledge of other relays.

`seen` signals update the UI dot only. They have no effect on routing decisions.

The online dot fades over 5 minutes using a visual gradient rather than binary on/off.

---

## Relay Discovery

Relay WSS coordinates propagate passively through the network:

1. **Shareable address** — third segment contains relay WSS for bootstrap
2. **`relay_info` response** — relay tells client its own WSS URL after auth
3. **Message payload** — every message carries sender's `relay.wss` inside the encrypted blob

A client stores `lastRelay` and `lastRelaySeen` per contact. The WSS address is a last-known location, not a permanent home. It updates automatically as contacts move between relays.

---

## Server Configuration

| Variable        | Default       | Description |
|---|---|---|
| `HTTP_PORT`     | `8000`        | Static file server port |
| `WS_PORT`       | `8888`        | WebSocket signal server port |
| `RELAY_WSS_URL` | —             | Public WSS URL of this relay (required for cross-relay) |
| `BUF_DIR`       | `./relay_buf` | Offline message buffer directory |
| `BUF_MAX_MSGS`  | `100`         | Max buffered messages per recipient |
| `BUF_MAX_AGE`   | `86400`       | Buffer expiry in seconds (24h) |
| `BUF_MAX_MB`    | `10`          | Max buffer size per recipient in MB |
| `AUTH_TIMEOUT`  | `15`          | Seconds to complete challenge-response before disconnect |

---

*MeshChat Protocol v1 — experimental, subject to change*  
*Last updated: June 2026*