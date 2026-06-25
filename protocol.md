# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

Current client/server implementation version: `0.3.2`, surfaced informationally via the `version` field on `sig:relay_info` for drift visibility (not yet enforced).

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
1. `contact.lastRelay` known → open or reuse a connection to their relay (`sendToRelay`)
2. No `lastRelay` known → send via the main signal connection (`sendSignal`, last resort)

If the contact's relay is unreachable, the fallback lands on the sender's own signal connection, which buffers the message server-side until the contact reconnects.

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
- `app:migrate` packets use different semantics entirely — overwrite-per-sender and a longer TTL — see [Relay Migration](#relay-migration) below.

---

## Relay Migration

A deliberate relay change is announced via a dedicated packet type so contacts (and a user's other devices) can update their routing without waiting for a regular message:

```json
{
  "type": "app:migrate",
  "from": "<publicId>",
  "to":   "<publicId>",
  "blob": { "v": 1, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The encrypted payload is `{ newRelay, ts }` — same encryption scheme as a regular message (`encryptMessage`), and decrypted the same way on receipt: always with the receiver's own `encKey`, regardless of who sent it. This scheme is symmetric — a contact who already holds your shareable address holds the same key you decrypt with.

**Signature is mandatory.** Unlike a regular message — where an invalid signature is flagged but the message is still displayed — an `app:migrate` packet with a missing or invalid signature is dropped outright. This packet redirects routing, so unlike message content it must not be trusted on decryption success alone.

**On commit**, the migrating client:
1. Stamps its own `lastRelay`/`lastRelaySeen` with the new address and the current time. No timestamp guard applies here — a deliberate migration *is* the new ground truth, not a candidate update competing with one.
2. Notifies every non-blocked contact, addressed normally (`sendToRelay` to their last-known relay, falling back to `sendSignal`).
3. Sends a copy to *itself*, addressed explicitly to the relay being left behind (`oldRelay`), in case another of the user's own devices is still parked there. This goes by literal URL rather than contact lookup — no contact relationship applies to one's own identity — and deliberately has **no signal fallback**: if the old relay is unreachable there's no salvageable fallback destination the way there is for an unreachable contact relay.

**On receipt**, handling diverges by sender:
- **From self** (another of the user's own devices) — adopted silently through the same timestamp-guarded `updateRelay` used everywhere else: no ceremony, no notify-back. If adopting moves `lastRelay` forward, the receiving device replants a breadcrumb at the relay it is *itself* now leaving behind, carrying the same `newRelay`/`ts` it just adopted (not a fresh timestamp), so a third, further-behind device can still find the trail.
- **From a contact** — same passive relay-learning already used for the `relay` field embedded in regular messages, just arriving as its own dedicated packet instead of riding along with conversation traffic.

**Server-side buffering** uses different semantics from regular packets, specifically because of what this packet type is for:
- **Always durably buffered**, even when a live recipient session is reached — a stale-but-not-yet-closed session of the *same* identity could otherwise swallow the only copy meant for a device that's still catching up.
- **Overwrite-per-sender** — a newly buffered `app:migrate` packet replaces any older one already buffered from the same sender, rather than queuing a backlog of stale relay-change history.
- **Long TTL** (`BUF_MAX_AGE_MIGRATE`, default 7 days vs. 24h for ordinary packets) — an address correction is still useful long after a normal message would be.

**Not yet implemented:** a confirmation/warning UI before committing a migration, a boot-time drain of the previous relay's buffer, breadcrumb replanting initiated by passive-follower devices (today only the device that received the original migrate notice replants), and a decision on delete-on-read vs. persist-until-TTL for migrate packets specifically.

---

## Signal Server Protocol

### Client → Server
| Type | Fields | Auth required | Description |
|---|---|---|---|
| `sig:auth_init`        | `enc_key`, `bits`               | no  | Begin challenge-response |
| `sig:auth_proof`       | `nonce`                         | no  | Return decrypted nonce |
| `sig:announce`         | `ids[]`                         | no  | Check local presence of up to 10 IDs |
| `app:message`          | `from`, `to`, `blob`, `sig`     | yes | Deliver message — `from` must match authed identity on this socket |
| `app:migrate`          | `from`, `to`, `blob`, `sig`     | yes | Notify of a relay migration — `from` must match authed identity; always durably buffered in addition to live delivery (see [Relay Migration](#relay-migration)) |
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
| `sig:relay_info`     | `wss`, `version`     | Relay's own WSS URL and protocol version (version is informational only — surfaced for drift visibility, not yet enforced) |
| `sig:seen`           | `id`                 | A queried ID is locally connected |
| `sig:pong`           | —                    | Keepalive response |
| `error`              | `reason`             | Protocol error (e.g. rate limited, not_authenticated) |

### Notes
- `app:message` and `app:migrate` are the only types that require auth AND validate `from` ∈ `client_ids` on the socket.
  Other types that require auth (`sig:relay_req`, `sig:ping`) only require the socket to be authed,
  not a matching `from`.
- `app:migrate` is always written to the durable buffer in addition to any live delivery, even when a recipient session is reached — its purpose is to be found later by a device that isn't online yet, including another session of the same identity that's still mid-disconnect from the relay being left behind.
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
  // ts alone isn't a reliable order for near-simultaneous messages — id is
  // added as a stable tiebreak so the result is identical regardless of
  // which side of the merge a message originated from.
  return Object.values(byId).sort((x, y) => (x.ts - y.ts) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
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

Updates are timestamp-guarded: a new `lastRelay` value is only adopted if its timestamp is newer than the one already stored (`updateRelay`). This rule applies uniformly to relay info embedded in messages, peer backups, restores, file imports, and migration notices alike — local storage is always the source of truth. A relay server's own `sig:relay_info` response is treated as a confirmation, not an authoritative fact, except on a completely fresh identity with no local record yet — in which case it's adopted as an unconfirmed placeholder timestamped `0`, so any genuinely-dated record arriving later can still outrank it.

The relay itself is untrusted infrastructure. Cryptographic proof — signatures, encryption — is the only trust boundary; the relay's say-so, or which domain it runs on, is never trusted on its own. Relays never forward to one another; all topology lives in client state and propagates passively through ordinary traffic.

---

## Server Configuration

| Variable        | Default       | Description |
|---|---|---|
| `HTTP_PORT`     | `8000`        | Static file server port |
| `WS_PORT`       | `8888`        | WebSocket signal server port |
| `RELAY_WSS_URL` | —             | Public WSS URL of this relay (required for cross-relay) |
| `BUF_DIR`       | `./relay_buf` | Offline message buffer directory |
| `BUF_MAX_MSGS`  | `100`         | Max buffered messages per recipient |
| `BUF_MAX_AGE`   | `86400`       | Buffer expiry in seconds (24h) — regular packets |
| `BUF_MAX_AGE_MIGRATE` | `604800` | Buffer expiry in seconds (7d) — `app:migrate` packets only |
| `BUF_MAX_MB`    | `10`          | Max buffer size per recipient in MB |
| `AUTH_TIMEOUT`  | `15`          | Seconds to complete challenge-response before disconnect |

---

*MeshChat Protocol v1 — experimental, subject to change*  
*Last updated: June 2026*