# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

Current client/server implementation version: `0.3.2`, surfaced informationally via the `version` field on `sig:relay_info` for drift visibility (not yet enforced).

---

## Core Concepts

**Identity** is a keypair derived deterministically from a username and passphrase. The same credentials always produce the same identity. There is no registration, no server-side account, and no recovery mechanism beyond the credentials themselves.

**Contacts** are identified by their publicId — a short hash of their encryption public key. Adding a contact requires their shareable address, exchanged out-of-band (QR code, copy-paste).

**Relays** are WebSocket servers that route packets between clients. A relay has no knowledge of message contents. Clients choose which relay to use. Relays are interoperable — clients on different relays communicate directly.

**Authentication** gates both sending and receiving. A client must prove possession of their encryption key before the relay accepts any messages from them or registers them for inbound routing. The `from` field of any `app:message` must match an identity already proven on that socket. When connecting to a foreign relay to send, the client runs the same challenge-response handshake before any messages are transmitted. The queue is held until auth completes, then flushed.

---

## Identity and Key Derivation

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

```
publicId = base64url( SHA-256(encryptionKey)[0:12] )
```

The server derives publicId from the presented enc key during auth and never trusts a client-supplied ID claim.

### Device Identity

Each device generates a random 32-byte seed on first run, stored in localStorage under a per-identity key (`meshchat_device_seed_v1_<publicId>`). A `deviceId` is derived from it the same way as `publicId`:

```
deviceId = base64url( SHA-256( Ed25519.getPublicKey(seed) )[0:12] )
```

`deviceId` is strictly local — it never appears inside any encrypted backup blob or `serialiseContacts()` output, so it is never included in backups, exports, or restore payloads. It rides only as plaintext envelope metadata on specific wire packets where device distinction is meaningful (currently `app:message` and the self-sync backup path). The underlying seed is architecturally prepared for a future X25519 DH key via the standard Ed25519↔X25519 birational conversion — no re-keying needed when that work happens.

---

## Shareable Address

Everything needed to reach someone, encoded as a single dot-separated string:

```
<encKey_b64>.<signPublicKey_b64>.<relayWss_b64>
```

All three segments are base64url encoded. The third segment is `btoa(wssUrl)` — standard base64 of the relay WebSocket URL. It is optional but included when sharing via QR code or copy-paste, bootstrapping direct relay connectivity on first contact.

Implementations must decode the third segment with `atob()` before use. Segments beyond the third must be ignored for forward compatibility.

---

## Relay Authentication

Authentication happens on connect, before routing or buffer delivery. The protocol is a simple challenge-response proving possession of the enc key.

### Sequence

```
client → server:  auth_init      { enc_key: [...bytes], bits: 256 }
server → client:  auth_challenge { bits: 256, iv: [...], data: [...] }
client → server:  auth_proof     { nonce: [...bytes] }
server → client:  auth_ok        { public_id: "..." }
             or:  auth_fail      { reason: "..." }
```

1. Client sends enc key bytes
2. Server encrypts a random 32-byte nonce with the presented key (AES-GCM) and sends it back
3. Client decrypts and returns the nonce plaintext
4. Server verifies, derives publicId from the enc key, registers the socket, flushes buffer
5. Client proceeds with `sig:relay_req`, presence polling, and normal operation

The server never trusts the client's claimed publicId — it derives it authoritatively from the presented enc key.

An optional `no_receive: true` flag on `sig:auth_init` completes the challenge-response without registering the socket as a recipient and without triggering a buffer flush. Used by disposable connectivity probes (e.g. the migrate panel's TEST function) that must not silently consume buffered packets.

### Cross-relay connections

When a client opens a connection to a foreign relay to deliver a message, it runs the **full auth handshake** — same `sig:auth_init` → `sig:auth_challenge` → `sig:auth_proof` → `sig:auth_ok` sequence. The connection is registered as a sender session on the foreign relay for the duration it remains open. The outbound queue is held until auth completes, then flushed.

The home relay is never targeted via this path. `getOrOpenRelayConn` checks the target hostname against `relayHostname(getSignalUrl())` at the top and returns null immediately if they match — callers fall back to the existing main signal socket instead. This prevents a redundant second session from being registered on the home relay alongside the already-authed main socket.

### Auth failure

On `auth_fail` the client does not retry immediately — the socket `onclose` handler drives reconnect with the normal backoff. Reason codes: `bad_init`, `bad_key_length`, `timeout`, `proof_invalid`, `not_authenticated`.

### Security properties

- Proves possession of the enc key without revealing any secret
- The enc key is already public by design (shared in the shareable address) — presenting it to the server is not a privacy concern
- Replay attacks are prevented by the random nonce
- Buffer hijacking, ID spoofing, and fake presence are all closed by this mechanism

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

**Message signing** uses the sender's Ed25519 signing key:

```
sig = Ed25519.sign(JSON(wire), sender.signingKeySeed)
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

### Outer envelope (`app:message`)

The wire packet wrapping the encrypted blob:

```json
{
  "type":     "app:message",
  "from":     "<publicId>",
  "to":       "<publicId>",
  "blob":     { "v": 1, "iv": [...], "data": [...] },
  "sig":      [...],
  "deviceId": "<deviceId>"
}
```

`deviceId` is the sender's device identity (see [Device Identity](#device-identity)). It is plaintext — not inside the encrypted blob — so the relay and recipient can read it without decryption. Recipients record it in the local device registry to build passive knowledge of which devices a given identity runs. It is optional; old clients that omit it are handled gracefully (the contact's device list stays at the "unknown" placeholder).

---

## Transport and Routing

### Routing Rule

Every outbound message is sent to the **contact's relay WSS** — never to the sender's own relay, never based on online presence.

Priority:
1. `contact.lastRelay` hostname matches home relay → send via main signal socket (`state.ws`) directly
2. `contact.lastRelay` known, different host → open or reuse an outbound relay connection (`sendToRelay`)
3. No `lastRelay` known → send via the main signal connection (`sendSignal`, last resort)

If the contact's relay is unreachable, the fallback lands on the sender's own signal connection, which buffers the message server-side until the contact reconnects.

`state.online` / `seen` signals are **UI only** (the green dot). They have no effect on routing decisions.

### Relay Connections

When sending to a contact on a different relay:

- A WebSocket connection is opened to their relay WSS and the full auth handshake runs before any messages are sent
- Connections are keyed by hostname — one connection serves all contacts on the same relay
- Messages are queued until auth completes, then flushed
- A 30-second idle timer closes the connection after the last outbound message; timer resets on every outbound message but not on protocol traffic
- On connection failure or connect timeout (5s), queued messages fall back to the main signal connection
- The home relay hostname is never targeted via this path (see [Cross-relay connections](#cross-relay-connections))

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

The encrypted payload is `{ newRelay, ts }` — same encryption scheme as a regular message (`encryptMessage`), decrypted with the receiver's own `encKey`. This scheme is symmetric — a contact who already holds your shareable address holds the same key you decrypt with.

**Signature is mandatory.** An `app:migrate` packet with a missing or invalid signature is dropped outright — unlike a regular message where a bad signature is flagged but displayed. This packet redirects routing and must not be trusted on decryption success alone.

**On commit**, the migrating client:
1. Stamps its own `lastRelay`/`lastRelaySeen` with the new address and the current time — a deliberate migration is the new ground truth, no timestamp guard applies.
2. Notifies every non-blocked contact via `sendToRelay` (their last-known relay), falling back to `sendSignal`.
3. Sends a copy to *itself* at the relay being left behind (`sendViaRelayUrl(oldRelay, ...)`), in case another of the user's own devices is still parked there. No contact relationship applies to one's own identity, so this goes by explicit URL — and deliberately has **no signal fallback**: if the old relay is unreachable there is no salvageable fallback destination.

**On receipt**, handling diverges by sender:
- **From self** — adopted silently via the same timestamp-guarded `updateRelay` used everywhere. If adopting moves `lastRelay` forward, the receiving device replants a fresh breadcrumb at the relay it is *itself* now leaving behind, carrying the same `newRelay`/`ts` (not a new timestamp), so a further-behind device can still find the trail.
- **From a contact** — same passive relay-learning as the `relay` field embedded in regular messages, just arriving as its own dedicated packet.

**Server-side buffering** uses different semantics from regular packets:
- **Always durably buffered**, even when a live recipient session is reached — a stale-but-not-yet-closed session of the same identity could swallow the only copy meant for a device still catching up.
- **Overwrite-per-sender** — a newly buffered `app:migrate` replaces any older one from the same sender.
- **Long TTL** (`BUF_MAX_AGE_MIGRATE`, default 7 days vs. 24h for ordinary packets).

**Not yet implemented:** confirmation/warning UI before committing, boot-time drain of the previous relay's buffer, breadcrumb replanting by passive-follower devices (today only the device that received the original notice replants).

---

## Device Awareness

### Device Registry

Each client maintains a local device registry (`meshchat_known_devices_v1_<publicId>` in localStorage) — a map of identity → known devices:

```json
{
  "<identityId>": {
    "<deviceId>": <lastSeenTimestamp>,
    "<deviceId>": <lastSeenTimestamp>
  }
}
```

This is local-only, never included in backup blobs or `serialiseContacts()`. It is populated passively from two sources:

1. **`app:message` receipt** — the outer `deviceId` field records which device a contact sent from.
2. **Self-sync backup path** — `deviceId`/`fingerprint` fields on `sync:backup_push` and `sync:backup_accept` teach each of the user's own devices about the others (see [Peer Backup Protocol](#peer-backup-protocol)).

The registry is displayed in a per-contact device popover in the UI. Contacts with no recorded devices show an "unknown" placeholder. The data accumulates passively through normal traffic — no dedicated discovery handshake.

### Planned propagation

`deviceId` will be extended to `app:migrate` and `app:sync` envelopes in future passes. Per-device forward secrecy (X25519 DH) is architecturally prepared via the device seed but explicitly deferred.

---

## Signal Server Protocol

### Client → Server

| Type | Fields | Auth required | Description |
|---|---|---|---|
| `sig:auth_init`     | `enc_key`, `bits`, `no_receive?`          | no  | Begin challenge-response. `no_receive: true` skips registration and buffer flush (used by probes) |
| `sig:auth_proof`    | `nonce`                                   | no  | Return decrypted nonce |
| `sig:announce`      | `ids[]`                                   | no  | Check local presence of up to 10 IDs |
| `app:message`       | `from`, `to`, `blob`, `sig`, `deviceId?`  | yes | Deliver message — `from` must match authed identity on this socket |
| `app:migrate`       | `from`, `to`, `blob`, `sig`               | yes | Notify of a relay migration — always durably buffered in addition to live delivery |
| `app:sync`          | `from`, `to`, `msgs[]`, `reply`           | no  | Manual sync exchange |
| `sync:backup_offer` | `from`, `to`, `size`                      | no  | Offer backup blob to peer |
| `sync:backup_accept`| `from`, `to`, `deviceId?`, `fingerprint?` | no  | Accept a backup offer. With `deviceId`/`fingerprint`: device-freshness ack on the self-sync path |
| `sync:backup_push`  | `from`, `to`, `blob`, `deviceId?`, `fingerprint?` | no | Push backup blob. With `deviceId`/`fingerprint` on self-targeted push: carries sender device identity for freshness tracking |
| `sync:restore_req`  | `from`, `to`, `blob`                      | no  | Request peer send their stored backup |
| `sync:restore_ack`  | `from`, `to`                              | no  | Acknowledge restore request |
| `sync:restore_push` | `from`, `to`, `blob`                      | no  | Push stored backup to requester |
| `sync:token_req`    | `from`, `to`                              | no  | Request a contact token |
| `sync:token_resp`   | `from`, `to`, `token`                     | no  | Deliver a contact token |
| `sig:relay_req`     | —                                         | yes | Request relay's own WSS URL |
| `sig:ping`          | —                                         | yes | Keepalive |

### Server → Client

| Type | Fields | Description |
|---|---|---|
| `sig:auth_challenge` | `bits`, `iv`, `data` | Encrypted nonce for client to decrypt |
| `sig:auth_ok`        | `public_id`          | Auth succeeded, routing active |
| `sig:auth_fail`      | `reason`             | Auth failed or unauthed packet dropped |
| `sig:relay_info`     | `wss`, `version`     | Relay's own WSS URL and protocol version (informational, not yet enforced) |
| `sig:seen`           | `id`                 | A queried ID is locally connected |
| `sig:pong`           | —                    | Keepalive response |
| `error`              | `reason`             | Protocol error (e.g. rate limited, not_authenticated) |

### Notes

- `app:message` and `app:migrate` are the only types that require auth AND validate `from` ∈ `client_ids` on the socket. Other auth-required types (`sig:relay_req`, `sig:ping`) only require the socket to be authed, not a matching `from`.
- `app:migrate` is always written to the durable buffer in addition to any live delivery.
- `sync:backup_accept` and `sync:backup_push` carry optional `deviceId`/`fingerprint` fields used exclusively on the self-sync path. These fields are never set on the contact backup path. Old clients that omit them are handled gracefully.
- Sync and backup types are intentionally unauthenticated — they are e2e encrypted and routed by the server without inspection.
- `sig:announce` is unauthenticated to allow presence probing before auth completes.

---

## Peer Backup Protocol

Contacts back each other up automatically. The backup blob is the sender's encrypted contact store — encrypted with the backup key, unreadable to the peer storing it.

**Distribution (contact path):**
1. After saving contacts, sender broadcasts `backup_offer { size }` to all reachable contacts
2. Recipient replies `backup_accept`
3. Sender pushes `backup_push { blob }`
4. Recipient stores blob locally; serves it back on `restore_push`

**Self-sync (same identity, multiple devices):**

Skips the offer/accept negotiation entirely — the push goes directly. To avoid redundant full-blob broadcasts when devices are already converged, a content fingerprint is computed before each push:

```
fingerprint = base64url( SHA-256( JSON(serialiseContacts()) )[0:12] )
```

Each device maintains an in-memory table of `{ deviceId → fingerprint }` for the other devices it has heard from this session (`knownDeviceFingerprints`). If every known device already has the current fingerprint, the push is skipped. The table resets on reload — worst case is one extra push on cold start, no data-loss risk.

The `sync:backup_push` self-path carries `deviceId` and `fingerprint` on the outer envelope. The receiver merges, then replies with a `sync:backup_accept` carrying its own post-merge `deviceId` and `fingerprint` — a lightweight ack that lets the sender record the receiver's current state. The presence of `deviceId` on `backup_accept` is what distinguishes this device-ack from a normal contact offer-accept; old clients that omit it fall through to today's behavior unchanged.

**Restore handshake** (fires on connect for all known contacts):
1. Client sends `sync:restore_req` to each contact
2. Contact replies `sync:restore_ack`
3. Contact sends `sync:restore_push` containing the stored backup for the requester
4. Requester decrypts and merges into local state

A 5-minute cooldown per contact prevents restore flooding. The `sig:seen` presence signal also triggers a restore request, subject to the same cooldown.

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

`sig:announce` queries the **local relay only**. The relay can only report on clients currently authenticated and connected to it — it has no knowledge of other relays.

`sig:seen` signals update the UI dot only. They have no effect on routing decisions.

The online dot fades over 5 minutes using a visual gradient rather than binary on/off.

---

## Relay Discovery

Relay WSS coordinates propagate passively through the network:

1. **Shareable address** — third segment contains relay WSS for bootstrap
2. **`sig:relay_info` response** — relay tells client its own WSS URL after auth
3. **Message payload** — every `app:message` carries sender's `relay.wss` inside the encrypted blob

A client stores `lastRelay` and `lastRelaySeen` per contact. The WSS address is a last-known location, not a permanent home. It updates automatically as contacts move between relays.

Updates are timestamp-guarded: a new `lastRelay` value is only adopted if its timestamp is newer than the one already stored (`updateRelay`). This applies uniformly to relay info in messages, peer backups, restores, file imports, and migration notices — local storage is always the source of truth. A relay server's own `sig:relay_info` response is treated as a confirmation, not an authoritative fact, except on a completely fresh identity with no local record yet — in which case it's adopted as an unconfirmed placeholder timestamped `0`, so any genuinely-dated record arriving later can still outrank it.

The relay itself is untrusted infrastructure. Cryptographic proof — signatures, encryption — is the only trust boundary. Relays never forward to one another; all topology lives in client state and propagates passively through ordinary traffic.

---

## Client Storage Keys

| Key | Scope | Description |
|---|---|---|
| `meshchat_contacts_<publicId>`         | per identity | Encrypted contact store (backup key) |
| `meshchat_peer_backups_v1_<publicId>`  | per identity | Peer-supplied encrypted backup blobs |
| `meshchat_peer_tokens_v1_<publicId>`   | per identity | Contact tokens for restore gating |
| `meshchat_known_devices_v1_<publicId>` | per identity | Device registry — `{ identityId: { deviceId: lastSeenTs } }` |
| `meshchat_device_seed_v1_<publicId>`   | per device   | Raw 32-byte device seed (base64). Never shared, never backed up |

---

## Server Configuration

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT`           | `8000`        | Static file server port |
| `WS_PORT`             | `8888`        | WebSocket signal server port |
| `RELAY_WSS_URL`       | —             | Public WSS URL of this relay (required for cross-relay) |
| `BUF_DIR`             | `./relay_buf` | Offline message buffer directory |
| `BUF_MAX_MSGS`        | `100`         | Max buffered messages per recipient |
| `BUF_MAX_AGE`         | `86400`       | Buffer expiry in seconds (24h) — regular packets |
| `BUF_MAX_AGE_MIGRATE` | `604800`      | Buffer expiry in seconds (7d) — `app:migrate` packets only |
| `BUF_MAX_MB`          | `10`          | Max buffer size per recipient in MB |
| `AUTH_TIMEOUT`        | `15`          | Seconds to complete challenge-response before disconnect |

---

*MeshChat Protocol v1 — experimental, subject to change*  
*Last updated: June 2026*
