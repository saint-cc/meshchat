# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

Current client/server implementation version: `0.4.7`, surfaced informationally via the `version` field on `sig:relay_info` for drift visibility (not yet enforced). `0.3.6` added WebRTC data-channel shell escalation for agent contacts; `0.3.7` added the burn notice; `0.4.0` replaced the identity encryption key with an X25519 keypair (breaking, no backward compatibility); `0.4.1` adds web push notifications end to end — VAPID keypair generation, `sig:push_subscribe`/`sig:push_unsubscribe`, best-effort empty-payload pushes on genuinely-offline `app:message` delivery, the per-device opt-in checkbox (edit-contact panel, self only), the browser subscribe/re-subscribe flow, and the service worker's `push`/`notificationclick` handling; `0.4.2` is a client-side bugfix only (the WebRTC call notice previously always labelled the caller `"<name> (me)"`, regardless of who was actually calling, because it read the caller's own locally-decorated self-contact label instead of their plain username — no wire format change); `0.4.5` adds the endpoint-keyed offline buffer (`BUF_DIR/<publicId>/_endpoints/<endpointId>/`, its own caps/TTL/expiry sweep, independent of the identity-level bucket), extends self-sync device targeting to `sync:backup_push`/`sync:backup_accept` (see [Peer Backup Protocol](#peer-backup-protocol)), and moves `deviceId`/`endpointId`/`fingerprint` off those two types' outer envelope and into the encrypted `blob` — the relay never read them, and an unsigned outer field is silently rewritable in transit by an untrusted relay with zero detection; `0.4.6` replaces the separate `toEndpoint` field with a single compound `to` address (`"id"` or `"id::endpointId"` — see [Compound Addressing](#compound-addressing)), applied first to the `0.4.5` self-sync backup work; `0.4.7` is a client-side robustness pass on the restore/backup handshake family, no wire format change — the restore cooldown (previously one identity-keyed map shared across three unrelated jobs, which meant activity on any one job could silently suppress an unrelated device's legitimate turn) is split into three independent trackers (see [Peer Backup Protocol](#peer-backup-protocol)), and the short-window duplicate suppression already used for `backup_offer` is extended to `backup_accept`/`backup_push`/`restore_ack`/`restore_push`, keyed the same device/endpoint-aware way. See [Push Notifications](#push-notifications) for the full picture, including what's deliberately still out of scope.

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
| `meshchat-v1:x25519`     | X25519 private scalar — message encryption key agreement (see below) |
| `meshchat-v1:backup`     | AES-256-GCM backup file encryption |
| `meshchat-v1:signing`    | Ed25519 signing seed |

`meshchat-v1:x25519` derives an X25519 private scalar, which never leaves the device. The corresponding public key (`X25519.getPublicKey(seed)`) is what goes in the shareable address; the actual AES key used per-conversation is computed fresh via ECDH — see [Encryption](#encryption).

### PublicId

```
publicId = base64url( SHA-256(x25519PublicKey || ed25519PublicKey)[0:12] )
```

PublicId is deliberately derived from **both** public keys concatenated, not the X25519 key alone. If it depended only on the X25519 key, an attacker could present a victim's real (public, no secret required) X25519 public key alongside an Ed25519 public key of their own choosing, sign the relay's auth challenge with their own Ed25519 private key, and have the relay register their socket under the victim's publicId — unable to decrypt anything routed there, but able to silently swallow it or otherwise squat on the identity's routing. Hashing both keys together means a given publicId can only be produced by one specific (X25519, Ed25519) pair; a stolen public key from one identity can't be combined with a private key from another to land on the same publicId.

The server derives publicId from the two presented public keys during auth (see [Relay Authentication](#relay-authentication)) and never trusts a client-supplied ID claim.

### Device Identity

Each device generates a random 32-byte seed on first run, stored in localStorage under a per-identity key (`meshchat_device_seed_v1_<publicId>`). A `deviceId` is derived from it the same way as `publicId`:

```
deviceId = base64url( SHA-256( Ed25519.getPublicKey(seed) )[0:12] )
```

`deviceId` is strictly local — it never appears inside any encrypted backup blob or `serialiseContacts()` output, so it is never included in backups, exports, or restore payloads. It rides only as plaintext envelope metadata on specific wire packets where device distinction is meaningful (currently `app:message` and the self-sync backup path). The underlying seed is architecturally prepared for a future X25519 DH key via the standard Ed25519↔X25519 birational conversion — no re-keying needed when that work happens. (This is a *separate* X25519 use from the identity-level agreement key above — device-level forward secrecy is future Double Ratchet work, not part of this pass.)

### Device Endpoint ID

A second, deliberately *unlinkable* value derived from the same device seed as `deviceId`, presented to the relay instead of to contacts:

```
endpointId = base64url( HKDF-SHA256(
  key  = deviceSeed,
  salt = 32 zero bytes,
  info = "meshchat-v1:device-endpoint",
  bits = 256
)[0:12] )
```

`deviceId` and `endpointId` share one seed but are computed under different HKDF info labels. HKDF-SHA256 is a PRF: two outputs derived from the same key under different labels are computationally independent of one another — knowing one gives no leverage on the other without the seed itself. This closes a specific correlation gap that a single shared device identifier would otherwise open: a relay operator sees every `endpointId` that ever authenticates, and a contact sees every `deviceId` a sender's messages carry, but neither party can link their view to the other's. Without this split, a single "device identifier" doing both jobs would hand the relay a value contacts also recognise from their own device popover — turning "which socket to route to" into "which physical device a given contact is using," a strictly larger disclosure than routing requires.

This is **not** anonymity from the relay in any broader sense — a relay that wants to correlate connections by IP, timing, or reconnect pattern can still do so under whatever identifier is presented, `endpointId` included. What the split buys is narrower and specific: it prevents *joining* the relay's view with a contact's view through a shared identifier. Same tier of exposure as `publicId` already has at the identity level, one notch more granular, not a new category of leak.

`endpointId` is:
- **Presented to the relay** — optionally, in the clear, alongside the two public keys on `sig:auth_init` (see [Relay Authentication](#relay-authentication)). Optional for backward compatibility: a client that omits it simply gets no device-level routing, falling back to the existing broadcast-to-every-session behavior.
- **Learned passively by contacts** — inside the encrypted message payload, alongside `deviceId` and `n` (see [Message Payload](#message-payload)), the same way `deviceId` itself is learned. Recorded in the device registry (see [Device Registry](#device-registry)) only after signature verification, same rule as `deviceId`.
- **Never in the shareable address, never in backups** — it has no business in either. The shareable address is meant to be handed to strangers; `endpointId` is meaningful only to the relay currently holding a live socket for it.
- **Static per (device, identity)**, same tradeoff as everything else derived deterministically here — no rotation, no revocation.

---

### Compound Addressing

As of `0.4.6`, a packet's `to` field may carry an optional device-routing suffix — the same way a house number carries an optional unit letter: `1534` routes to the building, `1534b` to one specific unit inside it.

```
to = "<publicId>"                  — routes to every live session under this identity (unchanged, today's form)
to = "<publicId>::<endpointId>"    — routes to one specific registered device only
```

This replaces the separate `toEndpoint` field used in earlier `0.4.x` releases — one field to send and read instead of two, and a human glancing at a packet or a log line sees the whole routing story in one string. `parse_address()`/`build_address()` (`server.py`) and `parseAddress()`/`buildAddress()` (`meshchat-lib.js`) are the shared, mirrored implementations both sides use; nothing else should hand-roll the split.

The separator is `::`. base64url — the charset every id in this protocol uses (`publicId`, `deviceId`, `endpointId`, `callId`, `sessionId`, all `[A-Za-z0-9\-_]{8,64}`) — never contains `:`, so the split is unambiguous with no escaping needed, the same property that already makes the shareable address's `.`-joined segments unambiguous.

**`from` never uses this form** — with one deliberate exception, covering four types: `sync:backup_offer`/`sync:backup_accept`/`sync:backup_push` on the contact path, and `sync:restore_ack`/`sync:restore_push` (see [Peer Backup Protocol](#peer-backup-protocol)). `sync:restore_req` is deliberately **not** included — its `from` stays bare (see that section for why it doesn't need the exception). Everywhere else, `from` is not a routing instruction — it's "who sent this," and the relay derives the true sender from the already-authenticated socket regardless of what's written there, the same way it's always derived `from`. The exception exists because these handshakes may reach a genuinely fresh/not-yet-mutual contact with no shared key material at all — there is no encrypted channel to carry `endpointId` inside the way `app:message`'s payload or the self-sync blob do, so the address is the only channel guaranteed to reach them. The relay still derives `frm_id` from the compound string for its own auth check (the base id must be an already-authenticated identity, exactly as for a bare `from`) — the endpoint half is opaque to it, forwarded through unread, same as everywhere else `endpointId` appears.

**Validation.** The relay's `valid_id()` (bare-id validator, used for `deviceId`/`callId`/`sessionId`/`endpoint_id` and more) deliberately does *not* accept the compound form — `parse_address()` is a separate function specifically for `to`, so nothing else in the protocol accidentally starts accepting `id::endpoint` where a bare id is actually required. `app:migrate`/`app:burn` reject a compound `to` outright (dropped, same as any other malformed packet) — neither type is ever device-targeted by design, so a compound address there is either a bug or something probing the boundary.

**Delivery.** A compound `to` is honored on every branch that already knew how to route `app:message` device-targeted (`route_or_buffer`/`deliver_to_endpoint`) and on the shared `app:sync`/`sync:*`/`call:*`/`shell:*` branch — not a new capability, just a new, single-field way of expressing the same routing instruction that field previously carried. Live-only wherever it was live-only before; the offline buffer honors it wherever it already did (see [Offline Delivery](#offline-delivery)) — nothing about *what* gets buffered or delivered changed in this pass, only how the target device is written on the wire.



Everything needed to reach someone, encoded as a single dot-separated string:

```
<x25519PublicKey_b64>.<signPublicKey_b64>.<relayWss_b64>
```

All three segments are base64url encoded. **Both the first and second segments are public keys — there is no secret material anywhere in this address.** It is meant to be shared as freely as a phone number: printed on a sticker, posted publicly, handed to a stranger. Holding someone's address lets you *reach* and *encrypt to* them; it does not let you read anyone else's traffic with them, and does not let you impersonate them, since neither public key on its own is sufficient to derive the other side's private material.

The third segment is `btoa(wssUrl)` — standard base64 of the relay WebSocket URL. It is optional but included when sharing via QR code or copy-paste, bootstrapping direct relay connectivity on first contact.

Implementations must decode the third segment with `atob()` before use. Segments beyond the third must be ignored for forward compatibility.

---

## Relay Authentication

Authentication happens on connect, before routing or buffer delivery. The protocol proves possession of the identity's Ed25519 private key via a sign-the-nonce challenge.

### Sequence

```
client → server:  auth_init      { x25519_pub: [...bytes], ed25519_pub: [...bytes], endpoint_id?: "..." }
server → client:  auth_challenge { nonce: [...bytes] }
client → server:  auth_proof     { sig: [...bytes] }
server → client:  auth_ok        { public_id: "..." }
             or:  auth_fail      { reason: "..." }
```

1. Client sends both its X25519 and Ed25519 public key bytes, plus an optional `endpoint_id` (see [Device Endpoint ID](#device-endpoint-id)) — presented in the clear, same as the two public keys, and validated (`valid_id`) before the challenge is even issued
2. Server generates a random 32-byte nonce and sends it back in the clear — there is no shared secret between client and server to encrypt it with, and nothing about the nonce itself is worth hiding
3. Client signs the nonce with its Ed25519 private signing key and returns the signature
4. Server verifies the signature against the presented Ed25519 public key, derives publicId from **both** presented public keys (see [PublicId](#publicid)), registers the socket, flushes buffer. If a `endpoint_id` was presented, the socket is additionally registered into `connected_by_endpoint[publicId][endpoint_id]`, enabling device-targeted delivery for `app:message` (see [Device Endpoint ID](#device-endpoint-id) and [Transport and Routing](#transport-and-routing))
5. Client proceeds with `sig:relay_req`, presence polling, and normal operation

The sign-the-nonce scheme is a genuine possession proof — only the holder of the Ed25519 private key can produce a valid signature, and the server can verify it using only the public key the client just presented.

The server never trusts the client's claimed publicId — it derives it authoritatively from the two presented public keys.

An optional `no_receive: true` flag on `sig:auth_init` completes the challenge-response without registering the socket as a recipient and without triggering a buffer flush. Used by disposable connectivity probes (e.g. the migrate panel's TEST function) that must not silently consume buffered packets.

### Cross-relay connections

When a client opens a connection to a foreign relay to deliver a message, it runs the **full auth handshake** — same `sig:auth_init` → `sig:auth_challenge` → `sig:auth_proof` → `sig:auth_ok` sequence. The connection is registered as a sender session on the foreign relay for the duration it remains open. The outbound queue is held until auth completes, then flushed.

The home relay is never targeted via this path. `getOrOpenRelayConn` checks the target hostname against `relayHostname(getSignalUrl())` at the top and returns null immediately if they match — callers fall back to the existing main signal socket instead. This prevents a redundant second session from being registered on the home relay alongside the already-authed main socket.

### Auth failure

On `auth_fail` the client does not retry immediately — the socket `onclose` handler drives reconnect with the normal backoff. Reason codes: `bad_init`, `bad_key_length`, `bad_endpoint_id`, `timeout`, `proof_invalid`, `not_authenticated`.

### Security properties

- Proves possession of the Ed25519 private signing key via a genuine cryptographic signature, not a decrypt-what-you-just-sent round-trip
- Both public keys presented in `auth_init` are already public by design (shared in the shareable address) — presenting them to the server is not a privacy concern
- Replay attacks are prevented by the random nonce — a captured signature is only valid for that specific nonce, and each connection gets a fresh one
- publicId binds both public keys together (see [PublicId](#publicid)), closing the swap attack where someone presents a victim's X25519 public key alongside their own Ed25519 public key
- Buffer hijacking, ID spoofing, and fake presence are all closed by this mechanism

---

## Encryption

**Message encryption** uses a pairwise AES-256-GCM key derived fresh via X25519 Diffie-Hellman, not a raw key transmitted in the shareable address:

```
sharedSecret = X25519(
  privateKey = sender's own X25519 private scalar,
  publicKey  = recipient's X25519 public key
)
aesKey = HKDF-SHA-256(
  key  = sharedSecret,
  salt = 32 zero bytes,
  info = "meshchat-v1:pairwise",
  bits = 256
)
ciphertext = AES-GCM(
  key  = aesKey,
  iv   = random 12 bytes,
  data = JSON(payload)
)
wire = { v: 1, iv: [...], data: [...] }
```

Static-static ECDH is symmetric — `X25519(alicePriv, bobPub)` and `X25519(bobPriv, alicePub)` yield the identical value — so both sides independently derive the same `aesKey` without ever transmitting it. Because the key depends on *both* parties' private material, it is unique to that specific pair: Alice's key for talking to Bob is different from her key for talking to Carol, even though Alice has only one identity. Only the two parties to a given pairwise secret can compute it.

Self-targeted traffic (an identity's own multi-device sync, mini-backups, etc.) uses the same derivation against the identity's own public key — `X25519(myPriv, myPub)` is a well-defined DH operation and every device holding the same identity seed derives the identical result, so no special-casing is needed for the self case.

**This is static-static ECDH, not a ratchet.** The same pairwise key is reused for every message between a given pair indefinitely (until a passphrase change produces new identity keys). It provides real separation between contacts, but it does **not** provide forward secrecy: if either party's X25519 private key is later compromised, previously recorded ciphertext between that pair becomes decryptable in hindsight. See `known-limitations.md`. Forward secrecy (Double Ratchet, evolving the key per message/turn) is separate, later work that builds on top of this pairwise foundation.

**Message signing** uses the sender's Ed25519 signing key, unchanged from prior versions:

```
sig = Ed25519.sign(JSON(wire), sender.signingKeySeed)
```

The recipient verifies the signature against the sender's signing public key (known from the shareable address). Invalid signatures are flagged but not dropped — the message is displayed with a warning.

**Backup encryption** uses the backup key (separate from the message encryption key, unaffected by the X25519 change — it was never derived from or shared as part of the vulnerable scheme):

```
ciphertext = AES-256-GCM(key = backupKey, iv = random, data = gzip(JSON(contacts)))
```

---

## Message Payload

The plaintext payload (before encryption) for a text message:

```json
{
  "id":        "<uuid>",
  "type":      "text",
  "text":      "hello",
  "ts":        1234567890123,
  "deviceId":  "<deviceId>",
  "endpointId": "<endpointId>",
  "relay":     { "wss": "wss://sender.example.com/ws/" }
}
```

The `relay` field carries the sender's current relay WSS URL. Recipients update their routing table for the sender on every message received. This is how relay information propagates passively through the network.

`endpointId` (see [Device Endpoint ID](#device-endpoint-id)) travels alongside `deviceId` inside this same encrypted payload — it's how a contact passively *learns* a sender's endpointId, the same way they learn `deviceId`, recorded into the device registry only once the envelope's signature has verified. Optional; older payloads that omit it leave whatever's already on file for that device untouched rather than being treated as a clear-it signal.

**Other payload types:** `audio`, `image`, `reaction`, `system`. Audio and image carry `data` (base64) and `mimeType`. Reactions carry `targetId` and `emoji`. System notices carry `kind` and `text` — a real, encrypted `app:message` artifact (not a signaling-only packet) used today for the WebRTC call notice (`kind: "call"`), so an offline callee still gets it via the normal offline-buffer/push path and both sides keep a visible record of the attempt regardless of whether the call itself connects.

### Delivery Acknowledgement (RECEIVED)

There is no dedicated packet type for this — SEND and RECEIVED status both ride existing mechanisms rather than adding new wire surface.

**SEND** is purely local optimism: it means the packet left the socket (an open outbound relay connection, or the main signal connection), nothing more. It is never confirmed by the relay or the recipient.

**RECEIVED** reuses the reaction channel. The instant a recipient's client both decrypts an incoming `app:message` *and* successfully verifies its Ed25519 signature, it sends a `reaction` message back to the sender with `targetId` set to the original message's `id` and `emoji: null`:

```json
{ "id": "<derived-reaction-id>", "type": "reaction", "targetId": "<original msg id>", "emoji": null, "ts": ... }
```

This is the exact same shape and stable-ID derivation (`SHA-256("reaction:" + myPublicId + ":" + targetMsgId)`) used for an ordinary emoji reaction — see [Message Merging](#message-merging). The sender treats *any* reaction targeting one of its own outbound messages as proof a real device received and cryptographically verified it — the emoji value is irrelevant to this purpose, `null` is simply what an auto-ack carries. On receipt, the sender flips that message's local status from `sent` to `delivered`.

This acknowledgement deliberately never fires for self-targeted traffic (`msg.from === state.publicId`) — there is no delivery concept to signal to oneself — and only fires once signature verification has actually passed, so a message that merely decrypts but fails verification does not get silently marked delivered.

**READ status is explicitly deferred**, unlike RECEIVED — sensitive, opinions vary widely on whether it should exist at all, and it is not part of this mechanism. See `Roadmap.md`.

### Outer envelope (`app:message`)

The wire packet wrapping the encrypted blob:

```json
{
  "type":      "app:message",
  "from":      "<publicId>",
  "to":        "<publicId>",
  "blob":      { "v": 1, "iv": [...], "data": [...] },
  "sig":       [...],
  "deviceId":  "<deviceId>"
}
```

`deviceId` is the sender's device identity (see [Device Identity](#device-identity)). It is plaintext — not inside the encrypted blob — so the relay and recipient can read it without decryption. Recipients record it in the local device registry to build passive knowledge of which devices a given identity runs. It is optional; old clients that omit it are handled gracefully (the contact's device list stays at the "unknown" placeholder).

`to` may carry a compound `"<publicId>::<endpointId>"` address (see [Compound Addressing](#compound-addressing)) — the endpoint half, when present, is the **recipient's** `endpointId` (learned earlier via the mechanism above), a request to route this specific message to one registered device rather than fanning it out to every live session under that identity. The relay honors this via `deliver_to_endpoint`/`connected_by_endpoint` (see [Device Endpoint ID](#device-endpoint-id)); a targeted device that isn't currently registered is treated as "that device is offline," not silently broadcast to every session. Orthogonal to the sender's own `deviceId` field above — a message can identify its sender's device, target the recipient's device, both, or neither.

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
    <timestamp>_<uuid>.json          — identity-level bucket, reached by any live session under this identity
    _endpoints/
      <endpointId>/
        <timestamp>_<uuid>.json      — device-targeted bucket, reached only by a connection presenting this exact endpoint_id at auth
```

A packet whose `to` address is bare (see [Compound Addressing](#compound-addressing)) goes into the identity-level bucket, exactly as before compound addressing existed. A packet whose `to` carries a `::endpointId` suffix goes into that specific device's own bucket instead — mirroring the same split live delivery already makes between `deliver()` and `deliver_to_endpoint()`.

On reconnect and successful auth, the relay flushes all buffered packets oldest-first and deletes them on successful delivery. A connection that presents `endpoint_id` at auth gets **both** its identity-level bucket and its own endpoint bucket flushed; a connection that doesn't only ever gets the identity-level one — a device-targeted packet is never handed to whichever session happens to reconnect first, only to the one it was actually addressed to. Unauthenticated connections never receive buffered messages of either kind.

**Per-recipient limits** (configurable via environment), applied independently to the identity-level bucket and to each endpoint bucket:
- `BUF_MAX_MSGS` — maximum buffered packets (default 100, drops oldest)
- `BUF_MAX_MB`  — maximum total size in MB (default 10, drops new)
- `BUF_MAX_AGE` — expiry in seconds (default 86400 = 24h, swept periodically)
- `MAX_ENDPOINTS_PER_RECIPIENT` — maximum distinct endpoint buckets one identity can accumulate (default 20), checked only when a *new* bucket would be created; an already-admitted endpoint keeps accepting writes regardless. Same spirit as `MAX_BUF_RECIPIENTS` below, one level down — `endpoint_id` is only ever presented by an already-authenticated socket, though, so this is a narrower abuse surface than `to` itself, which only has to satisfy `valid_id()`.
- `app:migrate`/`app:burn` packets use different semantics entirely — overwrite-per-sender and a longer TTL, always identity-level (never device-targeted by design — see [Compound Addressing](#compound-addressing)) — see [Relay Migration](#relay-migration) below.

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

The encrypted payload is `{ newRelay, ts }` — same encryption scheme as a regular message (`encryptMessage`), using the same pairwise X25519-derived key as any other traffic between the two parties (see [Encryption](#encryption)). For the self-targeted case (a migration breadcrumb left for one's own other devices), this is the identity's own self-ECDH key, computed identically on every device holding the same identity.

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

## Burn Notice

A deliberate, irreversible local action — "stop trusting this identity" — announced via its own dedicated packet type. Structurally identical to `app:migrate` in every way that matters (mandatory signature, always-durable buffering, overwrite-per-sender, long TTL) but kept on a completely separate wire type and buffer bucket, so a routing update can never clobber a pending burn notice, or vice versa — they never share a slot.

```json
{
  "type": "app:burn",
  "from": "<publicId>",
  "to":   "<publicId>",
  "blob": { "v": 1, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The encrypted payload is `{ ts }` — deliberately thin. Unlike `app:migrate` there is no value to timestamp-guard and adopt; burn is a one-shot action, not a routing fact to compare against what's already stored. `ts` exists only so the signed blob carries some content and for an audit trail. Encryption/signing is otherwise identical to `app:migrate` — the same pairwise X25519-derived key as any other traffic between the two parties.

**Signature is mandatory.** Same rule as `app:migrate` and the `call:*`/`shell:*` groups: this packet drives an irreversible action, so an unsigned or invalid one is dropped outright rather than flagged and displayed.

**Self vs. contact — the packet means something different depending on sender:**

- **From self** — another of the user's own devices burned (or this is a second live session catching the same burn). Adopted silently, no ceremony, no notify-back — the receiving device wipes itself too. See [Self-Destruct](#self-destruct) below.
- **From a contact** — they burned; the receiving side converts the contact to `blocked`, recording `blockReason: "burned"` (local-only UI metadata — never on the wire, never a security boundary, just lets the edit-contact pane say *why* something is blocked rather than a bare yes/no). This also drops any stored peer token for that contact, in addition to the message/backup wipe an ordinary manual block already performs — burn is explicitly saying "treat this identity as gone for good," a stronger and less reversible intent than a manual block, so nothing usable for a future restore is left behind. An already-blocked contact is a no-op.

**On commit**, the burning client:
1. Notifies every non-blocked contact via `sendToRelay` (their last-known relay), falling back to `sendSignal` — identical routing to a regular message or `app:migrate`.
2. Sends a copy to *itself* via plain `sendSignal` (same pattern `pushMiniBackup` already uses for self-targeted packets) — no `sendViaRelayUrl`/old-relay dance the way `app:migrate` needs, since burn isn't a routing change. It only needs to reach whatever relay the "me" contact currently points to. A self-device parked at a genuinely different or stale relay won't see it until it next syncs there — the same known limitation `app:migrate` already has.
3. After a brief pause to let the outbound sends leave the socket, wipes itself (see below).

**Server-side buffering** mirrors `app:migrate`'s exception exactly, on its own bucket:
- **Always durably buffered**, even when a live recipient session is reached — same stale-session race `app:migrate` protects against.
- **Overwrite-per-sender**, but only within its *own* suffix (`_burn.json`) — a buffered `app:migrate` breadcrumb can never be evicted by an incoming burn, and vice versa.
- **Long TTL** (`BUF_MAX_AGE_BURN`, default 7 days — independent of, and identical in spirit to, `BUF_MAX_AGE_MIGRATE`).

### Self-Destruct

Not cryptographic revocation — it can't be. Identity is deterministic from `(username, passphrase)`; anyone who still knows the credentials (including the user themselves) can log back in and re-derive the exact same keys at any time. Burn is purely a **local wipe plus a social signal** — the notices sent to contacts are what actually change anything outside the wiping device, by asking them to stop trusting it.

On receiving a self-targeted burn — whether the network packet above, or triggering it locally — the client:
1. Clears every identity-scoped storage key: contact store, peer backups, peer tokens, device registry, and the device seed itself, so this device can't quietly re-announce its old `deviceId` if the same credentials are ever used here again.
2. Closes the signal socket.
3. Reloads to the login screen — equivalent to a genuinely fresh browser profile for this identity.

No trace is deliberately kept anywhere, on this device or otherwise, that the burn happened — consistent with the "not real revocation" framing above. A device that re-derives the same identity later has no way to know it was ever burned; that limitation is stated plainly here rather than implied otherwise.

**Not yet implemented:** any UI indication — on this device or another — that a contact blocked via burn was burned specifically, versus manually blocked, beyond the receiving side's own `blockReason`.

---

## Device Awareness

### Device Registry

Each client maintains a local device registry (`meshchat_known_devices_v1_<publicId>` in localStorage) — a map of identity → known devices:

```json
{
  "<identityId>": {
    "<deviceId>": { "lastSeen": <timestamp>, "lastN": <int>, "endpointId": "<endpointId or null>" }
  }
}
```

This is local-only, never included in backup blobs or `serialiseContacts()`. It is populated passively from two sources:

1. **`app:message` receipt** — the outer `deviceId` field records which device a contact sent from; the encrypted payload's `endpointId` field (see [Device Endpoint ID](#device-endpoint-id)), once present, is recorded alongside it — only ever adopting an explicitly-provided value, so a payload that omits it (e.g. from an older client) leaves whatever's already on file untouched rather than clearing it.
2. **Self-sync backup path** — `sync:backup_push` and `sync:backup_accept` teach each of the user's own devices about the others (see [Peer Backup Protocol](#peer-backup-protocol)). `deviceId`, `fingerprint`, and (as of this pass) `endpointId` all ride inside the encrypted `blob` on both types now, not as outer envelope fields — the relay never read them, and an unsigned outer field is silently rewritable in transit by an untrusted relay with zero detection, the same reasoning that already moved `app:message`'s `deviceId` off its outer envelope. `endpointId` specifically is learned the same "only adopt an explicit value" way as the message-receipt path above — this is what lets `pushBackupToContacts` target a specific known-stale sibling device instead of broadcasting to every live self-session.

The registry is displayed in a per-contact device popover in the UI. Contacts with no recorded devices show an "unknown" placeholder. The data accumulates passively through normal traffic — no dedicated discovery handshake.

### Planned propagation

`deviceId` will be extended to `app:migrate` and `app:sync` envelopes in future passes; `endpointId` (see [Device Endpoint ID](#device-endpoint-id)) would follow the same path if device-targeted delivery is ever needed for those types. Per-device forward secrecy (X25519 DH) is architecturally prepared via the device seed but explicitly deferred.

---

## Voice Calling

Audio calls are negotiated peer-to-peer over WebRTC. The relay carries only small, signed signaling packets to set up the call — it never sees or forwards media, and (unlike messages) these packets are not encrypted, since `from`/`to` are already visible on the wire for every packet type and there's nothing else here worth hiding.

**No TURN server.** ICE uses public STUN only — three servers for resilience (`stun.l.google.com:19302`, `stun1.l.google.com:19302`, `global.stun.twilio.com:3478`). Having no TURN is a permanent architectural decision, not a gap to be filled in later — some NAT pairings will never connect, and the UI should say so honestly rather than retrying forever or hiding the failure.

### Signaling packets — invite / claim / cancel / end

```json
{
  "type":     "call:invite",
  "from":     "<publicId>",
  "to":       "<publicId>",
  "callId":   "<uuid>",
  "ts":       1234567890123,
  "deviceId": "<deviceId>",
  "sig":      [...]
}
```

Four types: `call:invite`, `call:claim`, `call:cancel`, `call:end`. All share this shape and carry no `blob` — there is no payload here worth encrypting. `callId` ties every packet to one call attempt and is generated once by the caller at call start.

**Signature is mandatory** — the same rule as `app:migrate`: these packets drive state transitions (ringing, negotiating, hangup), not just displayed content, so an unsigned or invalid one is dropped outright rather than flagged and shown. The signed payload is `{ type, from, to, callId, deviceId, ts, blob: null }`.

Routing follows the normal contact-relay priority (`sendToRelay` → `sendSignal` fallback) — no special-cased delivery path.

**Call notice.** Entering the `calling` phase also sends a regular, encrypted `app:message` with `type: "system"`/`kind: "call"` (see [Message Payload](#message-payload)) — a visible, offline-deliverable record of the attempt on both sides, independent of whether the call itself connects. Its text is built from the caller's plain username (`state.user`), not any locally-decorated contact-list display name — see the `0.4.2` changelog note at the top of this document for the bug this fixed. This is deliberately only wired for voice calls, not shell escalation: shell targets are always agent contacts, and `agent.py`'s message handler treats any incoming text as a command to execute.

### Signaling packets — offer / answer / ice (WebRTC negotiation)

```json
{
  "type":     "call:offer",
  "from":     "<publicId>",
  "to":       "<publicId>",
  "callId":   "<uuid>",
  "ts":       1234567890123,
  "deviceId": "<deviceId>",
  "blob":     { "v": 1, "iv": [...], "data": [...] },
  "sig":      [...]
}
```

Three types: `call:offer`, `call:answer`, `call:ice`. Unlike the invite/claim/cancel/end group, these carry a `blob` — the SDP (`{ sdp }`) or one ICE candidate (`candidate.toJSON()`) — encrypted with the pairwise X25519-derived key shared between the two parties (see [Encryption](#encryption)), via the same `encryptMessage` scheme as a regular message. The signed payload is `{ type, from, to, callId, deviceId, ts, blob }` — **the ciphertext itself is inside the signature**, the same protection `app:migrate` relies on, so the relay can't swap the encrypted SDP/ICE payload for another without invalidating the signature.

Only accepted while `contact.call.callId` matches and the local role is the expected one for that packet (`call:offer` only while `role === "callee"`, `call:answer` only while `role === "caller"`). `call:ice` candidates arriving before the remote description is set are queued (`iceQueue`) and flushed once it's applied, since trickle ICE races the SDP exchange.

On `call:offer` receipt the callee builds the `RTCPeerConnection`, sets the remote description, flushes any queued ICE, acquires the local media stream, creates and sets the answer, and sends it back as `call:answer`. Local media uses `getUserMedia({ audio: { echoCancellation, noiseSuppression, autoGainControl } })`, falling back to a silent synthetic oscillator track in environments with no microphone (dev/testing only).

### Call state machine

Per-contact call state (`contact.call = { callId, phase, role }`), phases:

```
idle → calling ⇄ negotiating → connected → idle
  ↑        ↓                        ↓
  └── ringing                    failed → idle
```

| Phase | Meaning |
|---|---|
| `idle` | No active call with this contact |
| `calling` | We invited them, awaiting claim (role: `caller`) |
| `ringing` | They invited us, awaiting local answer (role: `callee`) |
| `negotiating` | Claimed on one side; WebRTC offer/answer/ICE exchange in progress |
| `connected` | Media flowing |
| `failed` | ICE/RTC failure — requires explicit reset back to `idle` |

The state machine (`transition()` in `statemachine.js`) is pure logic — dedup and staleness decisions (is this claim for the call in flight? is it from one of our own devices?) are resolved by the caller of `transition()` before it's invoked, not inside it.

### Multi-device dedup

An invite can reach several of the callee's devices at once. When one device answers, `answerCall()` sends `call:claim` twice:

1. To the caller — advances their state `calling → negotiating`.
2. **Self-targeted**, to the callee's own identity — every other device of theirs sees `from === state.publicId`, verifies it against their *own* signing key rather than a contact's, and transitions any device still `ringing` on that same `callId` to `idle` (`claimed_elsewhere`) — silently, no UI ceremony.

The device that actually claimed the call ignores its own echo by comparing `deviceId`.

### Role and negotiation

`role` (`caller` | `callee`) is set on entering `calling`/`ringing` and cleared on return to `idle`. On entering `negotiating`, the caller makes the WebRTC offer (`rtcOffer()` — acquires local media, creates and sets the offer, sends `call:offer`); the callee waits for it and answers via `handleCallOffer()`. This asymmetry lives in `onStateEnter()`, not in the wire protocol.

**Not yet implemented:** ICE connection state / candidate-type (`host`/`srflx`/`relay`) logging for diagnosing NAT failure patterns, an ICE-restart retry path for transient failures, and honest UI messaging distinguishing "still trying" from "this NAT pairing will not connect."

---

## Agent Contacts & Shell Escalation

A `type` field on a contact record — local-only, never on the wire, never included in `serialiseContacts()`/backups — marks a contact as an *agent*: a headless MeshChat identity (see `Agent.py`) running unattended and able to act on requests from trusted contacts. It only ever decides which header button the UI shows (call vs. shell); it carries no security meaning by itself. Real access control lives entirely on the agent's own side, in two independent, deliberately separate allowlists — being permitted one does not imply the other.

### Bounded command whitelist

The lighter-weight capability: ordinary encrypted `app:message` text, no new packet types. A contact the agent has whitelisted sends a short command (`ls`, `cd`, `pwd`, `cat`, `head`, `tail`, `file`, `df`, `du`, `whoami`, `hostname`, `uptime`); the agent executes it (`argv` list, never `shell=True`, `stdin=/dev/null`, per-command timeout, output capped and truncated on overflow) and replies with the output as a normal signed/encrypted text message. Single request/response per command — no pty, no session, no interactivity.

### Shell escalation

A full interactive pty, gated behind a **second, stricter allowlist** — being whitelisted for bounded commands does not imply shell eligibility; only contacts also explicitly named for shell access can ever get one. Reuses the `call:*` signaling shape and the same shared state machine (`transition()` in `statemachine.js`, `kind: "shell"` instead of `"call"` — identical phase/role logic, forked side effects) under its own wire prefix, with no audio/video involved at all:

```json
{
  "type":      "shell:invite",
  "from":      "<publicId>",
  "to":        "<publicId>",
  "sessionId": "<uuid>",
  "ts":        1234567890123,
  "deviceId":  "<deviceId>",
  "sig":       [...]
}
```

Seven types, mirroring the `call:*` group exactly: `shell:invite` / `shell:claim` / `shell:cancel` / `shell:end` (signed only, no `blob`); `shell:offer` / `shell:answer` / `shell:ice` (signed with an encrypted `blob` — SDP or one ICE candidate — inside the signature, same anti-swap protection as `call:offer`/`app:migrate`). `sessionId` plays `callId`'s role, generated once by the initiator. Signature is mandatory on every type in this group, same rule as `call:*` — an unsigned or invalid packet is dropped outright.

**Asymmetry is hardcoded, not negotiated:** the human client is always the offerer, the agent is always the callee. `agent.py` auto-claims any `shell:invite` from a contact on its shell allowlist the instant it verifies the signature (there's no human on that end to click answer), then waits for the human's `shell:offer`. One session per contact is enforced on both sides — a second invite while one is already active is ignored.

**Two data channels**, opened by the human/offerer once the peer connection is up:
- `shell-data` — raw pty bytes, ordered and reliable. Keystrokes flow one way, pty output the other; rendered client-side via `xterm.js`.
- `shell-ctrl` — JSON control messages, currently just `{"type":"resize","cols":N,"rows":N}`.

The agent spawns the pty (`pty.fork()`, attached to the user's `$SHELL -i`) on the data channel's `open` event and tears it down on `shell:end`/`shell:cancel`, ICE failure, the pty process exiting on its own, or `SHELL_IDLE_TIMEOUT_S` (default 300s) of silence in both directions — ssh-style idle, not tab-focus-based.

**No TURN** — same permanent architectural decision as voice calls, same STUN-only ICE config, same acceptance that some NAT pairings simply won't connect. If ICE fails, there is no escalation; the bounded command whitelist above needs no WebRTC and remains available regardless.

**Not yet implemented:** human-to-human shell sharing (the `ringing` phase exists in the shared state machine for parity but is unreachable against `agent.py` today, since it always auto-claims); the same ICE diagnostics/restart gaps noted under [Voice Calling](#voice-calling) apply here too.

---

## Push Notifications

**Status: implemented, client and server.** Opt-in per device, off by default.

Push is opt-in per device and deliberately generic — a push here means only "something arrived, open the app and check." No message content, sender identity, or any other metadata is ever included in a push payload. This is what lets the relay skip the standard Web Push payload-encryption layer (`aes128gcm`) entirely: every push sent is a bodyless POST, authenticated only via a signed VAPID JWT, carrying nothing for anyone — including the push service operator (Google, Mozilla, etc.) — to read.

### Browser support

Standard Web Push (`PushManager` + service worker + VAPID) — not Chrome-specific. Chrome/Edge/Opera and Firefox (desktop and Android) work with no caveats; Safari desktop works since Safari 16. **Safari on iOS/iPadOS only delivers push to a PWA that has actually been added to the Home Screen** (iOS 16.4+) — a page merely open in a Safari tab cannot receive push at all, regardless of subscription state. This is an Apple platform restriction, not something client code can route around. Requires HTTPS (or `localhost` for local dev) unconditionally — no service worker registers at all over plain `http://`. The client's `pushSupported()` check gates the opt-in checkbox off (rather than letting it silently fail) wherever `serviceWorker`/`PushManager` aren't available.

### VAPID keypair

Each relay generates its own EC P-256 keypair on first boot and persists it (`VAPID_KEY_FILE`, default sitting next to `BUF_DIR` rather than inside it). The public key is exposed to clients as `vapidPublicKey` on `sig:relay_info` — base64url encoding of the uncompressed EC point (`0x04 || X || Y`, 65 bytes), the exact format `PushManager.subscribe()`'s `applicationServerKey` expects client-side.

**This keypair is per-relay, not per-identity or global.** A subscription registered against one relay's VAPID key is cryptographically unusable at another relay — the push service binds a subscription to the specific public key presented at `subscribe()` time. This has a direct consequence for [relay migration](#relay-migration): a subscription doesn't automatically follow to a new relay. Handled without a dedicated "migration mode": the client's single `ensurePushSubscription()` entry point runs on every `sig:relay_info` (fresh login, ordinary reconnect, or the reconnect that follows a migration alike) and compares the browser's current subscription key against whichever relay it's presently talking to — a mismatch (only ever possible right after a migration) triggers an automatic unsubscribe-and-resubscribe against the new relay's key. Separately, `notifyMigration()` sends a best-effort `sig:push_unsubscribe` to the relay being left behind, piggybacked on the same connection as the self-targeted `app:migrate` breadcrumb, so the old relay isn't left holding a dead subscription indefinitely. The one accepted gap: a message that lands on the old relay from a contact who hasn't yet learned about the migration will not trigger a push (the message itself is still safely delivered/recovered via the existing migrate/drain mechanism) — a brief window, same spirit as the other timing windows already documented under [Relay Migration](#relay-migration).

### Subscribing

```json
{
  "type":         "sig:push_subscribe",
  "from":         "<publicId>",
  "deviceId":     "<deviceId>",
  "subscription": { "endpoint": "https://...", "keys": { "p256dh": "...", "auth": "..." } }
}
```

Stored at `PUSH_SUBS_DIR/<publicId>/<deviceId>.json` — one file per (identity, device) pair, mirroring `relay_buf`'s per-recipient layout. `sig:push_unsubscribe { from, deviceId }` removes it. Neither type requires a signature — unlike `app:migrate`/`app:burn`, this doesn't redirect routing or drive an irreversible action, so it sits at the same trust tier as the `sync:*` group: authed-socket only, `from` validated against `client_ids`.

The relay rejects any subscription whose `endpoint` isn't `https://`, or that's missing `keys.p256dh`/`keys.auth` — no further validation beyond that and the existing `WS_MAX_SIZE` frame cap.

### Firing a push

Triggered only from inside the offline-buffering path (`buf_write`) for `app:message`, and only when live delivery genuinely failed — a push exists to prompt someone to open the app, which is meaningless if they're already connected and receiving the message live. `app:migrate` and `app:burn` never trigger a push; neither is something a human needs to be woken up for.

Each subscription on file for the recipient gets its own push attempt: a bodyless HTTPS POST to `endpoint`, authenticated via `Authorization: vapid t=<jwt>, k=<vapidPublicKey>`, where the JWT (`ES256`, claims `{ aud, exp, sub }`) is signed fresh per push using the relay's VAPID private key. `aud` is the scheme+host of that specific `endpoint` (push services validate this). Pushes are best-effort — a transient failure (network error, 5xx) is logged and left alone, no retry, same as everything else in this protocol that isn't durably buffered. A `404`/`410` response means the push service has permanently invalidated the subscription; that subscription file is deleted immediately rather than left to fail forever.

### Client-side opt-in and subscribe flow

A checkbox in the edit-contact panel, self-entry only ("push notifications on this device"), controls a **per-device** local preference (`loadPushPref`/`savePushPref` — not part of `serialiseContacts()`/backups, same tier as the device seed itself: this is a statement about this browser, not the identity). Toggling it on calls `ensurePushSubscription()` immediately; toggling it off unsubscribes the browser's `PushSubscription` and sends `sig:push_unsubscribe` to the current relay.

`ensurePushSubscription()` is the single function that keeps the browser subscription and the relay's registration in sync — it runs on every `sig:relay_info`, short-circuits via `pushSyncedRelayWss` when nothing's actually changed (ordinary reconnect to the same relay), and only does real work — unsubscribe/resubscribe against a new `vapidPublicKey`, or subscribe fresh — when something has. See [VAPID keypair](#vapid-keypair) above for why a relay change is the one case this needs to notice.

The service worker (`sw.js`) handles the two events every push implies: `push` (show a generic "MeshChat — tap to check" notification; `event.data` is always null, there's nothing to parse) and `notificationclick` (focus an existing tab if one's open, otherwise open a new one).

### Not yet implemented

- A distinct missed-call/session indicator — **partially covered as of `0.4.x`**: the call notice (`type: "system"`/`kind: "call"`, see [Voice Calling](#voice-calling)) already rides this same push trigger for free, no server changes needed, since it's a normal `app:message`. What's still missing is anything that distinguishes "you got a call notice" from "you got a text" in the (deliberately generic) push body itself — not a gap in mechanism, just in payload specificity, which is out of scope per the design note above.
- Any push trigger beyond `app:message` — `call:invite`/`shell:invite` are live-only and never buffered, so a push for a missed call/session would need its own trigger point at delivery-failure time, not `buf_write`
- Any explicit messaging around the iOS "must be installed to Home Screen first" requirement — an iOS Safari tab user currently just sees the checkbox disabled with the generic "not supported in this browser" label

---

## Signal Server Protocol

### Client → Server

| Type | Fields | Auth required | Description |
|---|---|---|---|
| `sig:auth_init`     | `x25519_pub`, `ed25519_pub`, `no_receive?`, `endpoint_id?` | no  | Begin challenge-response, presenting both public keys. `no_receive: true` skips registration and buffer flush (used by probes). `endpoint_id`, if present, additionally registers the socket into `connected_by_endpoint` for device-targeted delivery (see [Device Endpoint ID](#device-endpoint-id)) |
| `sig:auth_proof`    | `sig`                                     | no  | Return Ed25519 signature over the server's nonce |
| `sig:announce`      | `ids[]`                                   | yes  | Check local presence of up to 10 IDs |
| `app:message`       | `from`, `to`, `blob`, `sig`, `deviceId?` | yes | Deliver message — `from` must match authed identity on this socket. `to` may be compound (`"id::endpointId"` — see [Compound Addressing](#compound-addressing)) to target one specific registered device instead of every live session under that identity |
| `app:migrate`       | `from`, `to`, `blob`, `sig`               | yes | Notify of a relay migration — always durably buffered in addition to live delivery |
| `app:burn`          | `from`, `to`, `blob`, `sig`               | yes | Notify of a burn (self-destruct / stop-trusting) — always durably buffered in addition to live delivery, own overwrite bucket |
| `app:sync`          | `from`, `to`, `msgs[]`, `reply`           | yes  | Manual sync exchange |
| `sync:backup_offer` | `from`, `to`, `size`, `ts`, `sig`         | yes  | Offer backup blob to peer. `from` carries the sender's own compound address on this type (see [Compound Addressing](#compound-addressing) exception) |
| `sync:backup_accept`| `from`, `to`, `ts?`, `sig?`, `blob?` | yes  | Accept a backup offer — `from` compound as above (contact-path variant only; self-sync's own `from` stays bare). Self-sync device-freshness ack: `blob` (present only on this variant, never on a plain contact-offer accept) encrypts `{ deviceId, endpointId, fingerprint }`. `to` may be compound to target the ack back at the specific sibling device that just sent the push it's acking |
| `sync:backup_push`  | `from`, `to`, `blob`, `ts?`, `sig?` | yes | Push backup blob — `from` compound as above (contact-path variant only). Self-sync path: `blob` encrypts `{ deviceId, endpointId, fingerprint, contacts }` (fingerprint-tracked full push) or a bare contacts map (`pushMiniBackup`'s untracked slim push — no fingerprint dance). `to` may be compound (see [Compound Addressing](#compound-addressing)) to target one specific self-device instead of every live self-session |
| `sync:restore_req`  | `from`, `to`, `blob`, `ts`, `sig`         | yes  | Request peer send their stored backup. Signature is mandatory (drop on missing/invalid) — decrypting this at all already requires the recipient to have the sender as a mutual contact, so verification is always possible; no fresh-client leniency needed |
| `sync:restore_ack`  | `from`, `to`, `ts?`, `sig?`               | yes  | Acknowledge restore request. `from` carries the sender's compound address (see [Compound Addressing](#compound-addressing) exception) — signed, but soft-verified: this ack is also sent as a bootstrap ping to online ids that aren't yet contacts (see [Restore handshake](#peer-backup-protocol)), so an unsigned/unverifiable one still proceeds, same stance as `sync:backup_offer` |
| `sync:restore_push` | `from`, `to`, `blob`, `ts?`, `sig?`       | yes  | Push stored backup to requester. Same compound `from` + soft-verification stance as `sync:restore_ack` — it's the reply half of the same bootstrap-reachable flow |
| `sync:token_req`    | `from`, `to`                              | yes  | Request a contact token |
| `sync:token_resp`   | `from`, `to`, `token`                     | yes  | Deliver a contact token |
| `call:invite`       | `from`, `to`, `callId`, `ts`, `deviceId?`, `sig` | yes | Invite a contact to a call — mandatory signature |
| `call:claim`        | `from`, `to`, `callId`, `ts`, `deviceId?`, `sig` | yes | Answer a call — also sent self-targeted for multi-device dedup |
| `call:cancel`       | `from`, `to`, `callId`, `ts`, `deviceId?`, `sig` | yes | Cancel/decline before connection |
| `call:end`          | `from`, `to`, `callId`, `ts`, `deviceId?`, `sig` | yes | Hang up an active or negotiating call |
| `call:offer`        | `from`, `to`, `callId`, `ts`, `deviceId?`, `blob`, `sig` | yes | WebRTC SDP offer — `blob` encrypted with the pairwise X25519-derived key, signed with `blob` included |
| `call:answer`       | `from`, `to`, `callId`, `ts`, `deviceId?`, `blob`, `sig` | yes | WebRTC SDP answer — same encryption/signing as `call:offer` |
| `call:ice`          | `from`, `to`, `callId`, `ts`, `deviceId?`, `blob`, `sig` | yes | One ICE candidate — same encryption/signing as `call:offer` |
| `shell:invite`      | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `sig` | yes | Invite a contact to shell escalation — mandatory signature |
| `shell:claim`       | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `sig` | yes | Accept a shell invite (agent auto-claims if allowlisted) |
| `shell:cancel`      | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `sig` | yes | Cancel/decline before connection |
| `shell:end`         | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `sig` | yes | End an active or negotiating shell session |
| `shell:offer`       | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `blob`, `sig` | yes | WebRTC SDP offer — human is always the offerer |
| `shell:answer`      | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `blob`, `sig` | yes | WebRTC SDP answer — agent is always the answerer |
| `shell:ice`         | `from`, `to`, `sessionId`, `ts`, `deviceId?`, `blob`, `sig` | yes | One ICE candidate — same encryption/signing as `shell:offer` |
| `sig:push_subscribe`   | `from`, `deviceId`, `subscription: { endpoint, keys: { p256dh, auth } }` | yes | Register a per-device push subscription. No mandatory signature — doesn't redirect routing or drive an irreversible action, same trust tier as `sync:*`. `endpoint` must be `https://`, `keys.p256dh`/`keys.auth` required |
| `sig:push_unsubscribe` | `from`, `deviceId`                        | yes | Remove a previously registered push subscription |
| `sig:relay_req`     | —                                         | yes | Request relay's own WSS URL |
| `sig:ping`          | —                                         | yes | Keepalive |

### Server → Client

| Type | Fields | Description |
|---|---|---|
| `sig:auth_challenge` | `bits`, `iv`, `data` | Encrypted nonce for client to decrypt |
| `sig:auth_ok`        | `public_id`          | Auth succeeded, routing active |
| `sig:auth_fail`      | `reason`             | Auth failed or unauthed packet dropped |
| `sig:relay_info`     | `wss`, `version`, `vapidPublicKey` | Relay's own WSS URL, protocol version (informational, not yet enforced), and its VAPID public key (base64url, uncompressed EC point) for push subscription |
| `sig:seen`           | `id`                 | A queried ID is locally connected |
| `sig:pong`           | —                    | Keepalive response |
| `error`              | `reason`             | Protocol error (e.g. rate limited, not_authenticated) |

### Notes

- `app:message`, `app:migrate`, `app:sync`, and all `sync:*` types require auth AND validate `from` ∈ `client_ids` on the socket. `sig:relay_req` and `sig:ping` only require the socket to be authed (no `from` field to check). `sig:announce` has no `from` field at all — its response targets the socket's own authed identity via `last_id()`.
- `app:migrate` and `app:burn` are always written to the durable buffer in addition to any live delivery — each to its own overwrite bucket, keyed by its own filename suffix, so one can never evict the other.
- `sync:backup_accept` and `sync:backup_push` carry an optional `blob` on the self-sync path, encrypting `{ deviceId, endpointId, fingerprint }` (plus `contacts` for the push) — never as outer envelope fields. `blob`'s presence on `sync:backup_accept` is what disambiguates a self-device-freshness ack from a normal contact-offer accept, which never sets one. Old clients that predate this — or omit `endpointId` inside the blob — are handled gracefully; only an explicitly-provided `endpointId` is ever adopted.
- `sync:backup_offer`/`sync:backup_accept`/`sync:backup_push` on the contact path (i.e. not the self-sync `blob` variant), and `sync:restore_ack`/`sync:restore_push`, carry a compound `from` and a signature (see [Peer Backup Protocol](#peer-backup-protocol) and the [Compound Addressing](#compound-addressing) exception) — the relay parses `from` for the auth check on exactly these four types, forwards it unread otherwise, same as it already does for `endpointId` everywhere else it appears. A receiving client only trusts (and only ever displays) the `endpointId` half once the accompanying signature has actually verified against a contact already on file; an unsigned packet, or one from a not-yet-added sender, is still processed — just without that annotation.
- `sync:restore_req` is signed too, but held to a stricter, *mandatory* standard than the four types above (dropped outright on missing/invalid) — it's the one type in this family that can only ever be decrypted by an already-mutual contact in the first place, so there's no fresh-client case to stay lenient for. Its `from` stays bare, unlike its three siblings.
- Compound `to` device-targeting (see [Compound Addressing](#compound-addressing)) is honored on the same shared delivery branch as `app:sync`, every `sync:*` type, and every `call:*`/`shell:*` type — not just `app:message`. In practice only `sync:backup_push`/`sync:backup_accept` use it today (self-device targeting); `call:*`/`shell:*` never send a compound `to`, so their delivery is unaffected. Like `app:message`'s device targeting, this is live-only here too — none of these types are durably buffered, so a `to` aimed at a currently-offline device simply reaches nobody, the same as an untargeted send to an offline recipient already does.
- Sync and backup types are e2e encrypted and routed by the server without inspection of contents — but the socket itself must be authed before any of these are accepted. This closes a prior gap where an unauthenticated connection could reach these branches before completing the challenge-response.
- All seven `call:*` types and all seven `shell:*` types are delivered live-only via the same `deliver()`/`from`-validation path as `app:sync` and the `sync:*` types; unlike `app:message`/`app:migrate`/`app:burn` they are never durably buffered, so an offline callee/agent simply never rings.
- `call:invite`/`call:claim`/`call:cancel`/`call:end` and `shell:invite`/`shell:claim`/`shell:cancel`/`shell:end` carry no `blob` — signed only, nothing to encrypt. `call:offer`/`call:answer`/`call:ice` and `shell:offer`/`shell:answer`/`shell:ice` carry an encrypted `blob` (SDP or one ICE candidate) and sign the ciphertext along with the envelope, same protection principle as `app:migrate`/`app:burn`.
- Delivery acknowledgement (RECEIVED) is not a distinct signal-server packet type — it is an ordinary `app:message` carrying a `reaction` payload with `emoji: null`, routed exactly like any other message. See [Delivery Acknowledgement](#delivery-acknowledgement-received).
- Device-targeted delivery (a compound `to`) is honored by the offline buffer too, not just live delivery — see [Offline Delivery](#offline-delivery)'s endpoint-bucket description. A device-targeted message that misses live delivery lands in that specific device's own bucket (`BUF_DIR/<id>/_endpoints/<endpointId>/`) and is only ever flushed to a connection presenting that exact `endpoint_id` at auth — never to whichever device happens to reconnect first.

---

## Peer Backup Protocol

Contacts back each other up automatically. The backup blob is the sender's encrypted contact store — encrypted with the backup key, unreadable to the peer storing it.

**Distribution (contact path):**
1. After saving contacts, sender broadcasts `backup_offer { size, ts, sig }` to all reachable contacts
2. Recipient replies `backup_accept { ts, sig }`
3. Sender pushes `backup_push { blob, ts, sig }`
4. Recipient stores blob locally; serves it back on `restore_push`

**`from` on all three carries the sender's own compound `"id::endpointId"` address** (`buildAddress(state.publicId, state.endpointId)`) — see the exception noted in [Compound Addressing](#compound-addressing). This exists specifically because this handshake may reach a genuinely fresh/not-yet-mutual contact: unlike self-sync (sender and recipient share one key trivially, so `deviceId`/`endpointId`/`fingerprint` ride inside the blob) or `app:message` (by the time a message exists, the pairwise key already works), there's no guarantee here that any shared key material exists yet. The address is the one channel guaranteed to reach a stranger.

**All three are signed** (`signBackupPacket`/`verifyBackupPacket`, same Ed25519 identity key as everything else) — but verification is only ever *possible* once the recipient already has this sender as a contact (needs their `signPublicKey`, the same precondition encryption already has on this path). An unsigned packet, or one from a sender not yet on file, is processed exactly as this handshake has always worked — bootstrap must keep functioning regardless. Only an **actively wrong** signature — `sig` present, sender's key already on file, verification genuinely fails (i.e. the untrusted relay tampered with it in transit) — is dropped, and logged either way. This is a deliberately softer stance than `app:migrate`/`app:burn` (which drop on any missing/invalid signature outright): those drive irreversible actions and have no fresh-contact case to protect; this handshake is routine and must degrade gracefully. The recipient's device/endpoint annotation in the local log line only ever appears once a signature has actually verified — an unverified compound `from` is still parsed for routing/display of the bare id, but its endpoint suffix is not trusted or shown.

**Self-sync (same identity, multiple devices):**

Skips the offer/accept negotiation entirely — the push goes directly. To avoid redundant full-blob broadcasts when devices are already converged, a content fingerprint is computed before each push:

```
fingerprint = base64url( SHA-256( JSON(serialiseContacts()) )[0:12] )
```

Each device maintains an in-memory table of `{ deviceId → fingerprint }` for the other devices it has heard from this session (`knownDeviceFingerprints`). If every known device already has the current fingerprint, the push is skipped. The table resets on reload — worst case is one extra push on cold start, no data-loss risk.

The `sync:backup_push` self-path encrypts `{ deviceId, endpointId, fingerprint, contacts }` as one blob — the outer envelope carries only `type`/`from`/`to`/`blob`, nothing else; `to` may be a compound address (see [Compound Addressing](#compound-addressing)) when the push is targeted, and everything else here would be a plaintext, unsigned, silently-rewritable-in-transit field otherwise (the relay is untrusted infrastructure — cryptographic proof is the only trust boundary, same principle `app:message`'s `deviceId` placement already follows). The receiver merges, then replies with a `sync:backup_accept` whose own blob encrypts `{ deviceId, endpointId, fingerprint }` — a lightweight ack that lets the sender record the receiver's current state and endpoint. The presence of `blob` on `backup_accept` is what distinguishes this device-ack from a normal contact offer-accept, which never sets one; old clients (or the pre-this-pass wire shape) fall through to today's behavior unchanged. Since self-sync packets carry no `sig`, this buys tamper-*evidence* (AES-GCM simply fails to decrypt on any bit flip) rather than the stronger sender-authentication `app:message`'s Ed25519 signature provides — sufficient here since this is self-to-self traffic on an already-authenticated socket, but worth stating plainly rather than implying an equivalent guarantee.

`pushMiniBackup` (a smaller, single-contact self-push fired after every outgoing message — see [Message Merging](#message-merging) context) shares this same `sync:backup_push` handler but sends a bare, unwrapped contacts map with no `deviceId`/`endpointId`/`fingerprint` at all — it doesn't participate in the fingerprint-tracking dance above. The receiving handler distinguishes the two shapes by checking for a string `deviceId` alongside an object `contacts` field; a genuine contacts map's top-level keys are always publicIds, never the literal string `"deviceId"`, so this is unambiguous.

**Per-device targeting.** When a known sibling device's fingerprint is stale AND its `endpointId` is already on file (`state.knownDevices[state.publicId][deviceId].endpointId`, populated passively by the ack exchange above), the push is sent with `to` set to the compound `buildAddress(state.publicId, endpointId)` address — reaching only that device, not every live self-session. A device already reached this way may still receive a broadcast copy (bare `to`) if some *other* stale device's `endpointId` isn't known yet (an older client, or one that simply hasn't acked this session); this is accepted, harmless redundancy — merging the same blob twice is a no-op — rather than something worth the complexity of excluding already-targeted sockets from the fallback broadcast. The ack itself is targeted the same way: `handleBackupPush`'s self branch now knows the pushing device's `endpointId` the instant the push arrives, so the reply ack's `to` becomes the compound address pointing back at it rather than broadcasting.

A broadcast (bare `to`, no unit) is still the first move whenever no device has been heard from yet this session — there's nothing to target, and the broadcast is what populates `knownDeviceFingerprints`/`endpointId` for every subsequent push to actually target against.

**Short-window duplicate suppression.** Separate from, and much shorter than, the restore cooldowns below: all five packet types in this family (`backup_offer`/`backup_accept`/`backup_push`/`restore_ack`/`restore_push`) pass through a 3-second dedup window before any other processing, purely to skip redundant work (a doubled log line, a redundant re-send, a repeat merge) when the same sender's traffic legitimately arrives twice in quick succession — a near-simultaneous retry, or more than one of a sender's live devices independently answering the same broadcast within the same tick. As of `0.4.7` the dedup key is device/endpoint-aware wherever a signature is available to check it against: once a packet's signature verifies, the key becomes `type:senderId:endpointId` rather than just `type:senderId`, so a second, genuinely distinct sibling device answering within the same window isn't mistaken for a duplicate of the first. Unverified traffic — or the two self-sync sub-paths, which carry no signature at all (see above) — falls back to keying on the decrypted `deviceId` where available, or the bare sender id otherwise, the same soft-verification tier used throughout this handshake family.

**Restore handshake** (fires on connect for all known contacts):
1. Client sends `sync:restore_req` to each contact
2. Contact replies `sync:restore_ack`
3. Contact sends `sync:restore_push` containing the stored backup for the requester
4. Requester decrypts and merges into local state

Restore flooding is prevented by three independent 5-minute cooldowns rather than one shared one (as of `0.4.7`). Earlier revisions used a single identity-keyed cooldown across all three of the jobs below, which meant activity on any one of them could silently suppress an unrelated device's legitimate turn for up to five minutes — e.g. one of a contact's devices completing a restore could leave a *different* device of theirs unable to get an ack for the same window, even though nothing about that second device's request was actually stale.

- **Outbound** — `sendRestoreRequest`'s own send cadence toward an identity. Stays identity-level: `restore_req` is addressed at the identity broadly, not at a specific device, so there's nothing narrower to key on here. The `sig:seen` presence signal triggers a restore request through this same path and cooldown.
- **Inbound serve** — whether to bother acking an incoming `restore_req`, keyed on `(senderId, deviceId)`. Safe to key on `deviceId` specifically because `restore_req` is mandatory-signed and already decrypted by the point this check runs (see [Signal Server Protocol](#signal-server-protocol) above) — there's no fresh-client leniency gap here the way there is for the rest of this family.
- **Inbound accept** — whether to bother processing an incoming `restore_push`, keyed on `(senderId, endpointId)` once the packet's signature verifies; falls back to identity-level for the unverifiable case, same soft-verification tier the rest of this handshake family uses. `restore_push` carries no `deviceId` at all — unlike `restore_req`, there's no channel here guaranteed available to encrypt it in, so it simply isn't learned on this path (see the trust-shapes note below) — only `endpointId`, via the compound `from`.

`deviceId` and `endpointId` are kept in separate cooldown maps rather than one with mixed key shapes, consistent with their deliberately unlinkable namespaces (see [Device Endpoint ID](#device-endpoint-id)) — a map mixing device-keyed and endpoint-keyed entries side by side would invite exactly the kind of correlation-by-accident this protocol otherwise goes out of its way to avoid.

**Two different trust shapes across these three types, not one.** `sync:restore_req` can only ever be *processed* by a recipient who already has the sender as a mutual contact — decryption itself requires `contact.encKey`, and a contact's `signPublicKey` is populated the instant they're added (straight from the shareable address, no prior traffic needed). So by the time a `restore_req` handler would check a signature, verification is always possible — it's **mandatory**, dropped outright on missing or invalid, same tier as `app:migrate`/`call:*`.

`sync:restore_ack` and `sync:restore_push` don't have that guarantee. Beyond replying to a genuine `restore_req`, `restore_ack` is also sent proactively as a bootstrap ping — a client with no local data at all (a fresh device, or one that's lost its storage) broadcasts it to *every* currently-visible id on `sig:seen`, contact or not, hoping a stranger happens to be a contact it lost track of. That means both types can legitimately reach, or be replied to by, someone with no shared key material yet — the same fresh-client shape `sync:backup_offer` has. Both carry the sender's own compound `from` address (the one exception alongside the backup handshake — see [Compound Addressing](#compound-addressing)) and are signed unconditionally, but verification is only *possible* once the recipient already has the sender as a contact; an unverifiable packet is processed exactly as this handshake has always worked, and only an actively wrong signature (key on file, doesn't check out) is dropped. `deviceId` is deliberately never carried by either — unlike `restore_req` (where it safely rides inside the already-encrypted blob), there's no channel here guaranteed available to encrypt it, so it simply isn't learned on this path; the device registry is still fed by every path that does have one (`app:message`, self-sync).

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

Reactions use a stable derived ID (`SHA-256("reaction:" + myId + ":" + targetMsgId)`) so a user's reaction to a given message always has the same ID — naturally replacing rather than duplicating on merge. The delivery-acknowledgement reaction (see [Delivery Acknowledgement](#delivery-acknowledgement-received)) uses this identical derivation, so it merges the same way.

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
| `meshchat_known_devices_v1_<publicId>` | per identity | Device registry — `{ identityId: { deviceId: { lastSeen, lastN, endpointId } } }` |
| `meshchat_device_seed_v1_<publicId>`   | per device   | Raw 32-byte device seed (base64). Never shared, never backed up |
| `meshchat_push_pref_v1_<publicId>`     | per device   | Push notification opt-in ("1"/"0"). Local-only preference — the actual `PushSubscription` lives in the browser's own PushManager storage, not here |

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
| `BUF_MAX_AGE_BURN`    | `604800`      | Buffer expiry in seconds (7d) — `app:burn` packets only, independent bucket |
| `BUF_MAX_MB`          | `10`          | Max buffer size per recipient in MB |
| `MAX_BUF_RECIPIENTS`  | `10000`       | Max distinct identity-level recipient directories under `BUF_DIR` at once — a brake on fanning out to unlimited fabricated recipient IDs, since `to` only has to satisfy `valid_id()` |
| `MAX_ENDPOINTS_PER_RECIPIENT` | `20`  | Max distinct endpoint buckets (`_endpoints/<endpointId>/`) one identity can accumulate — see [Offline Delivery](#offline-delivery) |
| `AUTH_TIMEOUT`        | `15`          | Seconds to complete challenge-response before disconnect |
| `VAPID_SUBJECT`       | `mailto:admin@example.com` | Operator contact required by the VAPID spec, sent in every push JWT's `sub` claim |
| `VAPID_KEY_FILE`      | next to `BUF_DIR` | Path to the persisted VAPID EC P-256 private key (PEM); generated on first boot if missing |
| `PUSH_SUBS_DIR`       | next to `BUF_DIR` | Push subscription storage — `<dir>/<publicId>/<deviceId>.json` |
| `PUSH_TTL_SECONDS`    | `60`          | `TTL` header sent with each push — how long the push service should hold it if the device is unreachable |

---

*MeshChat Protocol v1 — experimental, subject to change*  
*Last updated: August 2026*