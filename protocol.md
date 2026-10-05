# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

Implementation version: `0.5.5`, surfaced informationally via the `version` field on `sig:relay_info` (not enforced). This document describes the protocol as it stands today. Version history is in `CHANGELOG.md`; work not yet confirmed live is tracked in `Roadmap.md`; `X4DH.md` is the authoritative source for the X4DH cryptographic design; `known-limitations.md` lists the permanent trade-offs.

---

## Core Concepts

**Identity** is a keypair derived deterministically from a username and passphrase. The same credentials always produce the same identity. There is no registration, no server-side account, and no recovery mechanism beyond the credentials themselves.

**Contacts** are identified by their publicId — a short hash of their two public keys (see [PublicId](#publicid)). Adding a contact requires their shareable address, exchanged out-of-band (QR code, copy-paste).

**Relays** are WebSocket servers that route packets between clients. A relay has no knowledge of message contents. Clients choose which relay to use. Relays are interoperable — clients on different relays communicate directly.

**Authentication** gates both sending and receiving. A client must prove possession of their signing key before the relay accepts any messages from them or registers them for inbound routing. The `from` field of any packet must match an identity already proven on that socket. When connecting to a foreign relay to send, the client runs the same challenge-response handshake before any messages are transmitted. The queue is held until auth completes, then flushed.

---

## Identity and Key Derivation

All keys are derived deterministically from `(username, passphrase)`:

```
masterSecret = PBKDF2(
  password   = passphrase,
  salt       = SHA-256("meshchat-v1:" + username.toLowerCase().trim()),
  iterations = 1000000,
  hash       = SHA-256,
  bits       = 256
)
```

Every derivation parameter — iteration count, salt format, HKDF labels — is an input to the identity: changing any of them changes every derived key and therefore the `publicId`.

Three keys are expanded from the master secret via HKDF-SHA-256:

| Label | Use |
|---|---|
| `meshchat-v1:x25519`     | X25519 private scalar — key agreement (see [Encryption](#encryption)) |
| `meshchat-v1:backup`     | AES-256-GCM backup key — backup blobs, restore token, local storage |
| `meshchat-v1:signing`    | Ed25519 signing seed |

The X25519 private scalar never leaves the device. The corresponding public key (`X25519.getPublicKey(seed)`) is what goes in the shareable address; AES keys are computed per conversation via ECDH.

### PublicId

```
publicId = base64url( SHA-256(x25519PublicKey || ed25519PublicKey)[0:12] )
```

PublicId is derived from **both** public keys concatenated, not the X25519 key alone. If it depended only on the X25519 key, an attacker could present a victim's real (public, no secret required) X25519 public key alongside an Ed25519 public key of their own choosing, sign the relay's auth challenge with their own Ed25519 private key, and have the relay register their socket under the victim's publicId — unable to decrypt anything routed there, but able to silently swallow it or otherwise squat on the identity's routing. Hashing both keys together means a given publicId can only be produced by one specific (X25519, Ed25519) pair.

The server derives publicId from the two presented public keys during auth (see [Relay Authentication](#relay-authentication)) and never trusts a client-supplied ID claim.

### Device Identity

Each device generates a random 32-byte seed on first run, stored in localStorage under a per-identity key (`meshchat_device_seed_v1_<publicId>`). A `deviceId` is derived from it the same way as `publicId`:

```
deviceId = base64url( SHA-256( Ed25519.getPublicKey(seed) )[0:12] )
```

`deviceId` is local-only: it never appears in any backup blob, export, `serialiseContacts()` output or shareable address. It is the value contacts learn and show in their device popover. It travels in two ways:

- **Inside encrypted payloads** — `app:message` payloads (including `selfsync`), the self-sync backup blobs, and the `restore_req` blob.
- **As a signed plaintext field** on `call:*`, `data:*` and `session:*` packets. Relay-visible; see the consequence under [Device Endpoint ID](#device-endpoint-id).

### Device Endpoint ID

A second value derived from the same device seed as `deviceId`, presented to the relay instead of to contacts:

```
endpointId = base64url( HKDF-SHA256(
  key  = deviceSeed,
  salt = 32 zero bytes,
  info = "meshchat-v1:device-endpoint",
  bits = 256
)[0:12] )
```

`deviceId` and `endpointId` share one seed but are computed under different HKDF info labels. HKDF-SHA256 is a PRF, so two outputs derived under different labels are computationally independent: knowing one gives no leverage on the other without the seed. The purpose is to avoid a single device identifier doing two jobs — a relay sees every `endpointId` that ever authenticates (to route to a specific socket), and a contact sees every `deviceId` a sender's messages carry (to tell devices apart). Without the split, "which socket to route to" would also be "which physical device a given contact is using", a strictly larger disclosure than routing requires.

What the split does and does not buy:

- Message traffic, self-sync traffic and push registration never put both values in the same relay-visible place, so a relay cannot join its view with a contact's view through them.
- It is **not** anonymity from the relay. IP, timing and reconnect patterns still correlate connections under any identifier.
- It does **not** hide the link from a relay that sees the packets that carry `deviceId` in plaintext (`call:*`, `data:*`, `session:*`): the relay knows which `endpointId` the sending socket authenticated with, and reads the `deviceId` beside it.

`endpointId` is:
- **Presented to the relay** — optionally, in the clear, alongside the two public keys on `sig:auth_init` (see [Relay Authentication](#relay-authentication)). A client that omits it gets no device-level routing and falls back to broadcast to every session of the identity.
- **Learned by contacts** — from the encrypted payload of `app:message` (alongside `deviceId` and `n`), from self-sync blobs, and from the compound `from` address on handshake packets whose signature has verified. Recorded in the device registry (see [Device Registry](#device-registry)) only after signature verification.
- **Never in the shareable address, never in backups.**
- **Static per (device, identity)** — no rotation, no revocation.

---

### Compound Addressing

A packet's `to` field may carry an optional device-routing suffix — the way a house number carries an optional unit letter: `1534` routes to the building, `1534b` to one specific unit inside it.

```
to = "<publicId>"                  — every live session under this identity
to = "<publicId>::<endpointId>"    — one specific registered device only
```

`parse_address()`/`build_address()` (`server.py`) and `parseAddress()`/`buildAddress()` (`meshchat-lib.js`) are the shared, mirrored implementations; nothing else should hand-roll the split.

The separator is `::`. base64url — the charset every id in this protocol uses (`publicId`, `deviceId`, `endpointId`, `callId`, `sessionId`, all `[A-Za-z0-9\-_]{8,64}`) — never contains `:`, so the split is unambiguous with no escaping.

**`from` is bare** with one deliberate exception, covering five types: `sync:backup_offer`, `sync:backup_accept` and `sync:backup_push` on the contact path, and `sync:restore_ack` and `sync:restore_push` (see [Peer Backup Protocol](#peer-backup-protocol)). `sync:restore_req` is not in this set — its `from` stays bare. Everywhere else `from` is not a routing instruction, just "who sent this", and the relay derives the true sender from the authenticated socket regardless of what is written there. The exception exists because these handshakes may reach a genuinely fresh or not-yet-mutual contact with no shared key material, so there is no encrypted channel to carry `endpointId` — the address is the only channel guaranteed to reach them. The relay validates the base id of the compound `from` against the authenticated identities exactly as for a bare `from`; the endpoint half is forwarded unread.

**Which types take which form of `to`:**

| Form | Types |
|---|---|
| compound **required** (bare dropped) | `session:propose`, `session:ack` — a session is always device-to-device |
| compound **rejected** (dropped) | `app:migrate`, `app:burn` — never device-targeted |
| either | `app:message`, `app:sync`, every `sync:*`, every `call:*`, every `data:*` |

**Validation.** `valid_id()` (bare-id validator for `deviceId`, `callId`, `sessionId`, `endpoint_id` and similar) deliberately does not accept the compound form; `parse_address()` is a separate function for `to` (and for the compound `from` types), so nothing else accepts `id::endpoint` where a bare id is required.

**Delivery.** A compound `to` is delivered only to the socket(s) registered under that endpoint (`deliver_to_endpoint`/`connected_by_endpoint`). A targeted device that is not connected is treated as offline; it is never silently broadcast to every session. Which types are buffered for an offline target is covered under [Offline Delivery](#offline-delivery).

---

## Shareable Address

Everything needed to reach someone, encoded as a single dot-separated string:

```
<x25519PublicKey_b64>.<signPublicKey_b64>.<relayWss_b64>
```

All three segments are base64url encoded (the third is `btoa(wssUrl)`, standard base64). **Both the first and second segments are public keys — there is no secret material anywhere in this address.** It is meant to be shared as freely as a phone number. Holding someone's address lets you reach and encrypt to them; it does not let you read anyone else's traffic with them or impersonate them.

The third segment is optional but included when sharing via QR code or copy-paste, bootstrapping relay connectivity on first contact. Implementations decode it with `atob()`. Segments beyond the third are ignored for forward compatibility.

---

## Relay Authentication

Authentication happens on connect, before routing or buffer delivery. The protocol proves possession of the identity's Ed25519 private key via a sign-the-nonce challenge.

### Sequence

```
client → server:  sig:auth_init      { x25519_pub: [...bytes], ed25519_pub: [...bytes], endpoint_id?: "...", no_receive?: true }
server → client:  sig:auth_challenge { nonce: [...bytes] }
client → server:  sig:auth_proof     { sig: [...bytes] }
server → client:  sig:auth_ok        { public_id: "..." }
             or:  sig:auth_fail      { reason: "..." }
```

1. The client sends both public keys, plus an optional `endpoint_id` (see [Device Endpoint ID](#device-endpoint-id)), validated (`valid_id`) before the challenge is issued.
2. The server sends a random 32-byte nonce in the clear — there is no shared secret to encrypt it with, and nothing about the nonce is worth hiding.
3. The client signs the nonce with its Ed25519 signing key and returns the signature.
4. The server verifies the signature against the presented Ed25519 public key, derives the publicId from **both** presented keys (see [PublicId](#publicid)), registers the socket, and flushes the offline buffer. If an `endpoint_id` was presented the socket is additionally registered in `connected_by_endpoint[publicId][endpoint_id]`.
5. The client proceeds with `sig:relay_req`, presence polling and normal operation.

`no_receive: true` completes the handshake without registering the socket as a recipient and without a buffer flush. Used by disposable connectivity probes (the migrate panel's TEST) that must not consume buffered packets.

A socket is bound to one identity: a second, different identity proven on the same socket is rejected (`already_authenticated`); re-proving the same identity is a no-op.

**Admission limits.** A connection that sends `sig:auth_init` but never a proof is closed after `AUTH_TIMEOUT` (15s, enforced by a periodic sweep). Completed auths are additionally rate-limited server-wide (`GLOBAL_AUTH_RATE`/`GLOBAL_AUTH_BURST`), checked only after the proof is valid so garbage proofs don't spend from the budget; a rejected completion gets `server_busy`.

### Cross-relay connections

When a client opens a connection to a foreign relay to deliver a message, it runs the full handshake. The connection is registered as a sender session on the foreign relay for as long as it stays open; the outbound queue is held until auth completes, then flushed.

The home relay is never targeted this way: `getOrOpenRelayConn` checks the target hostname against `relayHostname(getSignalUrl())` and returns null on a match, and callers fall back to the main signal socket.

### Auth failure

On `sig:auth_fail` the client does not retry immediately — the socket `onclose` handler drives reconnect with backoff. Reason codes: `bad_init`, `bad_key_length`, `bad_endpoint_id`, `timeout`, `proof_invalid`, `server_busy`, `already_authenticated`, `not_authenticated`.

### Security properties

- Proves possession of the Ed25519 private signing key via a real signature, not a decrypt-what-you-just-sent round trip.
- Both public keys are public by design; presenting them to the server is not a privacy concern.
- A captured signature is only valid for its nonce; each connection gets a fresh one.
- publicId binds both public keys together, closing the swap attack described under [PublicId](#publicid).
- Buffer hijacking, ID spoofing and fake presence are closed by this mechanism.

---

## Encryption

Three independent key families:

- **Message keys** — per device pair (X4DH wire key) where a session exists, per identity pair (legacy pairwise key) otherwise. They protect `app:message` traffic and, with the legacy key, a few other packet types listed below.
- **Backup key** — passphrase-derived and deterministic. It protects backup blobs, the restore token and local storage.
- **Ephemeral wrap keys** — one-shot keys from an ephemeral-to-ephemeral X25519 exchange. They protect specific handshake pushes and the manual-SYNC batch (see [Ephemeral Wrap](#ephemeral-wrap) and [Manual Sync](#manual-sync-appsync)).

### Pairwise (legacy) key

```
sharedSecret = X25519(
  privateKey = own X25519 private scalar,
  publicKey  = counterpart's X25519 public key
)
aesKey = HKDF-SHA-256(
  key  = sharedSecret,
  salt = 32 zero bytes,
  info = "meshchat-v1:pairwise",
  bits = 256
)
ciphertext = AES-GCM(key = aesKey, iv = random 12 bytes, data = JSON(payload))
wire = { v: 1, iv: [...], data: [...] }
```

Static-static ECDH is symmetric — `X25519(alicePriv, bobPub)` and `X25519(bobPriv, alicePub)` yield the same value — so both sides derive the same `aesKey` without transmitting it. The key depends on both parties' private material, so it is unique to that pair. Self-targeted traffic uses the same derivation against the identity's own public key; every device holding the identity derives the identical result.

This key is **not** forward-secret: it is reused for every message between a pair indefinitely, and a later compromise of either party's X25519 private key exposes previously recorded ciphertext between that pair (see `known-limitations.md`).

It is the key in use wherever no X4DH wire key applies:

- a device pair with no X4DH session (an older client, or one that has not completed bootstrap);
- the broadcast fallback of a fanout (an unresolved or unknown device set);
- `app:migrate`, `app:burn`, and the encrypted blobs of `call:*`/`data:*` signaling (none are device-targeted);
- the manual-SYNC envelope and the `restore_req` blob.

### X4DH wire key

For a device pair that has an X4DH session (see [Session Establishment](#session-establishment-x4dh)), `app:message` traffic — text, audio, image, reaction, system-notice and `selfsync` payloads alike — encrypts under a key derived from that session's current root key (`RK0` or `RK1`):

```
wireKey = HKDF( salt = zero32, ikm = rootKeyBytes, info = "MeshChat-X4DH-v1/wire-message", length = 32 )
```

`RK0` (the asynchronous bootstrap stage, before a live round trip has completed) is accepted alongside `RK1` — a deliberate, disclosed trade-off (`X4DH.md` §10/§16.2): an `RK0`-only session protects against a future leak of the *initiator's* identity key but not the responder's. Once the live upgrade to `RK1` completes, that gap is closed for the device pair going forward.

`RK1`'s property is *session-level forward secrecy against later identity-key compromise, for traffic sent after the upgrade*. It is not per-message forward secrecy (the wire key is static per session) and not retroactive to traffic sent under `RK0`. Exact scope and qualifiers: `X4DH.md` §10.2.

Within one fanout to a single contact, some of that contact's devices may be on an X4DH wire key while others are simultaneously on the legacy key.

**Receive side.** `deviceId` is inside the encrypted payload, so the recipient cannot know which key applies before decrypting. It tries every X4DH session held for that sender (most recently established first), then the legacy key. AES-GCM's tag makes a wrong-key attempt fail cleanly, so this costs a few rejected decrypts, never a false positive. After a successful X4DH decrypt, the payload's `deviceId` is cross-checked against the session that decrypted it; a mismatch is treated like an invalid signature (flagged, unverified). Detail: `X4DH.md` §16.

### Message signing

```
sig = Ed25519.sign(JSON(wire), sender.signingKeySeed)
```

The recipient verifies against the sender's signing public key (known from the shareable address). An invalid signature on an `app:message` is flagged but not dropped — the message is displayed with a warning. Packet types that drive state rather than display (see the per-type rules below) drop on an invalid signature instead.

### Backup encryption

```
blob = { v: 2, iv: [...], data: AES-256-GCM( key = backupKey, iv = random, data = gzip(JSON(contacts)) ) }
```

The backup key is separate from the message keys. The blob itself is deterministic with respect to the passphrase: it never ratchets, so an exported file or a freshly recovered identity with no session state can always restore. See [Peer Backup Protocol](#peer-backup-protocol) for how it is transported.

---

## Session Establishment (X4DH)

X4DH is a MeshChat-specific 2DH/4DH session-establishment construction. It is not Signal's X3DH, does not use signed or one-time prekeys, and has not been formally analysed or independently audited.

Device pairs establish an X4DH session — an asynchronous root-key agreement that upgrades opportunistically when both sides are online — and use its output as the wire key above. `X4DH.md` is the authoritative document for the cryptographic design, the fixed-initiator glare-elimination rule and replay/staleness hardening; this section covers the two wire packet types and how the relay treats them.

```json
{
  "type":         "session:propose",
  "from":         "<publicId>",
  "to":           "<publicId>::<endpointId>",
  "sessionEpoch": "<uuid>",
  "ekPub":        [ /* fresh X25519 ephemeral public key bytes */ ],
  "deviceId":     "<deviceId>",
  "ts":           1234567890123,
  "sig":          [...]
}
```

`session:ack` is structurally identical, sent in reply once the recipient has generated its own ephemeral (`ekPub` is the responder's ephemeral). Both types:

- **Are mandatory-signed**, dropped on a missing or invalid signature. The signed fields are `type`, `from`, `to`, `sessionEpoch`, `ekPub`, `deviceId`, `ts`. The signature authenticates the ephemeral key and the session/device metadata from which the root key is derived, binding the session to the claimed identity and device pair; `deviceId` is an identity-authenticated claim, not proven with a separate device key.
- **Require a compound `to`** — a session is always device-to-device. The relay drops a bare `to` for these two types.
- **Are always durably buffered** in addition to any live delivery (the same exception `app:migrate`/`app:burn` get): a stale-but-not-yet-closed session of the same identity could otherwise swallow a packet meant for a device still catching up. `session:propose` additionally overwrites per sender in its own bucket (`_x4dh_propose.json` suffix) and uses the ordinary 24h TTL — an unanswered handshake attempt isn't something that must eventually be seen; a fresh one follows when the conversation resumes. `session:ack` is not overwritten — a stale ack for a superseded `sessionEpoch` fails the epoch-match check client-side and is harmless until it expires.
- **Never trigger a push notification** — transparent crypto housekeeping.

Session state is local-only and stored encrypted at rest under the backup key (see [Client Storage Keys](#client-storage-keys)); root keys are never part of any backup or export.

---

## Message Payload

The plaintext payload (before encryption) for a text message:

```json
{
  "id":          "<uuid>",
  "text":        "hello",
  "ts":          1234567890123,
  "deviceId":    "<deviceId>",
  "endpointId":  "<endpointId>",
  "n":           17,
  "ackDeviceId": "<deviceId>",
  "ackN":        41,
  "relay":       { "wss": "wss://sender.example.com/ws/" }
}
```

A text payload carries no `type` field; absence means text. Other payloads set `type`: `audio`, `image`, `reaction`, `system`, `selfsync`.

- `relay.wss` is the sender's current relay. Recipients update their routing table for the sender on every message received (timestamp-guarded — see [Relay Discovery](#relay-discovery)). This is how relay information propagates passively.
- `endpointId` travels alongside `deviceId` — it is how a contact learns a sender's endpointId, recorded in the device registry only once the envelope's signature has verified. Optional; an omitted value leaves whatever is on file untouched.
- `n` is a per-(sending device, contact) send counter, local to the sender and never synced between a sender's own devices. It counts text, audio, image and system payloads; reactions carry none. Recipients use it for gap detection (see [Device Registry](#device-registry)).
- `ackDeviceId`/`ackN` point at the specific `(deviceId, n)` message this one was composed as a reply-after — see [Message Merging](#message-merging). Absent when the sender has no usable pointer yet.

Payload types:

| `type` | Fields beyond the common ones |
|---|---|
| `audio`, `image` | `data` (base64), `mimeType` |
| `reaction` | `targetId`, `emoji` (`null` = cleared, or the RECEIVED auto-ack). `id` is a derived stable id, not a uuid |
| `system` | `kind`, `text` — a real, encrypted `app:message` (not signaling), used today for the call notice (`kind: "call"`) so an offline callee still gets it via the buffer/push path and both sides keep a record of the attempt |
| `selfsync` | `peerId`, `msg` — see below |

### Self-sync mirror (`selfsync`)

A message or manual reaction composed on one device is mirrored to the identity's other devices as an `app:message` addressed to the identity itself, through the normal per-device fanout (see [Contact-facing per-device fanout](#contact-facing-per-device-fanout)). Because it is an ordinary signed `app:message`, it gets per-sibling X4DH keys where a self-session exists (legacy self key otherwise), an Ed25519 signature, and per-endpoint offline buffering — each known sibling gets its own queued copy.

```json
{
  "id":         "ss:<inner id>",
  "type":       "selfsync",
  "peerId":     "<contact the message belongs to>",
  "msg":        { "id", "type", "ts", "text" | "mimeType" | "targetId" + "emoji", "deviceId", "n", "ackDeviceId", "ackN" },
  "ts":         1234567890123,
  "deviceId":   "<deviceId>", "endpointId": "<endpointId>", "relay": { ... }
}
```

What is mirrored: text, audio/image as a stub only (`id`, `type`, `mimeType` — never the media), and manual reactions. Not mirrored: call notices, RECEIVED auto-acks (every sibling receives the original from the contact itself and acks on its own), and messages to oneself (a self chat already fans to siblings as a plain message). Nothing is sent while no sibling device is known. The outer `id` is deterministic (`ss:` + inner id) and `ts` is the inner message's, so a retry or a second delivery path of the same copy hits the receive-side duplicate guard.

**Receive rules** (`handleSelfSync`) — each closes a specific hole:
- The packet must come from our own identity, and its signature must be valid. An ordinary message with a bad signature is displayed with a warning; here it is dropped, because the payload writes into a different conversation than the sender field suggests.
- Our own echo is ignored; a `peerId` that is unknown, blocked or ourselves is ignored.
- Fields are copied from a whitelist, never spread. A message already on file is skipped (a mirrored copy must not replace the local object and lose its delivery status); reactions are the exception, since the same id carries newer state.
- Never sends anything back (no ack, no re-fan), never bumps unread, never sets the local-only `ackTrusted` flag (the copy sits at its baseline `(ts, id)` position), and the embedded `n` is stored but never fed to gap detection.

### Delivery Acknowledgement (RECEIVED)

There is no dedicated packet type — SEND and RECEIVED status ride existing mechanisms.

**SEND** is purely local optimism: the packet left the socket (an open outbound relay connection, or the main signal connection). It is never confirmed by the relay or the recipient.

**RECEIVED** reuses the reaction channel. Once a recipient's client has decrypted an incoming `app:message`, verified its Ed25519 signature, *and* persisted it, it sends a `reaction` back to the sender with `targetId` set to the original message's `id` and `emoji: null`:

```json
{ "id": "<derived-reaction-id>", "type": "reaction", "targetId": "<original msg id>", "emoji": null, "ts": ..., "deviceId": "...", "endpointId": "..." }
```

The id is derived — `SHA-256("reaction:" + myPublicId + ":" + targetMsgId)` — and is identical for an ordinary emoji reaction, a cleared one and the auto-ack, so each replaces the previous state on merge (see [Message Merging](#message-merging)). The sender treats *any* reaction targeting one of its own outbound messages as proof that a real device received and verified it; the emoji value is irrelevant to this purpose. On merge, the sender flips that message's local status from `sent` to `delivered`; this reconciliation runs after every merge, whichever path (live, backup, restore, sync) delivered the reaction.

The ack never fires for self-targeted traffic, for a message that failed verification, or in response to a reaction.

**The ack goes through the same per-device fanout as any message** — every known device of the original sender receives its own copy. This is deliberate: an ack that reached only the originating device would leave the sender's other devices showing "sent" forever, since nothing else flips their local status. The cost is that M receiving devices acking N sending devices produce M×N ack packets. A targeted alternative is tracked in `Roadmap.md`.

**READ status is not implemented.**

### Outer envelope (`app:message`)

```json
{
  "type": "app:message",
  "from": "<publicId>",
  "to":   "<publicId>" | "<publicId>::<endpointId>",
  "blob": { "v": 1, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The envelope carries no `deviceId`; the sender's device is inside the encrypted payload. A compound `to` carries the **recipient's** `endpointId` (learned earlier), requesting delivery to one registered device rather than every live session; a targeted device that isn't connected is treated as offline, not silently broadcast. `blob` and `sig` differ per destination, because each targeted device may be encrypted under a different key.

---

## Transport and Routing

### Routing Rule

Every outbound message is sent to the **contact's relay WSS** — never to the sender's own relay, never based on online presence.

Priority:
1. `contact.lastRelay` hostname matches the home relay → send via the main signal socket (`state.ws`).
2. `contact.lastRelay` known, different host → open or reuse an outbound relay connection (`sendToRelay`).
3. No `lastRelay` known → send via the main signal connection (`sendSignal`), last resort.

If the contact's relay is unreachable the fallback lands on the sender's own signal connection, which buffers server-side until the contact reconnects. `state.online` and `sig:seen` signals are UI only (the green dot) and never affect routing.

### Contact-facing per-device fanout

Sending to a contact resolves its known devices from the [device registry](#device-registry):

- **Targeted** — a device with an `endpointId` on file and `lastSeen` within `FANOUT_STALE_MS` (7 days). It gets its own copy: compound `to`, encrypted under that device's X4DH wire key if a session exists, otherwise the legacy key.
- **Broadcast** — sent in addition (bare `to`, legacy key) whenever at least one known device is unresolved (no `endpointId` yet) or stale, or no devices are known at all (a fresh contact).

Staleness demotes a device from "own targeted copy" to "covered by the broadcast"; it never excludes anything. In a self fanout (identity to itself) the sending device is left out. A device reached by both a targeted copy and the broadcast can receive the same message twice; the receiver drops a repeated `(id, ts)` within a 3-second window, so unread counts and acks aren't doubled.

`FANOUT_STALE_MS` (whether a device still gets its own send) is deliberately independent of the registry retention period (whether it is kept in the registry at all).

### Relay Connections

When sending to a contact on a different relay:

- A WebSocket connection is opened to their relay WSS and the full auth handshake runs before anything is sent.
- Connections are keyed by hostname — one connection serves all contacts on that relay.
- Messages are queued until auth completes, then flushed.
- A 30-second idle timer closes the connection after the last outbound *message*; protocol traffic does not reset it. Protocol traffic (`sendSignal`) piggybacks on an open relay connection but never opens one.
- On connection failure or connect timeout (5s), queued messages fall back to the main signal connection.
- The home relay is never targeted this way (see [Cross-relay connections](#cross-relay-connections)).

### Offline Delivery

If the recipient is not connected when a buffered packet type arrives, the relay writes it to disk:

```
relay_buf/
  <recipientPublicId>/
    <timestamp>_<uuid>.json          — identity-level bucket, reached by any live session under this identity
    _endpoints/
      <endpointId>/
        <timestamp>_<uuid>.json      — device-targeted bucket, reached only by a connection presenting this exact endpoint_id at auth
```

A packet whose `to` is bare goes into the identity-level bucket; one with a `::endpointId` suffix goes into that device's own bucket — mirroring the split live delivery makes between `deliver()` and `deliver_to_endpoint()`.

**What is buffered.** Only `app:message`, `app:migrate`, `app:burn`, `session:propose` and `session:ack`. Everything else — `app:sync`, every `sync:*`, every `call:*`, every `data:*` — is live-only: a target that is offline simply never receives it. (In particular `sync:backup_push` is never buffered: contact-path pushes answer a live handshake and may be wrapped under an ephemeral held only ~60 seconds in memory, so a buffered copy flushed later could never be unwrapped.)

`app:migrate`, `app:burn`, `session:propose` and `session:ack` are written to the buffer even when a live session was reached; see their sections for why.

On auth, the relay flushes buffered packets oldest-first and deletes each on successful delivery. A connection that presents `endpoint_id` gets **both** the identity-level bucket and its own endpoint bucket; a connection that doesn't gets only the identity-level one — a device-targeted packet is never handed to whichever session reconnects first. Unauthenticated connections never receive buffered packets.

**Limits** (environment-configurable; applied independently to the identity-level bucket and to each endpoint bucket):
- `BUF_MAX_MSGS` — maximum buffered packets (default 100, drops oldest).
- `BUF_MAX_MB` — maximum total size (default 10, drops new).
- `BUF_MAX_AGE` — expiry (default 24h, swept periodically).
- `BUF_WRITE_RATE_LIMIT`/`BUF_WRITE_RATE_BURST` — rate of *new* buffered writes per bucket, independent of sender, so a flood of one-shot senders can't evict a real recipient's genuine messages. Only the offline path is gated; live delivery is unaffected. A bucket's limiter is separate from every other bucket's, including the same identity's other devices.
- `MAX_BUF_RECIPIENTS` — distinct recipient directories (a brake on fanning out to fabricated recipient ids, since `to` only has to satisfy `valid_id()`).
- `MAX_ENDPOINTS_PER_RECIPIENT` — distinct endpoint buckets one identity can accumulate (default 20), checked only when a new bucket would be created.
- `app:migrate`/`app:burn` use overwrite-per-sender and a long TTL, always identity-level — see [Relay Migration](#relay-migration) and [Burn Notice](#burn-notice).

**Push.** A push is fired only for an `app:message` that missed live delivery and is not self-addressed (`from ≠ to`) — see [Push Notifications](#push-notifications).

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

The encrypted payload is `{ newRelay, ts }`, under the legacy pairwise key (for the self-targeted breadcrumb, the identity's own self-ECDH key). `to` is always bare.

**Signature is mandatory.** A missing or invalid signature is dropped outright — unlike a regular message, where a bad signature is flagged but displayed. This packet redirects routing and must not be trusted on decryption success alone.

**On commit**, the migrating client:
1. Stamps its own `lastRelay`/`lastRelaySeen` with the new address and the current time (recording the old one as `prevRelay`) — a deliberate migration is the new ground truth, no timestamp guard applies.
2. Notifies every non-blocked contact via `sendToRelay` (their last-known relay), falling back to `sendSignal`.
3. Sends a copy to *itself* at the relay being left behind (`sendViaRelayUrl(oldRelay, ...)`), in case another of its own devices is still parked there. No contact relationship applies to one's own identity, so this goes by explicit URL, and deliberately has **no signal fallback**: an unreachable old relay has no salvageable fallback destination.
4. If push is enabled on this device, sends `sig:push_unsubscribe` to the old relay over the same connection (see [Push Notifications](#push-notifications)).
5. Reconnects its signal socket to the new relay, locks the migrate panel, and after 10 seconds connects to the old relay for 3 seconds to collect any stragglers left there; it also puts back its own breadcrumb, which that flush consumed.

**On receipt**, handling diverges by sender:
- **From self** — adopted silently via the timestamp-guarded `updateRelay`. If adopting moves `lastRelay` forward, the receiving device reconnects and replants a fresh breadcrumb at the relay it is *itself* now leaving behind, carrying the same `newRelay`/`ts` (not a new timestamp), so a further-behind device can still find the trail.
- **From a contact** — same passive relay-learning as the `relay` field in regular messages, arriving as its own dedicated packet.

**Server-side buffering:**
- **Always durably buffered**, even when a live recipient session is reached — a stale-but-not-yet-closed session of the same identity could swallow the only copy meant for a device still catching up.
- **Overwrite-per-sender** — a newly buffered `app:migrate` replaces any older one from the same sender.
- **Long TTL** (`BUF_MAX_AGE_MIGRATE`, default 7 days).

Gaps: there is no boot-time drain of the previous relay; the only drain is the one the committing device runs after commit.

---

## Burn Notice

A deliberate, irreversible local action — "stop trusting this identity" — announced via its own packet type. Structurally identical to `app:migrate` (mandatory signature, always-durable buffering, overwrite-per-sender, long TTL) but on a separate wire type and buffer bucket, so a routing update can never clobber a pending burn notice or vice versa.

```json
{
  "type": "app:burn",
  "from": "<publicId>",
  "to":   "<publicId>",
  "blob": { "v": 1, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The encrypted payload is `{ ts }` — deliberately thin: burn is a one-shot action, not a routing fact to timestamp-guard. `to` is always bare. Encryption is the legacy pairwise key, as for `app:migrate`.

**Signature is mandatory**, same rule as `app:migrate`: this packet drives an irreversible action.

**Self vs. contact — the packet means something different depending on sender:**

- **From self** — another of the user's own devices burned (or this is a second live session catching the same burn). The receiving device wipes itself too (see [Self-Destruct](#self-destruct)), silently, no notify-back.
- **From a contact** — they burned; the receiving side converts the contact to `blocked`, records `blockReason: "burned"` (local-only UI metadata — never on the wire, never a security boundary), clears the conversation and drops any stored peer backup and peer token for that contact. Burn says "treat this identity as gone for good", a stronger and less reversible intent than a manual block, so nothing usable for a future restore is left behind. An already-blocked contact is a no-op.

**On commit**, the burning client:
1. Notifies every non-blocked contact via `sendToRelay`, falling back to `sendSignal`.
2. Sends a copy to *itself* via plain `sendSignal` — it only needs to reach whatever relay the "me" contact points to. A self-device parked at a different or stale relay won't see it until it next syncs there.
3. After a brief pause to let the outbound sends leave the socket, wipes itself.

**Server-side buffering** mirrors `app:migrate` on its own bucket: always durably buffered, overwrite-per-sender only within its own suffix (`_burn.json`), long TTL (`BUF_MAX_AGE_BURN`, default 7 days).

### Self-Destruct

Not cryptographic revocation — it can't be. Identity is deterministic from `(username, passphrase)`; anyone who still knows the credentials (including the user) can log back in and re-derive the same keys at any time. Burn is a **local wipe plus a social signal**: the notices sent to contacts are what change anything outside the wiping device.

On receiving a self-targeted burn, or triggering one locally, the client:
1. Clears the identity-scoped storage keys: contact store, peer backups, peer tokens, device registry, device seed (so this device can't quietly re-announce its old `deviceId`), and X4DH sessions.
2. Closes the signal socket.
3. Reloads to the login screen.

No trace is kept, on this device or elsewhere, that a burn happened. A device that re-derives the same identity later has no way to know it was ever burned.

---

## Device Awareness

### Device Registry

Each client maintains a local device registry (`meshchat_known_devices_v1_<publicId>` in localStorage) — a map of identity → known devices:

```json
{
  "<identityId>": {
    "<deviceId>": { "lastSeen": <timestamp>, "lastN": <int>, "missing": [<int>, ...], "endpointId": "<endpointId or null>" }
  }
}
```

Local-only, never in backup blobs or `serialiseContacts()`. Populated passively from three sources:

1. **`app:message` receipt** — only after the signature verifies: `deviceId`, `n` and `endpointId` from the encrypted payload. An omitted `endpointId` leaves what's on file untouched.
2. **Self-sync traffic** — the discovery hello, the acks and the full pushes teach each of the user's own devices about the others. `deviceId`, `endpointId` and `fingerprint` ride inside the encrypted blob, never as outer fields: the relay is untrusted, and an unsigned outer field is silently rewritable in transit. `endpointId` is what lets a push target a specific sibling.
3. **`restore_req`** — the decrypted blob's `deviceId` is recorded (no endpoint).

Every registry write is also a chance to satisfy the precondition for starting an X4DH session with that device (see `X4DH.md` §13.3).

The registry is shown in a per-contact device popover, with a status dot per device (no session / `RK0` fresh / `RK0` stuck / `RK1`). Contacts with no recorded devices show an "unknown" placeholder. There is no dedicated discovery handshake.

**Retention.** Entries older than 30 days (`DEVICE_REGISTRY_CUTOFF_MS`) are pruned, and each identity's list is capped at 20 (`MAX_DEVICES_PER_IDENTITY`), oldest-by-`lastSeen` dropped first. Pruning runs at login and on a periodic sweep (`DEVICE_PRUNE_INTERVAL_MS`, 10 minutes). This is a different, longer number than `FANOUT_STALE_MS` (see [Contact-facing per-device fanout](#contact-facing-per-device-fanout)).

**Gap detection.** When a message arrives with `n` ahead of `lastN + 1`, the skipped values are added to that device's `missing` list (capped at 50); a late arrival removes its `n`. After every merge — live, backup, restore, manual sync — `missing` is reconciled against the messages actually stored, matching on `(deviceId, n)`. This is a display hint only: a dismissible banner ("message #N not received yet"). There is no wire-level backfill request, and the sender may no longer hold the message (see [Local retention](#local-retention)); dismissing stops the warning, it does not recover anything.

**Causal pointer.** `getAckPointer(contactId)` picks the `(deviceId, n)` stamped on an outgoing message as `ackDeviceId`/`ackN`: the most recent `(ts, id)` non-reaction message in the local conversation that carries a `(deviceId, n)` pair, whichever side sent it. It reads the conversation, not the registry, because registry `lastSeen` is bumped by any inbound packet — including a bare ack from whichever of a contact's devices won a race — and says nothing about conversational order. Outgoing messages therefore store their own `deviceId` and `n` locally.

---

## Voice Calling

Audio calls are negotiated peer-to-peer over WebRTC. The relay carries only small, signed signaling packets to set the call up — it never sees or forwards media.

**No TURN server.** ICE uses public STUN only — three servers for resilience (`stun.l.google.com:19302`, `stun1.l.google.com:19302`, `global.stun.twilio.com:3478`). Having no TURN is a permanent architectural decision: some NAT pairings will never connect, and the UI says so rather than retrying forever. A direct connection also means each side learns the other's network address through ICE.

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

Four types: `call:invite`, `call:claim`, `call:cancel`, `call:end`. All share this shape and carry no `blob`. `callId` ties every packet to one call attempt and is generated once by the caller. These packets are not encrypted — `from`/`to` are visible on the wire for every packet type and there is nothing else here worth hiding — but `deviceId` is, by the same token, plaintext (signed).

**Signature is mandatory** — these packets drive state transitions (ringing, negotiating, hangup), so an unsigned or invalid one is dropped outright. The signed payload is `{ type, from, to, callId, deviceId, ts, blob }` (`blob: null` for this group).

Routing follows the normal contact-relay priority (`sendToRelay` → `sendSignal` fallback). All `call:*` types are live-only: an offline callee never rings.

**Call notice.** Entering the `calling` phase also sends a regular encrypted `app:message` with `type: "system"`/`kind: "call"` (see [Message Payload](#message-payload)) — a visible, offline-deliverable record of the attempt on both sides, independent of whether the call connects. Its text uses the caller's plain username (`state.user`). It is wired only for voice calls.

### Signaling packets — offer / answer / ice

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

Three types: `call:offer`, `call:answer`, `call:ice`. These carry a `blob` — the SDP (`{ sdp }`) or one ICE candidate (`candidate.toJSON()`) — encrypted with the legacy pairwise key (see [Encryption](#encryption)). The signed payload includes the ciphertext, so the relay cannot swap the blob for another without invalidating the signature.

Only accepted while `contact.call.callId` matches and the local role is the expected one (`call:offer` only while `role === "callee"`, `call:answer` only while `role === "caller"`). `call:ice` candidates that arrive before the remote description is set are queued and flushed once it is applied, since trickle ICE races the SDP exchange.

On `call:offer` the callee builds the `RTCPeerConnection`, sets the remote description, flushes queued ICE, acquires local media, creates and sets the answer, and returns it as `call:answer`. Local media uses `getUserMedia({ audio: { echoCancellation, noiseSuppression, autoGainControl } })`, falling back to a silent synthetic track where no microphone exists (testing only).

### Session state machine

Voice calls and [data-channel tests](#data-channel-test) share one phase/role table (`transition()` in `statemachine.js`; `kind` selects `contact.call` or `contact.data`). Per-contact state is `{ callId | sessionId, phase, role }`:

```
idle → calling ⇄ negotiating → connected → idle
  ↑        ↓                        ↓
  └── ringing                    failed → idle
```

| Phase | Meaning |
|---|---|
| `idle` | No active session with this contact |
| `calling` | We invited them, awaiting claim (role: `caller`) |
| `ringing` | They invited us, awaiting local answer (role: `callee`) |
| `negotiating` | Claimed on one side; WebRTC offer/answer/ICE exchange in progress |
| `connected` | Media (or the data channel) flowing |
| `failed` | ICE/RTC failure — requires explicit reset back to `idle` |

`transition()` is pure logic: dedup and staleness decisions (is this claim for the session in flight? is it from one of our own devices?) are resolved by the caller before it is invoked. Side effects on phase entry live in `onStateEnter` (calls) and `onDataStateEnter` (data), which share no code because their consequences differ (media tracks vs. a data channel).

### Multi-device dedup

An invite can reach several of the callee's devices at once. When one device answers it sends `claim` twice:

1. To the caller — advances their state `calling → negotiating`.
2. **Self-targeted**, to the callee's own identity — every other device of theirs sees `from === state.publicId`, verifies against its *own* signing key rather than a contact's, and moves any device still `ringing` on that id to `idle` (`claimed_elsewhere`), silently.

The device that claimed ignores its own echo by comparing `deviceId`.

### Role and negotiation

`role` (`caller` | `callee`) is set on entering `calling`/`ringing` and cleared on return to `idle`. On entering `negotiating`, the caller makes the offer; the callee waits for it and answers. This asymmetry lives in the phase-entry handlers, not in the wire protocol.

Gaps: ICE connection-state and candidate-type logging for diagnosing NAT failures, an ICE-restart retry path, and UI messaging that distinguishes "still trying" from "this NAT pairing will not connect".

---

## Data-Channel Test

A connection test, nothing more: it answers "can these two devices reach each other directly?" (there is no TURN, so sometimes they cannot). The caller opens a WebRTC data channel, sends one ping, the callee echoes it, and the caller reports the round-trip time and ends the session. Nothing from the channel is stored or forwarded; the result is a transient toast on each side and is never written into `contact.messages` (so it is never backed up or synced).

Seven packet types, mirroring `call:*` exactly under their own prefix: `data:invite`/`data:claim`/`data:cancel`/`data:end` (signed only, no `blob`) and `data:offer`/`data:answer`/`data:ice` (signed, with an encrypted `blob` — SDP or one ICE candidate — inside the signature, legacy pairwise key). `sessionId` plays `callId`'s role. Signature is mandatory on every type; all are live-only. Same shared state machine, same multi-device claim dedup, same STUN-only ICE, same no-TURN trade-off.

```json
{ "type": "data:invite", "from": "<publicId>", "to": "<publicId>", "sessionId": "<uuid>", "ts": 1234567890123, "deviceId": "<deviceId>", "sig": [...] }
```

**Acceptance is explicit.** An incoming `data:invite` puts the contact in `ringing` and raises an accept/decline banner; nothing auto-claims, because answering lets the caller learn the answerer's network address through ICE. A second invite while a session is already active is ignored. A `data:offer` is only answered while `negotiating` with role `callee`.

**The channel.** The caller creates one channel, labelled `data`; the callee accepts only a channel with that label and closes anything else. When the caller's end opens it sends `{"t":"ping","n":"<nonce>"}`; the callee replies `{"t":"pong","n":"<nonce>"}`. The receive hook is strict because the peer has only been trusted enough to talk to: strings only, at most 128 characters, one known JSON shape, a nonce that must match the one sent, role-gated (only a callee answers a ping, only a caller accepts a pong), and at most 3 pongs echoed per session. ICE candidates that arrive before the peer connection exists are held (up to 50) and adopted when it is built.

**Timeouts.** Ring timeout 30s (invite → accept); negotiate timeout 20s (accept → result, which keeps running through `connected` until the pong is back). A timeout reports the failure and tells the peer (`data:cancel` while `calling`, `data:end` otherwise). A session whose test already succeeded closes quietly if the peer's `data:end` was lost. A peer that cancels or ends a session mid-test is reported to the user, unless this side's half had already succeeded.

---

## Push Notifications

Opt-in per device, off by default. A push means only "something arrived, open the app and check" — no message content, sender identity or other metadata is ever included. This lets the relay skip the standard Web Push payload-encryption layer (`aes128gcm`) entirely: every push is a bodyless POST authenticated only by a signed VAPID JWT, carrying nothing for anyone — including the push service operator — to read.

### Browser support

Standard Web Push (`PushManager` + service worker + VAPID). Chrome/Edge/Opera and Firefox (desktop and Android) work with no caveats; Safari desktop works since Safari 16. **Safari on iOS/iPadOS only delivers push to a PWA added to the Home Screen** (iOS 16.4+) — a page open in a Safari tab cannot receive push regardless of subscription state; this is an Apple restriction. HTTPS (or `localhost`) is required; no service worker registers over plain `http://`. The client's `pushSupported()` gates the opt-in checkbox off where `serviceWorker`/`PushManager` are unavailable.

### VAPID keypair

Each relay generates its own EC P-256 keypair on first boot and persists it (`VAPID_KEY_FILE`, default next to `BUF_DIR`). The public key is exposed as `vapidPublicKey` on `sig:relay_info` — base64url of the uncompressed EC point (`0x04 || X || Y`, 65 bytes), the format `PushManager.subscribe()`'s `applicationServerKey` expects.

**The keypair is per-relay.** A subscription made against one relay's key is unusable at another: the push service binds a subscription to the public key presented at `subscribe()` time. The client's `ensurePushSubscription()` runs on every `sig:relay_info` and compares the browser's current subscription key with the connected relay's; a mismatch (only possible after a [migration](#relay-migration)) triggers an unsubscribe-and-resubscribe. A subscription therefore follows the user to a new relay without a dedicated migration mode. The committing device additionally sends a best-effort `sig:push_unsubscribe` to the relay being left. One accepted gap: a message that lands on the old relay from a contact who hasn't learned about the migration yet will not trigger a push (the message itself is still recovered).

### Subscribing

```json
{
  "type":         "sig:push_subscribe",
  "from":         "<publicId>",
  "endpointId":   "<endpointId>",
  "subscription": { "endpoint": "https://...", "keys": { "p256dh": "...", "auth": "..." } }
}
```

Stored at `PUSH_SUBS_DIR/<publicId>/<endpointId>.json` as `{ endpoint, p256dh, auth }` — one file per (identity, device) pair. It is keyed by `endpointId`, not `deviceId`: `endpointId` is what the relay already sees at auth, and storing push state under `deviceId` would let the relay join its view to a contact's. On subscribe, any other file for the same identity holding the same browser `endpoint` URL is a stale duplicate and is removed. `sig:push_unsubscribe { from, endpointId }` deletes the file.

Neither type requires a signature — they redirect no routing and drive no irreversible action — but both require an authenticated socket with `from` matching it. The relay rejects a subscription whose `endpoint` isn't `https://` or that lacks `keys.p256dh`/`keys.auth`.

### Firing a push

Triggered from the offline-buffering path for an `app:message` that missed live delivery and is not self-addressed — a push for something the user is about to receive live, or for a mirrored copy of their own message, would be noise. `app:migrate`, `app:burn`, `session:*` and everything live-only never push. The call notice is an ordinary `app:message`, so it triggers a push like any message.

Each subscription on file gets its own push: a bodyless HTTPS POST to `endpoint` with `TTL: PUSH_TTL_SECONDS` and `Authorization: vapid t=<jwt>, k=<vapidPublicKey>`. The JWT (`ES256`, claims `{ aud, exp, sub }`, `exp` 12h out) is signed fresh per push; `aud` is the scheme and host of that specific endpoint. Pushes are best-effort: a transient failure (network error, 5xx) is logged and not retried. A `404`/`410` means the push service has permanently invalidated the subscription, and its file is deleted.

### Client-side opt-in and subscribe flow

A checkbox in the edit-contact panel (self entry only) controls a **per-device** local preference (`meshchat_push_pref_v1_<publicId>`) — a statement about this browser, not the identity, and not part of `serialiseContacts()`/backups. Toggling on calls `ensurePushSubscription()` immediately; toggling off unsubscribes the browser and sends `sig:push_unsubscribe` to the current relay. `ensurePushSubscription()` short-circuits via `pushSyncedRelayWss` when nothing has changed (an ordinary reconnect to the same relay) and does real work only on a new relay or when no subscription exists yet.

The service worker (`sw.js`) handles `push` (a generic "MeshChat — tap to check" notification; `event.data` is always null) and `notificationclick` (focus an existing tab, else open a new one).

### Gaps

- Anything that distinguishes a call notice from a text in the push itself (the payload is deliberately generic).
- A push for `call:invite`/`data:invite`: both are live-only and never buffered, so a push for a missed call would need its own trigger at delivery-failure time.
- iOS messaging: an iOS Safari tab user just sees the checkbox disabled with the generic "not supported in this browser" label.

---

## Signal Server Protocol

### Client → Server

| Type | Fields | Auth | Description |
|---|---|---|---|
| `sig:auth_init`     | `x25519_pub`, `ed25519_pub`, `no_receive?`, `endpoint_id?` | no | Begin challenge-response, presenting both public keys. `no_receive` skips registration and buffer flush (probes). `endpoint_id` additionally registers the socket for device-targeted delivery |
| `sig:auth_proof`    | `sig` | no | Ed25519 signature over the server's nonce |
| `sig:announce`      | `ids[]` (max 10) | yes | Presence query — see [Online Presence](#online-presence) |
| `app:message`       | `from`, `to`, `blob`, `sig` | yes | Encrypted message. `to` may be compound |
| `app:migrate`       | `from`, `to`, `blob`, `sig` | yes | Relay-migration notice; `to` bare; always durably buffered |
| `app:burn`          | `from`, `to`, `blob`, `sig` | yes | Burn notice; `to` bare; always durably buffered, own bucket |
| `session:propose`   | `from`, `to` (compound, required), `sessionEpoch`, `ekPub`, `deviceId`, `ts`, `sig` | yes | X4DH bootstrap/reset — mandatory signature, always durably buffered, overwrite-per-sender |
| `session:ack`       | `from`, `to` (compound, required), `sessionEpoch`, `ekPub`, `deviceId`, `ts`, `sig` | yes | X4DH live-upgrade reply — mandatory signature, always durably buffered, no overwrite |
| `app:sync`          | `from`, `to`, `blob`, `sig` | yes | Manual SYNC request or reply — see [Manual Sync](#manual-sync-appsync) |
| `sync:backup_offer` | `from` (compound), `to`, `size`, `ts`, `sig` | yes | Offer a backup blob to a contact |
| `sync:backup_accept`| contact path: `from` (compound), `to`, `ts`, `sig`, `ek?` — self-sync: `from` (bare), `to`, `blob` | yes | Accept a backup offer (contact path), or the self-sync device ack. `blob` present ⇒ self-sync variant |
| `sync:backup_push`  | contact path: `from` (compound), `to`, `blob`, `ts`, `sig`, `ek?` — self-sync: `from` (bare), `to`, `blob` | yes | Push a backup blob. Self-sync `blob` encrypts a full push or a discovery hello; `to` may be compound |
| `sync:restore_req`  | `from`, `to`, `blob`, `token?`, `ts`, `sig` | yes | Ask a contact to send its stored backup. Signature mandatory (dropped on missing/invalid) |
| `sync:restore_ack`  | `from` (compound), `to`, `ts`, `sig`, `ek?` | yes | Acknowledge a restore request, or bootstrap ping from a fresh device. Signed, soft-verified |
| `sync:restore_push` | `from` (compound), `to`, `blob`, `ts`, `sig`, `token?`, `ek?` | yes | Push the stored backup to the requester. Signed, soft-verified |
| `sync:token_req`    | `from`, `to` | yes | Request a restore token |
| `sync:token_resp`   | `from`, `to`, `ts`, `sig`, `token` | yes | Deliver a restore token (signed) |
| `call:invite` / `call:claim` / `call:cancel` / `call:end` | `from`, `to`, `callId`, `ts`, `deviceId`, `sig` | yes | Call signaling — mandatory signature |
| `call:offer` / `call:answer` / `call:ice` | as above plus `blob` | yes | WebRTC SDP / ICE, `blob` encrypted and inside the signature |
| `data:invite` / `data:claim` / `data:cancel` / `data:end` | `from`, `to`, `sessionId`, `ts`, `deviceId`, `sig` | yes | Data-channel test signaling — mandatory signature |
| `data:offer` / `data:answer` / `data:ice` | as above plus `blob` | yes | WebRTC SDP / ICE for the data channel |
| `sig:push_subscribe`   | `from`, `endpointId`, `subscription: { endpoint, keys: { p256dh, auth } }` | yes | Register a per-device push subscription |
| `sig:push_unsubscribe` | `from`, `endpointId` | yes | Remove it |
| `sig:relay_req`     | — | yes | Request the relay's own WSS URL |
| `sig:ping`          | — | yes | Keepalive |

### Server → Client

| Type | Fields | Description |
|---|---|---|
| `sig:auth_challenge` | `nonce` | Random 32 bytes, in the clear, for the client to sign |
| `sig:auth_ok`        | `public_id` | Auth succeeded, routing active |
| `sig:auth_fail`      | `reason` | Auth failed, or an unauthenticated packet was dropped |
| `sig:relay_info`     | `wss`, `version`, `vapidPublicKey` | The relay's own WSS URL, protocol version (informational), and VAPID public key (base64url, uncompressed EC point) |
| `sig:seen`           | `id` | The named id announced a presence query that included us |
| `sig:pong`           | — | Keepalive response |
| `error`              | `reason` | Protocol error (`rate_limited`, `not_authenticated`) |

### Notes

- **Authentication.** Every packet type except `sig:auth_init`/`sig:auth_proof` requires an authenticated socket; an unauthenticated one gets `sig:auth_fail { not_authenticated }`. Every type with a `from` field also requires `from` to be an identity authenticated on this socket (for the compound-`from` types, the base id). `sig:relay_req` and `sig:ping` have no `from`; `sig:announce` has none either and answers on behalf of the socket's own authenticated identity.
- **Which types are buffered.** `app:message`, `app:migrate`, `app:burn`, `session:propose`, `session:ack` — see [Offline Delivery](#offline-delivery). Every other type is delivered live to whoever is connected and otherwise lost; a compound `to` aimed at an offline device reaches nobody.
- **Compound `to`** is honored on the shared delivery branch for `app:sync`, every `sync:*`, `call:*` and `data:*`, as well as for `app:message` and `session:*`. Of the shared-branch types, only some `sync:*` self-sync packets send one today.
- **Compound `from`** is accepted only on `sync:backup_offer`, `sync:backup_accept`, `sync:backup_push`, `sync:restore_ack` and `sync:restore_push` (see [Compound Addressing](#compound-addressing)). A receiving client trusts and displays the endpoint half only once the accompanying signature has verified against a contact already on file.
- **Signature rules differ by type.** Mandatory (drop on missing/invalid): `app:migrate`, `app:burn`, `session:*`, `app:sync`, `sync:restore_req`, `sync:token_resp` (checked client-side), `call:*`, `data:*`. Soft (processed unless *actively* wrong — a signature present, the sender's key on file, verification failing): `sync:backup_offer`/`accept`/`push` on the contact path, `sync:restore_ack`, `sync:restore_push`. None: the self-sync backup packets (tamper-evident through AES-GCM only). `app:message` is flagged, not dropped.
- **Rate and size limits.** Each socket has its own token-bucket limiter (`RATE_LIMIT_RATE`/`RATE_LIMIT_BURST`) and shares a wider one with every other socket from the same source IP (`IP_RATE_LIMIT_RATE`/`IP_RATE_LIMIT_BURST`); either returns `error { rate_limited }`. Connections are capped in total (`MAX_CONNECTIONS`) and per IP (`MAX_CONNECTIONS_PER_IP`). A frame over `WS_MAX_SIZE` is dropped. `X-Real-IP`/`X-Forwarded-For` are honoured only when the TCP peer is inside `TRUSTED_PROXIES`.
- Unknown packet types are dropped.
- Sync and backup types are routed by the server without inspecting their contents.

---

## Peer Backup Protocol

The `sync:backup_*` types serve two jobs with different security stances: **contacts holding an encrypted copy of your contact list** (the contact path), and **an identity's own devices exchanging contact stores** (self-sync). The restore handshake, token and ephemeral wrap that go with them follow below. Messages you send are mirrored between your own devices by a different mechanism — see [Self-sync mirror](#self-sync-mirror-selfsync).

### Contact path

1. After every second received message, and on a 10-minute timer, the sender offers a backup to each reachable contact: `backup_offer { size, ts, sig }`.
2. The recipient replies `backup_accept { ts, sig, ek? }`.
3. The sender pushes `backup_push { blob, ts, sig, ek? }`.
4. The recipient stores the blob locally (after stripping the transport wrap) and serves it back on `restore_push`.

**The blob carries contacts only.** For each contact: name, keys, `blocked`, state timestamp and relay info — `messages` is empty. It is encrypted under the sender's backup key, so the holder cannot read it. A peer holding your backup is a third party with an indefinitely stored copy, and the contact list is what a restore needs; message history never has to ride along.

**`from` on all three carries the sender's compound `"id::endpointId"` address** — one of the five compound-`from` types (see [Compound Addressing](#compound-addressing)). Unlike self-sync (one shared key) or `app:message` (a working pairwise key by the time a message exists), this handshake may reach a contact who hasn't added the sender back, so there may be no shared key at all; the address is the one channel guaranteed to reach a stranger.

**All three are signed** with the identity's Ed25519 key, but verification is only possible once the recipient already has the sender as a contact (it needs their `signPublicKey`). An unsigned packet, or one from a sender not yet on file, is processed — bootstrap must keep working. Only an **actively wrong** signature (present, key on file, verification fails — i.e. tampered with by the untrusted relay) is dropped. This is softer than `app:migrate`/`app:burn`, which drop on any missing or invalid signature: those drive irreversible actions and have no fresh-contact case. The recipient only trusts or displays the endpoint suffix once a signature has verified.

**Replies are one-to-one.** An offer is addressed to a bare identity, so it fans out to every live session under it, and each reply is wrapped for exactly one specific ephemeral. A reply therefore goes only to the device that sent the opening packet: `backup_accept`, `backup_push`, and the replies in the restore handshake below are addressed compound (`id::endpointId`) to the endpoint in the *verified* `from` of the packet they answer (`replyAddress`). When the sender's endpoint is unknown, or the packet couldn't be verified, the reply falls back to the bare identity and bootstrap works as before.

**A pending offer outlives its first accept.** An identity with several devices legitimately answers one offer several times, each accept carrying its own `ek`. The sender keeps the offer for `BACKUP_OFFER_TTL` (60s) and pushes a separately-wrapped copy per accept; it is replaced by the next offer. The wrap (see [Ephemeral Wrap](#ephemeral-wrap)) is attached only when the opening packet verified.

**Token.** The first time a contact stores a backup from a sender it holds no token for, it sends `sync:token_req` (see [Restore Token](#restore-token)).

### Self-sync (same identity, multiple devices)

There is no offer/accept; a push goes directly. Self-sync never rides the deterministic backup key alone, because a full push carries the contact store with recent messages and a recorded copy plus a later passphrase compromise would expose all of it.

**Full push.** For each known sibling that is targetable (`endpointId` on file, seen within `FANOUT_STALE_MS`), has an X4DH self-session, and whose fingerprint doesn't already match ours, the device sends a `sync:backup_push` with a compound `to` and a `blob` encrypted under that pair's X4DH wire key:

```
blob = AES-256-GCM( wireKey(self-session with that sibling),
                    { deviceId, endpointId, fingerprint, contacts: serialiseContacts() } )
```

The `contacts` here are the full store (messages included), unlike the contact path. `deviceId`, `endpointId` and `fingerprint` ride inside the blob, never as outer fields.

**Discovery hello.** When a sibling is unknown, unresolved, stale, or has no session yet, the device instead (at most once per 60 seconds) broadcasts to its own identity a content-free hello under the backup key: `{ deviceId, endpointId, hello: true }` — no contacts, no fingerprint. Its only job is to let siblings learn the device, which can start an X4DH self-session that later pushes ride. A brand-new sibling therefore receives contacts from the first push after its session exists, not instantly; a genuinely wiped device restores immediately through the restore handshake below.

**Receiving.** The blob carries no key hint, so the receiver tries every X4DH self-session wire key (newest session first) and then the backup key last; when a session key decrypts it, the payload's `deviceId` must match the session's device. Then:
- a **hello** teaches the sibling (`recordKnownDevice`, which can trigger X4DH bootstrap) and is answered with a small ack;
- a **full push** from our own echo is ignored; otherwise it is merged (contact metadata, then `mergeMessages`, then delivery-status and missing-message reconciliation), saved, and — if it changed our own relay — followed by a signal reconnect. The sender's fingerprint is recorded and we ack with our own post-merge fingerprint;
- a bare contacts map (the older slim single-contact push shape) and a full push under the static backup key from an older sibling are still accepted, the latter logged as a legacy push that keeps the deterministic-key exposure.

**Ack.** `sync:backup_accept` with a `blob` encrypting `{ deviceId, endpointId, fingerprint? }` — under the session key (with fingerprint) when a session exists, otherwise content-free under the backup key — compound-addressed to the sender's endpoint when known. The presence of `blob` is what distinguishes it from a contact-offer accept, which never sets one.

**Fingerprint.** `fingerprint = base64url( SHA-256( JSON(serialiseContacts()) )[0:12] )`. Each device keeps an in-memory table `{ deviceId → fingerprint }` of what it has heard this session; if every targetable sibling already has the current fingerprint the push is skipped. The table resets on reload — worst case is one extra push on cold start.

Self-sync backup packets carry no `sig`: AES-GCM makes tampering evident but gives no sender authentication, which is sufficient for self-to-self traffic on an authenticated socket but weaker than `app:message`'s signature.

### Short-window duplicate suppression

All five handshake packet types (`backup_offer`/`accept`/`push`, `restore_ack`/`push`) pass a 3-second duplicate window before other processing, purely to skip redundant work when a sender's traffic legitimately arrives twice (a near-simultaneous retry, or several of the sender's devices answering one broadcast). Once a packet's signature verifies, the key is `type:senderId:endpointId` (plus a short fingerprint of the push's `ek` on the two push types), so a second, genuinely distinct sibling's packet isn't mistaken for a duplicate. Unverified traffic keys on the bare sender id; the self-sync paths key on the decrypted `deviceId`. The window is separate from, and much shorter than, the restore cooldowns below.

---

### Restore Token

When a contact stores a backup, a one-time token exchange (`sync:token_req` → `sync:token_resp`) follows, whose sole purpose is to authenticate the restore handshake for an owner who has lost its contacts: a wiped device has no `signPublicKey` on file for anyone, so it cannot verify a `restore_push` the ordinary way.

The token is issued by the **owner** of the backup (the party whose backup is being stored), sealed under the owner's own backup key, and held by the storing contact:

```
token = AES-256-GCM( key = issuer's own backup key, data = { v: 2, shareableKey: <the storing contact's shareableKey, as the issuer recorded it> } )
```

Because it is sealed under a key derived from the issuer's username and passphrase — unchanged by a wipe — the issuer, and only the issuer, can open it again after losing all local storage. The holder keeps the token it was given for each owner (`state.peerTokens`) but cannot read it.

`sync:token_resp` is signed and is accepted only while a `sync:token_req` of the recipient's own is outstanding (60 seconds) and the sender is a known, non-blocked contact; a forged or replayed response is dropped. A planted token would otherwise be kept as the first one ever received per sender and permanently block the real one.

**Binding.** A token is valid only if the identity it decrypts to (`tokenBoundId`, derived from the embedded `shareableKey` the way `addContact` derives a publicId) matches the packet's actual sender. A token is a bearer object once decrypted — nothing on the wire ties it to a presenter — so this check stops a token issued about one contact from being credited to another. A mismatched or malformed token is treated as no token, not as a hard failure.

### Restore handshake

Roles: the **owner** is the identity whose contact store needs restoring; a **holder** is a contact storing an encrypted copy of the owner's backup.

1. **`sync:restore_req`** — a client sends it to each contact it sees online (and every 10 minutes), telling it "I may be holding your backup". The `blob` (legacy pairwise key) carries `{ publicId_A, publicId_B, wss, signPublicKey, deviceId }`; the holder attaches the `token` it holds for that contact, if any. Signature is mandatory.
2. **`sync:restore_ack`** — the owner replies, asking for the data. The recipient of a `restore_req` must already have the sender as a contact (decrypting requires their key), checks the signature, the two ids and the cooldown, and checks the token: a token only counts if it opens under the owner's backup key *and* is bound to the sender. With a valid token the relay and signing key in the blob are adopted. A **fresh** client (at most itself as a contact) with no valid token ignores the request; a known contact needs none, since the request is already signature-verified and decrypted. The ack's `to` is compound at the requester's endpoint when already known for that `deviceId`.
3. **`sync:restore_push`** — whoever receives a `restore_ack` sends back its stored backup for the acker, if it has one: wrapped when the ack's signature verified and it carried an `ek`, with the token attached when the signature verified.
4. **The owner** decrypts (unwrap, then backup key) and merges into local state.

For a healthy pair the pushed backup merges to a no-op.

**A wiped device cannot take part in step 1** — with no contacts it cannot decrypt a `restore_req`. It instead waits for a `sig:seen` and answers with a `restore_ack` addressed to any online id, contact or not (`sendRestoreAckPing`; bare `to`, an `ek` attached, 60s cooldown per id). Whoever receives that ack, if its signature verifies against a contact already on file, attaches the token it holds for that contact to the resulting `restore_push`. The wiped device issued that token before the wipe and can still open it (same deterministic key), recovering the sender's `signPublicKey`, checking the bound-id match, and verifying the push's own signature before trusting the restored data. Without a valid token the push is accepted but unverified. A device acking *itself* (a sibling restoring from another of its own devices) is answered with the sibling's current contact store, wrapped the same way.

Restore flooding is limited by three independent 5-minute cooldowns, deliberately not one shared map:

- **Outbound** — `restore_req` toward an identity. Identity-level: it is addressed at the identity broadly.
- **Inbound serve** — whether to ack an incoming `restore_req`, keyed on `(senderId, deviceId)`. Safe because the request is mandatory-signed and already decrypted.
- **Inbound accept** — whether to process an incoming `restore_push`, keyed on `(senderId, endpointId)` once the signature verifies, else identity-level. `restore_push` carries no `deviceId` — there is no channel guaranteed to encrypt it in — only the endpoint via the compound `from`.

`deviceId` and `endpointId` are kept in separate maps to preserve their unlinkable namespaces.

**Trust shapes differ across these types.** `restore_req` can only ever be processed by a recipient who already has the sender as a contact, so verification is always possible and it is mandatory. `restore_ack` and `restore_push` can legitimately reach, or be answered by, someone with no shared key material (the bootstrap ping), so they are signed unconditionally but soft-verified, like the backup handshake.

### Ephemeral Wrap

`sync:restore_push` and contact-path `sync:backup_push` can carry an additional optional layer on top of the encryption above: a one-shot X25519 ephemeral-to-ephemeral wrap around the existing blob, generated per exchange and never written to disk. (Self-sync backup pushes use X4DH session keys instead, not this wrap; a self `restore_push` does use it.)

```
ek        = fresh X25519 ephemeral public key, attached to the ack/accept that precedes the push
wrapKey   = HKDF( salt = zero32, ikm = X25519(myEphemeralPriv, theirEk), info = "meshchat-v1:ephemeral-wrap", length = 32 )
outerBlob = AES-256-GCM( key = wrapKey, data = <the existing inner blob, untouched> )
```

The inner blob is unchanged — the recipient still decrypts it with its own passphrase-derived key after unwrapping, so restore-from-nothing and ordinary backup storage are unaffected. What the wrap adds: a passive observer who records the wire traffic and later obtains the passphrase cannot decrypt it, because the ephemeral private keys are held only in memory for up to 60 seconds.

**Sequencing.** Whoever sends a `restore_ack` or a `backup_accept` attaches a fresh ephemeral as `ek` and holds the private key in memory, keyed by whom the packet was addressed to. Whoever receives that packet and is about to push only wraps when the incoming signature verified, generating its own fresh ephemeral and attaching its public half to the push as `ek`. An `ek` on an unverifiable ack/accept is not trusted — a relay in between could otherwise supply its own ephemeral and read the reply. `ek` is inside the signed payload whenever present, and simply absent from it otherwise.

**Several ephemerals may be live for one peer at once.** An ack or accept addressed to a bare identity broadcasts to every live session under it, and a device can attach more than one ephemeral toward the same peer inside the 60-second window. The pending store therefore holds a *list* of candidates per slot (keyed `id::endpointId` when the responding device is known, else by identity); the receiver trial-decrypts a push against each candidate, newest first, device-specific slot before the bare-identity slot, and then every other slot held for that identity as a safety net. A wrong candidate fails cleanly on the AES-GCM tag. **A candidate is never removed for having matched** — the same private half can legitimately unwrap several different replies — only by its own timeout. A push wrapped for a sibling's ephemeral simply fails to match and is dropped; that is expected on a multi-device identity, not a fault.

**Failure is closed.** If a push claims a wrap and no pending ephemeral is on file (expired, or the ack it answers was never sent by that client), or no candidate unwraps it, it is dropped rather than fed to the inner decrypt. A relay that strips `ek` without also invalidating the signature, which covers it, therefore breaks that attempt outright instead of causing a silent downgrade. The graceful fallback applies only where no wrap was attempted (an unverified sender, or a client that predates the mechanism). A sender whose own wrap *fails to build* falls back to sending unwrapped — the recipient still needs the data.

**Deliberately not an X4DH session.** A device answering a restore ack has typically just generated a brand-new `deviceId` and cannot have bootstrapped a session for this pair; this mechanism covers that gap rather than duplicating X4DH.

---

## Manual Sync (`app:sync`)

The SYNC button asks one contact for its recent messages. Requires the contact to be online (per presence) and is addressed to the contact's identity (bare `to`), so every live session of the contact may answer. It uses the legacy pairwise key — there is no single device pair to derive a session key for — but the message batch itself is never carried under that key alone.

```json
{ "type": "app:sync", "from": "<publicId>", "to": "<publicId>", "blob": { "v": 1, "iv": [...], "data": [...] }, "sig": [...] }
```

`blob` is encrypted under the pairwise key and `sig` signs the ciphertext; verification is mandatory. The payload is `{ from, to, syncId, reply, ek, wrapped? }`. The envelope's `from`/`to` are unsigned and relay-rewritable, so the receiver treats the payload copies as authoritative and drops on any mismatch (a pairwise-symmetric key would otherwise let a captured packet be reflected at its sender).

1. **Request** (`reply: false`) — the initiator generates a fresh ephemeral and a `syncId`, and holds the ephemeral private key in memory for 60 seconds (`pendingSyncs`). The request carries **no messages**, only `ek`.
2. **Reply** (`reply: true`) — the recipient generates its own ephemeral, derives the wrap key from the two ephemerals (`deriveEphemeralWrapKey`, see [Ephemeral Wrap](#ephemeral-wrap)), and returns its own `ek` plus `wrapped` — its most recent messages for the initiator, up to 10, encrypted under that key. A request with no valid `ek` is dropped.
3. **Accept** — the initiator accepts a reply only while a request of its own to that same contact is pending (`syncId`, 60 seconds), unwraps with the held ephemeral, and merges. A matching reply is deliberately not consumed — several of the contact's devices can each legitimately answer the one broadcast request, and merging the same batch twice is a no-op.

**One-directional:** only the side that pressed SYNC receives; press it on both sides for a two-way exchange. A recorded batch plus a later identity-key compromise exposes nothing, because the batch is protected by ephemeral keys that no longer exist.

**Inbound sanitising.** Messages are copied from a whitelist, never spread; a batch is capped at 50; only messages whose sender is one of the two parties of this conversation are kept; entries already on file are skipped (so a synced copy can't replace a local object and lose its delivery status) except reactions, where newer state must win; local-only fields never come in from the wire. The result goes through `mergeMessages` and the usual reconciliation.

A packet with no `blob` (plaintext `msgs`) is dropped.

---

## Message Merging

All message stores merge last-write-wins by message id, then a causal splice pass on top of the plain `(ts, id)` baseline:

- **Dedup by id is recency-based, not positional.** For most message types a given id's content is immutable once sent, so "last one wins" and "last one in time wins" are the same statement. Reaction ids are the deliberate exception: `deriveReactionId(myPublicId, targetMsgId)` intentionally produces the *same* id across every state a (sender, target) pair can be in — a real emoji, a manual clear and the RECEIVED auto-ack (`emoji: null`) all collide on one id, so an emoji change replaces rather than duplicates. A positional rule would let a stale auto-ack, arriving late by some other path (a delayed live delivery, a backup push, a manual sync), silently overwrite a newer real reaction with `null`. `mergeMessages` therefore resolves a same-id collision by `ts` (the more recent copy wins; on an exact tie the incoming copy wins), which is a no-op for immutable-content ids.
- **Baseline**: merge by id, sort by `(ts, id)` — `id` is a stable tiebreak for near-simultaneous messages, giving an order independent of which side of the merge a message came from.
- **Causal pass**: a message stamped with `ackDeviceId`/`ackN` is understood as "sent after seeing that specific `(deviceId, n)` message". If the target is present in the merged set, the message is spliced in directly after it, recursively, so a reply-to-a-reply nests. A pointer that resolves to nothing (target not yet present, or dropped by [local retention](#local-retention)) leaves the message at its baseline position. Multiple messages acknowledging the same target keep their relative `(ts, id)` order — this is not a full vector-clock reorder; reordering is the exception.
- **Trust gate.** A message participates as a splice *child* only if it carries the local-only flag `ackTrusted`, meaning its pointer was established live on this device — composed here, or received and verified here. A message arriving through a self-sync, backup, restore or manual-sync merge never carries the flag, so it falls back to its baseline position instead of being spliced on a foreign device's claim about "what I'd most recently seen". `ackTrusted` is sticky across a same-id collision (a later untrusted copy of the same immutable message doesn't erase it), is never serialised to the wire, backups or `selfsync` copies, and a message without it can still be a *parent* for someone else's trusted pointer — the index uses `deviceId`/`n`, which are content facts, not an ordering claim.
- **Cycle guard**: a genuine ack graph is a forest — a message can only acknowledge something that already existed. The merge walks each parent chain looking for a revisit and breaks the offending edge, demoting that message to its baseline slot, rather than risking runaway recursion on a malformed or replayed set.

Reactions use the stable derived id above, so they merge by replacement. The delivery-acknowledgement reaction uses the identical derivation.

### Local retention

Local persistence (`serialiseContacts()`, which feeds local storage and every backup) keeps roughly the 15 most recent messages per contact (`RETENTION_COUNT`); the manual-sync window (`getLast()`) is the 10 most recent (`EXCHANGE_COUNT`). Both select by recency via `selectRetainedMessages`, not by array position: the causal pass can move a message far from its timestamp-sorted place, so a positional `slice(-n)` could keep older messages over newer ones or sever a message from the parent its pointer targets — which then falls back to timestamp order with no way to recover the missing parent, since there is no wire-level backfill.

`selectRetainedMessages(messages, n)`:
1. Selects the `n` most recent messages by `(ts, id)`.
2. Does one rescue pass: for each kept message with an `ackDeviceId`/`ackN` pointer, if its target exists elsewhere in the full set but fell outside the window, it is kept too. This is not a transitive closure — a rescued parent's own parent is not chased. Ack chains are shallow in practice, and anything unresolvable degrades gracefully through the causal pass's own fallback.
3. Filters the *original* array to the surviving ids, preserving the order `mergeMessages` already established.

---

## Online Presence

Clients poll `sig:announce` about every 30 seconds (jittered), naming their own id plus a random batch of other contacts (3 to 10 ids in total, scaled to the contact count). For each named id that is connected to **that relay**, the relay delivers `sig:seen { id: <announcer> }` to that id's sessions. A client therefore learns a contact is online when that contact announces a batch that included us, and also marks a contact online on any verified packet it receives from them. The relay knows nothing about other relays.

Presence only drives the UI dot, which fades over 5 minutes (a visual gradient rather than on/off), and a few opportunistic actions (restore requests, the stuck-session detector). It never affects routing.

---

## Relay Discovery

Relay WSS coordinates propagate passively:

1. **Shareable address** — the third segment carries a relay WSS for bootstrap.
2. **`sig:relay_info`** — the relay tells the client its own WSS URL after auth.
3. **Message payload** — every `app:message` carries the sender's `relay.wss` inside the encrypted blob.

A client stores `lastRelay` and `lastRelaySeen` per contact. The WSS address is a last-known location, not a permanent home, and updates as contacts move.

Updates are timestamp-guarded: a new `lastRelay` is only adopted if its timestamp is newer than the stored one (`updateRelay`). This applies uniformly to relay info in messages, peer backups, restores, file imports and migration notices — local storage is the source of truth. A relay's own `sig:relay_info` is a confirmation, not an authoritative fact, except on a completely fresh identity with no local record, where it is adopted as an unconfirmed placeholder timestamped `0` so any genuinely dated record arriving later outranks it.

The relay itself is untrusted infrastructure. Cryptographic proof — signatures, encryption — is the only trust boundary. Relays never forward to one another; all topology lives in client state and spreads through ordinary traffic.

---

## Client Storage Keys

| Key | Scope | Description |
|---|---|---|
| `meshchat_contacts_<publicId>`         | per identity | Contact store, encrypted under the backup key |
| `meshchat_peer_backups_v1_<publicId>`  | per identity | Peer-supplied encrypted backup blobs |
| `meshchat_peer_tokens_v1_<publicId>`   | per identity | Restore tokens held for contacts |
| `meshchat_known_devices_v1_<publicId>` | per identity | Device registry — `{ identityId: { deviceId: { lastSeen, lastN, missing, endpointId } } }` |
| `meshchat_send_counters_v1_<publicId>` | per identity | Per-contact outbound `n` counters for this device |
| `meshchat_x4dh_sessions_v1_<publicId>` | per identity | X4DH session state, including root keys — encrypted at rest under the backup key |
| `meshchat_device_seed_v1_<publicId>`   | per device   | Raw 32-byte device seed (base64). Never shared, never backed up |
| `meshchat_push_pref_v1_<publicId>`     | per device   | Push opt-in (`"1"`/`"0"`). The `PushSubscription` itself lives in the browser's PushManager storage, not here |

Held in memory only, never persisted: pending X4DH proposal ephemerals, pending wrap ephemerals (`pendingRestoreEk`, `pendingBackupEk`), pending manual-sync ephemerals, the wire-key cache, and the media caches.

---

## Server Configuration

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT`           | `8000`        | Static file server port |
| `WS_PORT`             | `8888`        | WebSocket signal server port |
| `RELAY_WSS_URL`       | —             | Public WSS URL of this relay (required for cross-relay) |
| `PROTOCOL_VERSION`    | `0.5.5`       | Reported on `sig:relay_info`; informational |
| `WS_MAX_SIZE`         | `2097152`     | Maximum frame size in bytes; larger frames are dropped |
| `MAX_CONNECTIONS`     | `100`         | Total concurrent WebSocket sessions |
| `MAX_CONNECTIONS_PER_IP` | `15`       | Concurrent sessions per source IP |
| `TRUSTED_PROXIES`     | `127.0.0.1,::1` | Comma-separated IPs/CIDR ranges whose `X-Real-IP`/`X-Forwarded-For` are honoured; otherwise the TCP peer address is used |
| `RATE_LIMIT_RATE`     | `20`          | Per-socket token refill, packets/second |
| `RATE_LIMIT_BURST`    | `60`          | Per-socket burst |
| `IP_RATE_LIMIT_RATE`  | `3 × RATE_LIMIT_RATE`  | Budget shared by all sockets from one IP, packets/second |
| `IP_RATE_LIMIT_BURST` | `3 × RATE_LIMIT_BURST` | Burst for that shared budget |
| `GLOBAL_AUTH_RATE`    | `50`          | Server-wide cap on completed auths/second, independent of source IP |
| `GLOBAL_AUTH_BURST`   | `100`         | Burst for that cap |
| `BUF_DIR`             | `./relay_buf` | Offline message buffer directory |
| `BUF_MAX_MSGS`        | `100`         | Max buffered packets per bucket |
| `BUF_MAX_AGE`         | `86400`       | Buffer expiry in seconds (24h) — ordinary packets, including `session:*` |
| `BUF_MAX_AGE_MIGRATE` | `604800`      | Expiry in seconds (7d) — `app:migrate` only |
| `BUF_MAX_AGE_BURN`    | `604800`      | Expiry in seconds (7d) — `app:burn` only |
| `BUF_MAX_MB`          | `10`          | Max buffer size per bucket in MB |
| `BUF_WRITE_RATE_LIMIT`| `2`           | New buffered writes/second allowed per bucket |
| `BUF_WRITE_RATE_BURST`| `20`          | Burst for that limit |
| `MAX_BUF_RECIPIENTS`  | `10000`       | Max distinct recipient directories under `BUF_DIR` |
| `MAX_ENDPOINTS_PER_RECIPIENT` | `20`  | Max endpoint buckets one identity can accumulate |
| `VAPID_SUBJECT`       | `mailto:admin@example.com` | Operator contact for the VAPID spec, sent in every push JWT's `sub` claim |
| `VAPID_KEY_FILE`      | next to `BUF_DIR` | Persisted VAPID EC P-256 private key (PEM); generated on first boot if missing |
| `PUSH_SUBS_DIR`       | next to `BUF_DIR` | Push subscription storage — `<dir>/<publicId>/<endpointId>.json` |
| `PUSH_TTL_SECONDS`    | `60`          | `TTL` header sent with each push |

`AUTH_TIMEOUT` (15 seconds to complete the challenge-response) is a constant, not an environment variable.

---

*MeshChat Protocol v1 — experimental, subject to change*
*Last updated: October 2026*