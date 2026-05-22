# MeshChat Protocol v0

A decentralised, end-to-end encrypted messaging protocol.  
No accounts. No central authority. No plaintext on the wire.

---

## Overview

MeshChat is a store-and-forward messaging protocol built on three transport layers:
WebSocket for real-time delivery, email for async relay-to-relay delivery, and
a distributed backup system for message persistence across devices.

A relay server is a dumb router. It cannot read messages, does not store history,
and has no concept of users or accounts. Anyone can run one.

---

## Identity

Every user is identified by a keypair derived deterministically from their
username and passphrase using PBKDF2 + HKDF.

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| `encKey` | AES-GCM 256-bit | Encrypt messages sent to this user |
| `signKey` | Ed25519 | Sign outgoing messages |

**PublicId** — a stable identifier derived from the encryption key:
```
publicId = base64url( SHA-256(encKey)[0:12] )
```

**Shareable address** — everything needed to reach someone, encoded as a single string:
```
<encKey_b64>.<signPublicKey_b64>.<relayEmail>
```

The third field (`relayEmail`) is optional for existing contacts but included
when sharing via QR code or copy-paste. It bootstraps the email fallback path
before any WebSocket contact has been made.

This string is shared as a QR code or pasted manually. It contains no private
key material and is safe to share publicly.

---

## Relay Server

A relay server exposes two interfaces:

- **WebSocket** — real-time packet routing (`ws://` or `wss://`)
- **Email** — async offline delivery via SMTP out / IMAP in

### Identity

A relay optionally advertises its coordinates via `get_relay_info`:

```json
{ "type": "relay_info", "wss": "wss://relay.example.com/ws/", "email": "meshchat@relay.example.com" }
```

Both fields are optional. A relay with no email configured simply cannot
deliver to offline users on foreign relays.

### Routing

The relay routes packets by the `to` field. If the recipient is connected,
the packet is delivered immediately. If not, the relay reads `relay_email`
from the packet envelope and forwards via email to the recipient's relay.
If no `relay_email` is present, the packet is queued to the relay's own
email inbox for local delivery when the recipient reconnects.

---

## Packet Envelope

The envelope is plaintext. The relay can read it for routing purposes only.

```json
{
  "type":        "message",
  "from":        "<publicId>",
  "to":          "<publicId>",
  "relay_email": "alice@relay.example.com",
  "blob":        { "iv": [...], "data": [...] },
  "sig":         [...]
}
```

| Field | Description |
|-------|-------------|
| `type` | Packet type (see below) |
| `from` | Sender's publicId |
| `to` | Recipient's publicId |
| `relay_email` | Recipient's relay email — used by relay for offline forwarding |
| `blob` | AES-GCM encrypted payload (see below) |
| `sig` | Ed25519 signature over the encrypted blob |

The relay never sees message content. `relay_email` is the only routing hint
it receives, and it reveals nothing about the message itself.

---

## Encrypted Payload

The blob is encrypted with the **recipient's** `encKey` (AES-GCM, random IV per message).
Only the intended recipient can decrypt it.

```json
{
  "id":    "<uuid>",
  "type":  "text",
  "text":  "Hello!",
  "ts":    1700000000000,
  "relay": {
    "wss":   "wss://sender-relay.example.com/ws/",
    "email": "meshchat@sender-relay.example.com"
  }
}
```

| Field | Description |
|-------|-------------|
| `id` | UUID, used for deduplication and merging |
| `type` | `text` \| `audio` \| `image` \| `reaction` |
| `text` | Message body (type=text only) |
| `ts` | Unix timestamp in milliseconds |
| `relay` | Sender's current relay coordinates — recipient uses this to update routing |

The `relay` field inside the payload is how relay discovery propagates.
Every message passively teaches the recipient where to reach the sender.
It is updated only if the message timestamp is newer than the stored value,
preventing stale synced messages from overwriting fresh data.

---

## Message Types

### text
```json
{ "id": "...", "type": "text", "text": "Hello!", "ts": 0, "relay": {} }
```

### audio
```json
{ "id": "...", "type": "audio", "data": "<base64>", "mimeType": "audio/webm", "ts": 0, "relay": {} }
```

### image
```json
{ "id": "...", "type": "image", "data": "<base64>", "mimeType": "image/jpeg", "ts": 0, "relay": {} }
```

### reaction
Reactions use a **stable derived ID** so merging is idempotent:
```
reactionId = base64url( SHA-256("reaction:" + senderPublicId + ":" + targetMsgId)[0:12] )
```
```json
{ "id": "<reactionId>", "type": "reaction", "targetId": "<msgId>", "emoji": ":)", "ts": 0, "relay": {} }
```
`emoji` is `:)`, `:(`, or `null` (cleared).

---

## Signature Verification

The sender signs the encrypted blob (not the plaintext) using Ed25519:
```
sig = Ed25519.sign( JSON.stringify(blob), signingKeySeed )
```
The recipient verifies using the sender's signing public key (from the shareable address).
Messages that fail verification are displayed with a warning but not dropped —
they may be legitimately unsigned (older clients or relay-forwarded).

---

## WebSocket Packet Types

### Client → Server

| Type | Description |
|------|-------------|
| `connect` | Register publicId with relay |
| `get_relay_info` | Request relay's WSS and email identity |
| `who_online` | Poll presence for a list of publicIds |
| `message` | Send a message packet to another user |
| `msg_exchange` | Bilateral message sync (last N messages) |
| `backup_offer` | Offer a backup blob to a peer |
| `backup_accept` | Accept a pending backup offer |
| `backup_push` | Push a backup blob to a peer |
| `push_restore_request` | Request a restore from a peer |
| `push_restore_ack` | Acknowledge a restore request |
| `restore_push` | Push a full restore blob to a peer |
| `ping` | Keepalive |

### Server → Client

| Type | Description |
|------|-------------|
| `relay_info` | Relay's WSS URL and email address |
| `seen` | A queried publicId is online |
| `online_list` | List of online publicIds from a who_online query |
| `gone` | A connected peer has disconnected |
| `message` | Delivered message packet |
| `pong` | Keepalive response |
| `error` | Error (e.g. rate_limited) |

---

## Relay Discovery

Relay coordinates spread passively through the network:

1. **QR code / shareable address** — contains `relayEmail` for bootstrap
2. **`relay_info` response** — relay tells client its own coordinates on connect
3. **Message payload** — every message carries sender's `relay` field inside the encrypted blob

A client stores `lastRelay`, `lastRelayEmail`, `lastRelaySeen` per contact.
The WSS address is treated as a *last known location*, not a permanent home.
The email address is treated as a stable anchor and not overwritten automatically.

---

## Distributed Backup

Contacts and message history are encrypted and backed up peer-to-peer.
No relay stores backup data.

**Protocol:**
1. `backup_offer` — sender announces blob size to peer
2. `backup_accept` — peer accepts (constrained peers may never accept)
3. `backup_push` — sender transmits encrypted blob

Backup blobs are encrypted with the sender's own `backupKey` (derived from
passphrase via HKDF). A peer storing a backup cannot read it.

Self-sync (same user, multiple devices) skips the offer step.

---

## Message Merging

All message stores use ID-based merging:
```
merged = deduplicate_by_id( local + remote ).sort_by_timestamp()
```

This makes the protocol eventually consistent. Duplicate delivery (from
multiple relays or email) is handled by deduplication. Late-arriving messages
sort into the correct chronological position.

Reaction messages use their stable derived ID, so a changed reaction
naturally replaces the previous one during merging.

---

## Rate Limiting

The relay applies a token bucket rate limiter per WebSocket connection:
- Refill rate: 10 tokens/second
- Burst: 20 tokens

Connections exceeding this receive an `error` packet with `reason: rate_limited`.

---

## Email Relay Format

Offline messages are batched and sent as a single email per recipient:

```
From:    meshchat@sender-relay.example.com
To:      meshchat@recipient-relay.example.com
Subject: MC:<recipientPublicId>
Body:    [ <packet>, <packet>, ... ]   (JSON array)
```

The receiving relay polls IMAP for unseen messages with `MC:` subjects,
delivers packets to connected clients, and marks emails as seen.
If the recipient is still offline, the email is left unseen for retry
on the next poll cycle.

---

## Key Derivation

```
master  = PBKDF2( passphrase, SHA-256("meshchat-v1:" + username), 100000, SHA-256 )

encryptionKey   = HKDF( master, info="meshchat-v1:encryption" )   → AES-GCM key
backupKey       = HKDF( master, info="meshchat-v1:backup"     )   → AES-GCM key
signingKeySeed  = HKDF( master, info="meshchat-v1:signing"    )   → Ed25519 seed
```

The same username+passphrase always produces the same keys.
There is no account recovery mechanism — the passphrase is the identity.

---

## Design Principles

- **No central authority** — any node can be a relay, no registration required
- **Operator-blind** — relay operators cannot read messages or identify users beyond publicIds
- **Eventually consistent** — message stores converge over time across devices and relays
- **Graceful degradation** — WebSocket → email → manual export/import
- **Passive discovery** — relay locations propagate through normal message flow
- **No metadata inflation** — the envelope reveals sender, recipient, and relay hint only

---

*MeshChat Protocol v0 — subject to change*  
*Developed by saint-cc with Claude (Anthropic) as AI pair programmer*  
*Licensed under AGPL v3*