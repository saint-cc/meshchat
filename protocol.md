# MeshChat Protocol v0

A decentralised, end-to-end encrypted messaging protocol.  
No accounts. No central authority. No plaintext on the wire.

---

## Overview

MeshChat is a store-and-forward messaging protocol built on WebSocket transport
for real-time delivery and a distributed backup system for persistence across devices.

A relay server is a dumb router. It cannot read messages, does not store history,
and has no concept of users or accounts. Anyone can run one.

---

## Identity

Every user is identified by a keypair derived deterministically from their
username and passphrase using PBKDF2 + HKDF.

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| encKey | AES-GCM 256-bit | Encrypt messages sent to this user |
| signKey | Ed25519 | Sign outgoing messages |

### PublicId

publicId = base64url( SHA-256(encKey)[0:12] )

---

### Shareable Address

<encKey_b64>.<signPublicKey_b64>.<relayWss_b64>

All fields are base64url encoded. The relay field is optional and used only
for bootstrap discovery.

---

## Relay Server

A relay exposes a WebSocket interface:

- WebSocket: ws:// or wss://

### Routing

- Deliver immediately if recipient is connected
- Otherwise optionally queue temporarily for offline delivery

Queueing is implementation-defined.

---

## Packet Envelope

{
  "type": "message",
  "from": "<publicId>",
  "to": "<publicId>",
  "blob": { "iv": [], "data": [] },
  "sig": []
}

Relay only reads routing metadata.

---

## Encrypted Payload

Encrypted with recipient encKey (AES-GCM).

{
  "id": "<uuid>",
  "type": "text",
  "text": "Hello!",
  "ts": 1700000000000,
  "relay": {
    "wss": "wss://sender-relay.example.com/ws/"
  }
}

---

## Message Types

### text
{
  "id": "...",
  "type": "text",
  "text": "Hello!",
  "ts": 0,
  "relay": {}
}

### audio
{
  "id": "...",
  "type": "audio",
  "data": "<base64>",
  "mimeType": "audio/webm",
  "ts": 0,
  "relay": {}
}

### image
{
  "id": "...",
  "type": "image",
  "data": "<base64>",
  "mimeType": "image/jpeg",
  "ts": 0,
  "relay": {}
}

### reaction

reactionId = base64url(
  SHA-256("reaction:" + senderPublicId + ":" + targetMsgId)[0:12]
)

{
  "id": "<reactionId>",
  "type": "reaction",
  "targetId": "<msgId>",
  "emoji": ":)",
  "ts": 0,
  "relay": {}
}

---

## Signature Verification

sig = Ed25519.sign(JSON.stringify(blob), signingKeySeed)

Verified using sender public key from shareable address.

---

## WebSocket Types

Client → Server:
- connect
- get_relay_info
- who_online
- message
- msg_exchange
- backup_offer
- backup_accept
- backup_push
- push_restore_request
- push_restore_ack
- restore_push
- ping

Server → Client:
- relay_info
- seen
- online_list
- gone
- message
- pong
- error

---

## Relay Discovery

- QR/share address bootstrap
- relay_info exchange
- relay field inside messages

---

## Client Relay Selection

1. Contact online locally → direct send
2. Known relay → connect and send
3. fallback → local relay

Connection rules:
- one connection per hostname
- idle timeout 30s
- queued pre-open messages flushed on connect

---

## Backup System

Peer-to-peer encrypted backups.

Steps:
1. backup_offer
2. backup_accept
3. backup_push

Backup encrypted with backupKey.

---

## Message Merging

merged = deduplicate_by_id(local + remote).sort_by_timestamp()

---

## Rate Limiting

10 tokens/sec, burst 20.

---

## Key Derivation

master = PBKDF2(passphrase, SHA-256("meshchat-v1:" + username), 100000)

encryptionKey  = HKDF(master, "encryption")
backupKey      = HKDF(master, "backup")
signingKeySeed = HKDF(master, "signing")

---

## Design Principles

- No central authority
- Any node can be a relay
- Operator-blind relays
- Eventually consistent
- Minimal metadata
- Graceful degradation
