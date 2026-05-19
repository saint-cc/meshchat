# meshchat

A decentralized messaging protocol with portable cryptographic identities, multi-path transport, and stateless relays.

Meshchat is an experimental communication protocol designed for resilient, infrastructure-light messaging using deterministic identities, end-to-end encryption, and opportunistic delivery over WebSockets and email fallback.

---

## What is Meshchat?

Meshchat is a communication system where identities are derived locally from a username and passphrase instead of being created by a central server.

Messages are signed and encrypted end-to-end, while delivery can happen over multiple transport methods such as direct WebSocket connections or email-based store-and-forward relays.

The server is intentionally mostly stateless. Clients synchronize directly whenever possible and fall back to relays only when necessary.

---

## Design Principles

### C — Cryptographic Identity Portability

Identities are deterministic and portable. A user can reconstruct their identity anywhere using the same credentials.

### M — Multi-path Opportunistic Transport

Messages may travel over direct WebSocket connections, relays, or email fallback depending on network availability.

### S — Social Trust Without Central Authority

Trust decisions are local to the client. No server can globally define who should be trusted or blocked.

---

## Non-Goals

Meshchat is NOT:

- a blockchain
- a cryptocurrency
- a fully anonymous network
- a military-grade secure communication platform
- a globally consistent messaging system
- a centralized chat service

The project prioritizes resilience, portability, and decentralization over perfect metadata privacy or formal security guarantees.

---

## Protocol Overview

Basic packet structure:

```json
{
  "sender": "...",
  "receiver": "...",
  "type": "...",
  "relay": "...",
  "blob": "..."
}
```

### Packet Notes

- all packets are signed
- payloads are encrypted end-to-end
- relays cannot modify packets without invalidating signatures
- delivery ordering is not guaranteed
- eventual synchronization between peers is expected
- clients may connect through multiple transports simultaneously

---

## Identity Model

User identities are deterministically derived from:

- username (case-insensitive)
- passphrase

Derived key material is used for:

- signing
- encryption
- backup recovery

No account registration is required.

Losing the passphrase means losing the identity.

Changing the passphrase creates a new identity.

Existing trusted contacts must manually trust the new identity.  
The protocol intentionally does not allow identities to automatically delegate trust to replacement identities.

---

## Transport Model

Meshchat prefers direct encrypted WebSocket communication between clients.

When direct delivery fails:

- messages may be buffered through relays
- relays may optionally use email as asynchronous fallback transport

Email is used as a transport mechanism only.  
Relays cannot decrypt payload contents.

Contacts may exchange updated relay and WebSocket endpoint information over existing trusted channels, allowing identities to migrate between domains or infrastructure providers.

---

## Group Model

Groups are currently implemented as independent identities acting as routing entities.

A group may:

- receive encrypted messages
- redistribute messages to participants
- abstract participant identities from each other

Trust in a group derives entirely from trust in the group owner/operator.

More advanced group trust models may be explored later.

---

## Security Notes

Meshchat uses modern cryptographic primitives but does not claim perfect secrecy or anonymity.

Compromised identities remain compromised until manually abandoned or blocked by contacts.

Historical encrypted data may become decryptable if weak passphrases are used or future attacks succeed.

Users are strongly encouraged to use long, high-entropy passphrases.

The protocol prioritizes practical resilience and decentralized communication over formal guarantees against all future adversaries.

---

## Project Status

Experimental / proof-of-concept.

The protocol, transport behavior, and packet formats are still evolving and may change incompatibly.

Current implementations should be considered unstable and exploratory.

---

## Contributing

Alternative clients, relay implementations, protocol analysis, transport experiments, and security reviews are welcome.

The project intentionally allows heterogeneous implementations as long as protocol compatibility is preserved.

---

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

See the LICENSE file for details.
