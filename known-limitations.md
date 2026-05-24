# MeshChat — Known Limitations

This document describes known limitations, trade-offs, and intentional design decisions that may surprise users or implementors. It is not a bug list — most of these are inherent properties of a decentralised, infrastructure-light system.

---

## Protocol / Delivery

**No delivery confirmation**
Messages are fire-and-forget. There is no acknowledgement from the recipient that a message was received. The sender has no way to distinguish "delivered but not read" from "never arrived".

**Ordering not guaranteed**
Messages may arrive out of chronological order, especially across transport paths or after an offline period. The client sorts by timestamp, so the conversation will eventually look correct — but arrival order may differ from send order.

**Duplicate delivery possible**
A message may arrive more than once if it travels via multiple paths (relay WSS and email, for example). Deduplication by message ID handles this transparently, but it does happen.

**Cross-relay offline delivery is slow and best-effort**
When a contact is offline on their relay and the WSS path fails, messages fall back to email bridge. This depends on third-party mail server reliability and polling intervals. Delivery may be delayed by minutes or fail silently if the mail server is unavailable.

**No guaranteed eventual delivery**
If both the relay WSS and email fallback fail, messages are lost. There is no persistent retry mechanism beyond the email polling cycle.

---

## Identity

**No recovery without passphrase**
There is no account recovery mechanism. The username and passphrase are the identity. Losing them means losing access permanently, with no recourse.

**Passphrase change creates a new identity**
Changing the passphrase produces a completely different keypair. Existing contacts will not recognise the new identity. They must manually re-add the user and decide whether to trust the new key.

**No automatic trust delegation**
The protocol intentionally does not allow an identity to vouch for its own replacement. Contacts must make trust decisions manually. This is a feature, not a bug — but it is surprising to users expecting account-style recovery.

**Compromised identity stays compromised**
If a passphrase is leaked, the identity is compromised until every contact manually blocks and re-adds. There is no revocation mechanism.

---

## Multi-device

**Eventual consistency only**
Multiple devices holding the same identity will converge over time, but are not in real time sync. Messages sent on one device may not appear on another until they meet via backup or restore.

**Split brain on multiple relays**
If the same identity is active on two different relays simultaneously, relay routing information may conflict. The most recently seen relay wins over time through backup merges, but there is a window where contacts may route to the wrong relay.

**Audio and image messages are not backed up**
Audio and image data lives in memory only and is never written to localStorage or included in backups. It does not survive a page reload or device switch. Only a text stub remains in the conversation history.

---

## Privacy

**Relay operator sees metadata**
The relay operator can observe sender publicId, recipient publicId, message timing, and approximate message size. Message content is encrypted and unreadable, but the communication graph is visible.

**Recipient relay revealed to sender relay**
The `relay_email` field in the packet envelope tells the sender's relay where to forward offline messages. This reveals which relay the recipient uses.

**No forward secrecy**
Messages are encrypted with static keys derived from the passphrase. If a passphrase is compromised in the future and an attacker has stored ciphertext, past messages can be decrypted. There is no per-session key ratchet.

**PublicId is stable and linkable**
The publicId is deterministic and permanent for a given identity. Anyone who observes it can correlate activity across time and relays.

---

## Infrastructure

**No local offline queue**
When a contact is offline on the local relay, messages are currently buffered via email. A purpose-built local file queue is planned but not yet implemented. Email buffer introduces latency and external dependency for what should be a local operation.

**Email fallback requires third-party mail service**
The email bridge depends on an external SMTP/IMAP provider. Free mail services may rate-limit, delay, or drop messages. The relay has no visibility into whether an email was actually delivered.

**Single relay is a single point of failure**
If a user's relay goes offline, they become unreachable until it returns or they migrate to a new relay. There is no automatic failover or relay redundancy.

**No relay authentication**
Any client can connect to any relay and register any publicId. A malicious relay could selectively drop or delay messages. Trust in a relay is implicit.

---

## Group Messaging

**Groups are centralised by design**
Groups are currently implemented as independent identities operated by an owner. All trust in the group derives from trust in the group owner. There is no distributed group consensus.

**Group member privacy**
Group members may be able to infer other members' publicIds depending on implementation. True metadata-private group messaging is not a current goal.

---

## General

**Experimental protocol**
MeshChat Protocol v0 is unstable. Packet formats, key derivation, and transport behaviour may change incompatibly. Implementations should be considered exploratory.

**No formal security audit**
The cryptographic primitives used are sound, but the protocol as a whole has not been formally audited. Do not rely on it for high-stakes communication.

**Not anonymous**
MeshChat is not an anonymity network. IP addresses are visible to relay operators. It is not a replacement for Tor or similar tools.

---

*Last updated: May 2026*
*MeshChat Protocol v0 — subject to change*