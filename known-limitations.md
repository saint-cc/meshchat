```markdown
# MeshChat — Known Limitations

This document describes limitations and trade-offs that are inherent to MeshChat's design. These are not implementation bugs, but consequences of prioritising decentralisation, cryptographic identity and infrastructure independence.

---

# Identity

## No recovery without your passphrase

Your username and passphrase deterministically generate your cryptographic identity.

There are no accounts, recovery emails or password resets.

If you lose your passphrase, your identity is permanently lost.

---

## Changing your passphrase creates a new identity

Changing either your username or passphrase produces a completely different cryptographic identity.

Existing contacts cannot automatically determine that the new identity belongs to the same person.

---

## Compromised identities cannot be revoked

If your passphrase is compromised, the attacker permanently controls that identity.

Recovery requires creating a new identity and re-establishing trust with contacts.

---

## Burn notice is not revocation

The "burn" action (self-destruct) does not revoke a compromised identity — it can't. Identity is deterministic from your username and passphrase, so anyone who still knows them, including you, can log back in at any time and re-derive the exact same keys, exactly as before.

Burn only does two things: wipes local data on the device you burned from, and sends a signal asking your contacts to stop trusting that identity. Contacts who receive it convert you to blocked on their end. It cannot force this anywhere else, cannot stop a future login with the same credentials, and leaves no trace — on this device or any other — that a burn ever happened.

If your passphrase itself is compromised, burn does not help; see "Compromised identities cannot be revoked" above. Burn is for when *you* want to stop using an identity and tell others to stop trusting it, not for containing a stolen passphrase.

---

# Synchronisation

## Eventual completeness

Conversation history is synchronised opportunistically.

Messages always have a deterministic order, but a device may temporarily be missing parts of the conversation until synchronisation completes.

The protocol never invents or reorders history.

---

## Multi-device synchronisation is not instantaneous

Devices sharing the same identity exchange information through normal protocol traffic and peer backups.

They converge over time rather than maintaining constant real-time synchronisation.

---

## Media is currently transient

Images and audio are presently stored only in memory.

Reloading the page or switching devices loses the media payload while leaving the message itself intact.

---

# Privacy

## Relay operators observe metadata

Relay operators necessarily observe:

- sender public ID
- recipient public ID
- timing
- approximate message size
- client IP addresses

Message contents remain end-to-end encrypted.

---

## Forward secrecy is partial, not absent, and does not cover everything

Identity keys are static, and the identity-level pairwise key derived from them provides none of the protection described here — see `protocol.md`'s Encryption section. As of `0.5.0`, a device pair that has completed X4DH session establishment (`X4DH.md`) uses that session's root key to encrypt real message traffic instead, which changes this picture, but only partially:

- A session still sitting at `RK0` (the asynchronous bootstrap stage, before a live round trip has completed) protects only the *initiator's* identity key against a future compromise — not the responder's. See `X4DH.md` §10 for why the asymmetry runs that direction.
- A session that has completed the live upgrade to `RK1` closes that gap for both sides, for that specific device pair, going forward from the point the upgrade happened.
- None of this is a full ratchet yet — a device pair's session key is reused for every message under it until the session itself resets (X4DH.md §16.5/§16.6). Per-message forward secrecy (a real Double Ratchet) is separate, later work.
- Any device pair that hasn't (yet, or ever) completed X4DH bootstrap still falls back to the identity-level static key, with none of the above.
- Calls, shell escalation, relay migration notices, and burn notices are permanently out of scope for this — they aren't device-targeted infrastructure, so there's no session for them to ride on.

In short: if an attacker records encrypted traffic today and later compromises your identity, previously recorded traffic on any device pair without a completed X4DH session — and any non-message traffic regardless — may become decryptable. A device pair with a completed `RK1` session is protected against exactly that scenario for the messages sent after the upgrade; a device pair still at `RK0` is protected only against a future compromise of the initiator's key.

---

## Stable identities are linkable

A public ID remains stable for the lifetime of an identity.

Observers can correlate activity belonging to that identity across time and relay migrations.

---

# Infrastructure

## Relay availability affects reachability

Messages are always delivered to the recipient's current relay.

If that relay is unavailable, new messages cannot be delivered until the recipient reconnects elsewhere or the relay returns.

---

## Relay operators can refuse service

Relay authentication prevents identity spoofing, but it does not prevent a relay operator from refusing connections, delaying delivery or discarding buffered ciphertext.

End-to-end encryption protects message contents, not service availability.

---

## No TURN server — some calls and shell sessions will not connect

Voice calls and agent shell escalation negotiate directly between the two devices over WebRTC, using STUN only (three public STUN servers, for resilience). There is no TURN relay, and this is a permanent design decision rather than a gap awaiting a fix.

Most NAT setups traverse fine with STUN alone. Some do not — certain symmetric-NAT and carrier-grade-NAT pairings cannot establish a direct peer-to-peer path, and no amount of retrying will change that outcome. When this happens, the call or shell session simply fails to connect; the bounded command whitelist (for agent contacts) needs no WebRTC and is unaffected.

This trade-off avoids running or trusting a TURN relay server, which would otherwise see call/shell metadata and be able to observe (though not decrypt) the connection attempt. The cost is that a small fraction of NAT pairings are permanently unreachable for calls and shell sessions specifically — text messaging is unaffected, since it never uses WebRTC.

---

## Push notifications are relay-bound, best-effort, and not universal

Push notifications are opt-in, content-free (a notification only ever means "open the app and check" — never message content or sender identity), and tied to whichever relay you're connected to when you subscribe.

Migrating to a new relay means the old subscription stops working — MeshChat re-subscribes automatically at the new relay, but there is a brief window, right around a migration, where a message from a contact who hasn't yet learned your new relay can arrive without a notification. The message itself is still delivered and recovered normally; only the notification is affected.

Delivery through the underlying push service (Google's, Mozilla's, etc.) is best-effort — MeshChat does not retry a failed push. On iOS, push additionally only works if MeshChat has been added to the Home Screen; a page merely open in a Safari tab cannot receive push notifications at all, regardless of subscription state. This is a platform restriction, not a MeshChat limitation.

---

# General

## Experimental protocol

MeshChat Protocol v0 is still evolving.

Packet formats, routing behaviour and synchronisation mechanisms may change between releases.

---

## No formal security audit

The protocol has not undergone an independent security review.

It should be considered experimental software.

---

## MeshChat is not an anonymity network

MeshChat protects message confidentiality.

It does not attempt to hide who communicates with whom or conceal network-level metadata.

For anonymity, additional technologies such as Tor are required.
```