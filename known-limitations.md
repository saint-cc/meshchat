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

## No forward secrecy

Identity keys are static.

If an attacker records encrypted traffic today and later compromises your identity, previously recorded messages may become decryptable.

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
