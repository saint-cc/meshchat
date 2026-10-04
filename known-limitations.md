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

## Key-derivation changes are hard cutovers

The key-derivation parameters — PBKDF2 iteration count, HKDF labels, salt format — are inputs to your identity exactly as the username and passphrase are. Raising the iteration count from 100,000 to 1,000,000 in `0.5.2` therefore had the same effect as changing everyone's passphrase at once: logging in with the same credentials derived a completely different identity, with no local data under it and no path back to the old one.

No dual-version detection or migration was attempted, and any future change to these parameters will behave the same way.

---

## A weak passphrase can be attacked offline

Your `publicId` is public by design. Anyone who knows your username and your public ID can therefore test passphrase guesses entirely offline — derive the keys from a guess, hash the two public keys, compare against the known ID — with no captured traffic and no network access.

The 1,000,000 PBKDF2 iterations make each guess more expensive; they do not change the shape of the problem. The passphrase is the security floor for everything built on top of it, including every forward-secrecy property that depends on identity keys not leaking. The login screen's entropy meter is a rough guide, not a guarantee.

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

Devices sharing the same identity exchange information through mirrored copies of outgoing messages, self-backups and normal protocol traffic.

They converge over time rather than maintaining constant real-time synchronisation.

---

## Mirroring to your other devices is best-effort

Messages and reactions you send are mirrored to your other devices as small per-device messages. This has gaps:

- A device this one has never heard from is not mirrored to — there is nothing to address. It is discovered through the self-backup hello or its own traffic, and later sends then reach it.
- A device with no known routing ID, or not seen for more than 7 days, is reached through the identity-level buffer instead. The first of your devices to reconnect consumes that copy, so another offline device may miss it until the next self-backup cycle repairs it.
- Media is mirrored as a stub only. Call notices and delivery acknowledgements are not mirrored at all, so delivery status can differ between your devices.
- A brand-new device receives your contacts from the first backup push after its session with your other devices exists, not instantly. A genuinely wiped device still restores through the restore handshake.

---

## Peer backups restore contacts, not conversations

Backups held by your contacts carry your contact list only (since `0.5.5`). After a wipe, restore recovers who you know, not what you said. Message history comes back only from the other side of each conversation (manual SYNC) or from your own other devices.

Separately, each device persists — to local storage and into backups — only roughly the 15 most recent messages per contact, and there is no wire-level request to backfill older ones. The "not received yet" banner can tell you a gap exists; it cannot close it.

---

## Manual SYNC is one-way and needs the contact online

Pressing SYNC asks the other party for its most recent messages (up to 10) and receives them; it does not also send yours. Press it on both sides for a two-way exchange. It only works while the contact is online, and a client that predates the encrypted form cannot take part.

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
- which device routing ID (`endpointId`) is connected or addressed — not linkable to the device ID your contacts see, but stable per device

Message contents remain end-to-end encrypted.

---

## Forward secrecy is partial, not absent, and does not cover everything

Identity keys are static, and the identity-level pairwise key derived from them provides none of the protection described here — see `protocol.md`'s Encryption section. As of `0.5.0`, a device pair that has completed X4DH session establishment (`X4DH.md`) uses that session's root key to encrypt real message traffic instead, which changes this picture, but only partially:

- A session still sitting at `RK0` (the asynchronous bootstrap stage, before a live round trip has completed) protects only the *initiator's* identity key against a future compromise — not the responder's. See `X4DH.md` §10 for why the asymmetry runs that direction.
- A session that has completed the live upgrade to `RK1` closes that gap for both sides, for that specific device pair, going forward from the point the upgrade happened. Precisely, this is *session-level forward secrecy against later identity-key compromise*, with these qualifiers:
  - It covers only traffic sent after the upgrade; anything sent under `RK0` beforehand stays exposed as described above.
  - It relies on both ephemeral private keys being erased. In JavaScript that is best-effort (dropped and garbage-collected, not zeroised).
  - The wire key is static per session, so there is no per-message forward secrecy and no post-compromise recovery until the session resets.
  - The session root key is stored on the device, encrypted with a key derived from the passphrase. An attacker with both the device's storage and the passphrase obtains it directly, without needing any identity-key attack.
- None of this is a full ratchet yet — a device pair's session key is reused for every message under it until the session itself resets (X4DH.md §16.5/§16.6). Per-message forward secrecy (a real Double Ratchet) is separate, later work.
- Any device pair that hasn't (yet, or ever) completed X4DH bootstrap still falls back to the identity-level static key, with none of the above.
- Calls, data-channel tests, relay migration notices, and burn notices are permanently out of scope for this — they aren't device-targeted infrastructure, so there's no session for them to ride on.
- Copies of your own messages mirrored between your devices ride the same per-device keys as ordinary messages where a self-session exists, and the legacy self key otherwise — so the same qualifiers apply.
- Manual SYNC's envelope uses the identity-level key, but the message batch inside a reply is wrapped under a one-shot ephemeral key (since `0.5.5`), so a recorded batch is not exposed by a later identity-key compromise. The envelope itself carries only an ephemeral public key and a request ID.

In short: if an attacker records encrypted traffic today and later compromises your identity, previously recorded traffic on any device pair without a completed X4DH session — and any non-message traffic regardless — may become decryptable. A device pair with a completed `RK1` session is protected against exactly that scenario for the messages sent after the upgrade; a device pair still at `RK0` is protected only against a future compromise of the initiator's key.

## Restore and backup traffic have their own, narrower wire protection

The forward-secrecy discussion above is about `app:message` traffic specifically. The peer backup and restore handshake (`protocol.md`'s [Peer Backup Protocol](protocol.md#peer-backup-protocol)) uses a completely separate key hierarchy — the passphrase-derived backup key, not the pairwise/X4DH message key — and has its own, independent wire protection layered on top of it. As of `0.5.5` the contact path and the self restore push use the ephemeral wrap described below, while self-sync backup pushes ride X4DH session keys instead (see the last bullets):

- `sync:restore_push` and `sync:backup_push` (contact path since `0.5.1`; the self `restore_push` since `0.5.5`) can carry an additional one-shot X25519 ephemeral-to-ephemeral wrap (`protocol.md`'s [Ephemeral Wrap](protocol.md#ephemeral-wrap)) around the existing backup-key-encrypted blob. This protects against exactly the scenario described above — recorded wire traffic plus a later passphrase compromise — for these packet types, independent of whether the device pair has ever bootstrapped an X4DH session at all.
- This is a per-exchange, memory-only ephemeral, not a session — there is no root key, no upgrade path, and nothing persisted. It either happens for a given push or it doesn't; there's no `RK0`/`RK1`-style partial state to reason about.
- It's gated on the *preceding* ack/accept having a valid signature. An offer or ack from a sender with no established signing key on file (the genuinely-fresh-relationship case) gets no wrap — the same soft-verification stance the rest of this handshake family already has.
- **Once a push has actually been wrapped, there is no graceful fallback.** A relay that strips the ephemeral in transit (without also invalidating the signature, which covers it) causes that specific restore or backup attempt to fail closed rather than silently downgrading to the unwrapped form. This is deliberate — accepting a stripped wrap would defeat the point of having one — but it does mean an actively hostile relay has a cleaner denial-of-service target here than against an ordinary unwrapped exchange.
- Self-sync full backups (an identity's own devices exchanging contact stores) do not use the ephemeral wrap. As of `0.5.5` a full push goes to each known sibling under that pair's X4DH session key — the same per-device key `app:message` uses, with the same caveats: static per session, `RK0` narrower than `RK1`, no ratchet. It is skipped when the sibling's fingerprint already matches.
- Where no session exists yet, only a content-free discovery hello goes out under the passphrase-derived backup key: no contacts, no messages, just the device's ID and routing ID. That keeps contact data off the wire under the deterministic key, but a recorded hello plus a later passphrase compromise reveals the link between a device ID and its routing ID. Older siblings that still send a full push under the static backup key are accepted for interoperability, and those pushes keep the old exposure.
- Contacts holding your backup receive your contact list only, with no message history, which limits what any stored copy could expose in the first place.

Separately: the restore token (`protocol.md`'s [Restore Token](protocol.md#restore-token)) that authenticates a wiped device's restore push is a fixed, unrotated object for as long as the underlying contact relationship exists — the same token bytes travel on the wire every time that specific restore path is exercised, until the storing side re-adds the contact and a fresh one is issued. Its contents are opaque without the issuer's passphrase, but its presence is a stable, linkable fingerprint of that specific contact pair.

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

## No TURN server — some calls and data-channel tests will not connect

Voice calls and the data-channel connection test negotiate directly between the two devices over WebRTC, using STUN only (three public STUN servers, for resilience). There is no TURN relay, and this is a permanent design decision rather than a gap awaiting a fix.

Most NAT setups traverse fine with STUN alone. Some do not — certain symmetric-NAT and carrier-grade-NAT pairings cannot establish a direct peer-to-peer path, and no amount of retrying will change that outcome. When this happens, the call or test simply fails to connect.

This trade-off avoids running or trusting a TURN relay server, which would otherwise see call/data-channel metadata and be able to observe (though not decrypt) the connection attempt. The cost is that a small fraction of NAT pairings are permanently unreachable for calls and data-channel tests specifically — text messaging is unaffected, since it never uses WebRTC.

A direct connection also means the other party learns your network address when you accept a call or test, because ICE exchanges it. The data-channel accept prompt says so; the same is true of voice calls.

---

## Push notifications are relay-bound, best-effort, and not universal

Push notifications are opt-in, content-free (a notification only ever means "open the app and check" — never message content or sender identity), and tied to whichever relay you're connected to when you subscribe.

Migrating to a new relay means the old subscription stops working — MeshChat re-subscribes automatically at the new relay, but there is a brief window, right around a migration, where a message from a contact who hasn't yet learned your new relay can arrive without a notification. The message itself is still delivered and recovered normally; only the notification is affected.

Delivery through the underlying push service (Google's, Mozilla's, etc.) is best-effort — MeshChat does not retry a failed push. On iOS, push additionally only works if MeshChat has been added to the Home Screen; a page merely open in a Safari tab cannot receive push notifications at all, regardless of subscription state. This is a platform restriction, not a MeshChat limitation.

---

# General

## The X4DH freshness guard trusts the sender's clock

The check that stops an older `session:propose` from overwriting a newer session is state-rollback protection, not authentication and not cryptographic replay prevention. It compares timestamps from the sender's own clock, which has two consequences:

- After a wipe, burn or loss of session storage there is no record to compare against, so it does not stop a replayed propose. The likely outcome is a desynchronised session that stuck-session detection and retry later repair, not disclosure of key material.
- If a sender's clock is ever far ahead when a propose is adopted, its later legitimate proposes (including automatic retries) are refused until real time catches up with the stored value.

Both are reasoned from the code rather than observed live.

---

## Experimental protocol

MeshChat Protocol v0 is still evolving.

Packet formats, routing behaviour and synchronisation mechanisms may change between releases.

---

## X4DH has had no formal analysis

X4DH is a MeshChat-specific 2DH/4DH construction — not Signal's X3DH, and without signed or one-time prekeys. It has had no formal analysis.

It should be considered experimental software.

---

## MeshChat is not an anonymity network

MeshChat protects message confidentiality.

It does not attempt to hide who communicates with whom or conceal network-level metadata.

For anonymity, additional technologies such as Tor are required.