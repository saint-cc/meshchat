# X4DH — MeshChat Session Establishment

> **MeshChat X4DH is a MeshChat-specific 2DH/4DH session-establishment construction. It is not Signal's X3DH and does not use signed or one-time prekeys. It has not been formally analysed or independently audited.**
>
> **What `RK1` gives you, precisely:** session-level forward secrecy against a *later* compromise of either identity key, for traffic sent *after* the live upgrade completes. It is not per-message forward secrecy, and `RK0` (the async-only stage) does not have it. The exact scope and qualifiers are in §11.2 — read that before quoting this property anywhere.

X4DH establishes a cryptographic session between **two specific devices** and yields the root key from which the AES-256-GCM key for all `app:message` content between them is derived. It establishes a usable session immediately when the responder is offline, and opportunistically upgrades that session when both devices are online.

This document specifies the cryptography and the state machine. `protocol.md` specifies the surrounding wire protocol (envelopes, routing, the held outbox, HELLO). Implementation version `0.6.2`.

**Session-only content.** Every message that carries content is encrypted under a session wire key (§5.3) and under nothing else. There is no fallback to any identity-level key: if no send-ready session exists with a device (§7.2), content is not sent to it. The one thing the identity-level static key still carries is the content-free HELLO (`protocol.md`), which exists to give the two sides what this handshake needs (§3.3).

---

## 1. Overview

```text
                    MeshChat Relay
                         │
              asynchronous transport
                         │
        ┌────────────────┴────────────────┐
        │                                 │
      Alice                              Bob
   identity keys                     identity keys
   deviceId_A                        deviceId_B
        │                                 │
        └──────────── X4DH ───────────────┘
                         │
                         ▼
                    Root Key (RK0 → RK1)
                         │
                         ▼
        per-device-pair AES-256-GCM wire key
```

- **Asynchronous by default.** The initiator derives `RK0` from material it already holds and can send it immediately; the responder need not be online.
- **No key server.** The relay never holds or sees key material; it transports `session:propose`/`session:ack` and buffers them.
- **Opportunistic strengthening.** If the responder is online, its fresh ephemeral upgrades the session to `RK1`. The live path is an upgrade, never a requirement.
- **Device-specific.** `Alice::Laptop ↔ Bob::Phone` and `Alice::Desktop ↔ Bob::Phone` are separate sessions. `deviceId` is an identifier, not key material and not secret.
- **A session is not a ratchet.** The wire key is the same for every message under a session until the session itself resets (§9). Per-message key evolution is not implemented.

The root key is stored on the device and is the actual encryption root for real traffic.

---

## 2. Notation and Primitives

| Symbol | Meaning |
|---|---|
| `IK_X` | identity X25519 key pair of party X (`IK_X_priv` is the scalar from `meshchat-v1:x25519`; `IK_X_pub` is in the shareable address) |
| `EK_A`, `EK_B` | fresh one-time X25519 ephemeral key pairs of initiator A and responder B |
| `DHn` | 32-byte X25519 shared secret |
| `zero32` | 32 zero bytes |
| `HKDF(salt, ikm, info)` | HKDF-SHA-256, Extract-then-Expand as a single call, 32-byte output |

An ephemeral key pair is 32 random bytes as the private scalar, public key = `X25519.getPublicKey(scalar)`. Ids and signatures follow the conventions in `protocol.md` (Wire Conventions). Ed25519 signatures use the identity signing key, never a device key.

---

## 3. Roles and Triggers

### 3.1 Fixed initiator per pair

Glare (two competing proposals) is eliminated structurally: for any pair of identities, **the party whose `publicId` sorts lexicographically lower is always the initiator**, permanently, for both first bootstrap and any later reset. The other party's devices never send `session:propose` toward that identity — they only receive and adopt. A `session:propose` from a sender who should not be the initiator toward us is dropped.

```text
isFixedInitiator(contactId, theirDeviceId):
  if contactId == own publicId:  return ownDeviceId < theirDeviceId      // self pair, see 3.2
  return ownPublicId < contactId                                         // plain string comparison
```

### 3.2 Self pairs

Devices of one identity establish sessions with each other exactly like any contact pair (`contactId` = own publicId). `publicId` is identical on both sides, so the tiebreak falls through to `deviceId`: the device whose `deviceId` sorts lower is the initiator toward that specific sibling. Never propose toward the current device itself.

### 3.3 Trigger: passive, on endpoint discovery

`session:propose` is addressed `to = "<publicId>::<endpointId>"` — a specific device — so it can never be the first packet exchanged with a device whose `endpointId` has not been learned. The endpoint is learned passively, with no dedicated discovery packet: from the encrypted payload of any `app:message` (the device registry records it after signature verification), and from the HELLO exchange, which exists precisely to carry `deviceId` and `endpointId` to a contact before any session exists.

Every registry write for a device (`recordKnownDevice`) re-checks whether it just satisfied a precondition:

**Initiator side** — propose now if **all** hold: the device is not our own current device; the contact exists, is not blocked and has an X25519 key; we are the fixed initiator for the pair; **no** session record exists for that device; the device's `endpointId` is known; no proposal for that device is already in flight (guard set synchronously at decision time, since the session is only written after async crypto and two back-to-back registry writes would otherwise fire two proposals).

**Responder side** — complete a deferred ack (§4.3) if one is parked for that device and the endpoint is now known.

Both are no-ops the overwhelming majority of the time.

---

## 4. Handshake

```text
Alice (initiator)                                  Bob (responder)

  generate EK_A
  DH1 = X25519(IK_A_priv, IK_B_pub)
  DH2 = X25519(EK_A_priv, IK_B_pub)
  RK0 = HKDF(zero32, DH1||DH2, "…/root")
  store session at RK0 (initiator)
  hold EK_A_priv (memory only, 60 s)
  ── session:propose { ekPub = EK_A_pub } ───────►
                                                    DH1 = X25519(IK_B_priv, IK_A_pub)
                                                    DH2 = X25519(IK_B_priv, EK_A_pub)
                                                    RK0 = (same)        store session at RK0 (responder)
                                                    generate EK_B
                                                    DH3 = X25519(EK_B_priv, IK_A_pub)
                                                    DH4 = X25519(EK_B_priv, EK_A_pub)
                                                    RK1 = HKDF(RK0, DH3||DH4, "…/root-v2")
                                                    upgrade to RK1 (keep RK0, send under RK0)
  ◄─────────────── session:ack { ekPub = EK_B_pub } ──
  DH3 = X25519(IK_A_priv, EK_B_pub)
  DH4 = X25519(EK_A_priv, EK_B_pub)
  RK1 = HKDF(RK0, DH3||DH4, "…/root-v2")
  upgrade to RK1 (keep RK0, send under RK1)
  discard EK_A_priv
```

### 4.1 Propose (initiator)

Preconditions as in §3.3 (and the function itself re-checks that we are the fixed initiator and that the endpoint is known, refusing otherwise).

1. Generate `EK_A`. Compute `DH1`, `DH2`, `RK0` (§5.1).
2. `sessionEpoch` = new random UUID; `proposeTs` = `Date.now()` (one value, used for both storage and the packet's signed `ts`).
3. Hold `EK_A_priv` in a memory-only pending table keyed by `(contactId, theirDeviceId, sessionEpoch)`, discarded after 60 s by a **per-entry** timer. This is not a "give up" timeout: it bounds only the window for the opportunistic live upgrade. A genuinely offline device still receives and adopts the buffered propose later; it simply cannot get the `DH3/DH4` upgrade from this attempt.
4. Store the session at `RK0` (§6) with `initiator: true` and `proposeTs`. This replaces any existing session for that device (retiring its roots, §7.1).
5. Send:

```json
{ "type": "session:propose", "from": "<publicId>", "to": "<publicId>::<endpointId>",
  "sessionEpoch": "<uuid>", "ekPub": [...32], "deviceId": "<our deviceId>", "ts": <proposeTs>, "sig": [...] }
```

signed over `{ type, from, to, sessionEpoch, ekPub, deviceId, ts }` (see `protocol.md`), routed to the contact's relay with fallback to the main socket. The relay buffers it (overwrite per sender, 24 h TTL) as well as delivering live.

### 4.2 Receive propose (responder)

Checks, in order; any failure drops the packet:

1. `from`, `to`, `sessionEpoch`, `ekPub` present; `to` addresses us (bare id equals ours and endpoint equals ours).
2. Contact exists, not blocked, has an X25519 key.
3. Duplicate suppression: drop if `(from, deviceId, sessionEpoch)` was seen within 3 s. (A propose is buffered even when delivered live, so a brief reconnect can re-flush an already-handled one.)
4. Signature valid under the contact's signing key.
5. The sender must not be the fixed initiator's counterpart in reverse: drop if **we** are the fixed initiator toward `(from, deviceId)`.
6. Mark the sender online.
7. **Freshness guard** (§10): drop if a session for that device exists with a `proposeTs` and `msg.ts <= proposeTs`.

Then: compute `DH1`, `DH2`, `RK0` (§5.1), store the session at `RK0` with `initiator: false` and `proposeTs = msg.ts`, and — because a responder at `RK0` is send-ready at once (§7.2) — release anything held for that contact. If the sender's `endpointId` is known, complete the ack (below); otherwise park a deferred ack (§4.3).

**Complete ack.** Generate `EK_B`; `DH3`, `DH4`, `RK1` (§5.2); upgrade the session to `RK1` **only if it is still the session this propose created** (epoch match) with `sendStage = "rk0"`; if the upgrade is refused (a newer propose replaced it meanwhile) send nothing — acking a superseded epoch would leave the initiator holding an `RK1` we no longer have. Otherwise send `session:ack` (same shape, `ekPub = EK_B_pub`, own `deviceId`, `ts = now`, compound `to` at the sender's endpoint), signed likewise. The responder keeps `EK_B_priv` only as a local variable; it is not stored.

### 4.3 Deferred ack (the first-contact race)

The initiator proposes the moment it learns the responder's endpoint, which can precede the responder learning the initiator's — and an ack cannot be addressed without a compound `to`. So the responder parks the verified propose on its `RK0` session as `pendingAck = { ekPub: <initiator ephemeral public key, base64url>, receivedAt }`, and completes the ack as soon as the endpoint is learned (§3.3), provided **all** hold: the session is still at `rk0`, we are not the initiator, the same epoch is current, and no more than **30 s** (`X4DH_DEFERRED_ACK_WINDOW_MS`) have passed since `receivedAt`. Otherwise `pendingAck` is dropped and the session stays at `RK0` until the initiator retries (§9).

The 30 s window is half the initiator's 60 s ephemeral lifetime. A late ack would leave the responder at `RK1` and the initiator at `RK0`; the window keeps that from happening in practice. It must stay well below the proposal timeout. Only one completion runs per device at a time; if a newer propose parks its own `pendingAck` while a completion is running, that one is processed after.

### 4.4 Receive ack (initiator)

1. `from`, `to`, `sessionEpoch`, `ekPub` present; `to` addresses us; contact exists, not blocked; signature valid; mark online.
2. Look up the pending proposal by `(from, msg.deviceId, sessionEpoch)`. No match (stale, duplicate, already upgraded, or timed out) → drop.
3. The stored session for that device must have the same `sessionEpoch`; if not, discard the pending entry and drop.
4. `DH3 = X25519(IK_A_priv, EK_B_pub)`, `DH4 = X25519(EK_A_priv, EK_B_pub)`, `RK1` (§5.2). Upgrade the session to `RK1` with `sendStage = "rk1"` (the ack was built from `RK1`, so the responder provably holds it). Discard `EK_A_priv` at once rather than waiting for its timer.

---

## 5. Key Derivation

### 5.1 Stage 1 — `RK0` (offline-usable)

```text
IKM0 = DH1 || DH2
RK0  = HKDF( salt = zero32, ikm = IKM0, info = "MeshChat-X4DH-v1/root" )
```

Initiator: `DH1 = X25519(IK_A_priv, IK_B_pub)`, `DH2 = X25519(EK_A_priv, IK_B_pub)`. Responder: `DH1 = X25519(IK_B_priv, IK_A_pub)`, `DH2 = X25519(IK_B_priv, EK_A_pub)` — the same values.

### 5.2 Stage 2 — `RK1` (the live upgrade)

```text
IKM1 = DH3 || DH4
RK1  = HKDF( salt = RK0, ikm = IKM1, info = "MeshChat-X4DH-v1/root-v2" )
```

Initiator: `DH3 = X25519(IK_A_priv, EK_B_pub)`, `DH4 = X25519(EK_A_priv, EK_B_pub)`. Responder: `DH3 = X25519(EK_B_priv, IK_A_pub)`, `DH4 = X25519(EK_B_priv, EK_A_pub)`.

`RK0` is the **salt** of stage 2 (not re-derived from all four DH outputs), so `RK1` folds new DH material into the existing root. Both sides therefore compute `RK0` as a genuine intermediate; the responder computes both stages back-to-back on receiving the propose. Both info strings are fixed ASCII literals and versioned only to keep the two stages distinguishable; `sessionEpoch` and device identifiers are deliberately **not** mixed into the KDF — uniqueness comes from the fresh ephemerals, and the epoch/device metadata is authenticated by the signature (§10).

### 5.3 Wire key

```text
wireKey = HKDF( salt = zero32, ikm = rootKeyBytes, info = "MeshChat-X4DH-v1/wire-message" )   // → AES-256-GCM key
```

`rootKeyBytes` is whichever root a given generation holds (`RK0` or `RK1`). Derived wire keys are cached **by root content**, so a cache hit can never be stale. Message blobs under it are `v:2` envelope-bound (`protocol.md`).

---

## 6. Session Record and Storage

Local-only, identity-scoped (`meshchat_x4dh_sessions_v1_<publicId>`), **encrypted at rest** with the backup key (object blob), never included in any contact serialisation, backup or export, and removed by self-destruct. Shape: `contactId → theirDeviceId → record`.

```text
record = {
  sessionEpoch,
  stage:            "rk0" | "rk1",
  rootKey:          base64url (the newest root — RK1 once upgraded, else RK0),
  rk0Root?:         base64url (RK0 retained after upgrade, until the peer is confirmed to hold RK1),
  sendStage?:       "rk0" | "rk1"  (which root we encrypt under; absent = the current stage),
  initiator:        boolean,
  establishedAt:    local ms when RK0 was stored,
  upgradedAt:       local ms or null,
  proposeTs:        the originating propose's signed ts (the sender's clock),
  pendingAck?:      { ekPub, receivedAt }   (responder, §4.3),
  retryAttempts, retryExhaustedAt, lastRetryAt   (initiator retry budget, §9)
}
```

Storing a new `RK0` fully replaces the record **but carries `retryAttempts`, `retryExhaustedAt` and `lastRetryAt` forward** — they are per-(contact, device) budget, not per-epoch — and retires the replaced record's roots (§7.1). Reaching `RK1` resets the retry budget. `proposeTs` is the **sender's** clock, deliberately separate from `establishedAt` (our clock).

Held in memory only, never persisted: pending initiator ephemerals (`EK_A_priv`), the in-flight guards, retired roots, the wire-key cache.

**Write ordering and failure handling.** Session saves are serialised through a promise chain, and the snapshot is taken *inside* the queued step, so the last write in the queue always carries the freshest in-memory state. Without that, two overlapping saves could finish out of order and an older snapshot would overwrite a newer one. That damage stays invisible until a reload brings back a session at an older stage: an RK1 upgrade forgotten, a retired RK0 resurrected, a retry budget reset, and the two sides then disagree about which root is current. Every save also checks the persistence-halt flag that self-destruct raises (see `protocol.md`), at the last moment before writing, so a save that started before a wipe cannot finish after it and write the sessions back. If the stored blob fails to decrypt or parse, it is copied to `meshchat_x4dh_sessions_v1_<publicId>_unreadable` before loading falls back to an empty store. Nothing reads that copy back (recovery is manual), and self-destruct removes it.

---

## 7. Key Generations and Send-Readiness

### 7.1 Send under the newest root the peer has demonstrably reached; decrypt under every generation alive

The two sides of a pair can briefly disagree about which root is current: the responder upgrades to `RK1` before its ack is delivered; an ack can be lost (the initiator drops its ephemeral after 60 s); a reset replaces the session while the peer's packets are in flight. The rule that keeps this lossless:

- **Send root** = `rk0Root` if `stage == "rk1"` and `sendStage == "rk0"` and `rk0Root` exists, else `rootKey`.
- The **initiator** sends under `RK1` as soon as the ack lands.
- The **responder** keeps sending under `RK0` — which the initiator certainly holds — until a **verified** message from that device decrypts under our *current* `RK1`, proof the initiator upgraded. It then switches to `RK1`.
- **Confirmation** (`confirmX4DHPeerKey`): when a signature-verified message from a device decrypts under the session's current root and `stage == "rk1"`, set `sendStage = "rk1"` and retire `rk0Root` (below). Self-sync backup blobs carry no signature, but an AES-GCM success under `RK1` is the same proof of possession. Nothing ever switches the send key on an unverified packet.
- **Retired roots** — a root replaced by a reset or retired after confirmation — are kept **decrypt-only** for **120 s** (`X4DH_RETIRED_GRACE_MS`) in memory only, never persisted (so a reload drops them), then purged along with their cached wire keys (also swept every 30 s).
- **Decrypt keys** for a device, most likely first: current root, retained `rk0Root`, then retired roots newest first. The generation that matched is reported (`current` / `prev-rk0` / `retired`).

A lost ack therefore desyncs nothing: both sides stay on `RK0`, which both hold, until the stuck-retry (§9).

### 7.2 Send-readiness

A session is **send-ready** — we may encrypt content under it — when:

- `stage == "rk1"`; or
- `stage == "rk0"` and we are the **responder** (we hold a session only because the initiator's propose reached us, so the initiator certainly holds `RK0`; `sendStage` keeps us on that root); or
- `stage == "rk0"` and we are the **initiator** and more than **60 s** (`X4DH_PROPOSAL_TIMEOUT_MS`) have passed since `establishedAt`.

An initiator at `RK0` inside its handshake window is **not** ready: a message sent right after the propose can overtake it (the peer stores the session only after async work, and an offline peer's buffer is flushed in no order we control), and with no fallback key a message the peer cannot decrypt is a lost message. After the window the ack can no longer arrive, so an `RK0` session is what the stuck-retry logic sends under and counts as ready.

Consequently the first messages to a contact are held (`protocol.md`, Held Outbox) until a session is ready: immediately on the responder's side once the propose arrives, and for an initiator once the ack lands or its window closes.

---

## 8. Using a Session

**Encrypting.** For each targeted device with a send-ready session: derive the wire key for the send root (§7.1), seal the payload as a message blob `v:2` with `aad = envelopeAad("app:message", from, to)` where `to` is `"<contactId>::<endpointId>"`, sign `{ type, from, to, blob }`. Each device gets its own ciphertext. Nothing is encrypted for a device without a send-ready session, and there is no identity-level broadcast copy.

**Decrypting.** `deviceId` is inside the encrypted payload, so the receiver cannot know which key applies before decrypting. It tries, in order: every session held for that sender, most recently `establishedAt` first; within each session every live generation (§7.1); then, last, the static pairwise key. AES-GCM's tag makes a wrong-key attempt fail cleanly, so this costs a few rejected decrypts and never a false positive. On success under a session key, the payload's `deviceId` must equal that session's device; a mismatch is treated like an invalid signature (flagged, unverified). Only a verified decrypt under the current `RK1` triggers confirmation (§7.1).

**The static key** is accepted for exactly one content type: `hello`. A static-key `app:message` of any other type is dropped before it touches any local state.

**Out of scope for session keys, permanently:** `app:migrate`, `app:burn`, `call:*`, `data:*`, `app:sync` — none is device-targeted infrastructure, so there is no single device pair to key against.

**Self-sync** between an identity's own devices rides the same keys: mirrored copies of outgoing messages (`selfsync`, ordinary `app:message`s through the same fanout, session-only) and full self-backup pushes (object blob `v:3`, receiver trial-decrypts every self-session wire key newest first, then the backup key last, and cross-checks the payload's `deviceId` against the session that decrypted it). The deterministic backup key remains in two places: the content-free discovery hello/ack, and acceptance of a full push from a sibling that used the static backup key.

A brand-new device has no session, so it receives contacts through the first push after its session exists; a genuinely wiped device restores through the restore handshake (`protocol.md`), not this path.

---

## 9. Stuck Detection and Retry

A session can be left at `RK0` (a dropped `session:ack` is the usual cause). Absence of an ack is normal when the peer is simply offline, so "stuck" needs a real signal: **presence**. Detection runs only from the "mark online" step, i.e. only when the contact has just been seen online.

**Detection.** For each session of that contact with `stage == "rk0"` and `now − establishedAt` ≥ **120 s** (`X4DH_STUCK_RK0_THRESHOLD_MS` = 2 × the proposal timeout, so it is cleanly separated from the moment the pending ephemeral expires), log a warning — at most once per 5 minutes per session. The shape is told by `initiator`: `true` = we proposed and never got an ack; `false` = we received a propose but never acked (endpoint unknown at the time).

**Automatic retry** is gated separately, on genuine **offline→online transitions** only — never on routine re-confirmation of an already-online peer, never on a raw timer — and only for the initiator shape (nothing on a responder's own device can fix that shape; it self-heals once ordinary traffic teaches it the missing endpoint, §3.3).

```text
maybeAutoRetry(contact, device, session):          // on a genuine transition
  if !session.initiator: return
  if session.retryExhaustedAt:                     // this transition re-arms the budget
      retryAttempts = 0; retryExhaustedAt = null
  if retryAttempts >= 10:                          // the 10th retry itself is never suppressed
      retryExhaustedAt = now; warn "retries exhausted"; return
  ok = retry(contact, device)                      // see below
  if !ok: return                                   // a refusal costs nothing from the budget
  fresh = current session record                   // the retry replaced the record
  fresh.retryAttempts = attempts + 1; fresh.lastRetryAt = now
```

**Retry** is simply a fresh propose: refused unless a session exists, is at `stage == "rk0"`, and we are the fixed initiator; otherwise it runs §4.1 again, producing a new `sessionEpoch` and fresh ephemerals, so a superseded session's wire key can never be reproduced. Session bootstrap and session reset are the same mechanism. A retry replaces the session, so the old roots go to the decrypt-only grace (§7.1) and the retry counters carry forward (§6).

There is no time-based or message-count-based rotation: a healthy session runs on a static key until something knocks it loose.

---

## 10. Replay and State Rules

`session:propose` and `session:ack` are stateful. A client must at minimum ensure:

1. `sessionEpoch` is unique per locally initiated session.
2. A propose/ack comes from the expected sender identity; its signed contents cannot be modified without invalidating the signature.
3. An ack belongs to the pending proposal with the same `(contact, device, sessionEpoch)`.
4. An ephemeral private key is never reused for another session.
5. An already-consumed handshake cannot silently create a second session (the epoch checks above).
6. Conflicting states are resolved deterministically — by the fixed-initiator rule (§3.1) and the freshness guard below.

**Signature binding.** The signature authenticates the ephemeral key and the session/device metadata from which the root derives, binding the session to the claimed identity and device pair. The device half is an **identity-authenticated claim**: `deviceId` is asserted under the *identity* key's signature, not proven with a separate device key. Anyone holding the identity key could sign a propose claiming any `deviceId`; that is inside the trust model, but it is not device-key attestation.

**Freshness guard (state-rollback protection).** A responder refuses a propose whose signed `ts` is not **strictly newer** than the stored `proposeTs` for that device. Both values are the sender's clock, deliberately, so ordinary cross-device skew cannot read as a replay. It is downgrade protection, not authentication and not cryptographic replay prevention, with two consequences:

- With no session record (after a wipe, a burn, or loss of session storage) there is nothing to compare, so a replayed propose is not stopped. The likely outcome is a desynchronised session that stuck detection and retry repair; it does not disclose key material.
- If a sender's clock is ever far ahead when a propose is adopted, its later legitimate proposes (including automatic retries, which stamp `Date.now()`) are refused as stale until real time catches up. No plausibility bound on `ts` exists. The symptom is a session stuck at `RK0` with retries dropped on the receiving side.

The relay may deliver packets more than once or out of order; propose dedup (§4.2, step 3), the epoch checks and this guard are the minimum for that.

---

## 11. Security Properties and Limits

### 11.1 The initial asymmetry

`EK_A_pub` is sent in the clear. `DH2 = X25519(EK_A, IK_B)` never uses `IK_A`, so a later compromise of Alice's identity key alone cannot reconstruct `DH2` and therefore not `RK0`. A later compromise of **Bob's** identity key reconstructs both `DH1` and `DH2` (`EK_A_pub` is public) and therefore `RK0` in full. So the 2DH bootstrap protects the **initiator's** identity key against a future leak and not the responder's — a direct consequence of only the initiator contributing an ephemeral at message zero. This is the gap the live upgrade closes for both sides: `DH4 = X25519(EK_A, EK_B)` involves neither identity key, so `RK1` cannot be reconstructed from a later compromise of either (`DH3` alone only mirrors `DH2`'s asymmetry the other way).

`RK0` is nevertheless accepted for wire encryption (§7.2): per-device-pair separation is itself an improvement over an identity-wide static key, and the offline responder is the ordinary case, not an edge case. A session that completes the upgrade gains the stronger property with no re-keying step: the next derivation simply picks up the new root.

`DH1` is identity-level, not device-level: it is the identical value for every device pair between two identities. A later compromise of an identity key therefore breaks every `RK0`-only session that identity ever bootstrapped with that contact at once; an upgraded session is unaffected, which is why the opportunistic upgrade matters.

### 11.2 What `RK1`'s forward secrecy claims

`RK1` (and the wire key derived from it) cannot be reconstructed from a later compromise of either party's identity key. This is *session-level forward secrecy against later identity-key compromise*, with these qualifiers:

- **Only traffic after the upgrade.** Messages sent under `RK0` before the upgrade (or forever, if it never happens) stay exposed to a later leak of the responder's identity key. The upgrade is not retroactive.
- **Depends on both ephemeral private keys being erased.** The initiator holds `EK_A_priv` in memory until the ack lands or times out; the responder's `EK_B_priv` is a local variable that goes out of scope. In JavaScript neither is zeroised — dropped and left to the garbage collector, so erasure is best-effort.
- **Static per session, not per message.** There is no ratchet and no post-compromise recovery: whoever obtains a session's root key can read that session's traffic until the session resets.
- **The root key is stored on the device**, encrypted with a key derived from the passphrase. An attacker with both the device storage and the passphrase obtains it directly. That is normal for at-rest state and does not contradict the claim above, which is about network-recorded traffic plus a later identity-key leak.

### 11.3 Not covered by sessions

The static pairwise key (HELLO, `app:migrate`, call/data SDP and ICE blobs, `restore_req`) is not forward-secret. Calls, data-channel tests, relay migration and burn notices have no session to ride, permanently. Metadata (who talks to whom, timing, sizes, endpoint ids) is visible to relays. X4DH has had no formal analysis and should be treated as experimental.

---

## 12. Constants

| Constant | Value | Meaning |
|---|---|---|
| `X4DH_PROPOSAL_TIMEOUT_MS` | 60 000 | Life of `EK_A_priv` awaiting an ack; also the initiator's send-ready window |
| `X4DH_DEFERRED_ACK_WINDOW_MS` | 30 000 | Max age of a parked propose when its deferred ack may still be completed |
| `X4DH_RETIRED_GRACE_MS` | 120 000 | Decrypt-only life of a replaced/retired root |
| `X4DH_STUCK_RK0_THRESHOLD_MS` | 120 000 | Time at `RK0` (with the peer seen online) before a session is called stuck |
| stuck log cooldown | 300 000 | Per-session limit on stuck warnings |
| `MAX_X4DH_RETRY_ATTEMPTS` | 10 | Automatic retries per (contact, device) before exhaustion; re-armed by the next offline→online transition |
| propose dedup window | 3 000 | Duplicate suppression on `(from, deviceId, sessionEpoch)` |

HKDF labels: `MeshChat-X4DH-v1/root`, `MeshChat-X4DH-v1/root-v2`, `MeshChat-X4DH-v1/wire-message` (all fixed ASCII literals).

---

*MeshChat X4DH — implementation 0.6.2 — experimental*