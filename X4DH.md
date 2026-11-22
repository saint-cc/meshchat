# X4DH — MeshChat Session Establishment

> **MeshChat X4DH is a MeshChat-specific 2DH/4DH session-establishment construction. It is not Signal's X3DH and does not use signed or one-time prekeys. It has not been formally analysed or independently audited.**
>
> **What the session gives you, precisely:** session-level forward secrecy against a *later* compromise of either identity key, for traffic sent *after* the live upgrade to `RK1` completes; and, since 0.8.0, per-message forward secrecy against a later copy of the *stored session state* (a symmetric chain, no DH ratchet). It has **no post-compromise recovery**, and `RK0` (the async-only stage) has neither property in full. The exact scope and qualifiers are in §11.2 — read that before quoting these properties anywhere.
>
> **Hybrid post-quantum (0.7.1).** From 0.7.1 the `RK1` upgrade also mixes in an ML-KEM-768 shared secret (§5.2, §11.3). That protects the confidentiality of `RK1` traffic against a recorded-now, broken-later X25519 — it does **not** make `RK0` post-quantum, and identity signatures stay classical. Every `RK1` is hybrid: a propose without a KEM key, or an ack without a ciphertext, is dropped (§4.2, §4.4); there is no classical `RK1`.
>
> **Symmetric chain ratchet (0.8.0, "R1").** Each root (`RK0`, `RK1`) is expanded once into two one-way hash chains, one per direction, and every `app:message` is encrypted under its own one-time key from the sender's chain (§5.3–§5.5). The raw root is then deleted (`RK0` stays until the upgrade, §6). This is **not** a Double Ratchet: no DH or KEM step is mixed in after the session is established, so an attacker who copies the live session state can follow the chains forward until the session resets. Those steps (R2, R3) are separate, later work. Self-backup traffic carries no chain header and keeps a static key (§8.3). **Status:** first live tests on meshdev are good; skipped-key delivery, replay and rewound-sender handling, the strike → drop → re-establish path and the in-place conversion of pre-0.8.0 sessions are covered by an offline test harness only and have not been observed live.

X4DH establishes a cryptographic session between **two specific devices** and yields the root keys from which the one-time AES-256-GCM keys for all `app:message` content between them are derived (§5.3–§5.5). It establishes a usable session immediately when the responder is offline, and opportunistically upgrades that session when both devices are online.

This document specifies the cryptography and the state machine. `protocol.md` specifies the surrounding wire protocol (envelopes, routing, the held outbox, HELLO). Implementation version `0.8.0`.

**Session-only content.** Every message that carries content is encrypted under a one-time message key from a session's chain (§5.4) and under nothing else. There is no fallback to any identity-level key: if no send-ready session exists with a device (§7.2), content is not sent to it. The one thing the identity-level static key still carries is the content-free HELLO (`protocol.md`), which exists to give the two sides what this handshake needs (§3.3).

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
        per-direction chains → one-time AES-256-GCM message keys
```

- **Asynchronous by default.** The initiator derives `RK0` from material it already holds and can send it immediately; the responder need not be online.
- **No key server.** The relay never holds or sees key material; it transports `session:propose`/`session:ack` and buffers them.
- **Opportunistic strengthening.** If the responder is online, its fresh ephemeral upgrades the session to `RK1`. The live path is an upgrade, never a requirement.
- **Hybrid from `RK1`.** The live upgrade adds an ML-KEM-768 encapsulation on top of the two X25519 inputs, so `RK1` holds if either X25519 or ML-KEM holds (§11.3). `RK0` stays classical.
- **Device-specific.** `Alice::Laptop ↔ Bob::Phone` and `Alice::Desktop ↔ Bob::Phone` are separate sessions. `deviceId` is an identifier, not key material and not secret.
- **A symmetric chain ratchet, not a Double Ratchet.** Since 0.8.0 every message has its own key, derived from a per-direction hash chain and deleted after use (§5.4). No Diffie-Hellman or KEM step happens after establishment, so there is no post-compromise recovery: the chains are replaced only when the session itself resets (§9).

What is stored on the device is the chain state (and, at `RK0`, the root), not a standing key: a stored session cannot re-derive a message key that has been used and deleted (§6, §11.2).

---

## 2. Notation and Primitives

| Symbol | Meaning |
|---|---|
| `IK_X` | identity X25519 key pair of party X (`IK_X_priv` is the scalar from `meshchat-v2:x25519`; `IK_X_pub` is in the shareable address) |
| `EK_A`, `EK_B` | fresh one-time X25519 ephemeral key pairs of initiator A and responder B |
| `DHn` | 32-byte X25519 shared secret |
| `zero32` | 32 zero bytes |
| `kemPub`, `kemSk` | ML-KEM-768 (FIPS 203) key pair generated by the initiator per proposal; `kemPub` is 1184 bytes |
| `kemCt`, `SS_KEM` | ML-KEM-768 ciphertext (1088 bytes) from encapsulating to `kemPub`, and the 32-byte shared secret |
| `TH` | `SHA-256(kemPub ‖ kemCt)`, the transcript hash binding the exact KEM exchange |
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
  generate (kemPub, kemSk)
  hold EK_A_priv, kemSk (memory only, 60 s)
  ── session:propose { ekPub = EK_A_pub, kemPub } ►
                                                    DH1 = X25519(IK_B_priv, IK_A_pub)
                                                    DH2 = X25519(IK_B_priv, EK_A_pub)
                                                    RK0 = (same)        store session at RK0 (responder)
                                                    generate EK_B
                                                    (SS_KEM, kemCt) = Encaps(kemPub)
                                                    DH3 = X25519(EK_B_priv, IK_A_pub)
                                                    DH4 = X25519(EK_B_priv, EK_A_pub)
                                                    RK1 = HKDF(RK0, DH3||DH4||SS_KEM||TH, "…/root-v3")
                                                    upgrade to RK1 (keep RK0, send under RK0)
  ◄───── session:ack { ekPub = EK_B_pub, kemCt } ──
  DH3 = X25519(IK_A_priv, EK_B_pub)
  DH4 = X25519(EK_A_priv, EK_B_pub)
  SS_KEM = Decaps(kemCt, kemSk)
  RK1 = HKDF(RK0, DH3||DH4||SS_KEM||TH, "…/root-v3")
  upgrade to RK1 (keep RK0, send under RK1)
  discard EK_A_priv, kemSk
```

The diagram shows the only path there is: every session is hybrid.

### 4.1 Propose (initiator)

Preconditions as in §3.3 (and the function itself re-checks that we are the fixed initiator and that the endpoint is known, refusing otherwise).

1. Generate `EK_A` and an ML-KEM-768 key pair `(kemPub, kemSk)`. Compute `DH1`, `DH2`, `RK0` (§5.1).
2. `sessionEpoch` = new random UUID; `proposeTs` = `Date.now()` (one value, used for both storage and the packet's signed `ts`).
3. Hold `EK_A_priv`, `kemSk` and `kemPub` in a memory-only pending table keyed by `(contactId, theirDeviceId, sessionEpoch)`, discarded after 60 s by a **per-entry** timer, which also zeroes `kemSk`. This is not a "give up" timeout: it bounds only the window for the opportunistic live upgrade. A genuinely offline device still receives and adopts the buffered propose later; it simply cannot get the `DH3/DH4` upgrade from this attempt.
4. Store the session at `RK0` (§6) with `initiator: true` and `proposeTs`. This replaces any existing session for that device (retiring its generations, §7.1).
5. Send:

```json
{ "type": "session:propose", "from": "<publicId>", "to": "<publicId>::<endpointId>",
  "sessionEpoch": "<uuid>", "ekPub": "<base64url: 32 bytes>", "kemPub": "<base64url: 1184 bytes>", "deviceId": "<our deviceId>", "ts": <proposeTs>, "sig": "<base64url: 64 bytes>" }
```

signed over `{ type, from, to, sessionEpoch, ekPub, deviceId, ts, kemPub }` — `kemPub` last and only when present (see `protocol.md`), so a relay cannot strip it, routed to the contact's relay with fallback to the main socket. The relay buffers it (overwrite per sender, 24 h TTL) as well as delivering live.

### 4.2 Receive propose (responder)

Checks, in order; any failure drops the packet:

1. `from`, `to`, `sessionEpoch`, `ekPub` present; `to` addresses us (bare id equals ours and endpoint equals ours).
2. Contact exists, not blocked, has an X25519 key.
3. Duplicate suppression: drop if `(from, deviceId, sessionEpoch)` was seen within 3 s. (A propose is buffered even when delivered live, so a brief reconnect can re-flush an already-handled one.)
4. Signature valid under the contact's signing key.
5. The sender must not be the fixed initiator's counterpart in reverse: drop if **we** are the fixed initiator toward `(from, deviceId)`.
6. Mark the sender online.
7. **Freshness guard** (§10): drop if a session for that device exists with a `proposeTs` and `msg.ts <= proposeTs`.
8. **`kemPub`** (required): must be present, decode to exactly 1184 bytes and pass a trial encapsulation (which checks the key's modulus); otherwise drop, before anything is stored. A propose without `kemPub` (a classical initiator) is dropped — there is no classical `RK1`.

Then: compute `DH1`, `DH2`, `RK0` (§5.1), store the session at `RK0` with `initiator: false` and `proposeTs = msg.ts`, and — because a responder at `RK0` is send-ready at once (§7.2) — release anything held for that contact. If the sender's `endpointId` is known, complete the ack (below); otherwise park a deferred ack (§4.3).

**Complete ack.** Generate `EK_B` and encapsulate to the propose's `kemPub` (`SS_KEM`, `kemCt`; a failure here sends nothing); `DH3`, `DH4`, `RK1` (§5.2); upgrade the session to `RK1` **only if it is still the session this propose created** (epoch match) with `sendStage = "rk0"`; if the upgrade is refused (a newer propose replaced it meanwhile) send nothing — acking a superseded epoch would leave the initiator holding an `RK1` we no longer have. Otherwise send `session:ack` (same shape, `ekPub = EK_B_pub`, `kemCt`, own `deviceId`, `ts = now`, compound `to` at the sender's endpoint), signed likewise. The responder keeps `EK_B_priv` and `SS_KEM` only as local values (`SS_KEM` is zeroed after use); neither is stored. `pq` is set on the session when `RK1` is reached (§6).

### 4.3 Deferred ack (the first-contact race)

The initiator proposes the moment it learns the responder's endpoint, which can precede the responder learning the initiator's — and an ack cannot be addressed without a compound `to`. So the responder parks the verified propose on its `RK0` session as `pendingAck = { ekPub: <initiator ephemeral public key, base64url>, kemPub: <base64url>, receivedAt }`, and completes the ack as soon as the endpoint is learned (§3.3), provided **all** hold: the session is still at `rk0`, we are not the initiator, the same epoch is current, and no more than **30 s** (`X4DH_DEFERRED_ACK_WINDOW_MS`) have passed since `receivedAt`. Otherwise `pendingAck` is dropped and the session stays at `RK0` until the initiator retries (§9).

The 30 s window is half the initiator's 60 s ephemeral lifetime. A late ack would leave the responder at `RK1` and the initiator at `RK0`; the window keeps that from happening in practice. It must stay well below the proposal timeout. Only one completion runs per device at a time; if a newer propose parks its own `pendingAck` while a completion is running, that one is processed after.

### 4.4 Receive ack (initiator)

1. `from`, `to`, `sessionEpoch`, `ekPub` present; `to` addresses us; contact exists, not blocked; signature valid; mark online.
2. Look up the pending proposal by `(from, msg.deviceId, sessionEpoch)`. No match (stale, duplicate, already upgraded, or timed out) → drop.
3. The stored session for that device must have the same `sessionEpoch`; if not, discard the pending entry and drop.
4. If the ack carries `kemCt`: it must decode to exactly 1088 bytes (and we must still hold `kemSk`), else drop. Decapsulate. **The signature was verified in step 1, and that order matters:** ML-KEM decapsulation implicitly rejects, so a forged `kemCt` does not fail — it silently yields a different secret and a desynchronised session. An ack without `kemCt` (a classical responder) is dropped and the pending proposal is left to expire.
5. `DH3 = X25519(IK_A_priv, EK_B_pub)`, `DH4 = X25519(EK_A_priv, EK_B_pub)`, `RK1` (§5.2). Upgrade the session to `RK1` with `sendStage = "rk1"` (the ack was built from `RK1`, so the responder provably holds it) and `pq = true` iff the KEM was used. Discard and zero `EK_A_priv`/`kemSk` at once rather than waiting for the timer.

---

## 5. Key Derivation

### 5.1 Stage 1 — `RK0` (offline-usable)

```text
IKM0 = DH1 || DH2
RK0  = HKDF( salt = zero32, ikm = IKM0, info = "MeshChat-X4DH-v1/root" )
```

Initiator: `DH1 = X25519(IK_A_priv, IK_B_pub)`, `DH2 = X25519(EK_A_priv, IK_B_pub)`. Responder: `DH1 = X25519(IK_B_priv, IK_A_pub)`, `DH2 = X25519(IK_B_priv, EK_A_pub)` — the same values.

### 5.2 Stage 2 — `RK1` (the live upgrade, always hybrid)

```text
TH   = SHA-256( kemPub || kemCt )
IKM1 = DH3 || DH4 || SS_KEM || TH
RK1  = HKDF( salt = RK0, ikm = IKM1, info = "MeshChat-X4DH-v1/root-v3" )
```

Initiator: `DH3 = X25519(IK_A_priv, EK_B_pub)`, `DH4 = X25519(EK_A_priv, EK_B_pub)`. Responder: `DH3 = X25519(EK_B_priv, IK_A_pub)`, `DH4 = X25519(EK_B_priv, EK_A_pub)`. `SS_KEM` is the 32-byte ML-KEM-768 shared secret.

`TH` goes into the **IKM**, not into `info`, because info strings stay fixed ASCII literals; it binds the derivation to the exact public key and ciphertext used, so the two sides cannot agree on a key while disagreeing about the KEM exchange. There is no classical derivation any more (the earlier `root-v2` form, `DH3 || DH4` only, was removed).

`RK0` is the **salt** of stage 2 (not re-derived from all four DH outputs), so `RK1` folds new DH and KEM material into the existing root. Both sides therefore compute `RK0` as a genuine intermediate; the responder computes both stages back-to-back on receiving the propose. All info strings are fixed ASCII literals and versioned only to keep the derivations distinguishable; `sessionEpoch` and device identifiers are deliberately **not** mixed into the KDF — uniqueness comes from the fresh ephemerals, and the epoch/device metadata is authenticated by the signature (§10).

### 5.3 Generation material

A **generation** is the key material derived from one root: generation 0 from `RK0`, generation 1 from `RK1`. The first time a generation is needed its root is expanded **once**:

```text
aux    = HKDF( zero32, root, "MeshChat-X4DH-v1/wire-message" )    // static AES-256 key, §8.3
CK_i2r = HKDF( zero32, root, "MeshChat-R1-v1/chain/i2r" )         // chain seed, initiator → responder
CK_r2i = HKDF( zero32, root, "MeshChat-R1-v1/chain/r2i" )         // chain seed, responder → initiator
TK_i2r = HKDF( zero32, root, "MeshChat-R1-v1/tag/i2r" )           // tag key, same direction
TK_r2i = HKDF( zero32, root, "MeshChat-R1-v1/tag/r2i" )
```

and the raw root is then **deleted**: a stored session must not be able to re-derive keys that were already used and thrown away. The one exception is `RK0` while the session is still at stage `rk0`, because stage 2 uses it as its salt (§5.2); it is deleted when the upgrade runs, after generation 0 has been built. The initiator's send chain is `i2r` and its receive chain `r2i`; the responder's are the other way round, so one side's send chain is always the other's receive chain, and the two directions never share positions.

### 5.4 The symmetric chain

Each chain is a sequence of keys `CK_0, CK_1, …` starting at the seed:

```text
MK_i     = HMAC-SHA256( CK_i, 0x01 )     // the message key for position i: AES-256-GCM, used once, then deleted
CK_(i+1) = HMAC-SHA256( CK_i, 0x02 )     // replaces CK_i; CK_i is not kept
```

So a stored chain key can produce only messages that have **not** been sent (sender) or received (receiver) yet. The sender spends position `i` when it takes `MK_i`; the receiver, on a verified message at position `i` beyond its own, derives forward, **stores the keys of the positions it skipped** (§8.2) and keeps `CK` for `i + 1`.

### 5.5 Message blob and header

An `app:message` content blob is `v:3`:

```json
{ "v": 3, "h": { "g": 1, "i": 17, "t": "<base64url: 6 bytes>" }, "iv": "<base64url: 12 bytes>", "data": "<base64url>" }
```

- `g` — generation (`0` = `RK0`, `1` = `RK1`); `i` — chain position (integer, `0 … 2^31 − 1`).
- `t` — the **tag**: the first 6 bytes of `HMAC-SHA256( TK, u32be(i) )`. Only the two ends of this chain can compute it. It differs for every message, so it links nothing for a relay (unlike a per-session identifier, which would reveal which device sent what), and it lets the receiver find the right session without trial decryption and without any chain work for a packet that is not its own. A forged packet has no `TK`, so it cannot make the receiver derive thousands of chain steps.
- The header is parsed strictly: exactly these three fields, nothing else.
- `aad = UTF-8( JSON [ "meshchat-chain-v1", type, from, to, g, i ] )`, so a packet retyped, reflected, redirected, or given another generation or position no longer decrypts. The envelope signature covers the whole blob, header included (`protocol.md`).

Blob `v:2` (the envelope-bound form under the static pairwise key) is still used for the HELLO and nothing else (§8.2).

---

## 6. Session Record and Storage

Local-only, identity-scoped (`meshchat_x4dh_sessions_v1_<publicId>`), **encrypted at rest** with the backup key (object blob), never included in any contact serialisation, backup or export, and removed by self-destruct. Shape: `contactId → theirDeviceId → record`.

```text
record = {
  sessionEpoch,
  stage:            "rk0" | "rk1"   (which generation is the current, newest one),
  sendStage?:       "rk0" | "rk1"   (which generation we encrypt under; absent = the current stage),
  rootKey?:         base64url — present ONLY while stage is "rk0" (stage 2 needs RK0 as its salt, §5.2); deleted at the upgrade,
  gens:             { 0|1: {                                  // §5.3; gen 0 is built lazily at stage rk0
                        aux:  base64url (static key, §8.3),
                        s:    { k, n, tk }                    // SEND chain: next chain key, next position, tag key
                        r:    { k, n, tk, sk, seen }          // RECEIVE chain: next chain key, next expected position, tag key,
                                                              //   sk   = skipped message keys [[i, key, storedAtMs], …]
                                                              //   seen = last consumed positions [[i, iv], …]
                      } },
  initiator:        boolean,
  establishedAt:    local ms when RK0 was stored,
  upgradedAt:       local ms or null,
  pq?:              true on every rk1 record (a record at rk1 without it is dropped at load),
  proposeTs:        the originating propose's signed ts (the sender's clock),
  pendingAck?:      { ekPub, kemPub, receivedAt }   (responder, §4.3; both public values),
  retryAttempts, retryExhaustedAt, lastRetryAt   (initiator retry budget, §9)
}
```

Storing a new `RK0` fully replaces the record **but carries `retryAttempts`, `retryExhaustedAt` and `lastRetryAt` forward** — they are per-(contact, device) budget, not per-epoch — and retires the replaced record's generations (§7.1). Reaching `RK1` resets the retry budget. `proposeTs` is the **sender's** clock, deliberately separate from `establishedAt` (our clock).

Held in memory only, never persisted: pending initiator ephemerals (`EK_A_priv`, `kemSk`), the in-flight guards, retired generations (with their receive chains), the aux-key cache, the chain-strike counters (§9.1).

**Sessions before 0.8.0** stored raw roots (`rootKey`, `rk0Root`). They are converted in place at load — the derivation is deterministic and identical on both sides, so no handshake is needed — and the raw roots are deleted; a record that is not in a usable shape afterwards is dropped and re-established the ordinary way. A pre-0.8.0 *peer* is a different matter: it still sends `v:2` session-key messages, which a 0.8.0 client does not decrypt. The message change is a hard cutover (`known-limitations.md`).

**Write ordering and failure handling.** Session saves are serialised through a promise chain, and the snapshot is taken *inside* the queued step, so the last write in the queue always carries the freshest in-memory state. Without that, two overlapping saves could finish out of order and an older snapshot would overwrite a newer one. That damage stays invisible until a reload brings back a session at an older stage: an RK1 upgrade forgotten, a retired RK0 resurrected, a retry budget reset, and the two sides then disagree about which root is current. Every save also checks the persistence-halt flag that self-destruct raises (see `protocol.md`), at the last moment before writing, so a save that started before a wipe cannot finish after it and write the sessions back. If the stored blob fails to decrypt or parse, it is copied to `meshchat_x4dh_sessions_v1_<publicId>_unreadable` before loading falls back to an empty store. Nothing reads that copy back (recovery is manual), and self-destruct removes it.

**Chain persistence (0.8.0).** A chain position, once spent or consumed, must never be reused or forgotten, so two orderings are fixed. *Sending:* a position is spent in memory when its key is taken, and the packet goes out only after the write that records the spend has landed — all targets of one send take their keys first, then **one** awaited session write, then the packets. If that write fails nothing goes out (the positions stay spent; the receiver sees a gap). Without this a reload would hand the same position to a different plaintext, and the peer, who already deleted that key, could not read it. *Receiving:* the envelope signature is verified **before** decryption and a chain advances only for a verified packet; the message is saved (contacts) **before** the session write that records its consumed key, and the delivery ack goes out after both. A crash between the two writes re-delivers rather than loses. The advance itself happens in memory at decrypt, so an unrelated session write in that moment can persist it early; that window is the processing time of one packet and is accepted. All chain reads and writes of one session run under a per-session lock, so a position is never spent twice and two concurrent receives cannot both advance the chain.

---

## 7. Key Generations and Send-Readiness

### 7.1 Send under the newest generation the peer has demonstrably reached; decrypt under every generation alive

The two sides of a pair can briefly disagree about which generation is current: the responder upgrades to `RK1` before its ack is delivered; an ack can be lost (the initiator drops its ephemeral after 60 s); a reset replaces the session while the peer's packets are in flight. The rule that keeps this lossless:

- **Send generation** = 0 if `stage == "rk1"` and `sendStage == "rk0"` and generation 0 still exists, else the current one (`stage`).
- The **initiator** sends under generation 1 as soon as the ack lands.
- The **responder** keeps sending under generation 0 — which the initiator certainly holds — until a **verified** message from that device decrypts under our *current* generation 1, proof the initiator upgraded. It then switches to generation 1.
- **Confirmation** (`confirmX4DHPeerKey`): when a signature-verified message from a device decrypts under the session's current generation and `stage == "rk1"`, set `sendStage = "rk1"` and retire generation 0 (below). The self-backup blobs of §8.3 carry no signature, but an AES-GCM success under generation 1's aux key is the same proof of possession. Nothing ever switches the send generation on an unverified packet.
- **Retired generations** — those replaced by a reset or retired after confirmation — keep their aux key **and their receive chain** (skipped keys included), **decrypt-only**, for **120 s** (`X4DH_RETIRED_GRACE_MS`) in memory only, never persisted (so a reload drops them), then are purged along with their cached keys (also swept every 30 s).
- **Candidates** for a received packet, most likely first: the current generation, the retained generation 0, then retired generations newest first. For a chain message the header's `g` narrows this to the generations with that number, and the tag (§5.5) to at most one chain. The generation that matched is reported (`current` / `prev-rk0` / `retired`).

A lost ack therefore desyncs nothing: both sides stay on generation 0, which both hold, until the stuck-retry (§9).

### 7.2 Send-readiness

A session is **send-ready** — we may encrypt content under it — when:

- `stage == "rk1"`; or
- `stage == "rk0"` and we are the **responder** (we hold a session only because the initiator's propose reached us, so the initiator certainly holds `RK0`; `sendStage` keeps us on that generation); or
- `stage == "rk0"` and we are the **initiator** and more than **60 s** (`X4DH_PROPOSAL_TIMEOUT_MS`) have passed since `establishedAt`.

An initiator at `RK0` inside its handshake window is **not** ready: a message sent right after the propose can overtake it (the peer stores the session only after async work, and an offline peer's buffer is flushed in no order we control), and with no fallback key a message the peer cannot decrypt is a lost message. After the window the ack can no longer arrive, so an `RK0` session is what the stuck-retry logic sends under and counts as ready.

Consequently the first messages to a contact are held (`protocol.md`, Held Outbox) until a session is ready: immediately on the responder's side once the propose arrives, and for an initiator once the ack lands or its window closes.

---

## 8. Using a Session

### 8.1 Encrypting

For each targeted device with a send-ready session (§7.2), in order:

1. **Durability gate.** If the last session write failed, nothing is encrypted under session keys until storage works (§6).
2. **Take a key.** Under the session's lock: pick the send generation (§7.1), read the next position `i`, derive `MK_i` and `CK_(i+1)` and the tag, store `CK_(i+1)` and `i + 1` — in memory — and return `MK_i`.
3. **Seal.** Encrypt the payload as a `v:3` chain blob (§5.5) with `aad` over `[type, from, to, g, i]` where `to` is `"<contactId>::<endpointId>"`, sign `{ type, from, to, blob }`, zero `MK_i`.
4. **Persist, then send.** After *all* targets have taken their keys, one awaited session write records the spent positions; only then do the packets go out (§6). If the write fails nothing is sent.

Each device gets its own ciphertext under its own key. Nothing is encrypted for a device without a send-ready session, and there is no identity-level broadcast copy. A copy that turns out too large for the relay's frame cap is dropped after its position was spent; the receiver sees a gap.

### 8.2 Decrypting

1. **Verify the envelope signature first.** A chain advances only for a packet whose signature verified (below); the verdict is needed before anything is opened.
2. **Header.** A `v:3` blob's header is parsed strictly (§5.5) and the `aad` rebuilt from the envelope *as received*. A malformed header is an error. A `v:2` blob is opened under the static pairwise key and accepted only if it is a `hello`; anything else that arrives that way is dropped before it touches any local state.
3. **Find the chain.** For each session held for that sender (most recently established first) and each candidate generation (§7.1) with the header's `g`: compute the tag for position `i` from that chain's receive tag key and compare it with `t`. A mismatch is "not this chain" and costs one HMAC. A match means this *is* the sender's chain; no other candidate is tried.
4. **Open.**
   - `i` ahead of the chain's next position: derive forward on a **copy**, at most `2000` steps (`CHAIN_MAX_FORWARD`; further is refused), keep the keys of the skipped positions (the newest `100`, `CHAIN_SKIP_KEEP`), then open with `MK_i`.
   - `i` behind it: use the stored skipped key if there is one; if there is none, the position was already consumed.
5. **Commit.** Only if the AEAD tag passed **and** the signature verified (step 1) does the chain advance, skipped keys get stored (dropped again after 24 h, `CHAIN_SKIP_TTL_MS` — the relay buffer's lifetime) and the position is recorded with its `iv` in the `seen` list (the last `32`). A packet that opens but whose signature did not verify is returned without changing any state.
6. **Replays.** A consumed position seen again with the **same** `iv` is a re-delivery and is dropped quietly. The same position with a **different** `iv` means a sender re-used it — a peer restored from an old profile. That, and an AEAD failure on a matching tag, count as strikes (§9.1).

The payload's `deviceId` must equal the matched session's device; a mismatch is treated like an invalid signature (flagged, unverified). Only a verified decrypt under the current generation 1 triggers confirmation (§7.1). Mirrored copies of one's own messages (`selfsync`, and ordinary `app:message`s through the same fanout) are chain messages like any other.

**Out of scope for session keys, permanently:** `app:migrate`, `app:burn`, `call:*`, `data:*`, `app:sync` — none is device-targeted infrastructure, so there is no single device pair to key against.

### 8.3 The aux key — traffic with no chain header

Self-backup pushes (full contact-store pushes to a sibling) and the acks of that handshake are not `app:message`: they have no header, so there is no position to ratchet. They keep a **static per-generation key**, `aux` (§5.3) — what every message used before 0.8.0 — sent under the send generation and decrypted under every live one (the receiver tries each candidate's aux key, then the backup key last, and cross-checks the payload's `deviceId` against the session that decrypted it). This is a known, deliberate gap: such a blob is readable by whoever later obtains the session state, with exactly the caveats of the old static wire key (`known-limitations.md`). Closing it would mean moving these pushes onto the chain or onto an ephemeral wrap. The deterministic backup key also remains in two places: the content-free discovery hello/ack, and acceptance of a full push from a sibling that used the static backup key.

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

**Retry** is simply a fresh propose: refused unless a session exists, is at `stage == "rk0"`, and we are the fixed initiator; otherwise it runs §4.1 again, producing a new `sessionEpoch` and fresh ephemerals, so a superseded session's keys can never be reproduced. Session bootstrap and session reset are the same mechanism. A retry replaces the session, so the old generations go to the decrypt-only grace (§7.1) and the retry counters carry forward (§6).

There is no time-based or message-count-based rotation of the *root*: a healthy session keeps its two generations until something knocks it loose, and the only thing that moves is the chain.

### 9.1 Chain desync

Two chains can drift apart: a peer restored an old profile (it re-uses positions the other side already consumed), a position was lost to a crash, or a peer is further ahead than `CHAIN_MAX_FORWARD`. It shows up as **authenticated packets we cannot read**: the signature verifies and the tag matches a live chain, but the AEAD fails, or the position was consumed with a different `iv` (§8.2), or it is too far ahead. Each such packet is a *strike* against that session (memory only); a packet that decrypts resets the count. At `CHAIN_STRIKE_LIMIT` (3) in a row the session is dropped — the same operation as the manual × in the conversation panel — and the ordinary re-establishment paths take over:

- the **fixed initiator** proposes again at once (the peer's endpoint is already known);
- a **responder** sends a HELLO whose `sessions` list no longer names the device (the HELLO field described in `protocol.md`), which makes the initiator re-propose;
- a **self-pair** responder has no HELLO to send and waits for its sibling's own traffic.

Only strikes that are attributable count: an unsigned packet, a packet whose tag matches no chain (so a forged or foreign one), a replay, and a failure against a *retired* generation never do — otherwise whoever relays packets could force session resets. A position older than the newest-100 skipped window looks identical to a rewound sender and counts too; three of those in a row with nothing readable between them is what "desynced" has to mean.

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

`RK0` is nevertheless accepted for wire encryption (§7.2): per-device-pair separation is itself an improvement over an identity-wide static key, and the offline responder is the ordinary case, not an edge case. A session that completes the upgrade gains the stronger property with no re-keying step: the next message simply goes out under the new generation.

`DH1` is identity-level, not device-level: it is the identical value for every device pair between two identities. A later compromise of an identity key therefore breaks every `RK0`-only session that identity ever bootstrapped with that contact at once; an upgraded session is unaffected, which is why the opportunistic upgrade matters.

### 11.2 What the forward secrecy claims

Two separate properties, with separate qualifiers.

**(a) Against a later identity-key compromise.** `RK1` (and everything derived from it) cannot be reconstructed from a later compromise of either party's identity key. This is *session-level forward secrecy against later identity-key compromise*:

- **Only traffic after the upgrade.** Messages sent under `RK0` before the upgrade (or forever, if it never happens) stay exposed to a later leak of the responder's identity key. The upgrade is not retroactive.
- **Depends on both ephemeral private keys being erased.** The initiator holds `EK_A_priv` and `kemSk` in memory until the ack lands or times out; the responder's `EK_B_priv` is a local variable that goes out of scope. In JavaScript neither is zeroised — dropped and left to the garbage collector, so erasure is best-effort.

**(b) Against a later copy of the stored session state (0.8.0).** Once a message's key has been used and deleted, the stored state cannot reproduce it: not the receiver's (it holds `CK_(i+1)` and later, not `CK_i`), and not the sender's. Qualifiers:

- **Not post-compromise secure.** An attacker who copies the live state holds the current chain keys and can derive every *future* key in both directions, silently, until the session resets. There is no DH or KEM step to lock them out again (R2, R3).
- **Unconsumed keys are exposed.** The state holds the keys of skipped positions (up to 100 per chain, for up to 24 h) and, of course, every position not yet sent or received.
- **`RK0`'s root is stored until the upgrade.** While a session is at stage `rk0` its root is on the record, so a copy of the state taken then can re-derive every `RK0`-generation key, including used ones. Per-message forward secrecy for that generation starts when the upgrade deletes the root. Generation 0 stays as chains (no root) until the peer is confirmed on `RK1`.
- **Retired generations** keep their receive chains in memory for 120 s (§7.1); they are never written to storage.
- **Best-effort erasure in JavaScript.** Message keys are zeroed after use, but chain keys and skipped keys are also held as base64 strings, which JavaScript cannot wipe.
- **The stored state is encrypted at rest** with a key derived from the passphrase. An attacker with both the device storage and the passphrase obtains the current chain keys and the aux keys directly, without needing any identity-key attack. This does not contradict the claims above, which are about network-recorded traffic plus a later key leak, and about state copied at a later time.
- **Not all traffic is chain traffic** (§8.3, §11.4).

### 11.3 Post-quantum scope (hybrid `RK1`, 0.7.1)

`RK1` derived with `root-v3` depends on both the X25519 inputs and `SS_KEM`: an attacker has to break **both** to recover it. Traffic recorded today under such a session stays confidential if X25519 is broken later, provided ML-KEM-768 holds, and the reverse. Limits, stated plainly:

- **`RK0` is not post-quantum.** It is derived from X25519 only. Anything sent under `RK0` (an offline responder, the window before the ack) is exposed to a future X25519 break. Making `RK0` post-quantum would need a long-lived KEM key per device in the signed HELLO; that is not done.
- **Signatures and identity are classical.** Ed25519 and the X25519 identity keys are unchanged. This is confidentiality, not post-quantum authentication: an attacker with a quantum computer *at handshake time* could impersonate.
- **The KEM is ephemeral.** `kemSk` lives only in memory for the proposal's lifetime and is zeroed after use (best-effort in JavaScript, as for `EK_A_priv`).
- **No downgrade path.** A propose without `kemPub` and an ack without `kemCt` are dropped, and a stored `RK1` record without the `pq` mark is discarded at load; there is no classical `RK1` to fall back to. (A peer that cannot do ML-KEM therefore cannot establish a session at all.)
- **No formal analysis**, as for the rest of this document. ML-KEM-768 comes from the vendored `noble-mlkem.js`.

### 11.4 Not covered by sessions

The static pairwise key (HELLO, `app:migrate`, call/data SDP and ICE blobs, `restore_req`) is not forward-secret. Calls, data-channel tests, relay migration and burn notices have no session to ride, permanently. Self-backup pushes and their acks ride a session but keep the static aux key (§8.3), so a later copy of the session state exposes them. Metadata (who talks to whom, timing, sizes, endpoint ids) is visible to relays. X4DH has had no formal analysis and should be treated as experimental.

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
| ML-KEM-768 sizes | 1184 / 1088 / 32 | `kemPub` / `kemCt` / `SS_KEM` bytes (secret key 2400, memory only) |
| `CHAIN_MAX_FORWARD` | 2 000 | Furthest a header may point past the receive position (chain steps per packet, worst case) |
| `CHAIN_SKIP_KEEP` | 100 | Skipped message keys kept per receive chain (the newest) |
| `CHAIN_SKIP_TTL_MS` | 86 400 000 | Life of a stored skipped key (= the relay buffer's lifetime) |
| `CHAIN_SEEN_KEEP` | 32 | Consumed positions remembered with their `iv` (replay vs rewound sender) |
| `CHAIN_STRIKE_LIMIT` | 3 | Consecutive authenticated, unreadable packets before the session is dropped |
| tag length | 6 bytes | `t` in the header (§5.5) |

HKDF labels: `MeshChat-X4DH-v1/root`, `MeshChat-X4DH-v1/root-v3` (hybrid `RK1`), `MeshChat-X4DH-v1/wire-message` (the aux key, §5.3), `MeshChat-R1-v1/chain/i2r`, `MeshChat-R1-v1/chain/r2i`, `MeshChat-R1-v1/tag/i2r`, `MeshChat-R1-v1/tag/r2i`; HMAC labels: the chain steps use the constant bytes `0x01` / `0x02`; the AAD label is `meshchat-chain-v1` (all fixed ASCII literals).

---

*MeshChat X4DH — implementation 0.8.0 — experimental*