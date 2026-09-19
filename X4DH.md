# X4DH — MeshChat Session Establishment

> **MeshChat X4DH is a MeshChat-specific 2DH/4DH session-establishment construction. It is not Signal's X3DH and does not use signed or one-time prekeys. It has not been formally analysed or independently audited.**
>
> **What `RK1` gives you, precisely:** session-level forward secrecy against a *later* compromise of either identity key, for traffic sent *after* the live upgrade completes. It is not per-message forward secrecy, and `RK0` (the async-only stage) does not have it. The exact scope and qualifiers are in §10.2 — read that before quoting this property anywhere.

> **X4DH is MeshChat's asynchronous session-establishment protocol.**
>
> It establishes a usable session immediately when the recipient is offline, and opportunistically upgrades that session when both devices are online.

**Status: root-key establishment, the fixed-initiator trigger (§13.3, both contact and self-pairs), a stuck-at-RK0 detector, a propose-freshness/downgrade guard (both §13.2), and both manual and automatic re-propose retry for the detector's initiator-side stuck case are implemented and confirmed live on meshdev. Automatic retry is bounded (10 attempts), gated strictly on genuine online-transitions for the affected contact (never on routine re-confirmation of an already-known-online peer, never on a raw timer), and re-arms its budget on the next transition after exhaustion — confirmed live, including a full stuck → automatic-retry → real `session:ack` → RK1 convergence against a genuinely-occurring stuck session, not a manufactured one. The one piece of this specific mechanism not yet directly observed is the exhausted → re-armed transition itself in isolation (see the note at the end of this Status block). The responder-side stuck case (endpoint unknown at propose time) remains detection-only by design — nothing on the responder's own device can fix it — and has been separately confirmed to self-heal via ordinary passive endpoint discovery (§13.3) once traffic teaches it the missing endpoint, independent of any retry mechanism.**

**As of the same work cycle: the session's root key (RK0 or RK1, whichever a device pair's session currently holds) is now the actual encryption key for real `app:message` traffic on that device pair — see §16 for the full mechanism. This replaces the old identity-level static key as the default for any device pair with an established session, with graceful per-device fallback to the legacy key everywhere a session doesn't yet exist. This is implemented, live, and is now the sole encryption path `app:message` sends go through (the previous identity-only fanout code was removed, not left as a parallel path) — every text/audio/image/reaction/system-notice send since this pass landed has exercised it.**

`sendX4DHPropose`/`handleX4DHPropose`/`handleX4DHAck` work end to end — verified on `meshdev` with two live identities converging on byte-identical `RK1` over a real relay round trip, and, separately, between two devices sharing one identity (the `isFixedInitiator` self-tiebreak, §13.1) over the same relay. `maybeTriggerX4DHPropose` runs on every `recordKnownDevice()` call — every message receipt for contacts, and every self-sync backup accept/push for self — and proposes the instant the fixed-initiator side has both no existing session for that device and a known `endpointId` for it (§13.3's precondition). Confirmed live and unprompted in three shapes: a brand-new contact pair, a new device added to an already-established contact pair, and a self-pair discovering the sibling device's endpoint fresh via an ordinary self-chat message.

Two pieces of §13.2 hardening have since landed. **Stuck-at-RK0 detection** (`checkStuckX4DHSessions`, hooked into `markOnline()`) flags a session sitting at `RK0` for more than 2× the proposal timeout while presence confirms the other side is actually online — logging always fires on this signal; automatic retry is gated separately (see below). Confirmed on both roles it's meant to cover: the initiator case (never got `session:ack` back) via both a manufactured stuck session and multiple genuinely-occurring ones, and the responder case (never learned the sender's `endpointId` in time to ack) via a genuine, unprompted occurrence during unrelated testing — a real device pair actually hit this state and the detector caught it on its own, with no test scaffolding involved. **A propose-freshness guard** in `handleX4DHPropose` now refuses to adopt a `session:propose` whose signed `ts` isn't strictly newer than the session's own stored `proposeTs` (a new field, deliberately compared sender-clock-to-sender-clock rather than against the receiver's local `establishedAt`, so ordinary cross-device clock skew can never read as a replay) — closing the silent-downgrade gap a durably-buffered (`DURABLE_KINDS`) `session:propose` otherwise leaves open. Confirmed against a live forged-but-validly-signed stale propose, and again, separately, when that exact same packet came back out of the relay's own durable buffer later — arguably the more realistic version of the replay this guard exists to stop, and not something that was deliberately engineered for the test.

**Retry — both manual and automatic — has since been confirmed live against real stuck sessions.** `retryX4DHPropose(contactId, theirDeviceId)` — console-only, callable directly or invoked by the automatic path below — refuses outright unless a session exists, is genuinely at `stage: "rk0"`, and we're the fixed initiator for the pair; otherwise it calls `sendX4DHPropose` again exactly as if it were a fresh bootstrap. The manual path was confirmed twice against independently-occurring stuck sessions (not manufactured), each time re-establishing a new `sessionEpoch` cleanly and converging to `RK1` normally on the subsequent `session:ack`.

**Automatic retry** (`maybeAutoRetryX4DH`, called only from `checkStuckX4DHSessions` on a genuine `false→true` presence transition for the affected contact) wraps the same manual mechanism with a bounded budget: up to `MAX_X4DH_RETRY_ATTEMPTS` (10) real fired retries per (contact, device) session, tracked as `retryAttempts`/`retryExhaustedAt`/`lastRetryAt` fields on the session object itself, carried forward across every session overwrite (a retry's own fresh `RK0` does not reset the counter). A retry that internally refuses (no session / wrong stage / not the fixed initiator) costs nothing from the budget, since nothing was actually sent. Reaching the budget sets `retryExhaustedAt` and switches the log line to a distinguishable "retries exhausted" warning rather than going silent; a fresh online-transition arriving after exhaustion is itself the re-arm event, clearing the flag and immediately spending the first attempt of a new budget in the same call. **Confirmed live**: an automatic retry fired against a genuinely stuck initiator-side session, completed a real `sendX4DHPropose` → `session:ack` round trip once the target endpoint became known through ordinary traffic, and converged to `RK1` with the retry counter correctly reset to zero on success — end to end, no manual intervention beyond the presence transition itself. **Not yet directly observed in isolation**: the exhausted-budget → re-armed transition sequence on its own. This is a reasoned-not-observed gap, not a suspected bug — the console-only `x4dhDebug.forceStuck()` helper used for earlier detector testing cannot fake a genuinely live peer relationship (it doesn't know a real `endpointId`), so exercising the full exhaustion path requires either a peer that will provably never respond (a fabricated, unroutable endpoint) or patience with a real one; this remains open for a dedicated test rather than something inferred as broken.

`window.x4dhDebug` (console-only, not wired into any UI or automatic path) provides `list()` (session/stage/age/retry-state dump across every contact/device), `retry(contactId, deviceId)` (thin wrapper over the manual path, unaffected by the automatic budget), `forceStuck(contactId, deviceId, opts)` (manufactures an RK0 session sitting past the stuck threshold, with a chosen starting `retryAttempts`/`exhausted` state — does **not** fake `endpointId` or override the real `isFixedInitiator` comparison, both of which are read live from actual identity material), `simulateTransition(contactId)` (drives the detector with `isTransition=true` without waiting for a real presence signal), and `check(contactId, deviceId)` (surfaces the live `isFixedInitiator`/`endpointKnown`/session state in one call — the fastest way to see *why* a forced test isn't progressing, e.g. a null `endpointKnown` explains a silent `sendX4DHPropose` refusal that would otherwise only show up as a console-level `mlog.debug` line).

Client/protocol version is `0.5.0`. What that means has changed since this note was first written: the pieces of this document that were confirmed live and unprompted — root-key bootstrap/upgrade (§3–§7), the fixed-initiator rule (§13.1), the propose-freshness/stuck-RK0-detection/bounded-retry hardening (§13.2 and the Status block above), and the per-device wire-message key (§16) — have now graduated out of `meshdev`-only tracking and into `protocol.md`'s own formal wire spec (see its [Session Establishment](protocol.md#session-establishment-x4dh) and [Encryption](protocol.md#encryption) sections), per this project's documentation discipline: a feature moves into `protocol.md` only once it's been witnessed firing correctly live, not on a development-cycle timer. This document remains the authoritative source for the cryptographic design and derivations themselves — `protocol.md` only restates the wire shapes and relay-visible behavior, not the DH math. Not everything here has graduated: the exhausted → re-armed automatic-retry transition (see the Status block) is still reasoned-not-observed, and self-sync forward secrecy (the "self-devices get a ratchet session too" follow-on work tracked under `Roadmap.md`'s Per-device encryption & relay-stored messages section) remains design-only — both stay `0.5.0`-cycle, meshdev-tracked facts until independently confirmed. The root-key KDF construction (§6.1) and the wire-message key derivation built on top of it (§16) are both fully specified and live; chain-key derivation and the rest of the Double Ratchet remain a separate, not-yet-scoped design session (see `Roadmap.md`).

---

## Overview

MeshChat identities are deterministic.

A user's username and passphrase produce a stable set of cryptographic identity keys, including:

* **Ed25519** identity/signing key
* **X25519** identity key
* network identity material

Devices additionally have their own `deviceId`.

The relay knows how to route messages to a specific device and can buffer messages while that device is offline.

This means MeshChat does **not** require a conventional prekey server just to establish an asynchronous session.

X4DH uses this existing infrastructure to establish a fresh session:

```text
                    MeshChat Relay
                         │
              asynchronous transport
                         │
        ┌────────────────┴────────────────┐
        │                                 │
      Alice                              Bob
        │                                 │
   identity keys                     identity keys
   deviceId_A                        deviceId_B
        │                                 │
        └──────────── X4DH ───────────────┘
                         │
                         ▼
                    Root Key
                         │
                         ▼
                  Double Ratchet
```

The relay transports the protocol messages but never needs access to the resulting session keys.

---

# 1. Design Goals

X4DH is designed around several properties important to MeshChat.

### 1.1 Asynchronous by default

Alice must be able to initiate a session even when Bob is offline.

```text
Alice ── session:propose ──► Relay ──► buffer
```

No response from Bob is required before Alice can derive an initial session key.

### 1.2 No central key server

The relay does not maintain a separate cryptographic prekey infrastructure.

The information required to identify Bob is already available through MeshChat's existing contact/device restoration mechanism.

### 1.3 Opportunistic strengthening

If Bob is online, he can immediately contribute fresh ephemeral key material.

The existing session is then upgraded before normal application traffic begins.

```text
offline:

    2DH
     │
     ▼
    RK₀


online:

    2DH
     │
     ├── Bob contributes fresh ephemeral
     │
     ▼
    4DH
     │
     ▼
    RK₁
```

The live path is therefore an **upgrade**, not a requirement.

### 1.4 Device-specific sessions

A session belongs to two specific devices.

For example:

```text
Alice::Laptop  <── session ──>  Bob::Phone
Alice::Desktop <── session ──>  Bob::Phone
```

These are separate cryptographic sessions.

The `deviceId` is an identity/context value. It is **not a secret** and is not used as cryptographic key material.

---

# 2. Existing Identity

MeshChat derives long-lived identity material deterministically from the user's soft-login credentials.

Conceptually:

```text
username + passphrase
          │
          ▼
    master derivation
          │
    ┌─────┴──────────────┐
    │                    │
    ▼                    ▼
Ed25519 identity     X25519 identity
    │                    │
    ▼                    ▼
signatures          key agreement
```

The deterministic nature of these keys is intentional.

They provide a stable identity across logins and devices.

They are **not** intended to provide session freshness.

Freshness comes from newly generated ephemeral X25519 keys.

---

# 3. The Initial 2DH Bootstrap

When Alice wants to establish a new session with Bob, she generates a fresh X25519 ephemeral keypair:

```text
EK_A_priv
EK_A_pub
```

`EK_A_priv` never leaves Alice's device.

`EK_A_pub` is transmitted openly.

Alice then calculates two Diffie-Hellman values.

### DH1 — static identity agreement

```text
DH1 = X25519(IK_A_priv, IK_B_pub)
```

This is the existing static pairwise X25519 relationship.

### DH2 — Alice's fresh ephemeral

```text
DH2 = X25519(EK_A_priv, IK_B_pub)
```

The initial root is derived from both values via HKDF — see §6.1 for the precise, fully-specified construction (defined alongside the live upgrade, since both stages share one derivation scheme):

```text
RK0 = HKDF( salt = zero32, ikm = DH1 || DH2, info = "MeshChat-X4DH-v1/root", length = 32 )
```

Alice can therefore calculate `RK0` **immediately**.

She does not need to wait for Bob.

---

# 4. `session:propose`

Alice sends:

```json
{
  "type": "session:propose",
  "from": "<Alice>",
  "to": "<Bob>::<Bob's specific endpointId>",
  "sessionEpoch": "<uuid>",
  "ekPub": "<Alice's fresh, one-time X25519 public key>",
  "deviceId": "<Alice's own deviceId>",
  "ts": "...",
  "sig": [...]
}
```

The important fields are:

| Field          | Purpose                                          |
| -------------- | ------------------------------------------------ |
| `from`         | Alice's identity                                 |
| `to`           | Bob's specific destination/device                |
| `sessionEpoch` | Unique identifier for this session establishment |
| `ekPub`        | Alice's fresh ephemeral X25519 public key        |
| `deviceId`     | Alice's participating device                     |
| `ts`           | Timestamp / freshness metadata                   |
| `sig`          | Ed25519 authentication of the proposal           |

The signature binds the proposal to Alice's established identity.

The exact canonical serialization of the signed fields is part of the protocol implementation and must be unambiguous.

---

# 5. No Round Trip Required

This is a fundamental property of X4DH.

Alice already possesses:

```text
IK_A_priv
EK_A_priv
IK_B_pub
```

Therefore she can calculate:

```text
DH1
DH2
RK₀
```

before Bob receives anything.

The relay can therefore buffer:

```text
session:propose
```

while Bob is offline.

When Bob eventually receives it, he calculates the same root using:

```text
IK_B_priv
IK_A_pub
EK_A_pub
```

No cryptographic response is required for the session to become usable.

```text
Alice                         Relay                         Bob

  │                             │                            │
  │ session:propose             │                            │
  │────────────────────────────►│                            │
  │                             │                            │
  │        RK₀                  │       RK₀                  │
  │                             │                            │
  │                             │──── buffered ─────────────►│
  │                             │                            │
```

This is the guaranteed asynchronous baseline.

---

# 6. Live Upgrade

If Bob is online when the proposal arrives, he can generate his own fresh ephemeral X25519 keypair:

```text
EK_B_priv
EK_B_pub
```

Bob returns a `session:ack` containing `EK_B_pub`.

This adds fresh key material from Bob.

### DH3

```text
DH3 = X25519(IK_A_priv, EK_B_pub)
```

### DH4

```text
DH4 = X25519(EK_A_priv, EK_B_pub)
```

## 6.1 Precise KDF construction

The root key is derived in **two stages**, matching whichever of §3/§6 the session has actually reached — never as one combined four-DH computation, since `DH3`/`DH4` simply don't exist until Bob's ephemeral arrives.

**Stage 1 — offline, Alice only (§3):**

```text
IKM0 = DH1 || DH2
RK0  = HKDF( salt = zero32, ikm = IKM0, info = "MeshChat-X4DH-v1/root", length = 32 )
```

**Stage 2 — online upgrade, once `EK_B` arrives:**

```text
IKM1 = DH3 || DH4
RK1  = HKDF( salt = RK0, ikm = IKM1, info = "MeshChat-X4DH-v1/root-v2", length = 32 )
```

`zero32` is 32 zero bytes — there is no prior shared secret to salt Stage 1 with, the same convention `deriveSharedAesKey` already uses elsewhere in this codebase. `HKDF(...)` here means the standard Extract-then-Expand construction as a single call — exactly what `crypto.subtle.deriveBits({ name: "HKDF", ... })` already does under the hood for every other derivation in this app (`hkdfExpand`, `deriveSharedAesKey`, `deriveDeviceEndpointId`) — not a separately exposed PRK step requiring new primitives.

Using `RK0` itself as Stage 2's **salt** — rather than concatenating all four DH outputs into one derivation in a single shot — is what makes this the **incremental form** already settled on above: `RK1`'s derivation has the same "fold new DH material into the existing root" shape as every later Double Ratchet turn, on either side. This isn't a stylistic choice between two equivalent formulas; treating the online upgrade as the ratchet's first real step rather than a special bootstrap-only combination is the entire point of picking the incremental form.

Both `info` strings are fixed, ASCII-only literals, matching every other domain-separation label already in this codebase (`meshchat-v1:x25519`, `meshchat-v1:pairwise`, `meshchat-v1:device-endpoint`) — no non-ASCII characters, since a label that has to byte-for-byte match across two independent implementations is exactly the wrong place for anything that could silently mis-encode. They're versioned (`/root` vs. `/root-v2`) purely to keep the two stages cryptographically distinguishable from one another; `sessionEpoch` and device identifiers are deliberately **not** mixed into either string — see §11 for why domain separation and session freshness are being kept as two separate concerns here.

**Deliberately out of scope here: chain keys.** Deriving `CK_A→B`/`CK_B→A` directly from `RK0`/`RK1` at handshake time is tempting but premature — X4DH stops at the root key (§15). Symmetrically deriving both directions' chain keys from one shared root before any real ratchet step exists would also be a materially *weaker* construction than an actual Double Ratchet, not a simplified version of one: in Signal's design, the first sending chain key exists on only one side until the other side's first DH-ratchet reply arrives, and that asymmetry is precisely where the self-healing property against a one-time key compromise comes from. How chain keys get seeded from `RK0`/`RK1` is a decision for the dedicated ratchet-design session flagged in `Roadmap.md` (which deliberately wants Signal Sesame, Matrix Olm/Megolm, Session, and SimpleX surveyed fresh before committing to a shape), not something to pre-empt here. §16 below is a deliberate, scoped-down interim step in the meantime — a static per-session wire key, not a ratchet — see that section for the full reasoning on why it's acceptable to ship ahead of the ratchet work rather than a shortcut around it.

---

# 7. Complete Handshake

The complete live exchange therefore looks like:

```text
Alice                                      Bob

IK_A                                       IK_B
  │                                          │
  │ generate EK_A                            │
  │                                          │
  │ DH1 = DH(IK_A, IK_B)                     │
  │ DH2 = DH(EK_A, IK_B)                     │
  │                                          │
  │ derive RK₀                               │
  │                                          │
  │──── session:propose ───────────────────► │
  │       EK_A_pub                           │
  │                                          │
  │                               generate EK_B
  │                                          │
  │                               DH3 = DH(IK_A, EK_B)
  │                               DH4 = DH(EK_A, EK_B)
  │                                          │
  │◄──────── session:ack ─────────────────── │
  │             EK_B_pub                     │
  │                                          │
  │ derive RK₁                               │
  │                                          │
  │                               derive RK₁ │
  │                                          │
  └────────── Double Ratchet ────────────────┘
```

(See §6.1 for the exact two-stage HKDF construction both sides run to reach `RK₀`/`RK₁`, and §16 for what a device pair's session key is actually used for once established.)

The important distinction is:

```text
2DH = immediately usable
4DH = opportunistically stronger
```

The protocol never blocks waiting for the second endpoint.

## 7.1 State this requires that isn't obvious from the diagram

Two consequences fall out of the shape above that a naive reading of "Alice derives RK₀ and moves on" would miss:

- **Alice cannot discard `EK_A_priv` the instant she sends `session:propose`**, the way a stateless one-shot ephemeral might suggest. She needs it available if/when `session:ack` arrives, to compute `DH4`. This means a small, genuinely new piece of local state: a pending-outbound-proposal entry keyed by `(contactId, deviceId, sessionEpoch)`, holding `EK_A_priv` until either the ack lands (fold into `RK1`, then discard) or a bounded timeout passes (discard anyway, staying at `RK0` for that attempt). This state is exactly as sensitive as any other ephemeral private key in this document and must never be written anywhere that persists across the timeout — local memory only, same tier as the device seed.
- **Bob does still compute `RK0` — but it costs him nothing extra.** An earlier draft of this section assumed a combined, single-shot KDF over all four DH outputs, under which Bob genuinely could skip straight to `RK1`. §6.1's incremental construction (`RK1` salted with `RK0`, not re-derived from scratch) means `RK0` is a real intermediate value on both sides, not just Alice's. This isn't a meaningful cost: Bob already holds `IK_B_priv` and, from the proposal itself, `IK_A_pub` and `EK_A_pub` — computing `DH1`/`DH2` and folding them into `RK0` is two ordinary ECDH calls plus one HKDF call, all with material he already has in hand, with no extra network round trip. Only Alice, the initiator, ever has to sit at `RK0` *waiting on a reply*; Bob simply computes both stages back-to-back the instant the proposal arrives, before ever sending `session:ack`.

---

# 8. Offline Path

If Bob is unavailable:

```text
Alice
  │
  │ session:propose
  ▼
Relay
  │
  │ buffer
  │
  ▼
Bob
```

Alice already has:

```text
RK₀
```

and can proceed according to the asynchronous session rules.

When Bob eventually receives the proposal, the session can be upgraded if the protocol state still permits it.

The upgrade is therefore not a prerequisite for delivery.

---

# 9. Security Properties

X4DH deliberately separates three different concepts.

### Identity

Long-lived deterministic keys answer:

> "Which MeshChat identity is this?"

### Session establishment

Ephemeral X25519 keys answer:

> "Which fresh cryptographic session are these two devices establishing?"

### Ongoing secrecy

The Double Ratchet answers:

> "How do we continually replace the keys used for future messages?"

```text
Identity
   │
   ▼
X4DH
   │
   ▼
Root Key
   │
   ▼
Double Ratchet
   │
   ├── message key 1
   ├── message key 2
   ├── message key 3
   ├── message key 4
   └── ...
```

Note: as of §16, the diagram's bottom half ("Double Ratchet" deriving per-message keys) is still aspirational — the real, shipped state today is Root Key → one static wire key per session, reused for every message under it. §16 is explicit about this being an interim step, not a claim that the Double Ratchet box above is already built.

---

# 10. The Initial Asymmetry

The asynchronous 2DH bootstrap has an important limitation, and it is
directional — it protects one party's future key compromise and not the
other's, not both equally.

Alice's ephemeral public key is transmitted in the clear:

```text
EK_A_pub
```

`DH2 = X25519(EK_A, IK_B)` never uses `IK_A` as an input at all — Alice's
long-term identity key does not appear anywhere in this term's formula.
Concretely: if an attacker later obtains Alice's long-term identity
private key alone, they can reconstruct `DH1` (paired with Bob's
already-public `IK_B_pub`), but they **cannot** reconstruct `DH2` — `IK_A`
was never one of its inputs, and `EK_A`'s matching private half was
generated once and discarded, never derivable from `IK_A`. With `DH2`
unrecoverable, `RK0 = HKDF(zero32, DH1 || DH2, ...)` cannot be
reconstructed from a future compromise of Alice's identity key alone.

The reverse is not true. If an attacker later obtains **Bob's** long-term
identity private key, they can reconstruct both terms — `DH1` (paired
with Alice's public `IK_A_pub`) and `DH2` (paired with the already-public
`EK_A_pub`, since `IK_B` is `DH2`'s only long-term input) — and therefore
`RK0` in full.

So the asymmetry runs opposite to how it might intuitively read: the
2DH bootstrap protects the **initiator's** (Alice's) identity key against
a future leak, and does nothing to protect the **responder's** (Bob's).
This is a direct consequence of only the initiator contributing an
ephemeral at message zero — it is not a flaw to patch, it is exactly the
gap the live upgrade below closes, symmetrically, for both sides.

Consequently, the initial 2DH state should **not** be described as having
the full forward-secrecy properties of a completed ephemeral-to-ephemeral
handshake. This is the specific property §16.2 refers to when it explains
why RK0 is accepted for wire encryption anyway — a deliberate, disclosed
trade-off, not an unnoticed gap.

The live upgrade adds Bob's fresh ephemeral key:

```text
EK_B
```

and produces:

```text
DH3
DH4
```

`DH4 = X25519(EK_A, EK_B)` is the term that actually closes the gap: it
never involves either party's long-term identity key, so it cannot be
reconstructed from a *future* compromise of **either** `IK_A` or `IK_B`,
however that compromise happens. `DH3` alone only mirrors `DH2`'s own
asymmetry in the other direction (protects against a future leak of
Bob's key, not Alice's) — it is `DH4` specifically that makes `RK1`
resistant to a future leak of either identity key. The session
transitions into this fully ephemeral-inclusive state whenever Bob happens to be
reachable at bootstrap time. Traffic sent under `RK0` before the upgrade lands
keeps `RK0`'s weaker property (§16.2) — the upgrade does not retroactively
strengthen it.

This is an intentional trade-off.

MeshChat X4DH chooses:

> **immediate asynchronous usability over requiring a responder prekey.**

## 10.1 `DH1` is identity-level, not device-level

`IK_A`/`IK_B` are the existing per-*identity* static X25519 keys (§2) —
the same ones used for today's pre-X4DH pairwise messaging key. They are
**not** per-device. Consequently `DH1 = X25519(IK_A, IK_B)` is the
identical value for *every* device pair between Alice and Bob — Alice's
laptop and Alice's phone both compute the same `DH1` against any of
Bob's devices, since none of `IK_A`/`IK_B` vary by device at all.

This is not a new vulnerability introduced by X4DH — it's the same
identity-key exposure the static pairwise scheme already has (see
`protocol.md`'s Encryption section: "if either party's X25519 private
key is later compromised, previously recorded ciphertext... becomes
decryptable in hindsight"). It is worth stating plainly here anyway,
because X4DH changes the *blast radius* of that same fact: a single
future compromise of `IK_A` or `IK_B` doesn't just retroactively break
one 2DH-only session, it retroactively breaks **every** 2DH-only session
that identity has ever bootstrapped with that contact, across every
device pair, all at once — since `DH1` alone is already half of every
one of those sessions' `RK0` inputs. A session that completed the live
4DH upgrade (§6) is unaffected by this specific exposure, because `DH4`
never involves either identity key (§10) — this is precisely why the
opportunistic upgrade matters, not just as a "nice to have."

## 10.2 What `RK1`'s forward secrecy does and does not claim

The claim, stated once and precisely: **`RK1` (and the wire key derived from it) cannot be reconstructed from a later compromise of either party's identity key**, because `DH4 = X25519(EK_A, EK_B)` uses only two ephemeral keys that are never derivable from any identity key. This is *session-level forward secrecy against later identity-key compromise*. Qualifiers that must travel with it:

- **Only traffic after the upgrade.** Messages sent under `RK0` in the window before `session:ack` lands (or forever, if it never does) remain exposed to a later leak of the responder's identity key (§10). The upgrade is not retroactive.
- **Depends on both ephemeral private keys actually being erased.** The initiator holds `EK_A_priv` in memory until the ack lands or times out (§7.1); the responder's `EK_B_priv` is a local variable that goes out of scope. In JavaScript neither is zeroised — they are dropped and left to the garbage collector, so erasure is best-effort, not guaranteed.
- **Static per session, not per message.** The wire key is the same for every message under a session (§16.6). There is no ratchet, so there is no post-compromise recovery: whoever obtains a session's root key can read that session's traffic until the session resets. This is session-level forward secrecy, not the per-message property a Double Ratchet provides.
- **The root key is stored on the device.** `RK0`/`RK1` are persisted in the session store, encrypted with a key derived from the passphrase. An attacker who obtains both the device's storage and the passphrase gets the root key directly — no identity-key math needed. That is normal for at-rest state and does not contradict the claim above (which is about *network-recorded* traffic plus a later identity-key leak), but the claim should not be read as broader than that threat model.

---

# 11. Session Epoch

Every session establishment receives a unique:

```text
sessionEpoch
```

For example:

```text
"8f7e...a912"
```

This value distinguishes independent attempts to establish sessions between the same devices.

**It is authenticated, not mixed into the root-key KDF.** An earlier draft of this document sketched `sessionEpoch` and both sides' identity/`deviceId` as direct KDF inputs; §6.1's precise construction deliberately doesn't do this. The reasoning: `RK0`/`RK1`'s uniqueness already comes from `EK_A` (and `EK_B`) being freshly generated per session — two different `sessionEpoch` attempts between the same device pair necessarily produce different ephemeral keys, and therefore different DH outputs and different root keys, with no help needed from mixing metadata into the KDF itself.

`sessionEpoch`, `deviceId`, and both identities instead live where they're actually enforced: inside the **signed** fields of `session:propose`/`session:ack` (§4, §13). The signature authenticates the ephemeral key and the session/device metadata from which the root key is derived, thereby binding the resulting session to the claimed identity and device pair; \1
The device half of that binding is an **identity-authenticated device claim**: `deviceId` is asserted under the *identity* key's signature, not proven with a separate device key. Anyone holding the identity key could sign a propose claiming any `deviceId`. That is inside the trust model (the identity-key holder can already act as the identity), but "device binding" here should not be read as device-key attestation.

This still prevents otherwise identical key material from being interpreted as the same protocol session — the guarantee just comes from freshness plus authentication, rather than from the KDF's `info` string carrying session metadata directly.

Note for §16: the wire-message key inherits this same property indirectly. Since it's derived from whichever root key a session currently holds, and a session reset (retry) always produces a fresh `sessionEpoch` with fresh ephemerals, a superseded session's wire key can never be silently reproduced by a later reset — the two epochs' root keys, and therefore their wire keys, are unrelated values.

---

# 12. Device Binding

Sessions are device-to-device.

For example:

```text
Alice::A1
      │
      │ sessionEpoch = X
      ▼
Bob::B7
```

is distinct from:

```text
Alice::A2
      │
      │ sessionEpoch = Y
      ▼
Bob::B7
```

Note that `A1`/`A2`/`B7` above stand for **device identity** — the thing
a session is conceptually bound to, and the thing a contact's device
popover shows. The relay never sees this value. Routing uses a
deliberately separate, unlinkable identifier instead:

```text
networkID::endpointID
```

`deviceID` and `endpointID` are two independent HKDF derivations off the
same local device seed, under different info labels — by construction,
neither is computable from the other without the seed itself (see
`protocol.md`'s Device Endpoint ID section). This is not an
implementation detail that happens to hold today and might drift later —
it is the deliberate point of the split: the relay learns only which
live socket to hand a packet to (`endpointID`), and never learns which
physical device a contact would recognise from their own device popover
(`deviceID`). A session is bound to a `deviceID`; addressing a proposal
or an ordinary ratcheted message to that device on the wire always goes
through whichever `endpointID` is currently on file for it, resolved
the same passive, already-shipped way `endpointId` is learned for
ordinary message fanout today.

---

# 13. Replay and State Rules

Implementations must treat `session:propose` and `session:ack` as stateful protocol messages.

At minimum, a client should ensure that:

1. `sessionEpoch` is unique for a locally initiated session.
2. A proposal is associated with the expected sender identity.
3. The signed contents cannot be modified without invalidating the signature.
4. An acknowledgement belongs to the corresponding `sessionEpoch`.
5. `EK_A` and `EK_B` are associated with that same session.
6. An ephemeral private key is never reused for an unrelated session.
7. An already-consumed handshake cannot silently create a second ratchet state.
8. Conflicting session states are resolved deterministically — see 13.1 below for the specific rule.

The relay may deliver messages more than once or out of order. Cryptographic state machines must therefore be designed for duplicate and delayed delivery — see 13.2 for the minimum guard this requires.

## 13.1 Fixed initiator per pair — eliminating glare structurally

Rather than detect and untangle two competing proposals after the fact,
X4DH removes the possibility at the source: for any given pair of
identities, **the party whose `publicId` sorts lexicographically lower
is always the initiator**, permanently, for both first-ever bootstrap
and any later reset. The other party's devices never send
`session:propose` toward that identity — they only ever receive and
adopt.

This is fixed at the relationship level, not renegotiated per device or
per session. When a new device of the non-initiating party appears
(learned the same passive way `endpointId` discovery already works —
see 13.3), the fixed initiator proposes fresh to that specific device;
the new device itself never initiates back. Because only one side of
any pair is ever capable of sending a proposal, two independent,
mutually-conflicting proposals for the same pair cannot occur — this is
not a race that resolves correctly most of the time, it is structurally
absent.

**Self-sessions need a second tiebreak.** `publicId` is identical on
both sides of a self-pair — comparing it against itself resolves
nothing, and self-devices are meant to establish ratchet sessions with
each other exactly like any other contact pair (`Roadmap.md`). For this
one case, fall through to comparing `deviceId`: the device whose
`deviceId` sorts lexicographically lower is the fixed initiator toward
that specific sibling device. Same permanence rule as the identity-level
case — decided once per device pair, not renegotiated per session or
reset.

## 13.2 Stale or out-of-order proposals

The endpoint-keyed offline buffer's overwrite-per-sender behavior
(mirroring `app:migrate`/`app:burn`'s own buckets) means a stale
proposal is usually replaced before ever being delivered. This is not a
provable guarantee against every possible double-delivery ordering,
so a receiving device should additionally refuse to adopt a
`session:propose` whose `ts` is older than its currently-active
session's own establishment time for that device — a cheap, sufficient
\1
**What this guard is — and isn't.** It is *state-rollback (downgrade) protection*, not authentication and not replay prevention in the cryptographic sense. Authentication is the signature's job; the guard only stops a validly signed but older `session:propose` from overwriting newer local session state. As implemented it compares the packet's signed `ts` against the stored `proposeTs` (both the sender's clock, deliberately — see `storeX4DHSessionRK0`) and refuses `ts <= proposeTs`. Two consequences worth stating rather than leaving implicit:

- **It is not a replay defence when no session record exists.** It incidentally rejects an exact replay of the *latest* propose, but only while a session record for that device is on file. After a wipe, a burn, or loss of the session store there is nothing to compare against, so a replayed propose would be accepted. The worst case is a desynchronised session (the original initiator no longer holds the matching pending ephemeral, so no upgrade completes) that stuck-at-RK0 detection and retry then repair; it does not yield key material. *Reasoned-not-observed.*
- **A sender clock set far ahead poisons later proposes.** Because `proposeTs` is the sender's clock, if a propose stamped far in the future is ever adopted, every subsequent legitimate propose from that sender (including automatic retries, which stamp `Date.now()`) is refused as stale until real time catches up with the stored value. The symptom would be a session stuck at `RK0` with retries dropped on the receiving side while the detector keeps flagging it. No plausibility bound on `ts` exists today; adding one is a possible hardening. *Reasoned-not-observed.*

**Stuck-at-RK0 detection and retry** (implemented, confirmed live — see the Status block at the top of this document) are what turn this section's replay-hardening rules into a self-correcting system rather than a purely defensive one: a session that ends up stuck despite the guards above (a dropped `session:ack`, most commonly) is now flagged automatically the next time presence confirms the peer is online, and — for the initiator-side shape specifically — automatically re-proposed within a bounded retry budget. See the Status block and Roadmap.md for the full mechanics; this subsection remains the specification of *why* staleness matters, not the retry logic itself.

## 13.3 Precondition: `to`'s endpoint must already be known

`session:propose` is addressed `to = "<publicId>::<endpointId>"` — a
specific device, not a broadcast. This means it can never be the very
first packet exchanged with a device whose `endpointId` has not yet
been learned, including a genuinely first-ever contact.

In practice this precondition resolves for free, with no dedicated
discovery packet: an ordinary first message necessarily rides today's
existing static pairwise key (there is no session yet to ride, by
definition), and the RECEIVED auto-ack that fires automatically in
response already carries the acker's `endpointId` in its payload — a
mechanism that predates X4DH and needs no change. By the time that
single round trip completes, both sides have learned each other's
`(deviceId, endpointId)` pair passively, exactly the way ordinary
per-device message fanout already learns it today. The fixed initiator
(13.1) then has everything needed to address a proposal at that
specific device. There is no window where a real conversation is
blocked waiting on this — ordinary messages continue over the static
key for as long as no session exists for the target device, and
transparently start riding the session the moment 13.1's proposal
completes.

This same passive-discovery mechanism is also what lets a responder-side
stuck session (§13.2, the "endpoint unknown at propose time" shape)
self-heal on its own — confirmed live: a session flagged as stuck in
this shape reached `RK1` cleanly once ordinary traffic taught the
missing `endpointId`, with no retry mechanism involved at all. The
detector for this shape exists to make the *symptom* visible, not
because the underlying gap has no path to recovery.

---

# 14. Relay Independence

The relay does not participate in the key agreement.

It only transports protocol messages:

```text
Alice
  │
  │ encrypted/authenticated protocol packet
  ▼
Relay
  │
  ├── forward
  ├── broadcast where appropriate
  └── buffer when necessary
  │
  ▼
Bob
```

The relay never needs:

```text
IK_A_private
IK_B_private
EK_A_private
EK_B_private
RK₀
RK₁
message keys
```

This preserves MeshChat's existing relay philosophy:

> **The relay is a transport, not a trusted cryptographic authority.**

---

# 15. X4DH and the Double Ratchet

X4DH establishes the initial root state.

It is not itself the message ratchet.

After session establishment:

```text
X4DH
  │
  ▼
Root Key
  │
  ▼
Double Ratchet
```

The Double Ratchet is responsible for deriving new message keys and performing subsequent DH ratchet steps.

A conceptual session therefore looks like:

```text
              X4DH
                │
        ┌───────┴────────┐
        │                │
      async            live
        │                │
       2DH              4DH
        │                │
        └───────┬────────┘
                │
             Root Key
                │
                ▼
        Double Ratchet
                │
       ┌────────┴────────┐
       │                 │
   symmetric          DH ratchet
   ratchet             ratchet
       │                 │
       └────────┬────────┘
                │
                ▼
          message keys
```

**This diagram describes the eventual target shape, not what's shipped today.** As of §16, the box actually in production between "Root Key" and real wire traffic is a single static per-session key derivation — not the Double Ratchet pictured above. §16 documents exactly what stands in for the Double Ratchet's box in the meantime, and why that's an accepted, disclosed interim state rather than an oversight.

---

# 16. Wire-Message Encryption (Interim, Pre-Ratchet)

**Status: implemented and confirmed live**, landed in the same work cycle as automatic retry (see the Status block at the top of this document). This section documents what actually encrypts real `app:message` traffic today, sitting in the gap between §15's root key and the not-yet-built Double Ratchet.

## 16.1 What changed

Before this pass, `app:message` traffic (text, audio, image, reaction, system notices) encrypted under one static identity-level key — X25519 static-static ECDH between the two full identities, unchanged since `protocol.md`'s `0.4.0` (see that document's Encryption section) — fanned out as a single shared ciphertext to every device address a contact resolved to. That key never varied by device pair, and never used any X4DH material at all.

As of this pass, whichever root key a given device pair's session currently holds — `RK0` or `RK1` — is used to derive the actual AES-256-GCM key that encrypts real message traffic for that specific device pair:

```text
wireKey = HKDF( salt = zero32, ikm = rootKeyBytes, info = "MeshChat-X4DH-v1/wire-message", length = 32 )
```

Same "32 zero bytes, no prior shared secret" salting convention as §6.1's own root-key stages, and its own domain-separation `info` label, distinct from `/root` and `/root-v2` — the third and, for now, final consumer of the shared HKDF-over-raw-bytes pattern already used throughout this protocol.

This key is genuinely used — it is not a side channel or a validation-only artifact. Every text, audio, image, reaction, and system-notice send in the shipped client goes through this derivation for any device pair that has a session; the old identity-only sending code path was removed outright, not kept as a parallel option.

## 16.2 Why RK0 is eligible, not just RK1

§10 already establishes that an `RK0`-only session lacks the specific forward-secrecy property `DH4` provides — a future compromise of Bob's identity key can still reconstruct an `RK0`-only session's root key in full.

Using `RK0` for wire encryption anyway is a deliberate, disclosed trade-off, not an oversight. Per-device-pair separation is itself a real improvement over the identity-level static key it replaces, which has *zero* device granularity and *zero* protection against a future identity-key compromise either. `RK0` delivers that improvement the instant a session bootstraps, without waiting for a live round trip that may never happen — the offline peer is the ordinary case X4DH is built around (§5), not an edge case. A session that does complete the live upgrade gains `DH4`'s stronger property automatically, the moment `upgradeX4DHSessionToRK1` fires — no separate code path, migration, or re-keying event is needed on the wire-key side; the next call to derive the wire key simply picks up the new root.

## 16.3 Fallback and coexistence

A device pair with no X4DH session yet — or one that never bootstraps one, such as an older client — falls back to the legacy identity-level key exactly as it worked before this pass. This is graceful degradation *per device*, not a hard cutover: within a single fanout to one contact, some of that contact's devices may be encrypted under X4DH wire keys while others are simultaneously on the legacy key, depending on which devices have completed session establishment.

The broadcast fallback — reached when a device is unresolved (no known `endpointId` yet) or when no devices are known for a contact at all — always uses the legacy key. There is no single device pair to derive an X4DH key *for* when addressing "every live session under this identity" at once; this path is unchanged from before X4DH existed.

`app:migrate`, `app:burn`, and the `call:*`/`shell:*` signaling groups are **permanently** out of scope for this mechanism, not just deferred. The first two are never device-targeted by protocol design (`protocol.md`'s Compound Addressing section — a compound `to` is rejected outright for both types), so there is no single device pair to key against. Calls and shell escalation aren't device-aware infrastructure yet — their `RTCPeerConnection` state is keyed by contact, not device — and folding them into per-device keying is its own, separate follow-on scope.

## 16.4 Receive-side key resolution — trial decryption

`deviceId` — the field that would tell a recipient which key applies — lives *inside* the encrypted payload by deliberate design (`protocol.md`'s Device Identity section: moved there specifically so the relay can never see or rewrite it). This creates an unavoidable chicken-and-egg for any per-device-keyed scheme built this way: the recipient cannot know which key to try before decrypting, because which device sent the message is exactly what's still encrypted.

This is resolved by trial decryption on receipt: every X4DH session held for that sender is tried, most-recently-established first as a cheap "most likely still active" heuristic, followed by the legacy identity-level key as a final fallback. AES-GCM's authentication tag makes a wrong-key attempt fail cleanly and immediately — a rejected `crypto.subtle.decrypt` call, never a corrupted or ambiguous result — so this costs at most a handful of failed attempts, bounded by how many devices a contact actually runs (typically one to three in practice), and never produces a false positive.

A successful decrypt under a specific device's session key is then cross-checked against `plain.deviceId` — the sender's own claim, now visible inside the decrypted payload. The two should always agree: a decrypt can only succeed under the key belonging to the specific device pair that session was established with, so `plain.deviceId` disagreeing with which session actually decrypted it would mean something is wrong with session bookkeeping, not a normal occurrence. This case is treated the same as an invalid signature — flagged, message marked unverified, never silently trusted — rather than assumed benign.

## 16.5 Renegotiation

Deliberately reactive only, for this phase — no time-based or message-count-based rotation trigger exists, and none is currently planned as part of this interim design. A device pair's wire key is genuinely static — the same key encrypts every message under that session — until the underlying X4DH session itself resets, and today that only happens via the existing stuck-at-RK0 detection → retry mechanism (§13.2, and the Status block at the top of this document for the full retry-budget mechanics). There is no scheduled key-rotation feature to layer on top of a healthy, non-stuck session; "run static until something knocks it loose" is the accepted shape for this phase.

## 16.6 What this explicitly is not

Still not a ratchet, and not meant to be mistaken for one. A device pair's wire key is reused for every message under that session, identically in spirit to how the old identity-level key was reused for every message under an entire identity pair — the structural improvements here are the *granularity* (per device pair, not per identity) and the *rotation trigger* (a session reset via retry, rather than effectively never). Real per-message key evolution — a genuine forward ratchet, where compromising today's key does not compromise tomorrow's — remains the separate, later Double Ratchet work this document has scoped itself away from since §6.1 and §15. See `Roadmap.md`'s Double Ratchet section for how that later work is expected to build on top of the session infrastructure this section relies on, rather than replace it outright.

---

# 17. Why Not X3DH?

X3DH solves an important problem: asynchronous session establishment when the responder is offline.

MeshChat already has a mechanism that provides much of the required asynchronous infrastructure:

* contacts are restored from the network;
* devices have persistent identities;
* the relay can route to specific devices;
* the relay can buffer messages;
* public identity keys are already exchanged.

Rather than introducing a separate prekey infrastructure, X4DH uses those existing properties and makes the responder's fresh ephemeral contribution **opportunistic**.

The design principle is:

```text
Don't wait for Bob.

If Bob is available:
    improve the session.

If Bob is unavailable:
    continue anyway.
```

---

# 18. Summary

X4DH can be summarized in one diagram:

```text
                 Alice                         Bob
                   │                            │
              IK_A / EK_A                  IK_B / EK_B
                   │                            │
                   │                            │
                   ├─────── session:propose ───►│
                   │          EK_A_pub          │
                   │                            │
                   │       offline:             │
                   │          2DH               │
                   │           │                │
                   │          RK₀               │
                   │                            │
                   │       online:              │
                   │          EK_B_pub          │
                   │◄────── session:ack ────────┤
                   │                            │
                   │       DH3 + DH4            │
                   │            │               │
                   │           RK₁              │
                   │            │               │
                   └────────────┴───────────────┘
                                │
                         Double Ratchet
                                │
                         message keys
```

### The core idea

**X4DH does not make availability a cryptographic requirement.**

The first two DH operations provide an immediately usable asynchronous session.

When both endpoints are available, two additional DH operations incorporate fresh key material from Bob and upgrade the same session.

The result is a session-establishment mechanism designed specifically around MeshChat's existing decentralized, buffered relay architecture.

As of §16, that root key is also doing real work today, ahead of the Double Ratchet's arrival: it's the direct source of the AES-256-GCM key actually encrypting live `app:message` traffic, per device pair, with graceful fallback to the legacy identity-level key wherever a session doesn't yet exist. The "message keys" box at the bottom of the diagram above is still the eventual target — what ships today is a single static key per session standing in its place, an accepted and disclosed interim step rather than the finished design.