# X4DH — MeshChat Session Establishment

> **X4DH is MeshChat's asynchronous session-establishment protocol.**
>
> It establishes a usable session immediately when the recipient is offline, and opportunistically upgrades that session when both devices are online.

**Status: designed, not yet implemented.** Client/protocol version holds at `0.4.9` until this activates end to end — the jump to `0.5.0` is reserved for when it does. The root-key KDF construction (§6.1) is now fully specified; chain-key derivation and the rest of the Double Ratchet remain a separate, not-yet-scoped design session (see `Roadmap.md`).

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

**Deliberately out of scope here: chain keys.** Deriving `CK_A→B`/`CK_B→A` directly from `RK0`/`RK1` at handshake time is tempting but premature — X4DH stops at the root key (§15). Symmetrically deriving both directions' chain keys from one shared root before any real ratchet step exists would also be a materially *weaker* construction than an actual Double Ratchet, not a simplified version of one: in Signal's design, the first sending chain key exists on only one side until the other side's first DH-ratchet reply arrives, and that asymmetry is precisely where the self-healing property against a one-time key compromise comes from. How chain keys get seeded from `RK0`/`RK1` is a decision for the dedicated ratchet-design session flagged in `Roadmap.md` (which deliberately wants Signal Sesame, Matrix Olm/Megolm, Session, and SimpleX surveyed fresh before committing to a shape), not something to pre-empt here.

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

(See §6.1 for the exact two-stage HKDF construction both sides run to reach `RK₀`/`RK₁`.)

The important distinction is:

```text
2DH = immediately usable
4DH = opportunistically stronger
```

The protocol never blocks waiting for the second endpoint.

## 7.1 State this requires that isn't obvious from the diagram

Two consequences fall out of the shape above that a naive reading of "Alice derives RK₀ and moves on" would miss:

- **Alice cannot discard `EK_A_priv` the instant she sends `session:propose`**, the way a stateless one-shot ephemeral might suggest. She needs it available if/when `session:ack` arrives, to compute `DH4`. This means a small, genuinely new piece of local state: a pending-outbound-proposal entry keyed by `(contactId, deviceId, sessionEpoch)`, holding `EK_A_priv` until either the ack lands (fold into `RK1`, then discard) or a bounded timeout passes (discard anyway, staying at `RK0` for that attempt). This state is exactly as sensitive as any other ephemeral private key in this document and must never be written anywhere that persists across the timeout — local memory only, same tier as the device seed.
- **Bob never needs to compute `RK0` at all.** The moment he generates `EK_B`, he already holds every input `RK1` requires — Alice's public `EK_A` from the proposal, and his own fresh `EK_B`. His first reply can go straight to `RK1`. Only Alice, the initiator, ever legitimately sits at `RK0` — and only for however long Bob takes to respond.

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
handshake.

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
transitions into this fully ephemeral-inclusive state before ordinary
messaging begins, whenever Bob happens to be reachable at bootstrap time.

This is an intentional trade-off.

MeshChat X4DH chooses:

> **immediate asynchronous usability over requiring a responder prekey.**

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

`sessionEpoch`, `deviceId`, and both identities instead live where they're actually enforced: inside the **signed** fields of `session:propose`/`session:ack` (§4, §13). The signature is what binds a given root key to a specific claimed session/device pair; the KDF's job is only to turn DH outputs into key bytes, with `info` providing fixed domain separation between the root key and any other future purpose this HKDF chain might need to serve (see §6.1) — not per-session uniqueness, which the ephemeral keys already guarantee on their own.

This still prevents otherwise identical key material from being interpreted as the same protocol session — the guarantee just comes from freshness plus authentication, rather than from the KDF's `info` string carrying session metadata directly.

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
guard against a delayed duplicate regressing an already-upgraded
session.

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

---

# 16. Why Not X3DH?

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

# 17. Summary

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
                   │           RK₁               │
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