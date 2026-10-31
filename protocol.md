# MeshChat Protocol v1

A decentralised, encrypted messaging protocol built on WebSocket relay servers. No accounts, no central authority, no plaintext.

Implementation version: `0.6.2`, reported informationally in the `version` field of `sig:relay_info` (not enforced). This document specifies the protocol as implemented, in enough detail to build an interoperable client. Packet shapes, key rules and signed field sets are exact; a peer that deviates will have its packets dropped. `X4DH.md` is the authoritative source for session establishment, session keys and send-readiness. `known-limitations.md` lists the permanent trade-offs.

---

## Core Concepts

**Identity** is a keypair set derived deterministically from a username and passphrase. The same credentials always produce the same identity. There is no registration, no server-side account and no recovery beyond the credentials.

**Contacts** are identified by their publicId — a short hash of their two public keys (see [PublicId](#publicid)). Adding a contact requires their shareable address, exchanged out-of-band (QR code, copy-paste). A packet from a sender who is not a contact is dropped, with one exception: the live-QR introduction (see [Live (one-way) QR](#live-one-way-qr)).

**Devices.** An identity may be logged in on several devices. Each device has its own `deviceId` and `endpointId`, and each pair of devices (between two identities, or within one) has its own cryptographic session.

**Relays** are WebSocket servers that route packets between clients. A relay has no knowledge of message contents. Clients choose which relay to use; clients on different relays communicate directly by opening connections to each other's relays.

**Authentication** gates both sending and receiving. A client must prove possession of its signing key, bound to the specific relay it dialed, before the relay accepts packets from it or registers it for inbound routing.

**The relay is untrusted infrastructure.** Cryptographic proof — signatures and authenticated encryption — is the only trust boundary. Everything outside a packet's ciphertext (`type`, `from`, `to`) is relay-visible and relay-rewritable, which is why ciphertext is bound to it (see [Envelope Binding](#envelope-binding)).

**Content is session-only.** All message content (text, audio, image, reaction, system notice, self-sync copy) is encrypted under a per-device-pair X4DH session key and under nothing else. The static pairwise key derived from the two identity keys carries exactly one kind of message — the content-free [HELLO](#hello) — plus a few signaling blobs listed under [Encryption](#encryption). A message cannot be sent to a device until a session with it is send-ready; until then it is held locally (see [Held Outbox](#held-outbox)). There is no fallback to the static key.

---

## Wire Conventions

- **Transport:** WebSocket text frames, one JSON object per frame. Frames larger than the relay's `WS_MAX_SIZE` (default 2 MiB) are dropped.
- **Binary fields** (`iv`, `data`, `sig`, `ek`, `ekPub`, `nonce`, public keys) are JSON arrays of integers 0–255.
- **Ids.** `publicId`, `deviceId` and `endpointId` are `base64url(SHA-256(...)[0:12])`, unpadded (16 characters). All ids are base64url, `[A-Za-z0-9_-]{8,64}`, which never contains `:`. `callId`, `sessionId`, `syncId` and `sessionEpoch` are random UUIDs.
- **base64url** in this document is the URL-safe alphabet without padding. The one exception is the relay segment of a shareable address, which is standard base64 (`btoa`).
- **Timestamps** are integer milliseconds since the epoch, taken from the sender's clock.
- **Signatures** are Ed25519 over the UTF-8 bytes of `JSON.stringify(body)`: compact (no whitespace), keys in exactly the order listed, optional fields that the list marks "or null" present as `null`. Signature is serialised as an array of 64 integers.
- **Verification is by the sender's signing key**, known from their shareable address. For packets from your own identity (self-targeted), verify against your own signing key.

### Signed bodies

| Packet(s) | Signed body (key order) |
|---|---|
| `app:message`, `app:migrate` | `{ type, from, to, blob }` |
| `app:burn` | `{ type, from, to, ts }` |
| `app:sync` | `{ type, from, to, syncId, reply, ek, wrapped }` (`wrapped` is `null` on a request) |
| `session:propose`, `session:ack` | `{ type, from, to, sessionEpoch, ekPub, deviceId, ts }` (`deviceId` or `null`) |
| `call:*` | `{ type, from, to, callId, deviceId, ts, blob }` (`deviceId`, `blob` or `null`) |
| `data:*` | `{ type, from, to, sessionId, deviceId, ts, blob }` (`deviceId`, `blob` or `null`) |
| `sync:backup_offer`, `sync:backup_accept`, `sync:backup_push`, `sync:restore_ack`, `sync:restore_push` | `{ type, from, to, size, ts, blob }` (`size`, `blob` or `null`), then `ek` appended as a final key **only if the packet carries one** |
| `sync:restore_req` | `{ type, from, to, ts, blob }` |
| `sync:token_resp` | `{ type, from, to, ts, token }` (`token` or `null`) |
| per-message signature (a field inside an `app:message` payload, not a packet) | `{ l, id, from, to, ts, type, …content }` — see [Per-message signatures](#per-message-signatures). Serialised as a base64url string, not an integer array |

Fields outside these sets are not signed and must not be trusted: notably the `token` attached to `sync:restore_req` and `sync:restore_push`.

---

## Identity and Key Derivation

All keys are derived deterministically from `(username, passphrase)`:

```
masterSecret = PBKDF2(
  password   = passphrase (UTF-8),
  salt       = SHA-256("meshchat-v1:" + username.toLowerCase().trim()),
  iterations = 1000000,
  hash       = SHA-256,
  bits       = 256
)
```

Every derivation parameter — iteration count, salt format, HKDF labels — is an input to the identity: changing any of them changes every derived key and therefore the `publicId`.

Three 32-byte values are expanded with HKDF-SHA-256 (`ikm = masterSecret`, `salt` = 32 zero bytes, `info` = the label below as UTF-8):

| Label | Use |
|---|---|
| `meshchat-v1:x25519`  | X25519 private scalar — key agreement |
| `meshchat-v1:backup`  | AES-256-GCM backup key — backup blobs, restore token, local storage |
| `meshchat-v1:signing` | Ed25519 signing seed |

The X25519 private scalar never leaves the device. `X25519.getPublicKey(scalar)` and `Ed25519.getPublicKey(seed)` are the two public keys that appear in the shareable address.

### PublicId

```
publicId = base64url( SHA-256(x25519PublicKey || ed25519PublicKey)[0:12] )
```

PublicId depends on **both** public keys concatenated. If it depended only on the X25519 key, an attacker could present a victim's public X25519 key with an Ed25519 key of their own, sign the relay's challenge, and have the relay register their socket under the victim's publicId — unable to read anything, but able to swallow it. Hashing both keys means a given publicId can only be produced by one specific key pair.

The relay derives publicId from the two keys presented during auth and never trusts a client-supplied id; the client checks that `public_id` in `sig:auth_ok` equals the one it derived.

### Device Identity

Each device generates a random 32-byte seed on first run and stores it under a per-identity key (`meshchat_device_seed_v1_<publicId>`):

```
deviceId = base64url( SHA-256( Ed25519.getPublicKey(seed) )[0:12] )
```

`deviceId` is local-only: it never appears in any backup, export, `serialiseContacts()` output or shareable address. It is what contacts learn and show in their device popover. It travels:

- **inside encrypted payloads** — `app:message` payloads (including `selfsync`, `hello`), self-sync backup blobs, the `restore_req` blob;
- **as a signed plaintext field** on `call:*`, `data:*` and `session:*` packets. Relay-visible; see the consequence under [Device Endpoint ID](#device-endpoint-id).

**One device, one running instance.** Two browser tabs of the same profile share the device seed, so they are the same `deviceId` and `endpointId` to everyone, but each tab holds its own in-memory ephemerals and held outbox and both write the same local storage. A client must therefore allow only one live instance per (storage partition, identity): the reference client holds a Web Lock named `meshchat-identity-<publicId>` for the life of the tab, offers takeover with `{ steal: true }` at login, and a displaced tab closes its socket and reloads to the login screen (and does not auto-login straight back — see [Local Session](#local-session-auto-login-and-logout)).

### Device Endpoint ID

A second value from the same device seed, presented to the relay instead of to contacts:

```
endpointId = base64url( HKDF-SHA256(
  ikm  = deviceSeed,
  salt = 32 zero bytes,
  info = "meshchat-v1:device-endpoint",
  bits = 256
)[0:12] )
```

`deviceId` and `endpointId` share one seed but use different derivations; HKDF-SHA-256 is a PRF, so knowing one gives no leverage on the other without the seed. The split avoids one identifier doing two jobs: the relay sees every `endpointId` that authenticates (to route to a socket), a contact sees every `deviceId` a sender's messages carry (to tell devices apart).

What the split does and does not buy:

- Message traffic, self-sync traffic and push registration never put both values in one relay-visible place.
- It is **not** anonymity from the relay: IP, timing and reconnect patterns still correlate connections.
- It does **not** hide the link from a relay that sees packets carrying `deviceId` in plaintext (`call:*`, `data:*`, `session:*`): the relay knows the `endpointId` the sending socket authenticated with and reads the `deviceId` beside it.

`endpointId` is:
- **presented to the relay** — optionally, in the clear, in `sig:auth_init`, covered by the auth signature. A client that omits it gets no device-level routing;
- **learned by contacts** — from the encrypted payload of `app:message` (alongside `deviceId` and `n`), from self-sync blobs, and from the compound `from` address of handshake packets whose signature has verified. Recorded in the device registry only after signature verification;
- never in the shareable address, never in backups;
- static per (device, identity).

---

## Compound Addressing

A packet's `to` may carry an optional device-routing suffix:

```
to = "<publicId>"                  — every live session under this identity
to = "<publicId>::<endpointId>"    — one specific registered device only
```

The separator is `::`. Ids never contain `:`, so the split is unambiguous. Both halves must be valid ids. Implement one shared `parseAddress`/`buildAddress` pair; nothing else should hand-roll the split.

**`from` is bare** with one deliberate exception, covering five types: `sync:backup_offer`, `sync:backup_accept` and `sync:backup_push` on the contact path, and `sync:restore_ack` and `sync:restore_push`. For these, `from` is `"<publicId>::<endpointId>"` of the sending device. The exception exists because these handshakes may reach a fresh or not-yet-mutual contact with no shared key material, so the address is the only channel guaranteed to reach them. The relay validates the base id of a compound `from` against the authenticated identities exactly as for a bare `from`. `sync:restore_req` is not in this set — its `from` stays bare. Elsewhere `from` is not a routing instruction; the relay derives the true sender from the authenticated socket.

| Form of `to` | Types |
|---|---|
| compound **required** (bare dropped) | `session:propose`, `session:ack` |
| compound **rejected** (dropped) | `app:migrate`, `app:burn` |
| either | `app:message`, `app:sync`, every `sync:*`, every `call:*`, every `data:*` |

**Delivery.** A compound `to` is delivered only to the socket(s) registered under that endpoint. A targeted device that is not connected is treated as offline; the packet is never broadcast to the identity's other sessions instead. Which types are buffered is in [Offline Delivery](#offline-delivery).

**Receive-side check (every handler).** A packet is accepted only if the base id of `to` equals our own publicId **and**, when an endpoint is named, it equals our own `endpointId`. `app:migrate` and `app:burn` require `to` to be exactly our bare publicId. The relay routes on the endpoint, but a relay is exactly the party that cannot be trusted to do so.

---

## Shareable Address

```
<x25519PublicKey_b64url>.<ed25519PublicKey_b64url>.<relayWss_b64>
```

The first two segments are base64url public keys (32 bytes each); there is no secret anywhere in the address, and it can be shared as freely as a phone number. Holding it lets you reach and encrypt to someone; it does not let you read anyone's traffic or impersonate anyone.

The third segment is `btoa(wssUrl)` (standard base64), optional but included when sharing, to bootstrap relay connectivity. Decode with `atob`. Segments beyond the third are ignored. A parser must reject anything with fewer than 2 or more than 3 segments, or keys that are not 32 bytes.

The address a client displays always reflects its own local truth about its relay (see [Relay Discovery](#relay-discovery)).

### Live (one-way) QR

The plain address QR is two-way: each side must add the other, because a packet from a non-contact is dropped. A **live QR** lets one side show and the other scan; the shower is added automatically.

```
liveKey = <shareableAddress> "~" <token>
token   = base64url(16 random bytes)          // exactly 22 characters, [A-Za-z0-9_-]
```

`~` is not in base64url, base64 or the `.` separator, so the split is unambiguous. A key containing `~` whose token is malformed must be rejected outright — never silently treated as a plain address.

**Shower** (needs to stay online while the QR is displayed):

1. Arms a fresh token, held in memory only, valid for **120 s**, single use. Arming again replaces it. Closing the add-contact dialog or switching to the offline QR disarms at once. An expired QR is not re-armed automatically.
2. Displays `liveKey` (QR, and copyable text).

**Scanner:**

1. Parses `liveKey`, adds the shower as a contact (as for any address).
2. Sends an **introduction**: an `app:message` from the scanner to the shower, `to` = the shower's bare publicId.

```
payload = { id: <uuid>, type: "intro", ts, addr: <scanner's own shareable address>, deviceId, endpointId }
eph     = fresh X25519 keypair
shared  = X25519(eph.priv, showerX25519PublicKey)
wrapKey = HKDF-SHA256(ikm = shared, salt = tokenBytes (16), info = "meshchat-v1:qr-intro", 256 bits) → AES-256-GCM key
blob    = messageBlob_v2(wrapKey, payload, aad = envelopeAad("app:message", from, to))
blob.intro = 1
blob.ek    = eph.pub (32 bytes)
sig        = Ed25519.sign({ type, from, to, blob }) — blob includes intro and ek
```

The token is never transmitted; it is only a KDF salt, so the AES-GCM tag check is the token check.

**Shower, on a packet from a non-contact with `blob.intro === 1`** (anything else from a non-contact is dropped):

1. Drop unless a token is armed, not expired (judged on the shower's own clock when the packet is processed, so a packet a relay buffered and flushes late is rejected), and not mid-claim.
2. Require `type === "app:message"`, `blob.v === 2`, a `sig`, string `from`, and `blob.ek` an array of 32 integers 0–255.
3. Derive `wrapKey` from `X25519(showerScalar, ek)` and the token; decrypt with `envelopeAad(type, from, to)`. A failure (wrong token, junk) is ignored silently and **does not** disarm the QR.
4. Take the claim lock (two valid introductions arriving together must not both win), then require: `plain.type === "intro"`, `plain.addr` parses as an address, the address's two keys hash to `msg.from`, the envelope signature verifies under the signing key in that address, the sender is neither us nor an existing contact, the token has not expired mid-claim.
5. Add the contact (placeholder local name, e.g. `QR contact <short id>`), record `deviceId`/`endpointId` if both are well-formed ids, mark online, **disarm the token (single use)**, and send a [HELLO](#hello) with no rate-limit delay. A failed check releases the claim lock but never burns the token.
6. Never reply to a rejected introduction.

Residual risk by construction: whoever obtains the token itself (a photo of the screen) and reaches the shower first can add themselves, once. The shower sees who was added and can rename the contact; the intended scanner sees no hello come back.

---

## Relay Authentication

Authentication happens on connect, before routing or buffer delivery. The client proves possession of the identity's Ed25519 key by signing a fixed-layout message that binds the proof to the relay it dialed.

### Sequence

```
client → server:  sig:auth_init      { auth_v: 2, x25519_pub: [...32 bytes], ed25519_pub: [...32 bytes], endpoint_id?: "...", no_receive?: true }
server → client:  sig:auth_challenge { nonce: [...32 bytes] }
client → server:  sig:auth_proof     { sig: [...64 bytes] }
server → client:  sig:auth_ok        { public_id: "..." }
             or:  sig:auth_fail      { reason: "..." }
```

1. The client sends `auth_v`, both public keys, an optional `endpoint_id` and `no_receive` (sent only when `true`). The server requires `auth_v` to equal its own (`2`), `no_receive` to be a boolean if present, both keys to be 32 bytes, and `endpoint_id` to be a valid id.
2. The server sends a random 32-byte nonce in the clear. The client refuses to sign any challenge whose nonce is not exactly 32 bytes, so a relay cannot choose the length or content of what is signed.
3. The client signs the auth message (below) and returns the signature.
4. The server rebuilds the same message from the nonce it issued and what the client presented, against its own configured host(s), and verifies. It derives publicId from **both** presented keys, registers the socket, and flushes the offline buffer. If an `endpoint_id` was presented the socket is also registered under that endpoint.
5. The client checks that `public_id` equals its own, then proceeds with `sig:relay_req`, presence polling and normal operation. A mismatch drops the connection.

`no_receive: true` completes the handshake without registering the socket as a recipient and without a buffer flush. Used by disposable probes (the migrate panel's TEST) that must not consume buffered packets.

A socket is bound to one identity: a different identity proven on the same socket is rejected (`already_authenticated`); re-proving the same identity is a no-op. A client answers a challenge only while it is itself waiting for one on that socket. Any other `sig:auth_*` arriving later on a socket is ignored.

### The signed auth message

```
"meshchat-auth-v1" 00 | relayHost 00 | nonce(32) | x25519_pub(32) | ed25519_pub(32) | endpoint_id 00 | no_receive(1 byte)
```

`00` is a zero byte. `endpoint_id` is empty (just its terminating `00`) when absent. `no_receive` is `01` or `00`.

| Field | Why it is there |
|---|---|
| `"meshchat-auth-v1"` label | Every packet signature is over JSON text, which starts with `{`; an auth signature can never verify as a packet signature |
| `relayHost` | The host the client **dialed**, taken from the URL of the socket itself, never from anything in the challenge. A relay that forwards someone else's challenge gets a signature bound to *its* host, which the real relay rejects |
| `nonce` | Fixed length; the relay chooses neither length nor content |
| keys, `endpoint_id`, `no_receive` | Inside the signature, they cannot be swapped in transit |

Host normalisation is identical on both sides: lowercase, IPv6 brackets and trailing dot stripped; the server additionally encodes IDNA/punycode to ASCII.

**Server-side host binding.** The relay verifies against its own configured host name(s): the host of `RELAY_WSS_URL`, plus any extra names in `RELAY_AUTH_HOSTS` for a relay reachable under more than one name. A client signs the host it dialed, so an unlisted name fails with `proof_invalid`. The host is never derived from the `Host` header. With no valid `RELAY_WSS_URL` the relay refuses every `sig:auth_init` with `relay_not_configured`.

There is no dual-version path: a client with a different `auth_v` gets `auth_version`.

### Cross-relay connections

To deliver to a contact on a foreign relay, the client opens a connection to that relay and runs the full handshake against that relay's own host before sending anything. The connection is registered there as a session for as long as it stays open; the outbound queue is held until auth completes, then flushed. `sig:auth_*` messages arriving on such a socket belong to that socket's own handshake and are never handed to the main signal handler. The home relay is never targeted this way (the main signal socket is used).

### Admission limits

A connection that sends `sig:auth_init` but never a proof is closed after `AUTH_TIMEOUT` (15 s, enforced by a periodic sweep). Completed auths are additionally rate-limited server-wide (`GLOBAL_AUTH_RATE`/`GLOBAL_AUTH_BURST`), checked only after the proof is valid; a rejected completion gets `server_busy`.

### Auth failure

On `sig:auth_fail` the client does not retry immediately — the socket `onclose` handler drives reconnect with backoff. Reason codes: `auth_version`, `relay_not_configured`, `bad_init`, `bad_key_length`, `bad_endpoint_id`, `timeout`, `proof_invalid`, `server_busy`, `already_authenticated`, `not_authenticated`.

### Security properties

- Proof of possession of the Ed25519 key is a real signature, not a decrypt round trip.
- The signature is bound to the dialed host: no relay can use a challenge as a signing oracle, and a proof captured at one relay is worthless at another.
- A captured signature is valid only for its nonce and host; each connection gets a fresh nonce.
- publicId binds both public keys, closing the key-swap attack.

---

## Encryption

Four independent key families:

- **Session wire keys** — per device pair, derived from an X4DH session root (see `X4DH.md`). Protect all `app:message` content and self-sync backup traffic.
- **Static pairwise key** — per identity pair, derived from the two identity keys. Protects only [HELLO](#hello), `app:migrate`, the SDP/ICE blobs of `call:*` and `data:*`, and the `restore_req` blob.
- **Backup key** — passphrase-derived and deterministic. Protects backup blobs, the restore token, local storage, and the discovery hello/ack of self-sync.
- **Ephemeral wrap keys** — one-shot keys from an ephemeral-to-ephemeral X25519 exchange. Protect specific handshake pushes and the manual-sync batch.

### Primitive: blobs

AES-256-GCM, random 12-byte IV, 128-bit tag. A blob is `{ v, iv: [...12], data: [...ciphertext+tag] }`. Two formats exist; which applies is fixed per packet type, and a receiver rejects any other version:

| Format | Plaintext | Unbound | Envelope-bound |
|---|---|---|---|
| **message blob** | UTF-8 JSON | `v:1` | `v:2` |
| **object blob** | gzip(UTF-8 JSON) | `v:2` | `v:3` |

A decrypt that is given an AAD requires exactly the bound version and never falls back to an unbound blob; a decrypt without one refuses a bound blob.

### Static pairwise key

```
sharedSecret = X25519(ownX25519Scalar, counterpartX25519PublicKey)
aesKey       = HKDF-SHA256(ikm = sharedSecret, salt = 32 zero bytes, info = "meshchat-v1:pairwise", 256 bits)
```

Static-static ECDH is symmetric, so both sides derive the same key. Self-targeted traffic uses the same derivation against the identity's own public key. This key is **not** forward-secret: a later compromise of either identity's X25519 scalar exposes everything recorded under it. This is why it carries only content-free or short-lived material.

### X4DH wire key

For a device pair with an X4DH session, all `app:message` content encrypts under:

```
wireKey = HKDF-SHA256(ikm = rootKeyBytes, salt = 32 zero bytes, info = "MeshChat-X4DH-v1/wire-message", 256 bits)
```

where `rootKeyBytes` is `RK0` or `RK1` of that session. The send/decrypt generation rules, trial decryption and send-readiness are specified in `X4DH.md` §6–§8. Summary: **send** under the newest root the peer has demonstrably reached; **decrypt** under every generation still alive; a sibling device within one fanout may be on a different root than another.

### Envelope Binding

A packet's `{ type, from, to }` sit outside its ciphertext, where a relay can rewrite them. Two mechanisms tie the ciphertext to them:

1. **AAD.** The AES-GCM additional data is
   ```
   aad = UTF-8( JSON.stringify( ["meshchat-env-v1", type, from, to] ) )
   ```
   built by the receiver from the packet *as received* — `to` bare or compound exactly as sent — never from anything inside the payload. Rewriting any of the three in transit fails the GCM tag and the packet is dropped at decrypt.
2. **Signature scope.** The Ed25519 signature covers `type`, `from` and `to` as well as the content (see [Signed bodies](#signed-bodies)), so a signature for one type can never verify as another.

### Message signing

```
sig = Ed25519.sign( UTF-8(JSON.stringify({ type, from, to, blob })), senderSigningSeed )
```

For `app:message`, an invalid or missing signature on a packet whose ciphertext nevertheless decrypts is flagged, not dropped: a content message is displayed with an "unverified" warning. A HELLO or selfsync with an invalid signature is ignored/dropped, and every packet type that drives state rather than display drops on an invalid signature.

### Per-message signatures

The envelope signature proves a *packet* came from its sender; it says nothing about a message once that message has been copied somewhere else. A manual-sync batch (`app:sync`) is signed by the peer as a whole, which proves the batch is theirs — not that every entry in it is something *we* said. Without more, a peer could slip entries with `from` set to us into our own conversation history. So every message a client composes also carries its own signature, made with the identity signing key (any device of the identity can sign; any holder can verify against the signer's public key).

```
body = { l: "meshchat/msg/1", id, from, to, ts, type, …content }
sig  = base64url( Ed25519.sign( UTF-8(JSON.stringify(body)), signingSeed ) )      // 64 raw bytes
```

`type` is `"text"` when the payload has none. Content, in this key order: text → `text`; system → `kind` (or `null`), `text`; audio/image → `mimeType` (or `null`); reaction → `targetId`, `emoji` (or `null`). `to` is the **other party of the conversation** (our own id for the self chat). It is not stored with the message: the verifier supplies it from the conversation it is checking, so a message signed for one contact cannot be replayed into another conversation. Not signed: `deviceId`, `n` and the ack pointer (ordering hints, never authorship), `status`, `valid`, and media bytes (the stub's `mimeType` is covered, the payload is not).

The signature travels as `sig` inside the encrypted payload (every content payload type, and the inner message of a `selfsync`) and is stored on the record, so a receiver keeps the **sender's** signature next to its own copy. That is what lets a wiped device get its own sent messages back from a peer's sync batch and verify them. The receiver keeps it only if it verifies against the sender's key (with `to` = the receiver) **and** the stored `ts` is unchanged: a record whose `ts` was clamped on receipt (see [Message ids and timestamps](#message-ids-and-timestamps)) no longer matches what was signed and is stored without one. A `hello`, a QR introduction and the outer payload of a `selfsync` carry none. A payload without one (an older client) is still accepted on the strength of its envelope; it simply cannot be vouched for in a later sync.

The signature is checked where it matters — in a sync batch (see [Manual Sync](#manual-sync-appsync)), in a `selfsync` copy, and on receipt — never trusted from its mere presence. `SYNC_ACCEPT_UNSIGNED_OWN` is the transition switch (reference client: `true`): while set, an *unsigned* entry in a peer's sync batch claiming `from` = us (a message from before this existed) is accepted but stored `valid: false` and shown "⚠ unverified"; unset, it is dropped. An entry whose signature is present but wrong is always dropped.

### Packet security matrix

| Packet | Content protection | Signature | Buffered offline |
|---|---|---|---|
| `app:message` — content | session wire key, message blob `v:2` bound | mandatory to *trust*; invalid ⇒ shown flagged. Plus an inner per-message signature | yes (+ push) |
| `app:message` — `hello` | static pairwise key, message blob `v:2` bound | invalid ⇒ ignored | yes (+ push) |
| `app:message` — QR intro | token-derived key, `v:2` bound, plus `intro`/`ek` | mandatory | yes |
| `app:migrate` | static pairwise key, `v:2` bound | mandatory | yes — always, overwrite per sender, 7 d |
| `app:burn` | none (sign-only) | mandatory | yes — always, overwrite per sender, 7 d |
| `app:sync` | message batch in an ephemeral wrap; rest plaintext | mandatory | no |
| `session:propose` / `session:ack` | none (public keys) | mandatory | yes — always; propose overwrites per sender |
| `call:invite/claim/cancel/end`, `data:…` equivalents | none | mandatory | no |
| `call:offer/answer/ice`, `data:offer/answer/ice` | static pairwise key, message blob `v:1` unbound, inside the signature | mandatory | no |
| `sync:backup_offer/accept/push` (contact path) | backup-key object blob `v:2` (+ ephemeral wrap on push) | conditional | no |
| `sync:restore_req` | static pairwise key, object blob `v:2` unbound | mandatory | no |
| `sync:restore_ack/push` | backup-key object blob (+ ephemeral wrap) | conditional (self `restore_ack`: mandatory) | no |
| `sync:token_req` | none | none | no |
| `sync:token_resp` | token sealed under backup key | mandatory (client-checked) | no |
| self-sync `sync:backup_push/accept` | session wire key or backup key, object blob `v:3` bound | none (tamper-evident only) | no |

**Conditional signature.** If we hold a signing key for the claimed sender — a contact on file or, for `restore_push`, one recovered from an opened restore token — the packet **must** verify, and a missing or invalid signature is dropped. If we hold no key for the sender (a fresh or not-yet-mutual device bootstrapping) the packet is processed unverified, as this handshake has always had to allow. A *missing* signature from a known sender is treated as tampering, not as "unverifiable": otherwise a relay could strip `sig` (and `ek`, which the signature covers) from a known contact's packet and have it processed on the unverified path — overwriting the backup we hold for them, or making us send a backup unwrapped.

---

## Session Establishment (X4DH)

Device pairs establish an X4DH session — an asynchronous root-key agreement that upgrades opportunistically when both sides are online — and use it for the wire key above. `X4DH.md` specifies the derivations, state machine, guards and retry logic. This section covers the wire packets and relay behaviour.

```json
{
  "type":         "session:propose",
  "from":         "<publicId>",
  "to":           "<publicId>::<endpointId>",
  "sessionEpoch": "<uuid>",
  "ekPub":        [ /* 32 bytes: fresh X25519 ephemeral public key */ ],
  "deviceId":     "<deviceId>",
  "ts":           1234567890123,
  "sig":          [...]
}
```

`session:ack` is structurally identical, sent in reply (`ekPub` is the responder's ephemeral). Both types:

- are **mandatory-signed** (see [Signed bodies](#signed-bodies)) and dropped on a missing or invalid signature. `deviceId` is an identity-authenticated claim, not proven with a separate device key;
- **require a compound `to`** — a session is always device-to-device; the relay drops a bare `to`;
- are **always durably buffered** in addition to live delivery (a stale-but-not-yet-closed session of the same identity could otherwise swallow a packet meant for a device still catching up). `session:propose` additionally overwrites per sender in its own bucket and uses the ordinary 24 h TTL; `session:ack` is not overwritten;
- **never trigger a push**.

Session state is local-only and stored encrypted at rest under the backup key; root keys are never part of any backup or export.

---

## Messages

### Payload

The plaintext payload of a text message:

```json
{
  "id":          "<uuid>",
  "text":        "hello",
  "ts":          1234567890123,
  "sig":         "<base64url per-message signature>",
  "deviceId":    "<deviceId>",
  "endpointId":  "<endpointId>",
  "n":           17,
  "ackDeviceId": "<deviceId>",
  "ackN":        41,
  "relay":       { "wss": "wss://sender.example.com/ws/" }
}
```

A text payload carries no `type`; absence means text. Other payloads set `type`.

- `id` must match `[A-Za-z0-9_-]{1,64}` (a uuid for ordinary messages), and `ts` is clamped by the receiver — see [Message ids and timestamps](#message-ids-and-timestamps).
- `sig` is the [per-message signature](#per-message-signatures). Optional on the wire only for compatibility with older clients; every current client sends it on text, audio, image, system and reaction payloads.
- `relay.wss` is the sender's current relay. Recipients update their routing table for the sender from it **only when the message's signature verified**, timestamp-guarded and clamped (see [Relay Discovery](#relay-discovery)).
- `endpointId` travels alongside `deviceId`; a contact learns a sender's endpoint from it, recorded in the device registry only after signature verification. An omitted value leaves what is on file untouched.
- `n` is a per-(sending device, contact) send counter, local to the sender, never synced between a sender's own devices. It counts text, audio, image and system payloads (assigned when the message is composed, even if it is then held); reactions and hellos carry none. Recipients use it for gap detection.
- `ackDeviceId`/`ackN` point at the `(deviceId, n)` message this one was composed as a reply-after (see [Message Merging](#message-merging)). Absent when the sender has no usable pointer yet.

| `type` | Fields beyond the common ones |
|---|---|
| *(absent)* text | `text` |
| `audio`, `image` | `data` (base64), `mimeType` |
| `reaction` | `targetId`, `emoji` (`":)"`, `":("`, or `null` = cleared / RECEIVED ack). `id` is a derived stable id, not a uuid |
| `system` | `kind`, `text` — a real encrypted `app:message`; used today for the call notice (`kind: "call"`) |
| `selfsync` | `peerId`, `msg` — see [Self-sync mirror](#self-sync-mirror-selfsync) |
| `hello` | see [HELLO](#hello) |

Image payloads are JPEG, downscaled to at most 800 px on the long edge. Media is held in memory only (never persisted); the stored message keeps a stub.

### HELLO

A content-free `app:message`:

```json
{ "id": "<uuid>", "type": "hello", "ts": 1234567890123, "deviceId": "<deviceId>", "endpointId": "<endpointId>", "relay": { "wss": "..." } }
```

Envelope: `app:message`, `to` = the contact's **bare** publicId (every device of the contact), blob = message blob `v:2` under the **static pairwise key**, signed like any `app:message`. It is the only thing that key still carries as a message. It holds nothing worth protecting beyond what the relay already sees; its purpose is to tell the other side "this device, at this endpoint, exists", which is the input X4DH bootstrap needs (the fixed initiator can only propose once it knows the responder's `endpointId`; the responder can only ack once it knows the initiator's).

**Send rules**

- Never to ourselves, a blocked contact, or a contact with no static key.
- Per-contact rate limit: at least 20 s between event-driven hellos (the timestamp is taken before any async work, so two callers in one tick cannot both send). The held-outbox retry uses 15 min.
- Routed like any message to that contact (contact's relay, else main socket).

**Triggers** — a hello is sent when:
- a send finds no send-ready session for a contact, or some fresh device of the contact has no session at all (`contactNeedsHello`);
- a contact transitions from offline to online and `contactNeedsHello` holds;
- the held outbox ticks (see below), the contact is believed online, a message is still held, and `contactNeedsHello` holds (15 min interval);
- the reply rule below fires;
- a live-QR introduction is accepted.

`contactNeedsHello(contact)`: true when no device of the contact is known (a fresh contact), or any known device whose `lastSeen` is within `FANOUT_STALE_MS` (7 d) has no session record. A device whose handshake is merely in progress has a session record and does not count.

**Receive** (after the general pipeline has decrypted, verified, and recorded the sender's device): ignore if the signature is invalid, if from ourselves, or if `deviceId`/`endpointId` are missing. Otherwise the pipeline has already recorded the device and relay hint. **Reply rule:** if we hold no session record for `(sender, deviceId)`, answer with our own hello. Loops cannot occur — replies stop once a session record exists, and sending is rate-limited.

**Relay side effects:** a hello is an ordinary `app:message` to the relay, so an offline recipient gets it buffered for 24 h and a web push fires, exactly as for a real message. Receivers must already have the sender as a contact; a hello from a stranger is dropped, and the next trigger retries.

### Self-sync mirror (`selfsync`)

A message or manual reaction composed on one device is mirrored to the identity's other devices as an `app:message` addressed to the identity itself, through the normal per-device fanout. Because it goes through the fanout it is **session-only**: it is sent only to siblings with a send-ready X4DH session; a sibling without one is skipped (not downgraded to a static key), and the periodic full self-backup repairs it once a session exists.

```json
{
  "id":         "ss:<inner id>",
  "type":       "selfsync",
  "peerId":     "<contact the message belongs to>",
  "msg":        { "id", "type", "ts", "text" | "mimeType" | "targetId" + "emoji", "sig", "deviceId", "n", "ackDeviceId", "ackN" },
  "ts":         <inner message's ts>,
  "deviceId":   "<deviceId>", "endpointId": "<endpointId>", "relay": { ... }
}
```

What is mirrored: text, audio/image as a stub only (`id`, `type`, `mimeType` — never the media), and manual reactions. Not mirrored: call notices, RECEIVED auto-acks (every sibling receives the original from the contact itself and acks on its own), messages to oneself. Nothing is sent while no sibling device is known; a sibling that has never been heard from cannot be addressed and is discovered through the self-backup hello or its own traffic. The outer `id` is deterministic (`ss:` + inner id) and `ts` is the inner message's, so a retry or a second delivery of the same copy hits the receive-side duplicate guard. Mirroring happens when a message actually leaves (status `sent`), not when it is held.

**Receive rules** — each closes a specific hole:
- Must come from our own identity and carry a valid signature; otherwise dropped (unlike an ordinary message, there is no displayed-with-a-warning case, since the payload writes into a different conversation than the sender field suggests).
- Our own echo (`deviceId` equal to ours) is ignored. A `peerId` that is unknown, blocked or ourselves is ignored.
- Inner message needs a string `id` ≤ 64 chars and a finite `ts`.
- Fields are copied from a whitelist, never spread. Stored copy: `from` = us, `valid: true`, `status: "sent"`. A non-reaction already on file is skipped (a mirrored copy must not replace the local object and lose its delivery status); reactions are the exception since the same id carries newer state.
- The inner `sig`, when present, is kept only if it verifies against **our own** signing key (with `peerId` as the conversation's other party). A sibling's copy without a valid one is still accepted — the decrypt authenticated it — it just cannot be forwarded later as signed.
- Never sends anything back (no ack, no re-fan), never bumps unread, never sets the local-only `ackTrusted` flag, and the embedded `n` is stored but never fed to gap detection.

### Delivery acknowledgement (RECEIVED)

There is no dedicated packet type.

**Local message status** (sender-side, never on the wire):

| `status` | Meaning |
|---|---|
| `waiting` | held locally until a send-ready session exists (see [Held Outbox](#held-outbox)) |
| `sent` | at least one packet left the device (a relay socket or the main signal socket accepted it); no relay or recipient confirmation |
| `delivered` | a recipient device decrypted, verified and persisted it (an ack reaction arrived) |
| `failed` | nothing left the device, or the held message expired / lost its content |

Only our own messages carry a status. `waiting` is meaningful only on the device that composed the message and is stripped from everything serialised for another device (backups, self-sync pushes, exports); only the device's own local-storage write keeps it.

**RECEIVED** reuses the reaction channel. Once a recipient has decrypted an incoming message, verified its signature **and persisted it**, it sends a `reaction` back to the sender with `targetId` = the original id and `emoji: null`:

```json
{ "id": "<derived-reaction-id>", "type": "reaction", "targetId": "<original msg id>", "emoji": null, "ts": ..., "deviceId": "...", "endpointId": "..." }
```

The id is `base64url(SHA-256("reaction:" + myPublicId + ":" + targetMsgId)[0:12])` and is identical for an ordinary emoji reaction, a cleared one and the auto-ack, so each replaces the previous state on merge. The sender treats *any* reaction targeting one of its own outbound messages as proof of delivery and sets that message's status to `delivered` (whatever it was before). This reconciliation runs after every merge, whichever path (live, backup, restore, sync) delivered the reaction.

The ack never fires for self-targeted traffic, for a message that failed verification, for hello or selfsync packets, or in response to a reaction. It goes through the normal per-device fanout (every known device of the original sender gets its own copy, so every sending device's status flips) and is **never held**: a device with no send-ready session simply does not receive it. It is also sent for an **exact redelivery** of a message already on file (the copy on file may have arrived by another route first — a sync, a sibling — and the sender's `sent` only flips to `delivered` on our ack); a refused id collision (see [Message ids and timestamps](#message-ids-and-timestamps)) is never acked. READ status is not implemented.

### Outer envelope (`app:message`)

```json
{
  "type": "app:message",
  "from": "<publicId>",
  "to":   "<publicId>" | "<publicId>::<endpointId>",
  "blob": { "v": 2, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The envelope carries no `deviceId`; the sender's device is inside the encrypted payload. Content messages always use a compound `to` (the recipient's `endpointId`, learned earlier); `blob` and `sig` differ per destination because each device has its own key and the AAD and signature cover that destination's `to`. Only HELLO and the QR introduction use a bare `to`.

### Receiving an `app:message`

Normative order:

1. Require `from`, `blob`, and `isAddressedToMe(to)`.
2. Look up `contact = contacts[from]`. No contact: if `blob.intro === 1` hand to the QR-intro handler, else drop. A blocked contact: drop.
3. Mark the sender online.
4. Decrypt by trial: every X4DH session held for that sender, most recently established first; within a session every live key generation (current root, retained `RK0`, recently retired roots); then the static pairwise key last. The AAD is built from the envelope as received. A wrong key fails cleanly on the GCM tag. Record which key worked (session + generation, or static).
5. **If the static key worked and `plain.type !== "hello"`, drop the packet** before it touches the device registry, dedup cache, unread counters or ack.
6. Verify the signature (`valid`).
7. If decrypted under a session key and valid, `plain.deviceId` must equal the session's device; a mismatch sets `valid = false`.
8. If valid and decrypted under the session's **current** `RK1`, confirm the peer holds `RK1` (see `X4DH.md` §7).
9. **Shape check, content messages only** (not `hello`, not `selfsync`): `id` well-formed, `text` a string for text/system payloads, and for a reaction `id` equal to the derived reaction id of `(from, targetId)`. Otherwise drop. This runs before the duplicate guard so a rejected packet cannot stamp the window.
10. Drop if `(from, plain.id, plain.ts)` was seen within the last 3 s (a targeted copy and another path can both arrive). The sender is part of the key so one contact's packet cannot suppress another's.
11. If valid and `plain.deviceId`: record the device (`deviceId`, `n`, `endpointId`). If valid and `plain.relay.wss`: adopt it as a relay hint (clamped, timestamp-guarded).
12. `hello` → hello handler, stop. `selfsync` → self-sync handler, stop.
13. Build the stored message: `ts` clamped (see below), `n`, `deviceId` and ack pointer copied from the payload, media as a stub. Keep the payload's per-message `sig` only if it verifies (`to` = us) and `ts` was not clamped.
14. **Id check** (see below): drop if this id may not be used here. An exact redelivery is dropped quietly but still gets the RECEIVED ack (if valid, not from ourselves, not a reaction); a refused collision gets nothing.
15. Only now write the media caches and the packet-inspector cache (both are keyed by id), merge, reconcile delivery status and missing numbers, bump unread if the chat is not open.
16. **Persist**, then trigger a backup round.
17. Only now send the RECEIVED auto-ack (if not a reaction, `valid`, and `from` is not ourselves).

### Message ids and timestamps

A conversation's messages are keyed by `id` alone, and a same-id collision is resolved by `ts` — both chosen by whoever sent the packet. Left alone that lets a contact replace a message already in the conversation (ours included) by reusing its id, overwrite one of our reactions (the reaction id is a hash of public values), stamp a future `ts` so its copy outranks every genuine later one, and overwrite the audio/image cache entry of a message id before any merge rule could object. These rules run before the receive path touches any cache or merges anything:

- **Well-formed ids.** `[A-Za-z0-9_-]{1,64}`.
- **Reaction ids are slots.** A reaction's `id` must equal `base64url(SHA-256("reaction:" + senderId + ":" + targetId)[0:12])`, so it can only occupy its own sender's slot for that target.
- **An id already on file is refused**, except as a reaction replacing its own earlier state. Refused: an id belonging to a message from the other party; an id belonging to a message of a different type; an id reused with different content (messages are immutable). Allowed: same sender, same type, `reaction` (the newer `ts` wins, see [Message Merging](#message-merging)); and an identical copy that is now verified, which may upgrade an existing `valid: false` copy. An identical unverified redelivery is dropped quietly (debug log); the others are logged as warnings.
- **`ts` is clamped to the receiver's clock plus 5 minutes** (`MSG_TS_SKEW_MS`); a missing, non-numeric or non-positive `ts` becomes "now". A sender cannot claim to be from the future, only slightly ahead to absorb ordinary clock skew. The clamp is on the receiver's clock, the same idea as the relay-hint clamp under [Relay Discovery](#relay-discovery).

---

## Sending

### Routing rule

Every outbound message goes to the **contact's relay WSS** — never to the sender's own relay, never based on online presence. Priority:
1. `contact.lastRelay` hostname equals the home relay → main signal socket.
2. `contact.lastRelay` known, different host → open or reuse an outbound relay connection.
3. No `lastRelay` known → main signal socket (last resort).

If the contact's relay is unreachable the fallback lands on the sender's own signal connection, which buffers server-side until the contact reconnects. Presence (`sig:seen`) is UI and opportunism only and never affects routing.

### Per-device fanout

A send to a contact addresses that contact's known devices from the [device registry](#device-registry):

- **Targeted** — a device with an `endpointId` on file that was seen within `FANOUT_STALE_MS` (7 d) **or** has an X4DH session with us. A device with a session stays targeted however long it has been quiet (its copy is encrypted under its own key and buffered in its own endpoint bucket). A device that is stale with no session is not targeted, and neither is one with no `endpointId`. In a self fanout the sending device itself is excluded.
- Each targeted device with a **send-ready** session gets **its own ciphertext**, compound `to`, signed, encrypted under that device's wire key. A targeted device without a send-ready session is skipped for this message.
- There is no identity-level broadcast copy and no static-key copy of any content.
- When some fresh device of the contact has no session (`contactNeedsHello`), a [HELLO](#hello) goes out as well. Self fanout never says hello (siblings bootstrap via the self-backup handshake and ordinary self traffic).

A message sent while some devices are ready and others are not goes to the ready ones only; the others do not receive it later except through manual SYNC, backup or self-sync repair.

### Send-readiness

A session is **send-ready** when we may encrypt content under it (`X4DH.md` §7.2):
- `RK1`: ready.
- responder at `RK0`: ready at once (the initiator certainly holds `RK0`).
- initiator at `RK0`: ready only once its handshake window (60 s from `establishedAt`) has closed; inside the window the ack may still arrive and a message sent now could overtake the propose.

### Held Outbox

A message to a contact with no send-ready session cannot go anywhere yet. It is not dropped and not downgraded: it is stored locally with `status: "waiting"` and sent automatically when a session is ready.

```
sendContent(contactId, payload, { hold = true }):
  self chat:   fan out to siblings; "sent" if nothing was addressable or at least
               one packet was written, else "failed"
  ready  = number of targeted devices with a send-ready session
  queued = hold && an earlier message to this contact is still "waiting"
  if ready == 0 or queued:
      if contactNeedsHello: sendHello
      if !hold:  outcome "failed" (not stored for later — it would be stale)
      else:      outcome "waiting"; if ready > 0, schedule a flush right after the caller stores the message
  else:
      fan out; outcome "sent" if ≥ 1 packet was written to a socket, else "failed"
```

The caller stores the message with `status = outcome`. Rules:

- **Order is kept.** A new message queues behind earlier held ones even if a session is ready by now; flushing sends oldest first (`ts`, then `id`).
- **Only this device's messages are flushed.** A held message is `from` us, `status: "waiting"`, and `deviceId` equal to this device's.
- **Flush triggers:** a responder `RK0` session is stored, a session is upgraded to `RK1`, the post-store schedule above, and a 5 s tick for contacts with held messages (the one transition with no event is an initiator's `RK0` ageing out of its window). Flushes are single-flight per contact; a trigger arriving mid-flush causes one more pass.
- **Flush:** for each held message, in order: if older than 24 h → `failed`; rebuild the wire payload from storage and caches; if the content is gone (audio/image media is memory-only) → `failed`; if no target is ready, stop (everything behind it waits too); otherwise fan out and set `sent`/`failed`, cache the packet for the inspector, and mirror to siblings via self-sync on `sent`. The rebuilt payload keeps the original `id`, `ts`, `sig`, `n` and ack pointer (the peer's duplicate guard and gap bookkeeping depend on `id`/`ts`/`n`, and the signature covers `id` and `ts`) and uses the current `deviceId`, `endpointId` and `relay`.
- **Slow nudge:** on a tick pass, if a message is still held, the contact is believed online and `contactNeedsHello` holds, a hello is sent at most every 15 min. Offline contacts are not nudged: their earlier hello is already buffered at the relay and each extra one would push-notify them.
- **Persistence:** held text survives a reload (status is in local storage). Held audio/image does not (their payload lives only in memory) and fails at the next flush.
- **Never held:** call notices (`hold: false`), reactions and RECEIVED acks (sent directly through the fanout).

### Call notice

Entering the `calling` phase also sends a regular `app:message` with `type: "system"`/`kind: "call"` through `sendContent` with `hold: false` — a visible, offline-deliverable record of the attempt on both sides, independent of whether the call connects. Its text uses the caller's plain username (e.g. `"<name> is attempting a WebRTC connection"`). It is wired only for voice calls.

### Relay Connections

When sending to a contact on a different relay:

- A WebSocket connection is opened to their relay WSS and the full auth handshake runs before anything is sent.
- Connections are keyed by hostname — one connection serves all contacts on that relay.
- Messages are queued until auth completes, then flushed.
- A 30 s idle timer closes the connection after the last outbound *message*; protocol traffic does not reset it. Protocol traffic (`sendSignal`) piggybacks on an open relay connection but never opens one.
- On connection failure or connect timeout (5 s), queued packets fall back to the main signal connection.
- Only connections the client itself opened are reused; an inbound connection is never piggybacked on.

### Offline Delivery

If the recipient is not connected when a buffered packet type arrives, the relay writes it to disk:

```
relay_buf/
  <recipientPublicId>/
    <timestamp>_<uuid>.json          — identity-level bucket, reached by any live session under this identity
    _endpoints/
      <endpointId>/
        <timestamp>_<uuid>.json      — device-targeted bucket, reached only by a connection presenting this exact endpoint_id at auth
```

A packet whose `to` is bare goes into the identity-level bucket; one with a `::endpointId` suffix goes into that device's own bucket.

**What is buffered.** Only `app:message`, `app:migrate`, `app:burn`, `session:propose` and `session:ack`. Everything else — `app:sync`, every `sync:*`, every `call:*`, every `data:*` — is live-only. (`sync:backup_push` is never buffered: contact-path pushes answer a live handshake and may be wrapped under an ephemeral held about 60 s in memory, so a buffered copy flushed later could never be unwrapped.)

`app:migrate`, `app:burn`, `session:propose` and `session:ack` are written to the buffer even when a live session was reached.

On auth, the relay flushes buffered packets oldest-first and deletes each on successful delivery. A connection that presents `endpoint_id` gets **both** the identity-level bucket and its own endpoint bucket; a connection that doesn't gets only the identity-level one. Unauthenticated connections never receive buffered packets.

**Limits** (environment-configurable; applied independently to the identity-level bucket and to each endpoint bucket):
- `BUF_MAX_MSGS` — maximum buffered packets (default 100, drops oldest).
- `BUF_MAX_MB` — maximum total size (default 10, drops new).
- `BUF_MAX_AGE` — expiry (default 24 h, swept periodically).
- `BUF_WRITE_RATE_LIMIT`/`BUF_WRITE_RATE_BURST` — rate of *new* buffered writes per bucket, independent of sender. Only the offline path is gated.
- `MAX_BUF_RECIPIENTS` — distinct recipient directories.
- `MAX_ENDPOINTS_PER_RECIPIENT` — distinct endpoint buckets one identity can accumulate (default 20).
- `app:migrate`/`app:burn` use overwrite-per-sender, a long TTL, and are always identity-level.

**Push.** A push is fired only for an `app:message` (including a hello) that missed live delivery and is not self-addressed (`from ≠ to`).

---

## Relay Migration

A deliberate relay change is announced via a dedicated packet so contacts (and the user's other devices) update routing without waiting for a regular message:

```json
{
  "type": "app:migrate",
  "from": "<publicId>",
  "to":   "<publicId>",
  "blob": { "v": 2, "iv": [...], "data": [...] },
  "sig":  [...]
}
```

The encrypted payload is `{ newRelay, ts }`, under the static pairwise key (for the self-targeted breadcrumb, the identity's own self key), envelope-bound. `to` is always bare. **Signature is mandatory**: a missing or invalid one is dropped outright — this packet redirects routing and must not be trusted on decryption success alone.

**On commit**, the migrating client:
1. Stamps its own `lastRelay`/`lastRelaySeen` with the new address and the current time (recording the old one as `prevRelay`) — a deliberate migration is the new ground truth, no timestamp guard applies.
2. Notifies every non-blocked contact via the contact's relay, falling back to the main socket.
3. Sends a copy to *itself* at the relay being left (explicit URL, **no signal fallback**), in case another device is still parked there.
4. If push is enabled, sends `sig:push_unsubscribe` to the old relay over the same connection.
5. Reconnects its signal socket to the new relay and locks the migrate panel. After 10 s it connects to the old relay for 3 s to collect stragglers, and puts back its own breadcrumb, which that flush consumed.

A client offers migration only to a relay that passed a **TEST** (full auth handshake with `no_receive: true`) most recently; starting any new test revokes the previous pass.

**On receipt**, handling diverges by sender:
- **From self** — adopted silently via the timestamp-guarded `updateRelay`, `ts` clamped to the receiver's clock. If adopting moves `lastRelay` forward, the device reconnects and replants a breadcrumb at the relay it is itself leaving, carrying the same `newRelay` and the **original** `ts` (not a new or clamped one), so a further-behind device can still find the trail without manufacturing freshness.
- **From a contact** — same passive relay-learning as the `relay` field in messages, `ts` clamped the same way.

**Server-side buffering:** always durably buffered even when a live session was reached; overwrite-per-sender; long TTL (`BUF_MAX_AGE_MIGRATE`, default 7 d).

---

## Burn Notice

A deliberate, irreversible local action — "stop trusting this identity" — announced via its own packet. It is **sign-only**: no blob, no encryption, nothing secret.

```json
{ "type": "app:burn", "from": "<publicId>", "to": "<publicId>", "ts": 1234567890123, "sig": [...] }
```

`to` is always bare. The signature (mandatory) covers `{ type, from, to, ts }`, which authenticates the sender and prevents the relay from retyping, redirecting or reflecting it. A packet without `sig` or a finite `ts` is dropped.

**Receive:** require `to` equal to our bare publicId, a contact on file for `from` (for a self-burn, the self entry), and a valid signature.

- **From self** — another of the user's own devices burned. The receiving device wipes itself too (see [Self-Destruct](#self-destruct)), silently, no notify-back.
- **From a contact** — they burned. Unless already blocked (then no-op) the contact becomes `blocked` with `blockReason: "burned"` (local-only UI metadata), the conversation is cleared and the stored peer backup and peer token for that contact are dropped.

**On commit**, the burning client:
1. Sends the packet to every non-blocked contact (contact's relay, falling back to the main socket). No key is needed for a contact, so contacts with no static key are still notified.
2. Sends a copy to itself via the main socket.
3. After a ~400 ms pause to let the sends leave the socket, wipes itself.

**Server-side buffering** mirrors `app:migrate` on its own bucket: always durably buffered, overwrite-per-sender within its own suffix, `BUF_MAX_AGE_BURN` (default 7 d).

### Self-Destruct

Not cryptographic revocation — it can't be: identity is deterministic from `(username, passphrase)`, so anyone who still knows the credentials (including the user) can log back in and re-derive the same keys. Burn is a **local wipe plus a social signal**. On receiving a self-targeted burn, or triggering one locally, the client:
1. **Halts persistence first**, before any key is removed: every storage writer re-checks a halt flag immediately before its `localStorage.setItem` (after its own async encryption), so a save already in flight when the wipe starts cannot write the identity straight back. Without this the removals below would only be a suggestion. The flag is cleared only by the reload.
2. Deletes the remembered login ([auto login](#local-session-auto-login-and-logout)).
3. Removes the identity-scoped storage keys: contact store, peer backups, peer tokens, device registry, device seed (so this device cannot quietly re-announce its old `deviceId`) and X4DH sessions, together with the `_unreadable` quarantine copy of any of them. (Send counters, the push preference and the theme are not cleared.)
4. Closes the signal socket.
5. Reloads to the login screen (after ~300 ms).

No trace is kept that a burn happened.

---

## Device Awareness

### Device Registry

Each client keeps a local device registry (`meshchat_known_devices_v1_<publicId>`) — identity → known devices:

```json
{
  "<identityId>": {
    "<deviceId>": { "lastSeen": <timestamp>, "lastN": <int>, "missing": [<int>, ...], "endpointId": "<endpointId or null>" }
  }
}
```

Local-only, never in backups or `serialiseContacts()`. Populated passively from:

1. **`app:message` receipt** — only after the signature verifies: `deviceId`, `n` and `endpointId` from the encrypted payload (including hello). An omitted `endpointId` leaves what is on file untouched.
2. **Self-sync traffic** — the discovery hello, acks and full pushes teach each of the user's devices about the others. `deviceId`, `endpointId` and `fingerprint` ride inside the encrypted blob, never as outer fields.
3. **`restore_req`** — the decrypted blob's `deviceId` is recorded (no endpoint).
4. **A QR introduction** — the verified payload's `deviceId`/`endpointId`.

Every registry write is also a chance to satisfy the precondition for starting an X4DH session with that device (`X4DH.md` §3.3) or to complete a deferred session ack (`X4DH.md` §4.3).

**Retention.** Entries older than 30 days (`DEVICE_REGISTRY_CUTOFF_MS`) are pruned and each identity's list is capped at 20 (oldest by `lastSeen` dropped first), at login and every 10 minutes. This is deliberately a different, longer number than `FANOUT_STALE_MS` (7 d), which only decides whether a session-less device still gets its own targeted send.

**Gap detection.** When a message arrives with `n` ahead of `lastN + 1`, the skipped values go into that device's `missing` list (cap 50); a late arrival removes its `n`. After every merge — live, backup, restore, manual sync — `missing` is reconciled against the messages actually stored, matching on `(deviceId, n)`. This is a display hint only: a dismissible banner ("message #N not received yet"). There is no wire-level backfill request.

**Causal pointer.** The `(deviceId, n)` stamped on an outgoing message as `ackDeviceId`/`ackN` is the most recent `(ts, id)` non-reaction message in the local conversation that carries a `(deviceId, n)` pair, whichever side sent it. It reads the conversation, not the registry (registry `lastSeen` is bumped by any inbound packet, including bare acks, and says nothing about conversational order). Outgoing messages therefore store their own `deviceId` and `n` locally.

---

## Voice Calling

Audio calls are negotiated peer-to-peer over WebRTC. The relay carries only small signed signaling packets and never sees media.

**No TURN server.** ICE uses public STUN only — `stun:stun.l.google.com:19302`, `stun:stun1.l.google.com:19302`, `stun:global.stun.twilio.com:3478`. This is permanent: some NAT pairings will never connect. A direct connection means each side learns the other's network address through ICE.

### Signaling — invite / claim / cancel / end

```json
{ "type": "call:invite", "from": "<publicId>", "to": "<publicId>", "callId": "<uuid>", "ts": 1234567890123, "deviceId": "<deviceId>", "sig": [...] }
```

Four types: `call:invite`, `call:claim`, `call:cancel`, `call:end`. All share this shape, carry no `blob`, are not encrypted, and are **mandatory-signed** (`blob: null` in the signed body). `callId` ties every packet to one attempt, generated once by the caller. All `call:*` are live-only: an offline callee never rings. A second invite while a call with that contact is past `idle` is ignored.

### Signaling — offer / answer / ice

Same shape plus `blob`: a message blob `v:1` (unbound) under the static pairwise key carrying `{ sdp }` or one ICE candidate (`candidate.toJSON()`). The ciphertext is inside the signature. Accepted only while `contact.call.callId` matches and the role is expected (`call:offer` only while `role === "callee"`; `call:answer` only while `role === "caller"`). `call:ice` that arrives before the remote description is set is queued and flushed once it is applied.

On `call:offer` the callee builds the peer connection, sets the remote description, flushes queued ICE, acquires local media (`getUserMedia({ audio: { echoCancellation, noiseSuppression, autoGainControl } })`), creates and sets the answer, and returns `call:answer`.

### Session state machine

Voice calls and [data-channel tests](#data-channel-test) share one table (`transition(id, event, kind)`; `kind` selects `contact.call` or `contact.data`). Per-contact state is `{ callId | sessionId, phase, role }`. `transition` is pure: dedup and staleness decisions (is this claim for the session in flight? from one of our own devices?) are resolved by the caller first. Event names `session_started`/`session_cancelled`/`session_ended` alias `call_started`/`call_cancelled`/`call_ended`.

| Phase | Event | Next (role) |
|---|---|---|
| `idle` | `call_started` | `calling` (caller) |
| `idle` | `invite_received` | `ringing` (callee) |
| `calling` | `claim_received` | `negotiating` |
| `calling` | `call_cancelled`, `no_answer`, `idle_timeout` | `idle` (role cleared) |
| `ringing` | `claimed_here` | `negotiating` |
| `ringing` | `claimed_elsewhere`, `call_cancelled` | `idle` |
| `negotiating` | `rtc_connected` | `connected` |
| `negotiating` | `rtc_failed`, `call_ended`, `call_cancelled`, `idle_timeout` | `idle` |
| `connected` | `call_ended`, `rtc_closed`, `idle_timeout` | `idle` |
| `connected` | `rtc_failed` | `failed` |
| `failed` | `reset` | `idle` |

Any other event in a phase is ignored. `role` is set on entering `calling`/`ringing` and cleared on return to `idle`.

**Phase-entry effects, calls:** `calling` → send `call:invite` and the call notice; `ringing` → show the incoming banner; `negotiating` → hide the banner if coming from `ringing`, and the caller makes the offer (the callee waits for it); `connected` → hide banner; `failed` → close the peer connection; `idle` → hide banner if coming from `ringing`/`calling`, close the peer connection.

**Phase-entry effects, data sessions:** `calling` → send `data:invite`, arm the ring timer; `ringing` → show accept/decline banner, arm the ring timer; `negotiating` → hide banner if from `ringing`, caller makes the offer, arm the negotiate timer; `connected` → nothing (the negotiate timer keeps running); `failed` → clear timer, report failure, close; `idle` → clear timer, hide banner if from `ringing`/`calling`, close.

### Multi-device dedup

An invite can reach several of the callee's devices at once. When one device answers it sends `claim` twice:

1. To the caller — advances their state `calling → negotiating`.
2. **Self-targeted**, to the callee's own identity — every other device sees `from === own publicId`, verifies against its **own** signing key, and moves any device still `ringing` on that id to `idle` (`claimed_elsewhere`), silently.

The claiming device ignores its own echo by comparing `deviceId`.

---

## Data-Channel Test

A connection test: it answers "can these two devices reach each other directly?" (there is no TURN, so sometimes they cannot). The caller opens a WebRTC data channel, sends one ping, the callee echoes it, and the caller reports the round-trip time and ends the session. Nothing from the channel is stored or forwarded; the result is a transient toast on each side and is never written into `contact.messages`.

Seven packet types mirror `call:*` under their own prefix: `data:invite`/`data:claim`/`data:cancel`/`data:end` (signed only, no `blob`) and `data:offer`/`data:answer`/`data:ice` (signed, encrypted `blob` — SDP or one ICE candidate — under the static pairwise key, inside the signature). `sessionId` plays `callId`'s role. All are mandatory-signed and live-only. Same shared state machine, same multi-device claim dedup, same STUN-only ICE.

```json
{ "type": "data:invite", "from": "<publicId>", "to": "<publicId>", "sessionId": "<uuid>", "ts": 1234567890123, "deviceId": "<deviceId>", "sig": [...] }
```

**Acceptance is explicit.** An incoming `data:invite` puts the contact in `ringing` and raises an accept/decline banner stating that accepting shares the network address; nothing auto-claims. A second invite while a session is active is ignored. A `data:offer` is only answered while `negotiating` with role `callee`.

**The channel.** The caller creates one channel labelled `data`; the callee accepts only a channel with that label and closes anything else. When the caller's end opens it sends `{"t":"ping","n":"<nonce>"}`; the callee replies `{"t":"pong","n":"<nonce>"}`. The receive hook is strict: strings only, at most 128 characters, one known JSON shape, `n` a string of at most 32 characters, a nonce that matches the one sent, role-gated (only a callee answers a ping, only a caller accepts a pong), at most 3 pongs echoed per session. ICE candidates that arrive before the peer connection exists are held (up to 50) and adopted when it is built.

**Timeouts.** Ring 30 s (invite → accept); negotiate 20 s (accept → result, which keeps running through `connected` until the pong is back). A timeout reports the failure and tells the peer (`data:cancel` while `calling`, `data:end` otherwise); a timeout while `ringing` just reports the expiry. A session whose test already succeeded (`finished`) closes quietly if the peer's `data:end` was lost. A peer that cancels or ends a session mid-test (`negotiating`/`connected`, this side's half not yet succeeded) is reported to the user. After a successful test the caller closes its end at once, so a `failed` connection state on the callee after `finished` is ignored.

---

## Push Notifications

Opt-in per device, off by default. A push means only "something arrived, open the app and check" — no content, sender identity or other metadata. Every push is a bodyless POST authenticated only by a signed VAPID JWT, so the standard Web Push payload-encryption layer is skipped entirely.

### Browser support

Standard Web Push (`PushManager` + service worker + VAPID). Chrome/Edge/Opera and Firefox work; Safari desktop since 16. **Safari on iOS/iPadOS only delivers push to a PWA added to the Home Screen** (16.4+). HTTPS (or `localhost`) is required. The client gates the opt-in off where `serviceWorker`/`PushManager` are unavailable.

### VAPID keypair

Each relay generates its own EC P-256 keypair on first boot and persists it (`VAPID_KEY_FILE`). The public key is exposed as `vapidPublicKey` on `sig:relay_info` — base64url of the uncompressed point (`0x04 || X || Y`, 65 bytes), the format `applicationServerKey` expects.

**The keypair is per-relay.** A subscription made against one relay's key is unusable at another. On every `sig:relay_info` the client compares the browser's current subscription key with the connected relay's; a mismatch (only possible after a [migration](#relay-migration)) triggers unsubscribe-and-resubscribe. A client skips redundant work when it has already registered with this relay's URL this session.

### Subscribing

```json
{
  "type":         "sig:push_subscribe",
  "from":         "<publicId>",
  "endpointId":   "<endpointId>",
  "subscription": { "endpoint": "https://...", "keys": { "p256dh": "...", "auth": "..." } }
}
```

Stored at `PUSH_SUBS_DIR/<publicId>/<endpointId>.json` as `{ endpoint, p256dh, auth }` — one file per (identity, device). It is keyed by `endpointId`, not `deviceId`: the relay already sees `endpointId` at auth, and storing push state under `deviceId` would let it join its view to a contact's. On subscribe, any other file for the same identity holding the same browser `endpoint` URL is a stale duplicate and is removed. `sig:push_unsubscribe { from, endpointId }` deletes the file.

Neither type requires a signature (they redirect no routing and drive no irreversible action) but both require an authenticated socket with `from` matching it. A subscription must pass the [endpoint policy](#push-endpoint-policy) and carry non-empty string `keys.p256dh` and `keys.auth` of at most 256 characters each; anything else is dropped without a reply (the log records the rejection reason and the endpoint's *host* only — the path is the device's push token).

Each identity may hold at most `PUSH_MAX_SUBS_PER_IDENTITY` subscription files (default 10; an identity costs nothing to create). The cap is counted after the stale-duplicate sweep, excluding the subscribing device's own file (a re-subscribe replaces it), and is not exact under concurrent subscribes — a brake on unbounded growth, not a quota. A new subscription beyond it is rejected.

### Push endpoint policy

A subscription's `endpoint` is a URL chosen by the client that the relay later POSTs to. Taken as-is that would make the relay an HTTP client any authenticated identity could aim at internal services, cloud metadata or other hosts. Real browser push endpoints live on a handful of vendor hosts, so the policy is an **allowlist**, enforced when the subscription arrives *and again on every send*.

An endpoint is accepted only if all of these hold:

- a string of at most 2048 characters containing only printable ASCII (no control characters, spaces or non-ASCII; IDN hosts must arrive in punycode);
- scheme `https`, no userinfo, port absent or `443`;
- the host is a plain DNS name — at least two labels of ASCII letters, digits and hyphens, with a TLD that starts with a letter (this is what keeps dotted-quad, decimal and hex spellings of an IP out, however a resolver would read them);
- the host is on the allowlist: an exact name, or an entry with a leading dot, which matches any name with at least one more label in front (`.push.services.mozilla.com` matches `updates.push.services.mozilla.com`, not the bare name).

Default allowlist (`PUSH_ALLOWED_HOSTS` **replaces** it): `fcm.googleapis.com` and `android.googleapis.com` (Chrome, Edge, Brave, Opera, Samsung, via FCM), `.push.services.mozilla.com` (Firefox), `.notify.windows.com` (Edge on Windows, WNS), `web.push.apple.com` (Safari). There is deliberately no `.googleapis.com` suffix: anyone can obtain a hostname under it. A push service that is not listed is rejected and its host logged, so supporting a new one is a configuration change. An empty list turns push off.

At **send time**, in addition:

1. The stored endpoint is re-validated. One that no longer passes (stored before the allowlist existed, or for a service since removed) has its subscription file dropped, like a dead subscription.
2. The host is resolved and **every** returned address must be a public, globally routable unicast address. IPv4-mapped IPv6 is judged as the IPv4 address it wraps; NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses are refused outright because they can embed a private IPv4 address; multicast is refused. A single non-public answer among public ones fails the send.
3. The connection is made to one vetted IP address, not to the name — resolving again inside the HTTP client would leave a DNS-rebinding window — while the `Host` header, SNI and certificate check all use the name. At most 3 addresses are tried, only a failed *connect* moves on to the next, and connect and read time out after 10 s.
4. **Redirects are never followed.** A 3xx is just a failed push. Nothing of the response beyond its status line is read.

### Firing a push

Triggered from the offline-buffering path for an `app:message` that missed live delivery and is not self-addressed. `app:migrate`, `app:burn`, `session:*` and everything live-only never push. A hello and the call notice are ordinary `app:message`s and do push.

Each subscription on file gets its own bodyless HTTPS POST to `endpoint` with `TTL: PUSH_TTL_SECONDS` and `Authorization: vapid t=<jwt>, k=<vapidPublicKey>`. The JWT (`ES256`, claims `{ aud, exp, sub }`, `exp` 12 h out) is signed fresh per push; `aud` is the scheme and host of that endpoint; the signature is raw `r||s`. The POST is made under the defences in the [endpoint policy](#push-endpoint-policy). Pushes are best-effort: a transient failure — network error, 5xx, a redirect, a non-public resolution — is not retried and leaves the file. A `404`/`410`, or an endpoint that no longer passes the policy, deletes the subscription file (the client re-subscribes at its next login).

### Client-side opt-in

A checkbox in the settings panel (the gear in the sidebar header) controls a **per-device** local preference (`meshchat_push_pref_v1_<publicId>`), not part of backups. Toggling on subscribes immediately; toggling off unsubscribes the browser and sends `sig:push_unsubscribe` to the current relay.

The service worker handles `push` (always shows a generic "MeshChat — tap to check" notification with a collapsing tag and re-alert; `event.data` is always null) and `notificationclick` (focus an existing window, else open one). It must show a notification for every push (`userVisibleOnly: true`). Its `fetch` handler is network-only and returns a 504 on network error.

### Limitations

- A push cannot distinguish a call notice from a text, or a hello from either.
- `call:invite`/`data:invite` are live-only, so a missed call produces no push.
- A message landing on the old relay from a contact who hasn't learned of a migration won't trigger a push (it is still recovered).

---

## Signal Server Protocol

### Client → Server

| Type | Fields | Auth | Description |
|---|---|---|---|
| `sig:auth_init`     | `auth_v`, `x25519_pub`, `ed25519_pub`, `no_receive?`, `endpoint_id?` | no | Begin challenge-response |
| `sig:auth_proof`    | `sig` | no | Ed25519 signature over the relay-bound auth message |
| `sig:announce`      | `ids[]` (max 10) | yes | Presence query |
| `app:message`       | `from`, `to`, `blob`, `sig` | yes | Encrypted message. `to` may be compound |
| `app:migrate`       | `from`, `to`, `blob`, `sig` | yes | Relay-migration notice; `to` bare; always durably buffered |
| `app:burn`          | `from`, `to`, `ts`, `sig` | yes | Burn notice; `to` bare; always durably buffered, own bucket |
| `session:propose`   | `from`, `to` (compound), `sessionEpoch`, `ekPub`, `deviceId`, `ts`, `sig` | yes | X4DH bootstrap/reset |
| `session:ack`       | same | yes | X4DH live-upgrade reply |
| `app:sync`          | `from`, `to`, `syncId`, `reply`, `ek`, `wrapped?`, `sig` | yes | Manual SYNC request or reply |
| `sync:backup_offer` | `from` (compound), `to`, `size`, `ts`, `sig` | yes | Offer a backup blob to a contact |
| `sync:backup_accept`| contact path: `from` (compound), `to`, `ts`, `sig`, `ek?` — self-sync: `from` (bare), `to`, `blob` | yes | `blob` present ⇒ self-sync ack |
| `sync:backup_push`  | contact path: `from` (compound), `to`, `blob`, `ts`, `sig`, `ek?` — self-sync: `from` (bare), `to`, `blob` | yes | Self-sync `to` may be compound |
| `sync:restore_req`  | `from`, `to`, `blob`, `token?`, `ts`, `sig` | yes | Ask a contact to send its stored backup |
| `sync:restore_ack`  | `from` (compound), `to`, `ts`, `sig`, `ek?` | yes | Acknowledge a restore request, or bootstrap ping from a fresh device |
| `sync:restore_push` | `from` (compound), `to`, `blob`, `ts`, `sig`, `token?`, `ek?` | yes | Push the stored backup to the requester |
| `sync:token_req`    | `from`, `to` | yes | Request a restore token |
| `sync:token_resp`   | `from`, `to`, `ts`, `sig`, `token` | yes | Deliver a restore token |
| `call:invite` / `call:claim` / `call:cancel` / `call:end` | `from`, `to`, `callId`, `ts`, `deviceId`, `sig` | yes | Call signaling |
| `call:offer` / `call:answer` / `call:ice` | as above plus `blob` | yes | WebRTC SDP / ICE |
| `data:invite` / `data:claim` / `data:cancel` / `data:end` | `from`, `to`, `sessionId`, `ts`, `deviceId`, `sig` | yes | Data-channel test signaling |
| `data:offer` / `data:answer` / `data:ice` | as above plus `blob` | yes | WebRTC SDP / ICE |
| `sig:push_subscribe`   | `from`, `endpointId`, `subscription` | yes | Register a per-device push subscription (endpoint policy-checked) |
| `sig:push_unsubscribe` | `from`, `endpointId` | yes | Remove it |
| `sig:relay_req`     | — | yes | Request the relay's own WSS URL |
| `sig:ping`          | — | yes | Keepalive |

### Server → Client

| Type | Fields | Description |
|---|---|---|
| `sig:auth_challenge` | `nonce` | Random 32 bytes, in the clear |
| `sig:auth_ok`        | `public_id` | Auth succeeded, routing active |
| `sig:auth_fail`      | `reason` | Auth failed, or an unauthenticated packet was dropped |
| `sig:relay_info`     | `wss`, `version`, `vapidPublicKey` | The relay's own WSS URL, protocol version (informational), VAPID public key |
| `sig:seen`           | `id` | The named id announced a presence query that included us |
| `sig:pong`           | — | Keepalive response |
| `error`              | `reason` | Protocol error (`rate_limited`, `not_authenticated`) |

### Notes

- **Authentication.** Every type except `sig:auth_init`/`sig:auth_proof` requires an authenticated socket; an unauthenticated one gets `sig:auth_fail { not_authenticated }`. Every type with a `from` also requires `from` to be an identity authenticated on this socket (for the compound-`from` types, the base id). `sig:relay_req`, `sig:ping` and `sig:announce` have no `from`; `sig:announce` answers on behalf of the socket's own authenticated identity.
- **Buffered types.** `app:message`, `app:migrate`, `app:burn`, `session:propose`, `session:ack` — see [Offline Delivery](#offline-delivery). Every other type is delivered live to whoever is connected and otherwise lost; a compound `to` aimed at an offline device reaches nobody.
- **Compound `to`** is honoured on the shared delivery branch for `app:sync`, every `sync:*`, `call:*` and `data:*`, as well as for `app:message` and `session:*`. Of the shared-branch types only some `sync:*` self-sync packets send one today.
- **Compound `from`** is accepted only on `sync:backup_offer`, `sync:backup_accept`, `sync:backup_push`, `sync:restore_ack` and `sync:restore_push`. A receiving client trusts and displays the endpoint half only once the accompanying signature has verified against a contact already on file.
- **Signature rules differ by type.** Mandatory (drop on missing/invalid): `app:migrate`, `app:burn`, `session:*`, `app:sync`, `sync:restore_req`, `sync:token_resp` (checked client-side), `call:*`, `data:*`. Conditional (must verify whenever we hold a signing key for the claimed sender; an unknown sender is still let through, because bootstrap has to work): contact-path `sync:backup_offer`/`accept`/`push`, `sync:restore_ack`, `sync:restore_push`. A `restore_ack` from ourselves (a sibling device) is always checked, because our own key is always on file. None: the self-sync backup packets. `app:message`: flagged, not dropped.
- **Rate and size limits.** Each socket has its own token-bucket limiter (`RATE_LIMIT_RATE`/`RATE_LIMIT_BURST`) and shares a wider one with every other socket from the same IP (`IP_RATE_LIMIT_*`); either returns `error { rate_limited }`. Connections are capped in total (`MAX_CONNECTIONS`) and per IP (`MAX_CONNECTIONS_PER_IP`). A frame over `WS_MAX_SIZE` is dropped. `X-Real-IP`/`X-Forwarded-For` are honoured only when the TCP peer is inside `TRUSTED_PROXIES`.
- Unknown packet types are dropped. Sync and backup types are routed without inspecting their contents.

---

## Peer Backup Protocol

The `sync:backup_*` types serve two jobs with different security stances: **contacts holding an encrypted copy of your contact list** (contact path), and **an identity's own devices exchanging contact stores** (self-sync). The restore handshake, token and ephemeral wrap that go with them follow below. Messages you send are mirrored between your own devices by a different mechanism — see [Self-sync mirror](#self-sync-mirror-selfsync).

### Contact path

1. After every second received message (once persisted), and on a 10-minute timer, the sender offers a backup to each reachable contact (one that is believed online on the sender's relay, or has an open outbound relay connection): `backup_offer { size, ts, sig }`. A new offer replaces the pending one.
2. The recipient replies `backup_accept { ts, sig, ek? }`, unconditionally (a constrained peer can simply never implement the handler).
3. The sender pushes `backup_push { blob, ts, sig, ek? }`.
4. The recipient stores the blob (after stripping the transport wrap) in `peerBackups` and serves it back on `restore_push`. The stored blob is the plain inner blob, always opaque to the holder.

**The blob carries contacts only**: for each contact, name, keys, `blocked`, state timestamp and relay info; `messages` is empty. It is an object blob under the sender's backup key. A peer holding your backup is a third party with an indefinitely stored copy; the contact list is what a restore needs, and message history never has to ride along.

**`from` on all three is the sender's compound `"id::endpointId"`.** All three are signed with the identity's Ed25519 key, but verification is only possible once the recipient already has the sender as a contact. The rule is conditional:

- **Sender on file** (we hold a `signPublicKey` for them): the packet must verify. A missing signature is as wrong as an invalid one, and either is dropped. Every legitimate sender signs these, so an unsigned packet from a known contact is a stripped one. Letting it through would let a relay remove `sig` and `ek` (both are inside the signed set) from a contact's packet and have it processed as unverified: overwriting the backup we hold for that contact (`backup_push`), or making us answer with a backup that is not wrapped (`backup_accept`).
- **Sender not on file**: processed regardless. A fresh or not-yet-mutual sender cannot be verified, and bootstrap must keep working.

The recipient trusts or displays the endpoint suffix only once a signature has verified.

**Held backups are capped at 1 MiB** (`MAX_PEER_BACKUP_BYTES`, counted as the length of the ciphertext array). A `backup_push` blob must be an object with a `data` array of at most that length, checked once on arrival and again after the transport wrap is removed; anything else is dropped before it can replace the blob already stored. Real contact-only backups are kilobytes. The cap exists so that overwriting a stored blob cannot also be used to fill the holder's storage.

**Replies are one-to-one.** An offer is addressed to a bare identity, so it fans out to every live session under it, and each reply is wrapped for exactly one ephemeral. A reply therefore goes only to the device that sent the opening packet: `backup_accept`, `backup_push` and the restore-handshake replies are addressed compound (`id::endpointId`) to the endpoint in the *verified* `from` of the packet they answer. When the sender's endpoint is unknown or unverified, the reply falls back to the bare identity.

**A pending offer outlives its first accept.** An identity with several devices legitimately answers one offer several times, each accept carrying its own `ek`. The sender keeps the offer for 60 s (`BACKUP_OFFER_TTL`) and pushes a separately-wrapped copy per accept. The wrap is attached only when the accept verified and carried an `ek`; if building the wrap fails the plain blob is sent.

**Token.** The first time a contact stores a backup from a sender it holds no token for, it sends `sync:token_req` (see [Restore Token](#restore-token)).

### Self-sync (same identity, multiple devices)

There is no offer/accept; a push goes directly. Self-sync never rides the deterministic backup key alone for contact data, because a full push carries the contact store with recent messages. Every self-sync blob is an object blob `v:3`, envelope-bound (AAD over `type`, `from`, `to`), so a relay cannot retype or redirect one.

**Full push.** For each known sibling that is targetable (`endpointId` on file, seen within `FANOUT_STALE_MS`), has an X4DH self-session, and whose fingerprint doesn't already match ours, the device sends a `sync:backup_push` with a compound `to` and a `blob` under that pair's wire key:

```
blob = objectBlob_v3( wireKey(self-session with that sibling), aad,
                      { deviceId, endpointId, fingerprint, contacts: serialiseContacts() } )
```

The `contacts` are the full store (messages included, `waiting` status stripped). `deviceId`, `endpointId` and `fingerprint` ride inside the blob, never as outer fields.

**Discovery hello.** When a sibling is unknown, unresolved, or has no session yet, the device instead (at most once per 60 s) broadcasts to its own identity (bare `to`) a content-free hello under the **backup key**: `{ deviceId, endpointId, hello: true }`. Its only job is to let siblings learn the device, which can start an X4DH self-session that later pushes ride. The hello exposes the `deviceId`↔`endpointId` link to anyone holding recorded traffic plus a later passphrase compromise — metadata only.

**Receiving.** The blob carries no key hint, so the receiver tries every X4DH self-session wire key (every live generation, newest session first) and then the backup key last; when a session key decrypts it the payload's `deviceId` must match the session's device, and a decrypt under the current `RK1` confirms the sibling holds it. Then:
- a **hello** (`hello === true`, a valid-id `deviceId`, no `contacts`) teaches the sibling (which can trigger X4DH bootstrap), deduped for 3 s, and is answered with a small ack;
- a **full push** from our own echo is ignored; otherwise it is merged (contact metadata, then message merge, then delivery-status and missing-message reconciliation), saved, and — if it changed our own relay — followed by a signal reconnect. The sender's fingerprint is recorded and we ack with our own post-merge fingerprint;
- a full push decrypted under the static backup key (rather than a session key) is accepted and logged as a static-key sender.

**Ack.** `sync:backup_accept` with a `blob` encrypting `{ deviceId, endpointId, fingerprint? }` — under the session key (with fingerprint) when a session exists, otherwise content-free under the backup key — compound-addressed to the sender's endpoint when known. The presence of `blob` is what distinguishes it from a contact-offer accept, which never sets one. The receiver records the sibling and, when present, the fingerprint.

**Fingerprint.** `fingerprint = base64url( SHA-256( JSON(serialiseContacts()) )[0:12] )`. Each device keeps an in-memory table `{ deviceId → fingerprint }` of what it has heard this session; if every targetable sibling already has the current fingerprint the push is skipped. The table resets on reload — worst case one extra push on cold start.

Self-sync backup packets carry no `sig`: AES-GCM with the envelope AAD makes tampering and retargeting evident but gives no sender authentication, which is sufficient for self-to-self traffic on an authenticated socket but weaker than `app:message`'s signature.

### Short-window duplicate suppression

All five handshake packet types (`backup_offer`/`accept`/`push`, `restore_ack`/`push`) pass a 3-second duplicate window before other processing, purely to skip redundant work. Once a packet's signature verifies, the key is `type:senderId:endpointId` (plus a short fingerprint of the push's `ek` on the two push types), so a genuinely distinct sibling's packet isn't mistaken for a duplicate, and a push never addressed to us cannot suppress the one that was. Unverified traffic keys on the bare sender id; the self-sync paths key on the decrypted `deviceId`. A packet dropped for a missing or invalid signature never reaches the window, so a forged packet cannot occupy a key and suppress the genuine one that follows. The window is separate from, and much shorter than, the restore cooldowns below.

### Restore Token

When a contact stores a backup, a one-time token exchange (`sync:token_req` → `sync:token_resp`) follows, whose sole purpose is to authenticate the restore handshake for an owner who has lost its contacts: a wiped device has no `signPublicKey` on file for anyone, so it cannot verify a `restore_push` the ordinary way.

The token is issued by the **owner** of the backup, sealed under the owner's own backup key, and held by the storing contact:

```
token = objectBlob_v2( ownerBackupKey, { v: 2, shareableKey: <the storing contact's shareableKey, as the owner recorded it> } )
```

Because it is sealed under a key derived from the owner's credentials — unchanged by a wipe — only the owner can open it again. The holder keeps the token it was given per owner but cannot read it.

`sync:token_resp` is signed and is accepted only while a `sync:token_req` of the recipient's own is outstanding (60 s) and the sender is a known, non-blocked contact; only the first token received per sender is kept. A forged or replayed response is dropped — this matters precisely because only the first token is kept.

**Binding.** A token is valid only if the identity it decrypts to (derived from the embedded `shareableKey` exactly as `addContact` derives a publicId) matches the packet's actual sender. A token is a bearer object once decrypted; this check stops a token issued about one contact being credited to another. A mismatched or malformed token is treated as no token, not a hard failure.

### Restore handshake

Roles: the **owner** is the identity whose contact store needs restoring; a **holder** is a contact storing an encrypted copy of the owner's backup.

1. **`sync:restore_req`** — a client sends it to each contact it sees online (and every 10 minutes), telling it "I may be holding your backup". Only one request is outstanding per contact: no further request goes out until a `restore_push` from that contact has been processed. The `blob` (object blob `v:2`, static pairwise key) carries `{ publicId_A, publicId_B, wss, signPublicKey, deviceId }`; the sender attaches the `token` it holds for that contact, if any. Signature mandatory. Recipient checks, in order: a contact on file for the sender (else drop — and, if fresh, send the bootstrap ping), valid signature, decrypt, `publicId_A` equals the sender, `publicId_B` equals us, contact not blocked; records the device (no endpoint); serve-cooldown; then the token: a token counts only if it opens under our backup key *and* is bound to the sender. With a valid token the relay and signing key in the blob are adopted — the relay hint stamped with the request's own *signed* `ts` (clamped to now), not the time of receipt, so a replayed old request keeps its original age. A **fresh** client (at most itself as a contact) with no valid token ignores the request; a known contact needs none, since the request is already signature-verified and decrypted.
2. **`sync:restore_ack`** — the recipient replies, asking for the data, `to` compound at the requester's endpoint when already known for that `deviceId`, with a fresh `ek` attached (its ephemeral slot keyed by the same endpoint). Sent via the requester's relay if known.
3. **`sync:restore_push`** — whoever receives a `restore_ack` sends back its stored backup for the acker, if it has one: wrapped when the ack's signature verified and carried an `ek`, with the token attached (unsigned outer field) when the signature verified.
4. **The owner** decrypts (unwrap, then backup key), merges into local state, marks the request fulfilled, clears `sessionFresh`, and reconnects if its own relay changed.

For a healthy pair the pushed backup merges to a no-op.

**A wiped device cannot take part in step 1** — with no contacts it cannot decrypt a `restore_req`. It instead says hi first: a `restore_ack` addressed to any online id, contact or not (bare `to`, an `ek` attached, 60 s cooldown per id). It does so while its session is *fresh* (no contacts beyond itself yet), on a `sig:seen` — and, because `sig:seen` is relay-local and a holder on another relay never produces one, also when an **unknown sender reaches the fresh device directly** with a `restore_req` or `backup_offer` (arriving over the holder's outbound relay connection); the ping is skipped if the sender is ourselves or already a contact. Whoever receives that ack, if its signature verifies against a contact already on file, attaches the token it holds for that contact to the resulting `restore_push`. The wiped device issued that token and can still open it (same deterministic key), recovering the sender's `signPublicKey`, checking the bound-id match, and verifying the push's own signature before trusting the restored data. Without a valid token the push is accepted but unverified. A device acking *itself* (a sibling restoring from another of its own devices) is answered with the sibling's current full contact store, wrapped the same way, but only if the ack verifies against our own signing key. Our own key is always on file, so an unsigned or invalid self-ack is dropped like any other ack from a known sender.

`sessionFresh` starts true, is cleared when a loaded local store holds any contact other than ourselves, and when a restore push is processed.

Restore flooding is limited by three independent 5-minute cooldowns, deliberately not one shared map:
- **Outbound** — `restore_req` toward an identity (identity-level).
- **Inbound serve** — whether to ack an incoming `restore_req`, keyed on `(senderId, deviceId)`.
- **Inbound accept** — whether to process an incoming `restore_push`, keyed on `(senderId, endpointId)` once the signature verifies, else identity-level. `restore_push` carries no `deviceId`, only the endpoint via the compound `from`.

`deviceId` and `endpointId` are kept in separate maps to preserve their unlinkable namespaces.

**Trust shapes differ across these types.** `restore_req` can only be processed by a recipient who already has the sender as a contact, so it is mandatory-signed. `restore_ack` and `restore_push` can legitimately reach, or be answered by, someone with no shared key material (the bootstrap ping), so they are signed unconditionally but verified conditionally, like the backup handshake: when we hold a key for the sender, the signature must verify, and when we do not, the packet proceeds unverified. For `restore_push` the key can come from the contact record or from the opened token. Holders always sign their push, and the token rides outside the signed set, so an unsigned push with a bound token is a stripped one and is dropped.

### Ephemeral Wrap

`sync:restore_push` and contact-path `sync:backup_push` can carry an additional layer: a one-shot X25519 ephemeral-to-ephemeral wrap around the existing blob, generated per exchange and never written to disk. (Self-sync backup pushes use X4DH session keys instead; a self `restore_push` does use the wrap.)

```
ek        = fresh X25519 ephemeral public key, attached to the ack/accept that precedes the push
wrapKey   = HKDF-SHA256(ikm = X25519(myEphemeralPriv, theirEk), salt = 32 zero bytes, info = "meshchat-v1:ephemeral-wrap", 256 bits) → AES-256-GCM key
outerBlob = objectBlob_v2( wrapKey, <the existing inner blob, untouched> )
```

The inner blob is unchanged — the recipient still decrypts it with its own passphrase-derived key after unwrapping, so restore-from-nothing and ordinary backup storage are unaffected. The wrap protects against a passive observer who records the wire traffic and later obtains the passphrase.

**Sequencing.** Whoever sends a `restore_ack` or a `backup_accept` attaches a fresh ephemeral as `ek` and holds the private key in memory for 60 s, keyed by whom the packet was addressed to (`id::endpointId` when the responding device is known, else `id`). Whoever receives that packet and is about to push wraps **only when the incoming signature verified**, generating its own fresh ephemeral and attaching its public half to the push as `ek`. An `ek` on an unverifiable ack/accept is not trusted — a relay in between could otherwise supply its own ephemeral and read the reply. `ek` is inside the signed payload whenever present.

**Several ephemerals may be live for one peer at once.** An ack or accept addressed to a bare identity broadcasts to every live session under it, and a device can attach more than one ephemeral toward the same peer inside the 60 s window. The pending store therefore holds a *list* of candidates per slot; the receiver trial-decrypts a push against each candidate, newest first, the device-specific slot before the bare-identity slot, then every other slot held for that identity as a safety net. A wrong candidate fails cleanly on the GCM tag. **A candidate is never removed for having matched** — the same private half can legitimately unwrap several different replies — only by its own timeout. A push wrapped for a sibling's ephemeral simply fails to match and is dropped; that is expected on a multi-device identity.

**Failure is closed.** If a push claims a wrap and no pending ephemeral is on file, or no candidate unwraps it, it is dropped rather than fed to the inner decrypt. A relay that strips `ek` without also invalidating the signature (which covers it) therefore breaks that attempt outright instead of causing a silent downgrade. The fallback applies only where no wrap was attempted (an unverified sender), and where a sender's own wrap fails to build (it then sends unwrapped).

---

## Manual Sync (`app:sync`)

The SYNC button asks one contact for its recent messages. It requires the contact to be online (per presence) and is addressed to the contact's identity (bare `to`), so every live session of the contact may answer. The packet is **sign-only**: no pairwise-key blob and no AAD. The only secret, the message batch, is wrapped under an ephemeral-to-ephemeral key; everything else (`syncId`, `ek`, `reply`) is a nonce, a one-shot public key, or a bit the relay could already infer.

```json
{ "type": "app:sync", "from": "<publicId>", "to": "<publicId>", "syncId": "<uuid>", "reply": false, "ek": [...32], "sig": [...] }
{ "type": "app:sync", "from": "<publicId>", "to": "<publicId>", "syncId": "<uuid>", "reply": true,  "ek": [...32], "wrapped": { "v": 2, ... }, "sig": [...] }
```

The signature covers `{ type, from, to, syncId, reply, ek, wrapped }` (`wrapped` is `null` in the signed body of a request, and absent on the wire). Verification is mandatory.

1. **Request** (`reply: false`) — the initiator generates a fresh ephemeral and a `syncId`, and holds the ephemeral private key in memory for 60 s. The request carries **no messages**, only `ek`.
2. **Reply** (`reply: true`) — the recipient generates its own ephemeral, derives `wrapKey` (the [Ephemeral Wrap](#ephemeral-wrap) derivation) from `X25519(replierEphemeralPriv, requesterEk)`, and returns its own `ek` plus `wrapped` = `objectBlob_v2(wrapKey, its 10 most recent messages for the initiator)`.
3. **Accept** — the initiator accepts a reply only while a request of its own to that same contact with that `syncId` is pending (60 s), unwraps with the held ephemeral, and merges. A matching reply is deliberately not consumed — several of the contact's devices can each legitimately answer the one broadcast request, and merging the same batch twice is a no-op.

**Receive checks:** `to` addresses us; sender is a known, non-blocked contact and not ourselves; signature valid; `syncId` a non-empty string of at most 64 characters; `reply` a boolean. A request needs a valid `ek` (32 integers 0–255) and is deduped for 3 s on `(from, syncId)`. A reply needs a valid `ek` and a `wrapped` object.

**One-directional:** only the side that pressed SYNC receives; press it on both sides for a two-way exchange.

**Inbound sanitising** (`sanitizeSyncedMessages`). The peer's batch is held to the same id and timestamp rules as a live message (see [Message ids and timestamps](#message-ids-and-timestamps)), and per-message signatures decide provenance:

- **Whitelist.** Messages are copied field by field, never spread. Local-only fields (`status`, `ackTrusted`) never come in from the wire. Accepted types: text, audio/image (stub), reaction, system.
- **Cap.** A batch is capped at 50 messages (`MAX_SYNC_MSGS`).
- **Parties.** Only messages whose sender is one of the two parties of this conversation are kept.
- **Ids and timestamps.** An id must match the message id pattern, and `ts` is clamped to our clock plus 5 minutes. A reaction's id must be exactly the one derived from its sender and its target. Conflicts are judged against the conversation *and* the batch built so far, so a batch cannot contradict itself.
- **Our own messages are never replaced.** A peer's claim about something *we* said can only fill a gap (the restore-after-wipe case this exists for). It never replaces an id of ours already on file, reaction or not.
- **Signatures.** A signed entry must verify against the key of the party it claims to be from (the peer's key, or our own), over the timestamp as signed, or it is dropped. Verified entries are `valid: true` and keep their `sig`.
- **Unsigned entries.** An unsigned entry claiming to be from the peer is kept with the `valid` flag it arrived with (it is the peer's own word about the peer's own message). An unsigned entry claiming to be from *us* is accepted as `valid: false` (shown with the "⚠ unverified" tag) while `SYNC_ACCEPT_UNSIGNED_OWN` is on, and dropped when it is off. The switch exists for the transition: our own older messages predate signatures.
- **Upgrade.** A signed copy upgrades an unverified one only when it is the same sender, type, text and `ts`; the delivery status is kept. Nothing else about an id already on file changes, so a synced copy cannot replace a local object and lose its status. Reactions are the exception: newer state wins, as in `mergeMessages`.

The result goes through `mergeMessages` and the usual reconciliation.

---

## Message Merging

All message stores merge last-write-wins by message id, then a causal splice pass on top of the `(ts, id)` baseline:

- **Dedup by id is recency-based, not positional.** Same-id collision resolves by `ts` (the more recent copy wins; on an exact tie the incoming copy wins). That is a no-op for immutable-content ids but essential for reaction ids, which deliberately collide across emoji states (a real emoji, a clear, and the RECEIVED auto-ack share one id), so a stale auto-ack arriving late by some other path cannot overwrite a newer reaction with `null`.
- **Baseline**: sort by `(ts, id)`; `id` is a stable tiebreak.
- **Causal pass**: a message stamped with `ackDeviceId`/`ackN` is understood as "sent after seeing that specific `(deviceId, n)` message". If the target is present in the merged set, the message is spliced directly after it, recursively, so a reply-to-a-reply nests. A pointer that resolves to nothing (target not yet present, or dropped by retention) leaves the message at its baseline position. Multiple messages acknowledging the same target keep their relative `(ts, id)` order.
- **Trust gate.** A message participates as a splice *child* only if it carries the local-only flag `ackTrusted`, meaning its pointer was established live on this device — composed here, or received and verified here. A message arriving through a self-sync, backup, restore or manual-sync merge never carries the flag and falls back to its baseline position instead of being spliced on a foreign device's claim. `ackTrusted` is sticky across a same-id collision, is never put on the wire, and a message without it can still be a *parent* for someone else's trusted pointer (the index uses `deviceId`/`n`, which are content facts).
- **Cycle guard**: a genuine ack graph is a forest. The merge walks each parent chain looking for a revisit and breaks the offending edge, demoting that message to its baseline slot.

Reactions merge by replacement, using the stable derived id.

### Local retention

Local persistence (the contact store written to local storage, and every backup) keeps roughly the 15 most recent messages per contact (`RETENTION_COUNT`); the manual-sync window is the 10 most recent (`EXCHANGE_COUNT`). Both select by recency via `selectRetainedMessages(messages, n)`, not by array position: the causal pass can move a message far from its timestamp-sorted place, so a positional slice could keep older messages over newer ones or sever a message from its parent.

1. Select the `n` most recent messages by `(ts, id)`.
2. One rescue pass: for each kept message with an `ackDeviceId`/`ackN` pointer, if its target exists elsewhere in the full set but fell outside the window, keep it too (not transitive).
3. Filter the *original* array to the surviving ids, preserving the order the merge already established.

---

## Online Presence

Clients poll `sig:announce` about every 30 s (±5 s jitter), naming their own id plus a random batch of other contacts (3 to 10 ids in total, `min(10, max(3, round(contacts × 0.1)))`). For each named id connected to **that relay**, the relay delivers `sig:seen { id: <announcer> }` to that id's sessions. A client learns a contact is online when that contact announces a batch that included us, and also marks a contact online on any verified packet received from them. The relay knows nothing about other relays.

On `sig:seen`: for ourselves, mark online and (if the session is fresh) send the restore ping; for a contact, mark online, send a `restore_req` if its cooldown allows, and (if fresh) send the restore ping; for an unknown id, (if fresh) send the restore ping.

Presence expires after 300 s (swept every 30 s) and drives the UI dot (a fade over 5 minutes) plus a few opportunistic actions: restore requests, stuck-session detection and retry (`X4DH.md` §9), the offline→online hello, the held-outbox nudge. It never affects routing.

---

## Relay Discovery

Relay WSS coordinates propagate passively:

1. **Shareable address** — the third segment carries a relay WSS for bootstrap.
2. **`sig:relay_info`** — the relay tells the client its own WSS URL after auth.
3. **Message payload** — every `app:message` (including hello) carries the sender's `relay.wss` inside the encrypted blob.

A client stores `lastRelay` and `lastRelaySeen` per contact. The WSS address is a last-known location, not a permanent home.

Updates are timestamp-guarded: a new `lastRelay` is adopted only if its timestamp is newer than the stored one (`updateRelay`), and adoption pins `lastRelaySeen` to it. This applies uniformly to relay info in messages, peer backups, restores, file imports and migration notices — local storage is the source of truth.

**Timestamps are clamped to the receiver's clock** (`min(ts, now)`) on every adoption path (`app:message`, `app:migrate`, `restore_req`): a hint can never claim to be from the future (which would win once and then outrank every genuine later notice), though it can still never be older than what is held. A non-numeric or missing timestamp is ignored, not defaulted to "now".

**Message-borne hints require a valid signature.** A `relay.wss` steers where we send that contact's traffic, so it is adopted only from a message whose signature verified; a message that decrypts but fails the signature is still displayed, but its hint is ignored.

**Relay hints are shape-checked** (`relayHintProblem`, applied inside `updateRelay`, so it covers every adoption path above, and to the relay segment of a pasted key in `addContact`). A hint is a URL a contact chose, and this client will open a WebSocket to it. The signature check decides *who* may steer our traffic; it says nothing about *where*. A WebSocket handshake is an ordinary HTTP GET with the URL's own path and query, so a hostile hint can aim a request at a local service. It can be reached even from an https page, because loopback is exempt from mixed-content blocking.

- **Always:** a string of at most 512 characters, printable ASCII only (IDN hosts arrive as punycode), scheme `ws:` or `wss:`, no credentials, no fragment, a host.
- **Strict** (the default, and always on an https page): `wss:` only, and the host must be a public DNS name or a public IPv4 literal. Refused: `localhost`, single-label names, the local-only suffixes `localhost`, `local`, `localdomain`, `internal`, `intranet`, `lan`, `home`, `corp` and `home.arpa`, non-public IPv4 ranges (private, loopback, link-local, CGNAT, documentation, multicast, reserved), and any IPv6 literal. The host is judged *after* URL normalisation, so `2130706433` and `0x7f.1` are seen as the `127.0.0.1` they are.
- **Loose:** only when the page itself is served over plain http (local development), where `ws:` and LAN hosts are what a dev setup is made of.

A rejected hint is logged and changes nothing, in particular not `lastRelaySeen`: otherwise a rejected hint with a fresh timestamp would shut out the genuine one that follows. What no client-side rule can see is a public-looking DNS name whose record points inside the network.

A relay's own `sig:relay_info` is a confirmation, not an authoritative fact, except on a completely fresh identity with no local record, where it is adopted as an unconfirmed placeholder with `lastRelaySeen = 0` so any genuinely dated record arriving later outranks it. A `wss` in `sig:relay_info` that contradicts a held `lastRelay` is logged and ignored; only a deliberate migration changes it. On each `sig:relay_info` the client also closes any outbound connection it holds to the host it is already signal-connected to.

The relay is untrusted infrastructure. Relays never forward to one another; all topology lives in client state and spreads through ordinary traffic.

---

## Local Session: Auto Login and Logout

Both live in `meshchat-identity.js` and never touch the wire. They exist because an identity is derived from a name and passphrase, and a page reload otherwise means typing them again.

### Auto login

An opt-in checkbox on the login screen (stored as `meshchat_autologin`) remembers the login on this device, so a page load logs straight in. It does not use the browser's password autofill, which cannot work here: Chrome withholds an autofilled password from scripts until a user gesture, phones want a tap, and Safari has no silent credential API.

**What is stored.** Not the passphrase. The 32-byte PBKDF2 master secret and the username go into IndexedDB (database `meshchat-remember`, store `kv`, record `remembered`), AES-GCM-encrypted under a **non-extractable** WebCrypto key kept beside it as a `CryptoKey`. The username rides as additional authenticated data, so a record whose name was swapped fails to decrypt instead of logging in under another name. Consequences:

- The master secret *is* the identity. Whoever holds it can log in as you, indefinitely, and identities cannot be revoked.
- It is not the passphrase, so a leak does not expose a passphrase reused elsewhere, and login skips the 1,000,000-iteration derivation.
- The non-extractable key stops a script or a storage dump from copying the key bytes. It does not stop a script from asking the page to decrypt, and it is no protection against someone with real access to the browser profile, because key and ciphertext both live in it.
- A normal login protects contacts and sessions at rest with a key derived from the passphrase. A remembered login drops that layer on this device.

**Flow.**

1. Login with the box ticked: once the identity lock is won, the master secret is remembered (`persistRememberCandidate`). A lock that was refused stores nothing.
2. Page load with a record present: the name field is filled, the passphrase field gets a placeholder that contains a NUL (so nobody can type it), and ENTER is pressed. The login handler sees that placeholder and takes the stored master secret instead of running the KDF.
3. If the user has typed anything in the meantime, or the login button is disabled, nothing fires.
4. A failed auto login does not delete the record. One page load makes one attempt, so nothing can loop, and a transient storage error should not cost the user their remembered login.

**An auto login never takes over.** It does not show the "take over?" confirm. Nobody is looking at the screen, and two auto-login tabs would otherwise steal the identity from each other forever. If the identity lock is held elsewhere it retries once after 1 s (a reload can race the old page's lock release), then gives up with "identity already open in another tab". A manual ENTER asks as usual.

**Suppression.** Two events stop the next page load of *this tab* from logging straight back in, by setting `meshchat_no_autologin` in `sessionStorage` (per tab, survives the reload, gone with the tab): being displaced by another tab, and logout. A login a human chose lifts the mark.

**Deletion.** The record is deleted by: unticking the checkbox, logout, and self-destruct (fire-and-forget there, since the page reloads after 300 ms). On load, if the checkbox is off but a record is left over (unticked in another tab), it is deleted.

**Disabled when unavailable.** The checkbox is disabled, with a reason, when IndexedDB or WebCrypto is missing, when IndexedDB is unusable (private modes), or when either of the two one-line hooks (the login handler calling the remembered-aware derivation, `selfDestruct` calling `forgetRemembered`) is absent. Without both, a remembered login would feed the placeholder to the real KDF and silently log in to a different, empty identity.

Not yet observed on real devices: storing a `CryptoKey` in IndexedDB on iOS Safari, and Safari clearing site storage after about 7 days without a visit unless the app is on the Home Screen (the remembered login would then simply disappear and the login screen shows).

### Logout

A full page reload, the same way self-destruct and a displacement end a session: the client keeps far too much module-level state (pending X4DH ephemerals, retired roots, the wire-key cache, media caches, timers) to reset in place. Unlike BURN it wipes nothing: contacts, device seed, X4DH sessions and held messages stay in storage, encrypted as before, and logging back in picks up where this left off (held messages go out then). That is why it asks for no confirmation.

Order:

1. End or decline anything in flight (calls and data tests), so the peer does not ring until its own timeout.
2. Flush storage: `saveContacts` and `saveX4DHSessions`, awaited.
3. Pause 300 ms, so what step 1 queued can leave the socket.
4. Close the socket without its `onclose` handler (which would schedule a reconnect).
5. Forget the remembered login, release the identity lock, mark the tab no-auto-login, reload. The login screen then says "logged out".

### Settings panel

Everything about *you* or *this device* sits in one panel (the gear in the sidebar header, or tapping your name there): push, theme, backup export/import, the in-page log, logout; your relay override and MIGRATE; and BURN. Contact-scoped actions (SYNC, EDIT, BLOCK) stay in the contact's menu, and your own chat has none. Settings apply live. The only SAVE is the relay field, which restarts the connection, sets `lastRelay` and `lastStateChange`, and does not bump `lastRelaySeen` or notify contacts; that is what MIGRATE is for. The theme is per identity and per device, and is never synced.

---

## Client Storage Keys

| Key | Scope | Description |
|---|---|---|
| `meshchat_contacts_<publicId>`         | per identity | Contact store, object blob under the backup key |
| `meshchat_peer_backups_v1_<publicId>`  | per identity | Peer-supplied encrypted backup blobs |
| `meshchat_peer_tokens_v1_<publicId>`   | per identity | Restore tokens held for contacts |
| `meshchat_known_devices_v1_<publicId>` | per identity | Device registry |
| `meshchat_send_counters_v1_<publicId>` | per identity | Per-contact outbound `n` counters for this device |
| `meshchat_x4dh_sessions_v1_<publicId>` | per identity | X4DH session state including root keys, encrypted at rest under the backup key |
| `meshchat_device_seed_v1_<publicId>`   | per device   | Raw 32-byte device seed (base64url). Never shared, never backed up |
| `meshchat_push_pref_v1_<publicId>`     | per device   | Push opt-in (`"1"`/`"0"`). The `PushSubscription` lives in the browser |
| `<key>_unreadable`                     | per store    | Quarantined copy of a contact-store or X4DH-session blob that failed to decrypt or parse (see below) |
| `meshchat_autologin`                   | per device   | Auto-login checkbox state (`"1"`). The intent only, not the secret |
| IndexedDB `meshchat-remember` → `kv` → `remembered` | per device | The remembered login: username plus the master secret, encrypted under a non-extractable key (see [Auto login](#auto-login)) |
| `meshchat_no_autologin`                | per tab (`sessionStorage`) | This tab must not auto-login (`"logout"` or `"displaced"`) |
| `meshchat_identity_displaced`          | per tab (`sessionStorage`) | Shows the displacement notice after the reload |
| `meshchat-theme-<publicId>`            | per device   | This identity's theme choice |
| `meshchat-theme`                       | per device   | Last theme shown. Used by the login screen and as the fallback |

The contact store written locally keeps `status: "waiting"` on held messages; every other serialisation strips it.

**Unreadable blobs.** When the contact store or the X4DH sessions fail to decrypt or parse (corruption, a half-written value, a format no longer understood), loading falls back to an empty state. The next save would then replace the stored blob with that empty state, turning a transient read problem into permanent data loss. So the raw stored string is first copied to `<key>_unreadable` (one slot per store, newest wins; it is the same ciphertext and needs no extra protection). Recovery is manual: nothing reads it back. Self-destruct removes it with the rest.

**Write ordering.** Contact-store saves and X4DH-session saves are each serialised through a promise chain, and the snapshot is taken inside the queued step, so the last write in the queue always carries the freshest state. Every save also checks the persistence-halt flag set by [self-destruct](#self-destruct) at the last synchronous moment before `localStorage.setItem`, after its own awaits, so a save that started before a wipe cannot finish after it and write the identity back.

Held in memory only, never persisted: pending X4DH proposal ephemerals, retired X4DH roots (decrypt-only grace), pending wrap ephemerals, pending manual-sync ephemerals, the wire-key cache, the armed live-QR token, the hello rate-limit table, and the media caches.

---

## Server Configuration

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT`           | `8000`        | Static file server port |
| `WS_PORT`             | `8888`        | WebSocket signal server port |
| `RELAY_WSS_URL`       | —             | Public WSS URL of this relay. **Required for auth**: its host is what clients' auth proofs are bound to; with no valid value the relay refuses every `sig:auth_init` (`relay_not_configured`) |
| `RELAY_AUTH_HOSTS`    | —             | Extra hostnames (bare, or full URLs; comma-separated) this relay also accepts an auth proof for. Only meaningful on top of a valid `RELAY_WSS_URL` |
| `PROTOCOL_VERSION`    | `0.6.2`       | Reported on `sig:relay_info`; informational |
| `WS_MAX_SIZE`         | `2097152`     | Maximum frame size in bytes; larger frames are dropped |
| `MAX_CONNECTIONS`     | `100`         | Total concurrent WebSocket sessions |
| `MAX_CONNECTIONS_PER_IP` | `15`       | Concurrent sessions per source IP |
| `TRUSTED_PROXIES`     | `127.0.0.1,::1` | Comma-separated IPs/CIDR ranges whose `X-Real-IP`/`X-Forwarded-For` are honoured |
| `RATE_LIMIT_RATE`     | `20`          | Per-socket token refill, packets/second |
| `RATE_LIMIT_BURST`    | `60`          | Per-socket burst |
| `IP_RATE_LIMIT_RATE`  | `3 × RATE_LIMIT_RATE`  | Budget shared by all sockets from one IP |
| `IP_RATE_LIMIT_BURST` | `3 × RATE_LIMIT_BURST` | Burst for that shared budget |
| `GLOBAL_AUTH_RATE`    | `50`          | Server-wide cap on completed auths/second |
| `GLOBAL_AUTH_BURST`   | `100`         | Burst for that cap |
| `BUF_DIR`             | `./relay_buf` | Offline message buffer directory |
| `BUF_MAX_MSGS`        | `100`         | Max buffered packets per bucket |
| `BUF_MAX_AGE`         | `86400`       | Buffer expiry in seconds — ordinary packets, including `session:*` |
| `BUF_MAX_AGE_MIGRATE` | `604800`      | Expiry in seconds (7 d) — `app:migrate` only |
| `BUF_MAX_AGE_BURN`    | `604800`      | Expiry in seconds (7 d) — `app:burn` only |
| `BUF_MAX_MB`          | `10`          | Max buffer size per bucket in MB |
| `BUF_WRITE_RATE_LIMIT`| `2`           | New buffered writes/second allowed per bucket |
| `BUF_WRITE_RATE_BURST`| `20`          | Burst for that limit |
| `MAX_BUF_RECIPIENTS`  | `10000`       | Max distinct recipient directories under `BUF_DIR` |
| `MAX_ENDPOINTS_PER_RECIPIENT` | `20`  | Max endpoint buckets one identity can accumulate |
| `VAPID_SUBJECT`       | `mailto:admin@example.com` | Operator contact, sent in every push JWT's `sub` claim |
| `VAPID_KEY_FILE`      | next to `BUF_DIR` | Persisted VAPID EC P-256 private key (PEM); generated on first boot if missing |
| `PUSH_SUBS_DIR`       | next to `BUF_DIR` | Push subscription storage |
| `PUSH_TTL_SECONDS`    | `60`          | `TTL` header sent with each push |
| `PUSH_ALLOWED_HOSTS`  | the defaults listed under [Push endpoint policy](#push-endpoint-policy) | Comma-separated allowlist of push-service hosts (an entry is an exact hostname, or a leading-dot suffix that needs at least one more label). **Replaces** the defaults rather than adding to them. A rejected endpoint's host is logged, so adding a service is a config change. Empty turns push off |
| `PUSH_MAX_SUBS_PER_IDENTITY` | `10`   | Push subscriptions kept per identity (one file per endpoint id). A further new endpoint is rejected |

`AUTH_TIMEOUT` (15 s), `AUTH_VERSION` (`2`) and the push request limits (endpoint at most 2048 characters, each key at most 256, 10 s timeout per connect and read, at most 3 resolved addresses tried per send) are constants, not environment variables.

---

## Constants

| Constant | Value | Used for |
|---|---|---|
| Dedup window | 3 s | Duplicate suppression of handshake packets, hellos, `(from, id, ts)` messages, X4DH proposes |
| Presence poll | 30 s ± 5 s | `sig:announce` |
| Presence expiry / prune | 300 s / 30 s | Online set |
| Backup timer / threshold | 10 min / every 2nd received message | Contact-path backup offers (+ restore requests on the timer) |
| Backup offer TTL | 60 s | Pending offer lifetime |
| Restore cooldowns | 5 min | Outbound, inbound-serve, inbound-accept (separate maps) |
| Restore ack ping cooldown | 60 s | Per id |
| Token request TTL | 60 s | Outstanding `sync:token_req` |
| Ephemeral wrap lifetime | 60 s | Restore and backup pending ephemerals |
| Manual sync pending TTL | 60 s | Pending request ephemeral |
| Self-backup hello cooldown | 60 s | Discovery hello |
| Retention / sync window | 15 / 10 messages | Persistence / manual sync |
| Sync batch cap | 50 messages | Inbound sanitising |
| Message timestamp skew | +5 min on our clock | `ts` clamp on every received message and synced entry |
| Message id pattern | `[A-Za-z0-9_-]{1,64}` | Received and synced message ids |
| Held peer backup cap | 1 MiB | Ciphertext length of a stored backup blob |
| Relay hint length | 512 characters | Relay hint shape check |
| Push endpoint / key length | 2048 / 256 characters | Subscription validation |
| Push subs per identity | 10 | `PUSH_MAX_SUBS_PER_IDENTITY` |
| Push send timeout / addresses tried | 10 s / 3 | Per connect and read; per send |
| Logout flush pause | 300 ms | Lets queued packets leave the socket |
| Auto-login lock retry | 1 s | One retry when the identity lock is still held |
| `FANOUT_STALE_MS` | 7 d | Targeted send to a session-less device |
| Device registry cutoff / cap / sweep | 30 d / 20 per identity / 10 min | Registry retention |
| HELLO interval | 20 s per contact | Event-driven hellos |
| HELLO nudge | 15 min per contact | Held outbox, believed-online contacts only |
| Held message max age / tick | 24 h / 5 s | Held outbox |
| X4DH constants | see `X4DH.md` §12 | Sessions |
| Live-QR token | 16 bytes, 120 s, single use | Live QR |
| Relay connection idle / connect timeout | 30 s / 5 s | Outbound relay connections |
| Signal reconnect delay | 3 s | Main socket |
| Relay test timeout | 5 s | Migrate TEST |
| Migration drain delay / open time | 10 s / 3 s | Old-relay drain |
| Data test ring / negotiate | 30 s / 20 s | Data-channel test |
| Data channel message / pong / early-ICE caps | 128 chars / 3 / 50 | Data-channel test |

---

*MeshChat Protocol v1 — implementation 0.6.2 — experimental, subject to change*
*Last updated: October 2026*