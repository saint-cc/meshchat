# MeshChat — Changelog

Version history for the client/server implementation. `protocol.md` describes
the protocol as it stands today only — this file is where "what changed and
why" lives. `X4DH.md`'s own Status block remains the authoritative record of
what's been confirmed live vs. design-only for the X4DH cryptographic work
specifically; entries below summarize, they don't replace it.

Format: newest first. An entry with no version number is meshdev/dev-cycle
work, not yet cut as a numbered release.

---

## Unreleased (meshdev)

- **Fixed: unbounded polling-loop leak.** `schedulePoll()`'s `setTimeout`
  chain was never tracked or cleared. `handleAuthOk` (fired on every
  successful auth, i.e. every reconnect) called it unconditionally, so a
  client that reconnected N times ended up running N independent, permanent
  polling loops stacked on top of one another — each firing `sig:announce`
  on its own ~30s±jitter schedule. Over a long or reconnect-heavy session
  this produced runaway `sig:announce` traffic and tripped the per-socket
  rate limiter in bursts of dozens to 80+ rejections at a time. Fixed by
  storing the timeout handle in a module-level variable and clearing it
  before scheduling the next one, making `schedulePoll()` idempotent across
  reconnects.

- **Fixed: `sendRestoreAckPing` had no cooldown of its own.** It was gated
  only by the `sessionFresh` flag, which clears exclusively inside
  `handleRestorePush` on a *successful* restore. A device that never
  completed a restore (nothing to restore, or the restore path was failing)
  kept `sessionFresh` at `true` indefinitely, so every `sig:seen` for every
  online contact — i.e. every poll interval — re-fired an identical
  restore-ack ping. Visible in relay logs as exact duplicate
  `RESTORE_ACK`/`RESTORE_REQ` pairs at regular intervals. Fixed by adding
  `lastRestoreAckPingSent` / `canSendRestoreAckPing()`, a short (60s)
  cooldown independent of the existing 5-minute `RESTORE_COOLDOWN` — this
  one only needs to stop spam, not slow down genuine restore attempts.

---

## 0.5.0

Lands X4DH session establishment (see `X4DH.md` for the full cryptographic
design and live-confirmation status) as the first working replacement for
the identity-level static pairwise key, on a per-device-pair basis, plus the
fanout/registry work that depends on it.

- **Session establishment wire types** — `session:propose`/`session:ack`.
  See `protocol.md`'s [Session Establishment](protocol.md#session-establishment-x4dh).
- **Per-device wire encryption for `app:message`** — real message traffic
  now encrypts under a session's root key (`RK0` or `RK1`) for any device
  pair that has completed X4DH bootstrap, with graceful per-device fallback
  to the legacy identity-level key. See `protocol.md`'s
  [Encryption](protocol.md#encryption) and `X4DH.md` §16.
- **Targeted acknowledgement routing** — the RECEIVED auto-ack and manual
  reactions address the single originating device directly
  (`resolveReactionTarget`) instead of fanning out to every known device,
  eliminating the M×N ack-packet multiplication a multi-device conversation
  previously produced. See `protocol.md`'s
  [Delivery Acknowledgement](protocol.md#delivery-acknowledgement-received).
- **Device registry retention tightened** — pruning cutoff dropped from 90
  to 30 days, and pruning now also runs on a periodic sweep, not only at
  login. See `protocol.md`'s [Device Registry](protocol.md#device-registry).
- **X4DH hardening, confirmed live on meshdev**: root-key bootstrap/upgrade,
  the fixed-initiator rule (both contact and self-pairs), a stuck-at-RK0
  detector, a propose-freshness/downgrade guard, and bounded automatic
  re-propose retry (10 attempts, gated on genuine online-transitions,
  re-arming on the next transition after exhaustion). Full detail in
  `X4DH.md`'s Status block.
- **Per-device X4DH status dot** in the contact/self device popover
  (no session / RK0 fresh / RK0 stuck / RK1) — UI-only, not covered
  elsewhere in the docs.
- **`sync:backup_push` now writes to the offline buffer on missed live
  delivery** — implemented; live confirmation still pending as of this
  entry.

## 0.4.9

Client-side correctness fix to `getAckPointer`. The previous version picked
a contact's "freshest" device by the device registry's `lastSeen`, which is
bumped by *any* inbound packet — including a bare RECEIVED-ack reaction —
so a multi-device contact's ack races could outrank a genuinely more recent
conversational message. Now reads only the local message list's own
`(ts, id)`-ordered `(deviceId, n)` pairs, excluding reactions; outgoing
sends now also stamp their own `deviceId` on the locally-stored copy, not
just the wire payload, so this lookup has something to read on both sides.

## 0.4.8

Finalizes causal message ordering end to end. `mergeMessages` resolves
`ackDeviceId`/`ackN` into parent edges and splices children depth-first
rather than trusting `(ts, id)` alone; `agent.py`'s `send_ack` mirrors the
RECEIVED auto-ack; local message retention (`selectRetainedMessages`)
selects by actual recency rather than a positional slice, since positional
truncation after a causal splice could otherwise drop a message's causal
parent or keep older messages over newer ones. `getAckPointer`'s device
tiebreak is now deterministic (`lastSeen` → `lastN` → `deviceId`).

## 0.4.7

Client-side robustness pass on the restore/backup handshake family, no wire
format change. The restore cooldown — previously one identity-keyed map
shared across three unrelated jobs, so activity on any one could silently
suppress an unrelated device's legitimate turn — is split into three
independent trackers. The short-window duplicate suppression already used
for `backup_offer` is extended to `backup_accept`/`backup_push`/
`restore_ack`/`restore_push`, keyed the same device/endpoint-aware way.

## 0.4.6

Replaces the separate `toEndpoint` field with a single compound `to`
address (`"id"` or `"id::endpointId"`), applied first to the 0.4.5 self-sync
backup work. See `protocol.md`'s [Compound Addressing](protocol.md#compound-addressing).

## 0.4.5

Adds the endpoint-keyed offline buffer
(`BUF_DIR/<publicId>/_endpoints/<endpointId>/`, own caps/TTL/expiry sweep,
independent of the identity-level bucket), extends self-sync device
targeting to `sync:backup_push`/`sync:backup_accept`, and moves
`deviceId`/`endpointId`/`fingerprint` off those two types' outer envelope
into the encrypted `blob` — the relay never read them, and an unsigned
outer field is silently rewritable in transit by an untrusted relay with
zero detection.

## 0.4.2

Client-side bugfix only, no wire format change. The WebRTC call notice
previously always labelled the caller `"<name> (me)"` regardless of who was
actually calling, because it read the caller's own locally-decorated
self-contact label instead of their plain username.

## 0.4.1

Web push notifications, end to end: VAPID keypair generation,
`sig:push_subscribe`/`sig:push_unsubscribe`, best-effort empty-payload
pushes on genuinely-offline `app:message` delivery, the per-device opt-in
checkbox (edit-contact panel, self only), the browser subscribe/re-subscribe
flow, and the service worker's `push`/`notificationclick` handling.

## 0.4.0

Replaces the identity encryption key with an X25519 keypair. **Breaking —
no backward compatibility.**

## 0.3.7

Adds the burn notice (self-destruct / stop-trusting signal).

## 0.3.6

Adds WebRTC data-channel shell escalation for agent contacts.