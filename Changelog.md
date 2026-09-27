# MeshChat — Changelog

Version history for the client/server implementation. `protocol.md` describes
the protocol as it stands today only — this file is where "what changed and
why" lives. `X4DH.md`'s own Status block remains the authoritative record of
what's been confirmed live vs. design-only for the X4DH cryptographic work
specifically; entries below summarize, they don't replace it.

Format: newest first. An entry with no version number is meshdev/dev-cycle
work, not yet cut as a numbered release.

---

## 0.5.2

Raises the PBKDF2 iteration count used for identity derivation from
100,000 to 1,000,000, following discussion on GitHub. **Breaking — no
backward compatibility, and none attempted.**

- **`masterSecret` derivation now uses 1,000,000 PBKDF2 iterations**
  (`protocol.md`'s Identity and Key Derivation section), up from 100,000.
  Every key derived from `masterSecret` — the X25519 identity key, the
  Ed25519 signing key, and the backup key — changes as a result, which in
  turn changes `publicId` (derived from the two public keys). For any
  existing identity this has the exact same effect as changing username
  or passphrase (see `known-limitations.md`'s "Changing your passphrase
  creates a new identity"): logging back in with the same credentials now
  derives a completely different identity, with no local data under the
  new `publicId` and no path back to the old one.
- **No dual-version detection or migration path was attempted, deliberately.**
  Same category as the earlier C64/AES128 encryption-key migration, which
  was painful in practice — this is a hard cutover, not something to
  soft-migrate. Testing is currently limited to a small number of people,
  so a clean break was judged acceptable while that's still true.
- **Practical consequence for anyone testing across this boundary:**
  every device and contact relationship needs to be re-established from
  scratch — re-login re-derives a new identity, and contacts must
  re-exchange keys/QR codes, exactly as if everyone had picked new
  passphrases at the same time. `meshdev` is incompatible with any
  pre-bump identity as a result.
- **Fixed: the restore/backup ephemeral wrap (`0.5.1`) clobbered itself
  across a contact's own multiple devices.** `pendingRestoreEk`/
  `pendingBackupEk` (see `protocol.md`'s
  [Ephemeral Wrap](protocol.md#ephemeral-wrap)) were keyed by the bare
  contact identity only. Two of a contact's devices online at once each
  independently trigger their own restore/backup round trip toward us;
  each attach overwrote the other's pending ephemeral in the same shared
  slot, so whichever push arrived second either unwrapped under the
  wrong key or found its entry already deleted — surfacing as `wrap
  present but no pending ephemeral for <id>, dropped` and a string of
  spurious unwrap failures on the device that was already online.
  Not a security issue (AES-GCM simply fails closed on the wrong key,
  same fail-safe behavior described in `known-limitations.md`) and not
  data-lossy (the next restore/backup cycle just retries) — a reliability
  bug, not a correctness one. Fixed by adding a per-device slot
  (`id::endpointId`, alongside the existing bare-identity slot) whenever
  the responding device is already known at attach time
  (`handleRestoreRequest` resolves it from the request's own
  `plain.deviceId`; `handleBackupOffer` already has it directly from the
  offer's compound `from`) — consumed the same way on the receiving end,
  falling back to the bare slot when no device was known yet. Wire
  format is unchanged; this is local bookkeeping only.
- **Fixed a second, related race in the same mechanism: a successful
  unwrap was consuming the pending ephemeral, even though `restore_ack`/
  `backup_accept` address a bare identity and therefore broadcast to
  *every* live session under it.** An identity running two-plus devices
  legitimately produces two-plus independent pushes in reply to one ack —
  each with its own fresh ephemeral, each validly unwrappable against our
  one stored private half (X25519 DH is safe to run more than once
  against the same private scalar paired with a different public key each
  time). Deleting the slot on the first successful unwrap discarded it
  before the next, equally legitimate push could ever arrive — reproduced
  live logging in as a third identity while two others were already
  online: the first device's push unwrapped fine, the second failed with
  the same `wrap present but no pending ephemeral` message the fix above
  was meant to close. The lookup (renamed `peekPendingEk`) now leaves the
  slot alone on a hit; it's only ever cleared by its own timeout or by a
  fresh attach superseding it.
- **Fixed a third, sibling bug in the same family, on the OFFER side of
  the peer-backup handshake specifically.** `pendingBackupOffer` tracked
  a single pending offer per bare identity, deleted the instant it
  satisfied one accept. Since `backup_offer`'s `to` is also a bare
  identity, one offer broadcasts to every live session under it — an
  identity running two-plus devices produces two-plus independent
  accepts (each with its own ek) in reply to a single offer, but only the
  *first* one to arrive ever got a push generated for it at all; the rest
  silently found nothing (a debug-only "no pending offer, ignored" line)
  and never received a working backup for that round — surfaced as one
  sibling device logging `unwrap failed` for a push that, in this case,
  genuinely was never wrapped for it. Reproduced live with two devices of
  one identity both accepting the same incoming offer from a third party,
  and separately with two devices of a *different* identity both
  accepting an offer from this one. Self-healing in practice (the next
  backup cycle gives every device another chance to be first) which is
  why it looked benign, but a device could go an arbitrary number of
  cycles without ever winning that race. Fixed the same way as the other
  two: `pendingBackupOffer[fromId]` is no longer deleted on a successful
  accept, only by its own TTL expiry or by the next offer replacing it —
  every accept within that window now gets its own independently-wrapped
  push.

## 0.5.1

Restore-token hardening and a new one-shot ephemeral wrap for the peer
backup/restore handshake, landed and confirmed live on meshdev across
several small, independently-tested steps.

- **Restore token now signed and bound to its sender.** `sync:token_resp`
  is signed (`signTokenPacket`/`verifyTokenPacket`) and only accepted
  while a `token_req` of the recipient's own is genuinely outstanding —
  closing a denial-of-restore where a planted, unsigned token could
  permanently wedge a contact's restore path (the receiver kept only the
  first token ever seen per sender, silently ignoring any genuine
  response after). Every use of a token — on `sync:restore_req`, and now
  on `sync:restore_push` too, see below — requires the identity it
  decrypts to (`tokenBoundId`) to match the packet's actual sender; a
  mismatched or malformed token is treated as no token rather than a hard
  failure. Issued tokens also shrank to `{ v: 2, shareableKey }` only —
  `name`/`date` were never read by anything and only ever leaked into an
  outer plaintext field.
- **The restore token now actually authenticates a wiped device's
  restore.** Previously the token only rode on the classic `restore_req`
  → `ack` → `push` path, which a genuinely wiped device (zero contacts,
  nothing to send a signed `restore_req` from) can never reach. It now
  also rides on the `restore_ack` → `restore_push` exchange a wiped
  device does use (`sendRestoreAckPing`'s proactive hi to an unknown
  peer): the holder attaches the token it holds for the acker once the
  ack's own signature verifies, and the wiped device — who issued that
  token before wiping and can still decrypt it via its own deterministic
  passphrase-derived key — uses it to recover the sender's signing key
  and verify the push, rather than accepting it unverified as before.
  See `protocol.md`'s [Restore Token](protocol.md#restore-token).
- **New: one-shot ephemeral wrap on `sync:restore_push` and
  `sync:backup_push`** (contact path; self-sync deliberately deferred). A
  fresh X25519 ephemeral-to-ephemeral DH, generated per exchange and held
  only in memory, wraps the existing backup-key-encrypted blob for
  transport. This is independent of X4DH — it protects a wiped device's
  very first restore, before any session could exist for its brand-new
  `deviceId` — and independent of whether the device pair ever
  bootstraps one. Gated on the preceding ack/accept's signature
  verifying, same soft-verification stance the rest of this handshake
  family already has. See `protocol.md`'s
  [Ephemeral Wrap](protocol.md#ephemeral-wrap) and `known-limitations.md`
  for what this does and doesn't cover, including the fail-closed
  behavior once a push has actually been wrapped.

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