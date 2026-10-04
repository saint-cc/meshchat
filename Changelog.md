# MeshChat — Changelog

Version history for the client/server implementation. `protocol.md` describes
the protocol as it stands today only — this file is where "what changed and
why" lives. `X4DH.md`'s own Status block remains the authoritative record of
what's been confirmed live vs. design-only for the X4DH cryptographic work
specifically; entries below summarize, they don't replace it.

Format: newest first. An entry with no version number is meshdev/dev-cycle
work, not yet cut as a numbered release.

---

## 0.5.5

Rolls up the 0.5.3–0.5.5 work as one entry (the individual cut points weren't
recorded at the time). Mostly the sibling-sync/backup rework decided in
September, plus the removal of agent/shell. **Several changes are wire-visible
and no compatibility shims were attempted** — same stance as `0.5.2`, while
testing is still limited to a small number of people. Per-item live-confirmation
status lives in `X4DH.md`/`Roadmap.md`, not here; at the time of writing this
release is being exercised on meshdev.

- **Removed: agent contacts, the bounded command whitelist and shell
  escalation.** `agent.py`, the `type` field on contacts, the xterm terminal UI
  and the `shell:*` packet family are gone. The shell work was only ever a test
  of the WebRTC data channel; it is expected to come back later as a plugin, not
  in this shape. A relay now drops `shell:*` as an unknown type.
- **Replaced by a data-channel test: `data:*`.** Seven wire types
  (`data:invite`/`claim`/`cancel`/`end`/`offer`/`answer`/`ice`), same shape,
  signing rules and shared state machine as `call:*` (`transition()` in
  `statemachine.js`, `kind: "data"`), keyed by `sessionId`. It is a connection
  test and nothing more: the caller opens one channel (`"data"`), sends a single
  ping, the callee echoes a pong, the caller reports the round-trip time and ends
  the session. Nothing is stored in `contact.messages` (so nothing is backed up
  or synced) — the result is a transient toast. Differences from the old shell
  path: **nothing auto-claims** — an incoming invite raises an accept/decline
  banner, since answering reveals the answerer's network address through ICE; the
  receive hook is strict (strings only, ≤128 chars, one known shape, nonce must
  match, role-gated, at most 3 pongs echoed); ring timeout 30s, negotiate timeout
  20s; early ICE candidates that overtake the offer are queued (capped at 50).
  Still STUN-only, still no TURN.
- **New: self-sync message path replaces `pushMiniBackup`.** A message or manual
  reaction composed on one device is now mirrored to the identity's other devices
  as an ordinary `app:message` whose payload type is `selfsync`
  (`{ peerId, msg }`), sent through the normal per-device fanout
  (`sendFannedX4DH`) addressed to the identity itself. Over the old mini backup
  this gives per-sibling X4DH keys where a self-session exists, an Ed25519
  signature (self-sync backup packets carry none), and per-endpoint offline
  buffers — an identity-level buffered packet is consumed by whichever device
  reconnects first, so two offline siblings could never both receive it. Receive
  side (`handleSelfSync`) is deliberately narrow: must be from our own identity,
  signature must be valid (unlike an ordinary message there is no
  displayed-with-a-warning case), own echo ignored, whitelisted field copy rather
  than a spread, never acks or re-fans, never bumps unread, never sets
  `ackTrusted`, and the embedded `n` is stored but never fed to
  `recordKnownDevice`. Media goes as a stub only; call notices and RECEIVED
  auto-acks are not mirrored. A self-addressed `app:message` never triggers a
  push. Self-fanout also no longer targets the sending device itself
  (`resolveDeviceTargets`). The retired mini-backup shape (a bare contacts map) is
  still accepted on receive. **Known gap:** a sibling we've never heard from is
  not synced to at all — there is nothing to address; it is discovered through
  the self-backup handshake or its own traffic.
- **Changed: self-sync backups no longer ride the static backup key.** The full
  self push is now a targeted, per-sibling send under that sibling's X4DH wire key
  (skipped when its fingerprint already matches). Where no usable session exists
  — no sibling known, endpoint unknown or stale, or no session yet — a
  content-free discovery **hello** (`{ deviceId, endpointId, hello: true }`, under
  the backup key, broadcast to our own identity, 60s cooldown) goes out instead,
  purely so siblings learn the device and X4DH can bootstrap a self-session.
  `handleSelfHello` answers with a small targeted ack (session key plus
  fingerprint if a session exists, otherwise content-free under the backup key).
  Receive side (`decryptSelfBackupBlob`) trial-decrypts every self-session wire
  key newest-first, then the backup key last, and cross-checks the payload's
  `deviceId` against the session it decrypted under. A full push under the static
  backup key from an older sibling is still accepted (and logged). Consequence: a
  brand-new sibling receives contacts from the first push after its session
  exists, not instantly; a genuinely wiped device still restores immediately via
  the `restore_ack`/`restore_push` path. The hello still exposes the
  `deviceId`↔`endpointId` link to recorded traffic plus a later passphrase
  compromise — metadata only, accepted for the discovery step.
- **Changed: self `restore_push` is now ephemeral-wrapped.** `0.5.1` deliberately
  left self-sync out of the wrap; the self branch of `handleRestoreAck` now wraps
  the push the same way the contact branch does, since it carries full message
  history. The ack's signature covers `ek`, so a relay cannot strip or swap it.
- **Changed: contact-path backups carry contacts only.** The blob offered/pushed
  to another contact (`serialiseContactsForPeers`) has `messages: []` on every
  entry. A peer holding your backup is a third party with an indefinitely stored
  copy; the contact list is what restore needs, and message history never had to
  ride along. Self-sync blobs are unaffected.
- **Changed: the server no longer buffers `sync:backup_push`.** The `0.5.0`
  behaviour (buffer on a missed live delivery) is reverted; it never got
  independent live confirmation and turned out to be the wrong tool. Contact-path
  pushes answer a live handshake and may be wrapped under an ephemeral held ~60s
  in memory, so a buffered copy flushed on reconnect can never be unwrapped (and
  an unwrapped stale one could overwrite a newer stored backup). The
  sibling-catch-up job moved to the `selfsync` path above, which gets per-endpoint
  buffering as an ordinary `app:message`. Self-sync full backups are online-only
  again.
- **Changed: handshake replies are one-to-one.** The root cause behind several
  `0.5.2` symptoms was addressing, not bookkeeping: the opening packet of the
  backup/restore handshake is addressed to a bare identity and fans out to every
  live session, and every reply was then also addressed bare, so with two devices
  under one identity each reply fanned out too — and each reply is wrapped for
  exactly one ephemeral. `backup_accept`, `backup_push`, `restore_ack` (when the
  requester's endpoint is already known) and `restore_push` are now addressed
  compound (`id::endpointId`) to the `from` endpoint of the verified opening
  packet (`replyAddress`). Unverified or fresh senders, and the bootstrap ping,
  keep the bare fallback. Dedup keys for `backup_offer`/`backup_accept`/
  `backup_push` are endpoint-aware once verified, so a second sibling's genuinely
  distinct packet isn't swallowed. `pendingEkCandidates` additionally searches the
  identity's other slots as a safety net — a wrong candidate costs one failed
  AES-GCM tag check, nothing more.
- **Changed: manual SYNC (`app:sync`) is encrypted, signed and wrapped.** The
  packet used to carry `msgs` and `reply` as plaintext JSON with no signature, so
  a relay could read the text and forge `from` to inject messages. It is now
  `{ type, from, to, blob, sig }`: the payload (`from`, `to`, `syncId`, `reply`,
  `ek`, and on a reply `wrapped`) is encrypted under the pairwise key and the
  ciphertext is signed, with verification mandatory on receive. The request
  carries no messages — only a fresh ephemeral `ek`; the reply carries its own
  `ek` and the batch wrapped under the ephemeral-to-ephemeral key, so a recorded
  batch plus a later identity-key compromise exposes nothing. **SYNC is therefore
  one-directional now:** the side that presses it receives the other side's recent
  messages; press it on both sides for a two-way exchange. A reply is accepted
  only while a request of our own to that contact is pending (`syncId`, 60s,
  `pendingSyncs`); inbound batches are whitelist-sanitised and capped at 50
  (`sanitizeSyncedMessages`). Legacy plaintext sync is dropped — a SYNC between a
  new and an old client simply does nothing.
- **Changed: push subscriptions are keyed by `endpointId`, not `deviceId`.**
  `sig:push_subscribe`/`sig:push_unsubscribe` carry `endpointId` and the relay
  stores `<publicId>/<endpointId>.json`. Keying on `deviceId` let the relay join
  its view (endpoints, seen at auth) with a contact's view (deviceIds) — exactly
  the correlation the `deviceId`/`endpointId` split exists to prevent. On
  subscribe, the relay drops any stale file for the same browser endpoint URL
  (including old `<deviceId>.json` files). Old clients that still send `deviceId`
  are dropped by the relay, so their push stops working until they update.
- **Doc correction: `resolveReactionTarget` does not exist.** The `0.5.0` entry
  above, and `protocol.md`'s Delivery Acknowledgement section, describe a targeted
  single-device ack path that was never present in `meshchat.js`.
  `sendReaction` has always used the full `sendFannedX4DH` fanout for both manual
  reactions and the RECEIVED auto-ack — deliberately, since an ack reaching only
  the originating device would leave the sender's other devices showing "sent"
  forever. The `0.5.0` text is left as written (it's history); the spec text is
  corrected separately. Narrowing the ack fanout would need pairing with the
  self-sync path first, and is not done.
- **Version.** `CLIENT_VERSION` and the relay's `PROTOCOL_VERSION` are both
  `0.5.5`, surfaced informationally via `sig:relay_info`.

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
- **Fixed: the restore/backup ephemeral wrap (`0.5.1`) could silently
  drop a push for a device pair that legitimately had every right to
  exchange one.** `pendingRestoreEk`/`pendingBackupEk` (see
  `protocol.md`'s [Ephemeral Wrap](protocol.md#ephemeral-wrap)) each held
  exactly one pending ephemeral per contact identity. `restore_ack` and
  `backup_accept` both address a bare identity, so a single outgoing one
  broadcasts to *every* live session under it — an identity running two-
  plus devices legitimately produces two-plus independent replies (each
  with its own ephemeral) to that one packet, and any given device can
  independently trigger its own attach toward the same target more than
  once (`sendRestoreAckPing`'s presence-driven ping and
  `handleRestoreRequest`'s reply both land on the same fallback slot
  whenever the responding device's endpoint isn't known yet). All three
  shapes hit the same one-slot-per-identity ceiling from a different
  angle, in sequence, live: two attaches racing to overwrite each other;
  a successful unwrap discarding the shared secret before a second,
  equally legitimate push could use it; and the two on our own side
  colliding with each other. None of it was a security issue (AES-GCM
  simply fails closed on a wrong key) or data-lossy (the next cycle just
  retries) — a reliability bug, not a correctness one, surfacing as
  `wrap present but no pending ephemeral` and plain `unwrap failed` in
  roughly equal measure. Rather than patch each shape as it turned up,
  each slot now holds a *list* of live ephemerals — every attach appends
  instead of overwriting (keyed by `id::endpointId` when the responding
  device is known, alongside a bare-identity fallback slot for when it
  isn't), and the receiving side trial-decrypts against every current
  candidate for that slot, newest first, exactly the way X4DH wire-key
  resolution already does for the same underlying reason
  (`decryptIncomingMessage`) — a wrong candidate fails cleanly and
  immediately, so trying a few costs nothing but a handful of failed
  decrypts. **A candidate is never removed for having matched a push** —
  an intermediate version of this fix removed the matching candidate on
  success, on the assumption that a used ephemeral was done; that was
  wrong, and reintroduced the second shape above one level down (the
  first of two replies to a broadcast ack to arrive would consume the
  only listed candidate, leaving the second with nothing). A single
  attach's ephemeral is exactly what shape #2 already established can
  legitimately answer more than one incoming push, so matching costs it
  nothing — the only way any candidate is ever removed now is its own
  timeout genuinely elapsing with nobody having used it. Wire format is
  unchanged throughout; this is local bookkeeping only.
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
- **Fixed: a push not addressed to this device could suppress the one
  that was.** The short-window duplicate check on `restore_push`/
  `backup_push` was keyed on `(sender, endpoint)` alone and stamps its
  timestamp the moment it's consulted — before the unwrap, so even for a
  packet that then fails to unwrap. With a doubled identity on either
  side, one broadcast ack/accept draws one reply per ephemeral (ours and
  our sibling's, both broadcast to both of us), all from the same sender
  endpoint within milliseconds; whichever arrived first — including the
  one wrapped for our sibling — claimed the 3s window, and the one
  actually meant for us was dropped as a "duplicate" on a debug-only log
  line, leaving only the visible `unwrap failed` from the wrong-for-us
  one. The dedup key now includes a short fingerprint of the push's own
  `ek` (`ekDedupTag`): distinct replies always carry distinct ephemerals,
  a genuine redelivery carries the same one. `unwrap failed against N
  candidate(s)` on a doubled identity is still expected noise — it's the
  copy of a broadcast reply meant for a sibling's ephemeral — but it no
  longer costs the real one.

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