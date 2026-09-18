# MeshChat — Roadmap

Working notes on what's done, what's next, and what still needs a real design
conversation before it gets touched. Not a promise of order or timing — just
so the list lives somewhere other than someone's head.

Current version: `0.5.0` per `protocol.md`'s formal wire spec, as of this
update — the X4DH session-establishment work (root-key bootstrap/upgrade,
per-device wire encryption, targeted ack routing, and the tightened device
registry retention) has now been witnessed firing correctly live and
unprompted enough times to graduate from this file's own tracking into
`protocol.md` itself, per this project's documentation discipline. `X4DH.md`
remains the authoritative document for the cryptographic design and the
live-confirmation status of pieces still in progress (automatic retry,
self-sync forward secrecy, etc.) — `protocol.md` only carries the wire
shapes and relay-visible behavior, not the DH derivations. One piece of the
`0.5.0` cycle has NOT graduated: the `sync:backup_push` offline-buffering fix
(see Done, below) is implemented but still not independently confirmed live,
so it stays here rather than in `protocol.md` until that changes.
See `protocol.md` for the authoritative wire spec and `known-limitations.md`
for permanent, by-design tradeoffs (no TURN, no real revocation, etc.) —
those aren't roadmap items, they're not going to change.

---

## Done

Recent, for context on where "next" picks up from:

- **Reaction/ack fanout narrowed to the single target device — confirmed
  live, now documented in `protocol.md`.** X4DH's per-device wire encryption
  had turned `sendReaction`'s fanout (shared with the RECEIVED auto-ack,
  which fires on every single incoming message) into the dominant source of
  server-side load: routing it through the same `resolveDeviceTargets`
  fanout an ordinary message correctly uses meant a receiver running M
  devices, acking a sender running N devices, produced M×N ack packets when
  only M were ever meaningful. `resolveReactionTarget(contactId,
  targetMsgId)` now looks up the specific device that sent the original
  message and, when it resolves (known `endpointId`, not stale — same test
  `resolveDeviceTargets` already applies), sends a single targeted packet
  instead of fanning; falls back to the full broadcast fanout unchanged
  whenever it doesn't resolve. Exercised live on meshdev and graduated into
  `protocol.md`'s own [Delivery Acknowledgement](protocol.md#delivery-acknowledgement-received)
  section — this file no longer needs to track it. Next step: pull
  `server.py`'s `STATS` log (`buf_rate_rejected`/`buf_cap_rejected`/
  `buf_endpoint_cap_rejected`) to see how much of the original throughput
  pressure this alone accounted for, before deciding whether server-side
  limits still need raising at all.
- **X4DH session establishment, per-device wire encryption, and the
  tightened device registry retention — all confirmed live and now
  documented in `protocol.md`.** Everything below in this file that
  describes root-key bootstrap/upgrade (§3–§7 of `X4DH.md`), the fixed-
  initiator rule (§13.1), the propose-freshness/stuck-RK0/retry hardening
  (§13.2 and the Status block at the top of `X4DH.md`), and the wire-key
  derivation (`X4DH.md` §16) is still accurate and still the right place
  for the cryptographic detail — `X4DH.md` remains authoritative there.
  What changed with this pass is that the wire-visible shapes and
  relay-visible behavior (the `session:propose`/`session:ack` packet types,
  their durable-buffering/overwrite treatment, and the per-device wire key
  as the thing that actually encrypts `app:message` traffic today) are now
  also written into `protocol.md` itself, per this project's
  documentation-discipline rule: a feature graduates out of Roadmap-only
  tracking once it's been witnessed firing correctly live and unprompted.
  The device registry's 30-day cutoff and periodic prune sweep
  (`pruneDeviceRegistry()`/`DEVICE_PRUNE_INTERVAL_MS`, described further
  down under Done) is documented the same way now, in `protocol.md`'s
  [Device Registry](protocol.md#device-registry) section.

- **X4DH root-key establishment is now fully automatic, both directions.**
  `maybeTriggerX4DHPropose` fires from `recordKnownDevice()` itself — no
  manual call needed anywhere — the instant the fixed-initiator side
  (§13.1) has a known `endpointId` for a device and no existing session
  with it yet (§13.3). Confirmed live and unprompted on meshdev for
  contact pairs (a brand-new pair, and a new device added to an already-
  established pair) and, separately, for self-pairs — `isFixedInitiator`'s
  `deviceId` tiebreak was implemented but untested when this cycle's own
  handoff was written; now confirmed via a sibling device discovering the
  other's endpoint through an ordinary self-chat message, with no manual
  call anywhere in the causal chain.
- **Two pieces of §13.2 replay/staleness hardening landed**, deliberately
  scoped to detection rather than retry (see the dropped-`session:ack` item
  under Planned, below, for what's still open). A stuck-at-RK0 detector
  (`checkStuckX4DHSessions`, hooked into `markOnline()`) flags a session
  sitting at RK0 past 2× the proposal timeout while presence confirms the
  peer is actually online — confirmed for both roles it covers: a
  manufactured stuck initiator session, and a genuine, unprompted stuck
  responder session hit during unrelated testing. A propose-freshness
  guard in `handleX4DHPropose` refuses a `session:propose` whose signed
  `ts` isn't strictly newer than the session's own stored `proposeTs`
  (compared sender-clock-to-sender-clock, not against the receiver's local
  clock, so ordinary skew can't read as a replay) — confirmed against a
  live forged-but-validly-signed stale propose, and again when that exact
  packet came back out of the relay's own durable buffer later.
- **Manual X4DH session-reset retry, confirmed live twice.**
  `retryX4DHPropose(contactId, theirDeviceId)` — a console-only helper, not
  wired into any automatic call site — re-runs `sendX4DHPropose` against a
  session already confirmed stuck at `RK0` by the existing detector,
  refusing outright if the session doesn't exist, isn't at `RK0`, or we're
  not the fixed initiator for the pair. This is the first real use of the
  "session bootstrap and session reset are the same mechanism" framing
  below — no new packet type or crypto construction needed, just
  permission to call the existing propose path a second time. Confirmed
  live against two independently-occurring (not manufactured) stuck
  sessions on meshdev; both re-established a fresh `sessionEpoch` and
  converged to `RK1` cleanly. A small per-device status dot was also added
  to the existing device popover (contact rows and the self row alike,
  since both go through the same `isFixedInitiator` machinery) —
  muted/blue/red/green for no-session / RK0-fresh / RK0-stuck / RK1, red
  threshold reusing `X4DH_STUCK_RK0_THRESHOLD_MS` verbatim so the UI can
  never silently disagree with the log-level detector.
- **`sync:backup_push` now buffers on missed live delivery** (`server.py`),
  closing a real data-loss gap: it was live-only (`sendSignal`, no
  relay-side buffer) with no retry, unlike the periodic full self-sync
  push. Concretely fixes `pushMiniBackup`'s one-shot-per-message sends
  silently vanishing if the sibling device was offline at that exact
  instant — previously the message would only ever arrive via the next
  10-minute periodic full push, and only then if the sibling happened to
  be online at that later moment either. Buffered at the same tier as
  `app:message` (buffer-on-miss only, no push-notify); deliberately not
  given `app:migrate`/`app:burn`'s "always buffer even when reached" tier
  or their overwrite-per-sender treatment — each push is scoped to one
  contact's slice, not an identity-wide fact, so overwriting by sender
  alone would silently drop every push but the last if several land while
  the recipient is offline. Implemented and syntax-validated; not yet
  independently confirmed live (no captured before/after test run yet).

- **Fixed: reactions silently disappearing on merge.** `mergeMessages`'
  `byId` dedup was positional last-write-wins (`for (const m of [...a,
  ...b]) if (m.id) byId[m.id] = m` — whichever copy landed later in the
  concatenated array won, full stop). Harmless for text/audio/image/system
  messages, since a given id's content there never changes after send —
  but `deriveReactionId(myPublicId, targetMsgId)` deliberately produces
  the *same* id across every state a (sender, target) pair can be in: a
  real emoji, a manual clear, and the RECEIVED auto-ack (`emoji: null`,
  fired automatically on decrypt+verify — see protocol.md's Delivery
  Acknowledgement section) all collide on one id by design, so an emoji
  change/clear replaces rather than duplicates on merge. That design was
  sound; the collision-resolution rule sitting on top of it wasn't. If a
  stale `emoji:null` auto-ack ever arrived at a `mergeMessages` call
  *after* a genuinely newer real reaction — a delayed live delivery, a
  peer/self backup push carrying an older snapshot, a multi-device
  fingerprint-mismatch resend — the old positional rule let the stale ack
  silently clobber the real reaction, with no error and no log line. Fix:
  `byId` collisions now resolve by `ts` (whichever action actually
  happened later in real time wins), not by which side of the merge
  concatenation the message happened to land on. No-op for
  immutable-content ids (same id always carries the same `ts` there), so
  applied unconditionally in the one shared dedup path rather than
  special-casing reactions out. See `meshchat-lib.js`'s `mergeMessages`
  comment and `protocol.md`'s [Message Merging](protocol.md#message-merging)
  section for the full writeup.
- X25519 static-static ECDH pairwise message encryption, replacing the old
  shared-AES-in-the-address scheme (breaking change, `0.4.0`)
- Burn notice (`app:burn`), two-gate confirmation UI, own buffer/TTL bucket
- WebRTC data-channel shell escalation for agent contacts (`shell:*`,
  `agent.py`, two-tier `CONTACTS`/`SHELL_CONTACTS` trust split)
- **Double Ratchet Phase 1 groundwork:**
  - per-(device, contact) send counters (`n`), excluding reactions
  - device registry upgraded to `{ lastSeen, lastN }` per device, with
    migration from the old bare-timestamp shape
  - passive gap/dupe/reorder detection, log-only (`mlog.debug`)
  - packet inspector (ⓘ) on every message bubble
- Edit-contact UI can now (un)set `contact.type` = agent after the fact
  (previously add-contact-only)
- `protocol.md` caught up to the above, plus a real drift fix: `deviceId`
  was documented as outer-envelope metadata but had already been moved
  inside the encrypted+signed payload in code — doc now matches reality
- **Push notifications (`0.4.1`)** — end to end: per-relay VAPID keypair
  generated on first boot, `sig:push_subscribe`/`sig:push_unsubscribe`,
  best-effort empty-payload pushes fired only on genuinely-offline
  `app:message` delivery, per-device opt-in checkbox (edit-contact panel,
  self only), browser subscribe/resubscribe handled uniformly through
  `ensurePushSubscription()` (including the post-migration VAPID-key
  mismatch case), and the service worker's generic `push`/
  `notificationclick` handling. Full detail lives in `protocol.md`'s
  [Push Notifications](protocol.md#push-notifications) section — no open
  design questions left on this one.
- **Message status — SEND / RECEIVED.** SEND was already implicit; RECEIVED
  is now live too, riding the existing reaction channel rather than a new
  packet type — `receiveMessage()` fires an auto-ack (`emoji: null`) back
  to the sender the moment a message both decrypts and verifies, and the
  sender flips that message's status to `delivered` on receipt. Rendered
  client-side as ✔️ (sent) / ✔️✔️ (delivered) / ✗ (failed). READ status is
  explicitly **not** part of this — see below, still deferred on purpose.
- **Causal message ordering — both slices done.** Slice 1: all four send
  paths (`sendMessage`, `sendAudioMessage`, `sendImageMessage`,
  `sendCallNotice`) now stamp `ackDeviceId`/`ackN` on outgoing
  text/audio/image/system payloads via `getAckPointer(contactId)` (reads
  the freshest usable entry straight off the existing device registry, no
  new storage), and both sides persist `deviceId`/`n`/`ackDeviceId`/`ackN`
  on the stored message object. Slice 2: `mergeMessages` (`meshchat-lib.js`)
  resolves a message's `ackDeviceId`/`ackN` against the merged set and
  splices it in directly after the message it references — recursively, so
  a reply-to-a-reply nests correctly — instead of trusting `ts`. Anything
  unresolvable (no ack fields, or a reference outside the merged set) keeps
  its place in the existing `(ts, id)` sort, unchanged. Deliberately not a
  full causal/vector-clock reorder — multiple acks on the same target keep
  their relative `(ts, id)` order rather than being further disambiguated,
  per the "reordering as the exception, not the norm" framing below.
  `protocol.md`'s [Message Merging](protocol.md#message-merging) and
  [Message Payload](protocol.md#message-payload) sections updated to match.
- **Endpoint-keyed offline buffer.** `server.py`'s `buf_write`/`buf_deliver`
  now support a per-`(publicId, endpointId)` bucket
  (`BUF_DIR/<publicId>/_endpoints/<endpointId>/`) alongside the existing
  identity-level one — the hard blocker flagged under per-device fanout
  below. A connection presenting `endpoint_id` at auth gets both buckets
  flushed; one that doesn't only ever gets the identity-level bucket, same
  as before this existed. Own rate limiter/lock per bucket, own
  `MAX_ENDPOINTS_PER_RECIPIENT` cap (default 20) independent of
  `MAX_BUF_RECIPIENTS`, own expiry sweep. `app:migrate`/`app:burn` never
  touch this — they aren't device-targeted and stay identity-level only.
  Dormant until something actually sets `toEndpoint` on a message that
  misses live delivery — see the next line for the first real consumer.
- **First real per-device fanout: self-sync backup targeting.**
  `sync:backup_push`/`sync:backup_accept` now carry `endpointId` (learned
  the same passive "only adopt an explicit value" way as the message path
  already does), and the relay honors `toEndpoint` on the shared
  `app:sync`/`sync:*`/`call:*`/`shell:*` delivery branch, not just
  `app:message`. `pushBackupToContacts`'s self branch went from "broadcast
  to every live self-session unless ALL of them are current" to targeting
  each individually-stale, endpoint-known sibling device directly, falling
  back to broadcast only for genuine discovery (no acks yet this session)
  or a stale device whose endpoint isn't known yet. Deliberately scoped to
  self-sync backup/restore only — the contact-facing `backup_offer`/
  `backup_accept`/`backup_push` path and the manual `app:sync` (SYNC
  button) exchange are untouched. See the "sync strategy needs a real
  rethink" note under Planned below — this slice was a deliberately narrow
  proof of per-device routing working end to end, not a sync-protocol
  redesign.

---

## Next up

Things with a rough shape already, not blocked on a bigger design call:

- **Keep `protocol.md` from drifting again.** No process yet beyond "notice
  it during unrelated work," which is how the `deviceId` envelope drift sat
  unnoticed for a while. Worth a lightweight habit at minimum (docs pass
  whenever a wire-format or storage-shape change lands), even without
  tooling.
- **Verify the epoch guard against a genuinely stale `session:ack` in
  practice, not just by code inspection.** `upgradeX4DHSessionToRK1`
  refuses to apply an ack whose `sessionEpoch` doesn't match the session's
  current one — this should mean a stale ack for a superseded epoch (e.g.
  the original far side's in-flight reply arriving late after a retry
  already re-proposed and moved the session on) is silently dropped rather
  than regressing anything. Worth deliberately producing this case (retry,
  then let the original ack arrive late) since it's cheap to check once
  the harness exists — distinct from, and not yet covered by, the
  exhausted-retry-budget re-arm gap tracked in `X4DH.md`'s own Status
  block.

---

## Planned — needs a design pass first

Real feature work, but each has an open question that needs deciding
before implementation starts, not just during it.

### READ status
- Deferred on purpose, separate from the now-shipped SEND/RECEIVED pass
  above — sensitive, opinions vary widely on whether/when it should even
  exist, not worth deciding under the same pass as RECEIVED
- Open question is as much product as protocol: per-conversation opt-out,
  or not implemented at all

### Device-layer routing — resolved, differently than originally framed
This item originally asked for routing addressed to a specific device via
`networkID::deviceID`, and flagged the real tension that would create:
`deviceId` lives *inside* the encrypted payload specifically so the relay
can't see or rewrite it, so routing by device would mean handing the relay
something it currently never sees. What actually shipped avoids that
trade-off entirely rather than accepting it: `endpointId` (see
`protocol.md`'s [Device Endpoint ID](protocol.md#device-endpoint-id)) is a
second, deliberately unlinkable identifier derived from the same device
seed, presented to the relay instead of `deviceId` — the relay learns only
which live socket to route to, never which physical device a contact would
recognise from their own device popover. Compound addressing
(`"id::endpointId"`, see `protocol.md`'s
[Compound Addressing](protocol.md#compound-addressing)) is live for
`app:message`, the `sync:*` self-targeting paths, and `session:propose`/
`session:ack`. This directly enabled the sync/backup device-smartness work
below — no further design pass needed on the routing mechanism itself.

### Passphrase KDF iteration count (PBKDF2 → possibly Argon2id)
- Flagged by external review: `masterSecret` derivation (see
  `protocol.md`'s Identity and Key Derivation) uses PBKDF2-HMAC-SHA256 at
  100,000 iterations. Current OWASP guidance for PBKDF2-HMAC-SHA256 is
  600k+ iterations — this sits well below that.
- Matters more than it might look at first glance: `publicId` is public
  by design (`SHA-256(x25519_pub || ed25519_pub)[0:12]`, shared freely in
  the shareable address), so given a known username an attacker already
  has a fast, fully offline verification oracle — derive candidate keys
  from a guessed passphrase, hash, compare against the known `publicId`
  — no captured ciphertext or network access required at all. Every
  forward-secrecy property X4DH/the ratchet ever provide is ultimately
  bounded by how expensive that oracle is to run at scale.
- Raising the iteration count alone is compatible with existing
  identities (same algorithm, more rounds) but still needs *some*
  migration story to actually take effect for already-created identities,
  not just new ones. Switching to Argon2id is a bigger lift — breaking,
  same blast radius as the 0.4.0 X25519 swap — and not a native WebCrypto
  primitive, unlike everything else in this codebase's crypto stack
  (would need a WASM dependency).
- Not urgent, not free — needs its own design pass on migration strategy
  before picking a direction. Deliberately kept separate from X4DH/
  ratchet work; the two are unrelated axes of the same broader "how
  strong are our guarantees really" question.

### Real per-message forward secrecy (the Double Ratchet, on top of X4DH)
This item used to be flagged as "the hardest open item" and framed as a
single big decision ("full per-device fanout vs. self-relays-to-self")
still to be made. That decision has effectively already been made and
shipped, just via a different route than originally pictured: X4DH session
establishment (`X4DH.md`) gives every device pair its own root key and its
own derived wire-message key (`protocol.md`'s
[Encryption](protocol.md#encryption) section), with graceful per-device
fallback to the legacy identity-level key — that *is* per-device
separation, Signal-shaped, without ever needing the "single device relays
to self" alternative. Several of the sub-items this section used to carry
forward are resolved along with it, not just theorized:
- **The offline buffer is device-keyed** — done. The endpoint-keyed buffer
  (`BUF_DIR/<publicId>/_endpoints/<endpointId>/`, see Done above and
  `protocol.md`'s [Offline Delivery](protocol.md#offline-delivery)) shipped
  ahead of and independent of the ratchet work, and X4DH's `session:propose`/
  `session:ack` already route and buffer through it.
- **Session bootstrap and session reset are the same mechanism** — done.
  `retryX4DHPropose` is exactly `sendX4DHPropose` called again against an
  already-established (but stuck) session; no separate reset packet type
  was needed.
- **Self-devices get a session too, no special-casing** — done. Self-pairs
  use the `deviceId` tiebreak (`X4DH.md` §13.1) instead of comparing
  `publicId` against itself, and are otherwise indistinguishable from any
  contact pair.
- **A dropped `session:ack` causing a silent 2DH downgrade** — no longer
  just detected, now also retried. `checkStuckX4DHSessions` flags it and
  `maybeAutoRetryX4DH` re-proposes automatically within a bounded budget
  (see Done and `X4DH.md`'s Status block). What's still genuinely
  unresolved: this is not closable against a relay that consistently and
  selectively drops the ack while otherwise behaving normally — no
  client-side signal distinguishes "genuinely offline" from "online, but
  the ack keeps vanishing," so a session under sustained selective
  interference can still exhaust its retry budget and stay stuck until a
  fresh online-transition re-arms it. That remains a
  `known-limitations.md`-shaped admission, not an implementation gap to
  close.

**What's actually still open, and still needs the dedicated deep-dive this
item originally asked for:** real per-message forward secrecy — a genuine
Double Ratchet layered on top of the root key X4DH now establishes.
`X4DH.md` §15/§16 are explicit that what ships today stops at a single
static wire key per session, not a ratchet; deriving symmetric send/recv
chain keys from `RK0`/`RK1` and stepping them per message (or per DH
ratchet turn) is genuinely not started. The competitive-research framing
still applies before committing to a shape — Signal Sesame, Matrix
Olm/Megolm, Session, and SimpleX pulled fresh rather than from memory —
since the relay's own "holds no prekey state" constraint diverges from
Signal's model and is worth weighing SimpleX/Session's server-holds-nothing
approach against at least as heavily as Signal's, rather than treating
Signal as the default to diverge from only where forced to. Two things
worth carrying into that session:
- **The `backupKey`-encrypted backup blob itself must not ratchet.** It
  needs to stay deterministic across every device holding the same
  passphrase — that determinism is what makes an exported backup file, or
  a freshly-recovered identity with no session state at all, restorable at
  all. What ratchets is the *transport* the already-encrypted blob rides
  inside, not the blob itself — same as how image/audio bytes already ride
  as opaque payload inside an ordinary `app:message` today.
- **`pushMiniBackup`'s purpose survives a ratchet, its plumbing doesn't.**
  It exists to keep siblings live-current after every outgoing message,
  not just periodically reconciled — worth keeping. It works today only
  because self-sync shares one static, coordination-free key across every
  device; a real per-message ratchet removes that coordination-free
  property. Once chain keys exist, mini-backup's payload just becomes
  whatever rides inside one, same as the full backup push. Bonus: self-sync
  packets carry no `sig` at all today (unlike `app:message`) — riding
  inside a real ratchet session fixes that for free, not as a separate
  task.
- **A worked Double Ratchet sketch matching this shape already exists**
  (from an external cross-model design discussion) — session state keyed
  by `(networkID, deviceID, sessionEpoch)`, a symmetric ratchet
  (`MK = HMAC(CK, "message")`, `CK' = HMAC(CK, "chain")`) with independent
  send/recv chains, and an 11-step DH-ratchet transition (reject stale
  `dhGen` → fold incoming DH into `RK` → reseed `CK_recv` → generate new
  local ephemeral → fold the complementary DH into `RK` → reseed `CK_send`
  → destroy the old ephemeral → advance `dhGen`) that deliberately doesn't
  disturb the old sending chain mid-transition. Textbook Signal-shape and
  consistent with everything landed so far — useful input for the
  competitive-research pass above, not a substitute for it, since Signal's
  is only one of the four systems that pass is meant to weigh.

### Sync / backup device-smartness (for later, no urgency)
- Self-device backup targeting is now done — see Done above. What's left
  here:
- Sync: when syncing a conversation (the manual `app:sync`/SYNC-button
  path), also check other-self devices, not just the other party
- Contact-facing backup (`backup_offer`/`backup_accept`/`backup_push`) has
  no device-targeting at all yet — still broadcasts to every live session
  under the contact's identity, same as before this pass
- Backup: if devices reliably merge first, a backup push might be able to
  go out as just "identity," with no contact-device specificity needed —
  **partially resolved above**: self-devices already get their own X4DH
  session like any other peer, so per-device addressing for self-sync is
  no longer a special case; whether that's enough to simplify backup
  distribution further still depends on the still-open Double Ratchet
  work above, not just the session-establishment piece that's already
  shipped

### Sync strategy — needs a real rethink, not just the dev2dev slice
Flagged explicitly during the self-device-backup-targeting session: the
whole sync story (manual `app:sync`, contact `backup_offer`/`accept`/
`push`, `restore_req`/`ack`/`push`, and now the self-device-targeted push
on top) has accreted piece by piece and deserves being looked at as one
system rather than patched incrementally forever. Not scoped yet — this is
a flag to come back to, not a plan. The self-device targeting slice above
was deliberately kept narrow (self-only, backup/restore only) specifically
so it wouldn't get tangled up with this larger question before the larger
question has actually been thought through.

---

## Ideas — not yet scoped

Lower-fidelity than "Planned" above — captured so they're not lost, not
because there's a plan yet.

### General plugin architecture (shell escalation as the worked example)
- Shell today is threaded through four places: `meshchat.js` (signaling,
  `shellConns`), `meshchat-gui.js` (terminal DOM), `statemachine.js` (the
  `kind: "shell"` fork), and `index.html` markup (button, panel). None of
  that is plugin-shaped yet — it's just the first agent-capable feature,
  hardcoded.
- A real plugin API needs hook points for at least: header-button
  registration (gated on `contact.type`), a state-machine "kind"
  registration instead of the hardcoded `call`/`shell` fork, and a
  message-render override (agent chats already render left-aligned with
  reactions suppressed — that's already a de facto per-type override,
  just not a general one).
- **Sub-question already sketched:** lazy-loading third-party plugin
  assets (xterm.js/xterm-addon-fit/xterm.css today are unconditional
  `<head>` tags everyone pays for, whether or not they ever touch shell).
  Answer sketched out: a small `assetLoader` (dedupes concurrent loads,
  ordered script loading, promise-based) triggered from the *action* that
  needs it (`startShell()`), not from app boot or even from adding an
  agent contact. Leaning self-hosted under `static/vendor/` over CDN —
  same lazy-load benefit either way, but avoids leaking "this identity
  uses shell" to a third party's request logs, which matters more here
  than it would in a typical app.
- Open: whether to scope a first pass as just the asset-loading slice
  (prove the lazy-load pattern against shell as-is), or go straight for
  the fuller manifest/hook-point design with shell as the reference
  implementation. Undecided — flagged in chat, not yet a decision.

---

## Deliberately not doing (yet or ever)

Carried over from `known-limitations.md` for visibility here too:

- No TURN server — permanent, not a gap to fill in
- No cryptographic identity revocation — burn is a social/local signal only
- READ receipts — deferred, not scheduled