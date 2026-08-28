# MeshChat — Roadmap

Working notes on what's done, what's next, and what still needs a real design
conversation before it gets touched. Not a promise of order or timing — just
so the list lives somewhere other than someone's head.

Current version: `0.4.5`. See `protocol.md` for the authoritative wire spec
and `known-limitations.md` for permanent, by-design tradeoffs (no TURN, no
real revocation, etc.) — those aren't roadmap items, they're not going to
change.

---

## Done

Recent, for context on where "next" picks up from:

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

### Device-layer routing (`networkID::deviceID`)
- Goal: routing addressed to a specific device, not just an identity,
  while keeping "no deviceID" as a valid per-identity local broadcast
- Real tension: `deviceId` currently lives *inside* the encrypted payload
  specifically so the relay can't see or rewrite it (deliberate fix, see
  `protocol.md`). Routing by device means the relay needs to know which
  device a socket represents before decryption — a small, deliberate step
  toward exposing device identity to relay infrastructure, at roughly the
  same metadata tier the relay already sees (`from`/`to` publicIds), just
  more granular
- Directly enables the sync/backup device-smartness ideas below

### Per-device encryption & relay-stored messages
- Flagged as the hardest open item, not a simple loose end
- Today's identity-level pairwise key means multi-device "just works" —
  every device re-derives the same ECDH secret independently
- Real forward secrecy (an actual ratchet) breaks that for free: a ratchet
  chain needs one authoritative sequence, and two devices of the same
  identity can't independently advance one chain without coordinating
  (same fork already noted in the `nextSendCounter` code comments)
- Two directions on the table:
  - **Full per-device fanout** (Signal's approach) — sender maintains a
    separate ratchet session per recipient device, no self-sync of crypto
    state needed, but N-way ciphertext fanout per message
  - Single-device-relays-to-self-via-existing-sync — architecturally
    cheaper, reuses Phase 1 self-sync machinery, but means one device
    holds plaintext on behalf of the others and gives up per-device
    forward secrecy
- **Agreed: full per-device fanout is the likely direction.** This gets
  its own dedicated deep-dive conversation before any of it starts —
  too large and too foundational to fold into general cleanup. Next
  session opens with competitive research first (Signal Sesame, Matrix
  Olm/Megolm, Session, SimpleX — current specifics pulled fresh rather
  than from memory) to feed that conversation rather than run parallel
  to it. Signal's own model assumes a server willing to hold prekey
  state, which the relay deliberately doesn't do — worth weighing
  SimpleX/Session's server-holds-nothing constraints at least as
  heavily as Signal's, rather than treating Signal as the default
  answer to diverge from only where forced to.

  **Two things carried forward from an earlier chat, not yet decided,
  just flagged so they aren't lost before that session starts:**
  - **The offline buffer must become device-keyed before fanout ships —
    this is a hard blocker, not a nice-to-have.** `buf_dir`/`buf_write`/
    `buf_deliver` in `server.py` are identity-level today, which is fine
    under the current static pairwise key (any device sharing the seed
    can decrypt whatever's buffered). It stops being fine under a real
    ratchet: a fanned-out ciphertext is bound to one specific device's
    chain, so a buffered packet handed to whichever device reconnects
    first is either undecryptable by that device or never reaches the
    one it was actually meant for. The `endpointId` plumbing (see
    `protocol.md`'s [Device Endpoint ID](protocol.md#device-endpoint-id))
    makes the mechanical part straightforward when it's time — keying
    `BUF_DIR` by `(publicId, endpointId)` instead of just `publicId` —
    but it needs to land as part of this work, not after.
  - **Session bootstrap and session reset are likely the same
    mechanism, not two.** Bootstrapping a never-before-seen device and
    recovering a desynced/corrupted session with a known device both
    reduce to "agree a fresh root key with this specific endpoint,
    discarding whatever chain state exists" — bootstrap is just the
    case where that state happens to be empty. Leaning toward one
    signed "propose new root key" packet type for both, mandatory
    signature (same trust tier as `app:migrate`/`app:burn` — this
    drives crypto state, not just display), with the manual "accept
    this device?" confirmation gating only the *never-seen-endpoint*
    case — resetting an already-trusted endpoint's session likely
    doesn't need the same friction, though it should still be visible
    (log line / quiet system notice) rather than silent. Detection of
    "this session needs a reset" (repeated AEAD failures, skipped-key
    cache overflow) probably wants to surface a prompt rather than
    auto-fire, at least until there's real usage data on false-positive
    rate. Design bootstrap and reset together — don't build bootstrap
    first and bolt reset on as an afterthought.
  - **Self-devices get a ratchet session too, same as any other
    peer — no special-casing.** Resolved during the self-device-backup-
    targeting session: self was never special-cased for encryption
    (`X25519(myPriv, myPub)` just falls out of the general pairwise ECDH
    function — see [Encryption](protocol.md#encryption)), and there's no
    reason the ratchet should be different. Each pair of a user's own
    devices establishes its own session exactly like a session with a
    contact would. This directly answers the open question under "Sync /
    backup device-smartness" below about what happens to self-sync once
    device-layer routing lands: it stops being a special case entirely.
    Two consequences worth carrying forward to that design session:
    - **The `backupKey`-encrypted backup blob itself does NOT ratchet.**
      It stays deterministic across every device holding the same
      passphrase, on purpose — that determinism is what makes an
      exported backup file, or a freshly-recovered identity with no
      session state at all, restorable in the first place. Ratcheting it
      would break that property for no gain. What ratchets is the
      *transport* the already-encrypted blob rides inside — the blob
      becomes opaque payload inside a per-device-pair session, the same
      way image/audio bytes already ride as opaque payload inside an
      ordinary pairwise `app:message` today.
    - **`pushMiniBackup`'s purpose survives, its plumbing doesn't.** It
      exists to keep siblings live-current on conversation after every
      outgoing message, not just periodically reconciled — a real need,
      worth keeping. But it works today only because self-sync shares one
      static, coordination-free key across every device; that's exactly
      the property a real ratchet removes. Once per-device sessions
      exist, mini-backup's payload just becomes whatever rides inside
      one, same as the full backup push above. Bonus: self-sync packets
      carry no `sig` at all today (unlike `app:message`) — riding inside
      a real ratchet session fixes that for free, not as a separate task.

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
  **resolved above**: self-devices get their own ratchet sessions like any
  other peer, so this stops being a special case once that work lands

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