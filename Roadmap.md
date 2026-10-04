# MeshChat — Roadmap

Working notes on what's done, what's next, and what still needs a real design
conversation before it gets touched. Not a promise of order or timing — just
so the list lives somewhere other than someone's head.

Current version: `0.5.5` (client `CLIENT_VERSION` and relay `PROTOCOL_VERSION`
both). `0.5.0`'s X4DH session-establishment work — root-key bootstrap/upgrade,
per-device wire encryption, the tightened device registry retention — graduated
into `protocol.md` once it had been witnessed firing correctly live and
unprompted. `X4DH.md` remains the authoritative document for the cryptographic
design and for the live-confirmation status of pieces still in progress
(automatic retry's exhausted → re-armed transition, etc.); `protocol.md` only
carries wire shapes and relay-visible behavior, not the DH derivations.

The `0.5.3`–`0.5.5` work (see `CHANGELOG.md`) is implemented and being exercised
on meshdev. Per this project's documentation discipline it stays listed under
"Implemented in 0.5.5, awaiting live confirmation" below until each piece has
been seen working live; only then does it move into `protocol.md`.

See `protocol.md` for the authoritative wire spec and `known-limitations.md`
for permanent, by-design tradeoffs (no TURN, no real revocation, etc.) —
those aren't roadmap items, they're not going to change.

---

## Done

Full writeups for graduated work now live in `CHANGELOG.md` (what shipped,
by version) and `protocol.md`/`X4DH.md` (the current spec itself). This
section only keeps what isn't fully captured there yet, or context specific
to what "next" picks up from:

- X4DH session establishment, per-device wire encryption, automatic
  bootstrap/retry, and tightened device registry retention — all confirmed
  live. See `CHANGELOG.md`'s `0.5.0` entry, `protocol.md`, and `X4DH.md`'s
  Status block (which remains authoritative for the crypto detail).
- Per-device X4DH status dot on the device popover (contact rows and self
  row alike) — muted/blue/red/green for no-session / RK0-fresh / RK0-stuck
  / RK1, threshold shared verbatim with `checkStuckX4DHSessions` so the UI
  can never disagree with the log-level detector. UI-only, not covered
  elsewhere in the docs.
- Fixed: reactions silently disappearing on merge (`mergeMessages`' `byId`
  dedup resolves by `ts` now, not array position) — see `protocol.md`'s
  [Message Merging](protocol.md#message-merging).
- PBKDF2 iteration count raised from 100,000 to 1,000,000 (`0.5.2`), as a
  hard cutover. What's still open about the KDF is under Planned, below.
- X25519 static-static ECDH pairwise encryption, burn notice, Double Ratchet
  Phase 1 groundwork (send counters, device registry upgrade, passive gap
  detection, packet inspector), push notifications, SEND/RECEIVED message
  status, causal message ordering, and the endpoint-keyed offline buffer —
  all shipped and documented; see `CHANGELOG.md` for which version each
  landed in and `protocol.md` for current behavior. (WebRTC shell escalation
  for agent contacts shipped in `0.3.6` and was removed again in `0.5.5`.)

**Correction to earlier versions of this file:** this section used to list
"reaction/ack fanout narrowed to the single target device
(`resolveReactionTarget`) — confirmed live". That was never true of the code;
see "Targeted RECEIVED acks" under Planned. It also listed
`sync:backup_push` buffering on missed live delivery as implemented but
unconfirmed; that was reverted in `0.5.5` (see `CHANGELOG.md`).

### Implemented in 0.5.5, awaiting live confirmation

Nothing below has been independently confirmed live as of this update — all of
it is reasoned-not-observed until a test run says otherwise. Each line says what
would confirm it; move it to `CHANGELOG.md`/`protocol.md` once witnessed.

- **Self-sync mirroring (`selfsync`).** Send from device A while sibling B is
  offline: B gets its own per-endpoint buffered copy on reconnect (relay log:
  `BUF write … endpoint=…`), two offline siblings both receive it, and no push
  fires for it.
- **Self-backup under session keys + discovery hello.** A full push to a sibling
  with a session logs `targeted, session key`; a sibling with no session yet gets
  only the content-free hello, and the self X4DH session bootstraps afterwards.
- **Self `restore_push` wrap.** A wiped device restoring from its own sibling
  logs `+wrap` on both sides.
- **One-to-one handshake replies.** On an identity running two devices, backup
  and restore cycles stop producing `wrap present but no pending ephemeral` /
  `unwrap failed` for replies that were addressed to a sibling. Residual
  `unwrap failed against N candidate(s)` is only expected on the bare-fallback
  paths (unverified/fresh sender, the bootstrap ping).
- **Manual SYNC, new form.** Request → wrapped reply, one-directional, `+wrap`
  in the log; a legacy plaintext sync is dropped.
- **Push keyed by `endpointId`.** `PUSH_SUB subscribed` logs the endpoint, and an
  old `<deviceId>.json` for the same browser is dropped as a stale duplicate.
- **Data-channel test.** Accept → ping/pong → RTT toast; decline, cancel and both
  timeouts behave; nothing auto-accepts.
- **Contacts-only peer backups.** A restore from a peer's copy logs
  `+N contacts +0 msgs`.
- **`sync:backup_push` not buffered.** A push to an offline target leaves no file
  in `relay_buf`.

---

## Next up

Things with a rough shape already, not blocked on a bigger design call:

- **Keep `protocol.md` from drifting again.** Still no process beyond "notice
  it during unrelated work", and the `0.5.5` docs pass showed how much that
  misses: a `resolveReactionTarget` the docs described but the code never had, a
  `sig:auth_challenge` row describing an encrypted nonce the relay no longer
  sends, server config variables missing from the config table, and stray `\1`
  characters (an apparent sed backreference accident) that swallowed text — and
  at least one heading — in `protocol.md`, `X4DH.md` and `known-limitations.md`.
  A docs pass whenever a wire-format or storage-shape change lands is still the
  minimum habit; a cheap grep for stray `\1`, and for function names the docs
  mention that no longer exist in the code, would have caught most of this.
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
below — no further design pass needed on the routing mechanism itself. Since `0.5.5` the same mechanism also carries the one-to-one
handshake replies and the `selfsync` mirror copies.

### Passphrase KDF (PBKDF2 → possibly Argon2id)
- Iteration count raised from 100,000 to 1,000,000 in `0.5.2`, following
  external review (OWASP guidance for PBKDF2-HMAC-SHA256 was 600k+), as a hard
  cutover: no dual-version detection, no migration path — the earlier
  C64/AES128 key migration was painful enough to rule that out. See
  `CHANGELOG.md`.
- Why this matters more than it might look: `publicId` is public by design
  (`SHA-256(x25519_pub || ed25519_pub)[0:12]`, shared freely in the shareable
  address), so given a known username an attacker already has a fast, fully
  offline verification oracle — derive candidate keys from a guessed
  passphrase, hash, compare against the known `publicId` — no captured
  ciphertext or network access required at all. Every forward-secrecy property
  X4DH/the ratchet ever provide is ultimately bounded by how expensive that
  oracle is to run at scale. More iterations raise the per-guess cost; they
  don't make it memory-hard.
- What's still open: whether to move to Argon2id at all. It would be breaking
  again (same blast radius as `0.4.0` and `0.5.2`) and isn't a native WebCrypto
  primitive, unlike everything else in this codebase's crypto stack — it would
  need a WASM dependency. Not urgent, not free; needs its own design pass.
  Because any such change is another hard cutover, it's worth weighing
  against batching with any other identity-derivation changes rather than
  doing it alone. Deliberately kept separate from X4DH/ratchet work; the two
  are unrelated axes of the same broader "how strong are our guarantees
  really" question.

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
- **Self-sync mirroring needs no special plumbing under a ratchet.**
  `pushMiniBackup` was retired in `0.5.5`: mirrored copies of our own outgoing
  messages now travel as ordinary `selfsync` `app:message`s over the per-device
  fanout, so a ratchet covers them exactly as it covers any message. What it
  leaves open is the periodic **full** self-backup, still its own handshake
  (`sync:backup_push`, self path), encrypted per sibling under the static X4DH
  wire key where a session exists — that path will need its own answer once
  chain keys exist.
- **Self-sync backup packets still carry no `sig`** (the `selfsync` messages
  do — they're ordinary signed `app:message`s). Riding inside a real ratchet
  session would fix that for the full-backup path too, not as a separate task.
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

### Targeted RECEIVED acks (not done — earlier docs said it was)
- `protocol.md`'s Delivery Acknowledgement section and the `0.5.0` changelog
  entry described a `resolveReactionTarget` that routes the RECEIVED auto-ack to
  the single originating device instead of fanning to every known one. It was
  never in the code: `sendReaction` sends every reaction — manual and auto —
  through the same `sendFannedX4DH` fanout as an ordinary message (one auto-ack
  was observed fanned to 6 targeted devices plus the broadcast fallback for a
  single contact). The docs are being corrected; this item tracks whether to
  actually build it.
- The M×N ack multiplication it was meant to fix is a real, correctness-shaped
  cost — raising server rate-limit constants would only defer it — so it's
  still worth doing, but not by itself. Targeting only the originating device
  would leave the sender's *other* devices showing "sent" forever, since nothing
  else flips their delivery status. The inline comment in `sendReaction` says
  exactly this.
- Needs pairing with the self-sync mirror: auto-acks are deliberately excluded
  from `selfsync` today (`isAuto`), so the pairing means deciding how a
  delivery-status flip reaches sibling devices — mirror the ack itself, or
  mirror just the status change.
- Before deciding, pull `server.py`'s `STATS` log (`buf_rate_rejected`/
  `buf_cap_rejected`/`buf_endpoint_cap_rejected`) to see how much throughput
  pressure ack fanout actually accounts for.

### Sync / backup device-smartness (for later, no urgency)
- Self-device backup targeting is done, and as of `0.5.5` so is moving self-sync
  content onto per-device X4DH keys (see Done and `CHANGELOG.md`). What's left:
- Sync: manual `app:sync` is now an encrypted, signed, one-directional
  request/reply (see `CHANGELOG.md`), but it still only talks to the other
  party — also checking other-self devices when syncing a conversation remains
  open
- Contact-facing backup: the opening `backup_offer` still broadcasts to every
  live session under the contact's identity, but as of `0.5.5` the
  `backup_accept` and `backup_push` replies are one-to-one (compound-addressed at
  the verified sender's endpoint). The remaining broadcast is the offer itself;
  device-targeting it is an optimisation now, not a correctness need
- Backup: the old idea that a push might go out as just "identity" once devices
  reliably merge first is resolved differently — contact backups are
  contacts-only, and self-sync content travels as `selfsync`. Whether that
  simplifies backup distribution further still depends on the open Double
  Ratchet work and on the self-to-self backup question under "Sync strategy"

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


`0.5.5` took a first, deliberately narrow step: backups to contacts carry
contacts only, backup pushes are online-only again, and self-to-self message
traffic moved off the backup path onto the normal per-device message path
(`selfsync`). That is a split of jobs, not the rethink — manual `app:sync`,
`backup_offer`/`accept`/`push`, `restore_req`/`ack`/`push`, the restore token and
the self-backup hello are all still separate, accreted mechanisms. Still open,
and meant to be worked out together: whether self-to-self backups keep carrying
messages (wrapped), and how RESTORE relates to the wrap and X4DH options. Not
scoped yet.

---

## Ideas — not yet scoped

Lower-fidelity than "Planned" above — captured so they're not lost, not
because there's a plan yet.

### General plugin architecture (agent/shell as the eventual first plugin)
- Agent contacts, the bounded command whitelist and shell escalation were
  removed in `0.5.5`: shell was only ever a test of the WebRTC data channel, and
  it was threaded through four places (signaling, terminal DOM, the state
  machine fork, `index.html` markup) as hardcoded first-feature code, not
  anything plugin-shaped. The idea is to bring them back later as a plugin
  instead of as core. What stays in core is the data channel itself (`data:*`,
  the connection test).
- A real plugin API needs hook points for at least: header-button registration
  (`callBtn`/`dataBtn` are hardcoded today), a state-machine "kind"
  registration instead of the hardcoded `call`/`data` fork in `transition()`/
  `onStateEnter`, and packet-type registration in the signal dispatcher
  (`handleSignal` is a plain switch). The old "message-render override" hook is
  moot with agent chats gone; revisit if a plugin needs it.
- **Sub-question, still applicable:** lazy-loading third-party plugin assets.
  xterm.js used to be three unconditional `<head>` tags everyone paid for;
  they went away with shell, so nothing loads eagerly today — the question
  returns with the first plugin that has assets. Answer sketched: a small
  `assetLoader` (dedupes concurrent loads, ordered script loading,
  promise-based) triggered from the *action* that needs it, not from app boot or
  from adding a contact. Leaning self-hosted under `static/vendor/` over CDN —
  same lazy-load benefit either way, but it avoids leaking "this identity uses
  X" to a third party's request logs, which matters more here than it would in
  a typical app.
- Open: whether to scope a first pass as just the asset-loading slice, or go
  straight for the fuller manifest/hook-point design with the returning plugin
  as the reference implementation. Undecided.

### Agent access without a full client (a MeshChat skill/tool)
- Idea, not yet built: a lightweight skill/tool (e.g. a `SKILL.md`) that
  lets an agent act as a MeshChat contact directly — derive keys, run the
  auth handshake, encrypt/decrypt, send — without pulling in the full JS
  client (WebRTC, multi-device sync, X4DH session bookkeeping, UI). The
  core crypto (PBKDF2/HKDF, X25519, Ed25519, AES-GCM) is all standard
  primitives, so a minimal implementation is plausible; it just wouldn't
  get X4DH's per-device forward secrecy for free and would likely fall
  back to the legacy pairwise key (see `protocol.md`'s Encryption section).
- Distinct from, and doesn't depend on, the agent-contact mechanism that used to
  exist (bounded command whitelist + shell escalation, removed in `0.5.5` — see
  `CHANGELOG.md`). That was a real client talking to another real client. This
  idea is about an agent *being* the client, with no GUI at all.
- Agent-to-agent messaging would fall out of this for free, since the
  protocol draws no distinction between a human's device and an agent's
  one — not tested, not a current goal, just a consequence of the design
  if the skill ever gets built.
- Currently just README/marketing framing; no design pass has started.

---

## Deliberately not doing (yet or ever)

Carried over from `known-limitations.md` for visibility here too:

- No TURN server — permanent, not a gap to fill in
- No cryptographic identity revocation — burn is a social/local signal only
- READ receipts — deferred, not scheduled