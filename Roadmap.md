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

Full writeups for graduated work now live in `CHANGELOG.md` (what shipped,
by version) and `protocol.md`/`X4DH.md` (the current spec itself). This
section only keeps what isn't fully captured there yet, or context specific
to what "next" picks up from:

- Reaction/ack fanout narrowed to the single target device (`resolveReactionTarget`)
  — confirmed live. See `protocol.md`'s [Delivery Acknowledgement](protocol.md#delivery-acknowledgement-received).
  **Still open**: pull `server.py`'s `STATS` log (`buf_rate_rejected`/
  `buf_cap_rejected`/`buf_endpoint_cap_rejected`) to see how much of the
  original throughput pressure this alone accounted for, before deciding
  whether server-side limits still need raising.
- X4DH session establishment, per-device wire encryption, automatic
  bootstrap/retry, and tightened device registry retention — all confirmed
  live. See `CHANGELOG.md`'s `0.5.0` entry, `protocol.md`, and `X4DH.md`'s
  Status block (which remains authoritative for the crypto detail).
- Per-device X4DH status dot on the device popover (contact rows and self
  row alike) — muted/blue/red/green for no-session / RK0-fresh / RK0-stuck
  / RK1, threshold shared verbatim with `checkStuckX4DHSessions` so the UI
  can never disagree with the log-level detector. UI-only, not covered
  elsewhere in the docs.
- **`sync:backup_push` now buffers on missed live delivery** (`server.py`)
  — implemented and syntax-validated, closing a real data-loss gap in
  `pushMiniBackup`'s one-shot sends. **Not yet independently confirmed
  live** — no captured before/after test run yet. Once confirmed, this
  moves to `CHANGELOG.md`/`protocol.md` like everything else above.
- Fixed: reactions silently disappearing on merge (`mergeMessages`' `byId`
  dedup resolves by `ts` now, not array position) — see `protocol.md`'s
  [Message Merging](protocol.md#message-merging).
- X25519 static-static ECDH pairwise encryption, burn notice, WebRTC shell
  escalation for agent contacts, Double Ratchet Phase 1 groundwork (send
  counters, device registry upgrade, passive gap detection, packet
  inspector), push notifications, SEND/RECEIVED message status, causal
  message ordering, and the endpoint-keyed offline buffer — all shipped
  and documented; see `CHANGELOG.md` for which version each landed in and
  `protocol.md` for current behavior.

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