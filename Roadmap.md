# MeshChat — Roadmap

Working notes on what's done, what's next, and what still needs a real design
conversation before it gets touched. Not a promise of order or timing — just
so the list lives somewhere other than someone's head.

Current version: `0.4.2`. See `protocol.md` for the authoritative wire spec
and `known-limitations.md` for permanent, by-design tradeoffs (no TURN, no
real revocation, etc.) — those aren't roadmap items, they're not going to
change.

---

## Done

Recent, for context on where "next" picks up from:

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

### Sync / backup device-smartness (for later, no urgency)
- Sync: when syncing a conversation, also check other-self devices, not
  just the other party
- Backup: if devices reliably merge first, a backup push might be able to
  go out as just "identity," with no contact-device specificity needed —
  worth revisiting once the device-layer routing question above is
  settled, since it changes what's possible here

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

### Account-based key layer on top of the deterministic bootstrap
- **Not a plan to replace deterministic identity.** The `(username,
  passphrase)` derivation stays permanently — it's the root of trust for
  routing/discovery and the only thing that lets a brand-new node
  bootstrap a DH exchange with someone at all. This idea is a layer
  *on top*: an actual random (non-derivable) account keypair, generated
  once, local-only, never in backups (backups can genuinely never
  contain it — if it's lost, the answer is renegotiate, not restore).
  Static/no-ratchet for now, same as today's pairwise key — the point
  isn't forward secrecy yet, it's making the *identity* key rotatable
  instead of eternally re-derivable from credentials, which is what
  actually unlocks real revocation (burn stops being social-only).
- Shape is structurally close to X3DH's identity-key/signed-prekey split:
  the deterministic bootstrap key plays "identity key" (never rotates,
  already trusted via the out-of-band QR/address exchange), the account
  key plays "signed prekey" (rotates, and every rotation is *signed by*
  the bootstrap key that vouches for it) — so a renegotiation packet is
  a signed statement from an already-trusted key, not fresh DH exposed
  to MITM. The real exposure isn't the crypto, it's (a) replay/rollback
  of an old-but-validly-signed rotation, which needs a strict monotonic
  epoch guard, stricter than `updateRelay`'s plain "newer wins", and
  (b) the human "accept this?" confirmation itself, which is a social-
  engineering target the same way Signal's safety-number-changed prompt
  is — load-bearing, same as the never-seen-device confirmation already
  planned for Double Ratchet bootstrap.
- **Renegotiation has to be async/store-and-forward**, not a live
  handshake — the relay deliberately holds no prekey-bundle state the
  way a real X3DH server would. Closest existing pattern is
  `app:migrate`/`app:burn`: overwrite-per-sender, long TTL, durably
  buffered even when a live session is reached (same stale-session race
  those two already guard against). "Fail" (an AEAD decrypt failure) is
  a reasonable *technical* trigger to prompt a user but must NOT be
  sufficient on its own to accept a new key — indistinguishable from
  ordinary corruption/desync, and accepting on decrypt-failure alone is
  a remotely-triggerable identity-swap primitive. Needs its own
  independent authentication step, not "then whatever key shows up
  next is trusted."
- **Multi-device forks this hard.** Deterministic identity is what lets
  a second device "just log in" and land on the same keys today; a
  random account key can't be independently re-derived, so multi-device
  needs an explicit pairing/transfer step instead. Two of the user's own
  devices independently deciding they're the "fresh node" and each
  proposing a new account key could genuinely fork what contacts believe
  the current key is — same class of race as `call:claim`'s self-
  targeted dedup echo, but identity-critical instead of cosmetic where
  that one is cosmetic.
- **Likely the same design conversation as device-layer routing, not a
  separate one** — see [Per-device encryption & relay-stored
  messages](#per-device-encryption--relay-stored-messages) above. An
  account key that ends up per-device (which multi-device pushes it
  toward) is close to what `endpointId` becomes the moment it stops
  being routing-only metadata and starts being a real keypair. Device
  routing is agreed to ship first regardless.
- **"Triple ratchet" — deliberately not scoped, flagged half-joking in
  chat but worth keeping on file:** a third tier stacked on top of the
  usual two (identity/account-key rotation below, Signal-style session
  ratchet above) rather than the unrelated "add a post-quantum KEM
  ratchet alongside classic DH" meaning the term has elsewhere. Same
  underlying problems as everything above, just a third rotation cadence
  — nothing to design until the layers below it are real.
- **Status: prep-only for the foreseeable future, not scheduled.** Real
  blockers exist ahead of it (device routing chief among them). The
  point of writing this down now is to have somewhere for the half-formed
  version of this thinking to live, not to imply it's next.

---

## Deliberately not doing (yet or ever)

Carried over from `known-limitations.md` for visibility here too:

- No TURN server — permanent, not a gap to fill in
- No cryptographic identity revocation — burn is a social/local signal only
- READ receipts — deferred, not scheduled