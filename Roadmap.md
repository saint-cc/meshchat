# MeshChat — Roadmap

Working notes on what's done, what's next, and what still needs a real design
conversation before it gets touched. Not a promise of order or timing — just
so the list lives somewhere other than someone's head.

Current version: `0.4.0`. See `protocol.md` for the authoritative wire spec
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

---

## Next up

Things with a rough shape already, not blocked on a bigger design call:

- **Causal message ordering.** Use the `n`/device-registry groundwork from
  Phase 1 to insert messages correctly instead of relying on `ts` (which
  drifts across devices/network delay). Likely shape: payload carries
  `ackDeviceId`/`ackN` — "the last (device, n) I'd seen from you when I sent
  this" — and merge inserts relative to that reference when present, falling
  back to today's `(ts, id)` sort otherwise. Turns sync closer into
  fetch-missing + dedupe, with reordering as the exception, not the norm.
- **Keep `protocol.md` from drifting again.** No process yet beyond "notice
  it during unrelated work," which is how the `deviceId` envelope drift sat
  unnoticed for a while. Worth a lightweight habit at minimum (docs pass
  whenever a wire-format or storage-shape change lands), even without
  tooling.

---

## Planned — needs a design pass first

Real feature work, but each has an open question that needs deciding
before implementation starts, not just during it.

### Push notifications
- Checkbox, opt-in, not silent
- Per-relay VAPID keypair, generated once on relay boot and persisted —
  same pattern as the device seed. No manual coordination needed between
  relay operators; each browser's push subscription is bound to whichever
  relay's public key it subscribed with, so this is fully automatable
- Payload content: relay can't decrypt, so no message content either way.
  Open question is whether to distinguish packet *kind* (message vs.
  incoming call) in the payload, or keep it fully generic ("tap to check")
  and let the woken app handle the specifics through normal signaling.
  Leaning toward generic-for-now — avoids committing to new wire metadata
  before there's a proven need
- New pieces needed: persistent subscription store server-side (separate
  from the ephemeral offline buffer), resubscribe step on relay migration,
  fanout across a person's multiple devices (subscriptions are
  per-browser-instance; ties into the device-layer work below)

### Message status (SEND / RECEIVED)
- SEND is already implicit (message left the socket)
- RECEIVED needs a small signed ack packet, mirrors the reaction/`call:*`
  packet pattern already in place
- Open question: does RECEIVED fire automatically on successful
  decrypt+verify, or is there a reason to hold it back — and what
  "received" even means once a message has landed on one of a person's
  several devices but not the others (see device-layer routing below)
- **READ status is explicitly deferred** — sensitive, opinions vary
  widely, not worth deciding under the same pass as RECEIVED

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
  too large and too foundational to fold into general cleanup

### Sync / backup device-smartness (for later, no urgency)
- Sync: when syncing a conversation, also check other-self devices, not
  just the other party
- Backup: if devices reliably merge first, a backup push might be able to
  go out as just "identity," with no contact-device specificity needed —
  worth revisiting once the device-layer routing question above is
  settled, since it changes what's possible here

---

## Deliberately not doing (yet or ever)

Carried over from `known-limitations.md` for visibility here too:

- No TURN server — permanent, not a gap to fill in
- No cryptographic identity revocation — burn is a social/local signal only
- READ receipts — deferred, not scheduled