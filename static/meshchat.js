/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat.js  (formerly script.js)
   Core client: `state`, WebSocket/relay plumbing, the protocol
   handlers (messages, migrate, burn, calls, data sessions,
   sync/backup), and the crypto functions that reach into `state`
   directly (decryptMessage, signBlob — see lib.js for their
   stateless counterparts, decryptObject/verifyBlob etc.).

   pid(id) — trims a publicId to 8 chars for display. Lives in
   lib.js since it's pure, but used constantly below.
   NOTE: deliberately NOT named short() to avoid collision with
         the url-truncation var in lib.js's linkify().

   Load order: meshchat-lib.js → meshchat-gui.js → meshchat.js → statemachine.js
═══════════════════════════════════════════════════════════════ */
const CLIENT_VERSION = "0.5.9";

const POLL_INTERVAL_MS        	= 30_000;			// base interval between presence polls
const POLL_JITTER_MS          	= 10_000;			// ± random jitter added to poll interval
const PRUNE_INTERVAL_MS       	= 30_000;			// how often to sweep expired online entries
const BACKUP_INTERVAL_MS      	= 10 * 60 * 1000;	// periodic backup + restore-request sweep
const WS_RECONNECT_MS         	= 3_000;			// delay before reconnecting signal websocket
const RELAY_CONNECT_TIMEOUT_MS 	= 5_000;			// max wait for relay websocket to open
const RELAY_RECONNECT_MS      	= 5_000;			// delay before reconnecting a persistent relay
const RESTORE_COOLDOWN 			= 5 * 60 * 1000;
const BACKUP_THRESHOLD  		= 2;
const BACKUP_OFFER_TTL   		= 60_000;
const RELAY_IDLE_MS  			= 30_000;
const RETENTION_COUNT 			= 15;   			// per-contact local persistence cap — see selectRetainedMessages
const X4DH_PROPOSAL_TIMEOUT_MS 	= 60_000;			// how long EK_A_priv is held awaiting session:ack — see X4DH.md §7.1

/* ══════════════════════════════════════════
   DEVICE REGISTRY — retention tuning
   Was 90 days / 20 devices, checked only inside loadDeviceRegistry()
   (i.e. once, at login). In practice a contact's registry can grow well
   past the cap mid-session — every app:message receipt and every
   self-sync accept/push calls recordKnownDevice(), which writes
   unconditionally and never trims — so a chatty session (or a contact
   who churns through one-off/incognito devices that never reconnect)
   could badly overshoot 20 entries for hours before the next reload
   ever swept it back down.
   Lowered to 30 days (devices that vanish — incognito windows, etc. —
   were sitting in the list for a full quarter before aging out, well
   past the point they were ever useful) and now enforced periodically
   via pruneDeviceRegistry()/DEVICE_PRUNE_INTERVAL_MS below, not just at
   load. Deliberately independent of FANOUT_STALE_MS (7 days, further
   down) — that one governs whether a device still gets its own X4DH-
   targeted send; this one governs whether it's kept in the registry at
   all. A device can fall out of fanout-freshness (7d) well before it's
   actually pruned from the list (30d) — that's intentional, not a bug
   to reconcile: fanout staleness is about not wasting a targeted
   encrypt+send on a probably-dead device, while registry retention is
   about not letting the popover/storage grow unbounded. The two don't
   need to share a number.
══════════════════════════════════════════ */
const DEVICE_REGISTRY_CUTOFF_MS  = 30 * 24 * 60 * 60 * 1000;   // was 90 days
const MAX_DEVICES_PER_IDENTITY   = 20;
const DEVICE_PRUNE_INTERVAL_MS   = 10 * 60 * 1000;   // periodic sweep, piggybacked on its own timer rather than only running at login

/* ══════════════════════════════════════════
   STATE
══════════════════════════════════════════ */
const state = {
  user: null, publicId: null, shareableKey: null,
  keys: null, cryptoKey: null, encKey: null,
  contacts: {}, peerBackups: {}, peerTokens: {}, knownDevices: {}, sendCounters: {},
  currentChat: null, ws: null, online: new Set(),
  unread: {}, knownDeviceFingerprints: {},
  // vapidPublicKey — this relay's VAPID public key, from the most recent
  // sig:relay_info. pushSyncedRelayWss — the wss URL we've already sent
  // sig:push_subscribe to THIS session; lets ensurePushSubscription()
  // skip resending on every ordinary reconnect to the same relay, while
  // still firing again automatically after a migration (new relay = new
  // key = mismatch against this).
  vapidPublicKey: null, pushSyncedRelayWss: null,
  // endpointId — separate HKDF derivation off the same device seed as
  // deviceId, deliberately unlinkable from it. See deriveDeviceEndpointId
  // (lib.js) and getOrCreateDeviceSeed below. Local-only until presented
  // to the relay at auth time (sig:auth_init) and, passively, to contacts
  // inside message payloads — never in serialiseContacts()/backups, same
  // tier as deviceId itself.
  endpointId: null,
  // x4dhSessions — X4DH.md session-establishment state, keyed by
  // contactId -> theirDeviceId -> { sessionEpoch, stage, rootKey, ... }.
  // Loaded/saved by loadX4DHSessions()/saveX4DHSessions() below, local-
  // only, never in serialiseContacts()/backups (see that section for why
  // this is also encrypted at rest, unlike knownDevices/sendCounters).
  x4dhSessions: {}
};

const SIGNAL_URL		=`wss://${window.location.hostname}/ws/`;
const STORAGE_KEY		= "meshchat_contacts";
const PEER_BACKUP_KEY	= "meshchat_peer_backups_v1";
const PEER_TOKEN_KEY	= "meshchat_peer_tokens_v1";
const DEVICE_REGISTRY_KEY = "meshchat_known_devices_v1";
const DEVICE_KEY_STORAGE = "meshchat_device_seed_v1";
const SEND_COUNTER_KEY = "meshchat_send_counters_v1";
const PUSH_PREF_KEY = "meshchat_push_pref_v1";   // per-device opt-in preference, local-only
const X4DH_SESSION_KEY = "meshchat_x4dh_sessions_v1";   // X4DH.md session-establishment state — encrypted at rest, see its own section below
const EXCHANGE_COUNT	= 10;

/* ══════════════════════════════════════════
   RESTORE HANDSHAKE — rate limiting
   Three distinct jobs used to share ONE map (lastRestoreTime), which
   meant activity on any one of them could silently suppress a
   completely different device's legitimate turn for up to
   RESTORE_COOLDOWN:
     1. OUTBOUND — sendRestoreRequest deciding whether to send another
        restore_req to this identity. Stays identity-level: we address
        restore_req at the identity broadly, not at a specific device.
     2. INBOUND SERVE — handleRestoreRequest deciding whether to bother
        acking an incoming restore_req. Device-keyed: restore_req is
        mandatory-signed and already decrypted by the point this check
        runs, so plain.deviceId is fully trustworthy here.
     3. INBOUND ACCEPT — handleRestorePush deciding whether to bother
        processing an incoming restore_push. Endpoint-keyed once the
        packet's signature verifies — restore_push carries no deviceId
        at all (see protocol.md), only endpointId via the compound
        `from`, and only trustworthy post-verification. Falls back to
        identity-level for the unverifiable case, same tier the rest of
        this handshake family already uses.
   Kept as three separate maps rather than one with mixed key shapes —
   deviceId and endpointId are deliberately unlinkable namespaces (see
   deriveDeviceEndpointId in lib.js); a map mixing device-keyed and
   endpoint-keyed entries side by side invites exactly the kind of
   correlation-by-accident this app otherwise goes out of its way to
   avoid.
══════════════════════════════════════════ */

// 1. OUTBOUND — sendRestoreRequest's own send cadence toward an identity.
const lastRestoreRequestSent = {};

function canSendRestoreRequest(id) {
  const last = lastRestoreRequestSent[id];
  return !last || (Date.now() - last) > RESTORE_COOLDOWN;
}
// Called whenever a restore_push actually lands and gets processed for
// this identity — regardless of which of their devices sent it — since
// that's what completes the outbound request/response cycle from our
// side. Also clears pendingRestoreRequest, letting a future genuine gap
// trigger a fresh request instead of staying wedged on the old one.
function markRestoreRequestFulfilled(id) {
  lastRestoreRequestSent[id] = Date.now();
  pendingRestoreRequest.delete(id);
}

// 2. INBOUND SERVE — handleRestoreRequest's "did I just ack this device
// recently" gate. Falls back to the bare identity if deviceId is somehow
// unavailable (shouldn't happen on this path — see call site).
function inboundServeKey(id, deviceId) { return deviceId ? `${id}:${deviceId}` : id; }
const lastRestoreRequestServed = {};
function canServeRestoreRequest(id, deviceId) {
  const last = lastRestoreRequestServed[inboundServeKey(id, deviceId)];
  return !last || (Date.now() - last) > RESTORE_COOLDOWN;
}
function markRestoreRequestServed(id, deviceId) {
  lastRestoreRequestServed[inboundServeKey(id, deviceId)] = Date.now();
}

// 3. INBOUND ACCEPT — handleRestorePush's "did I just accept a push from
// this specific device recently" gate. endpointId is only ever passed in
// once verified by the caller — an unverified/absent one collapses to
// the bare identity, same soft-verification tier the rest of this
// handshake pair already uses.
function inboundAcceptKey(id, endpointId) { return endpointId ? `${id}:${endpointId}` : id; }
const lastRestorePushAccepted = {};
function canAcceptRestorePush(id, endpointId) {
  const last = lastRestorePushAccepted[inboundAcceptKey(id, endpointId)];
  return !last || (Date.now() - last) > RESTORE_COOLDOWN;
}
function markRestorePushAccepted(id, endpointId) {
  lastRestorePushAccepted[inboundAcceptKey(id, endpointId)] = Date.now();
}

/* ══════════════════════════════════════════
   INBOUND DUPLICATE SUPPRESSION — short window
   Mirrors the restore-cooldown trackers' shape just above, but generic across
   packet kinds — keyed by a caller-supplied "kind:senderId" string rather
   than baked to one packet type. Exists for the case a sender's own
   traffic (a near-simultaneous retry, or more than one live device
   answering the same broadcast) delivers the functionally same packet
   twice within the same second or two — mergeMessages() etc. already
   make RE-PROCESSING harmless, this is purely about not doing the
   redundant work (a doubled log line, a redundant re-send, a repeat
   merge) in the first place. A few seconds is enough to catch "two
   sessions answered in the same tick," nowhere near enough to ever
   suppress a genuinely later occurrence of the same packet type from the
   same sender (e.g. the next ~10-minute backup cycle).
══════════════════════════════════════════ */
const DEDUP_WINDOW_MS = 3000;
const _recentInbound  = new Map();   // "kind:senderId" → last-seen timestamp

function isDuplicateInbound(key, windowMs = DEDUP_WINDOW_MS) {
  const now  = Date.now();
  const last = _recentInbound.get(key);
  _recentInbound.set(key, now);
  return last !== undefined && (now - last) < windowMs;
}

// ekDedupTag(ek) — short fingerprint of a packet's ephemeral public key,
// for dedup keys on the wrapped push types (restore_push/backup_push).
// isDuplicateInbound stamps its timestamp on EVERY call, including for a
// packet that then fails to unwrap — so keying a push's dedup on
// (sender, endpoint) alone lets a push that was never addressed to us
// (one broadcast reply meant for a sibling device's ephemeral) poison the
// window for the genuinely-ours push arriving milliseconds later from the
// same endpoint, which then got suppressed as a "duplicate" (debug-only
// line, invisible). Two distinct pushes always carry distinct ek values;
// a true redelivery of the same push carries the same one — so adding
// this to the key keeps real duplicate suppression while letting
// different replies from one endpoint through independently.
function ekDedupTag(ek) {
  if (!Array.isArray(ek) || !ek.length) return "";
  return ":" + ek.slice(0, 6).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
}

/* ══════════════════════════════════════════
   ONLINE PRESENCE — time-based expiry
══════════════════════════════════════════ */
const onlineTimestamps = {};
const ONLINE_EXPIRY    = 300_000;

function markOnline(id) {
  const wasOnline = state.online.has(id);
  onlineTimestamps[id] = Date.now();
  state.online.add(id);
  touchDot(id);   // gui.js — fading-dot timestamp
  if (!wasOnline) mlog.info(`● ONLINE       ${pid(id)}`);
  // X4DH.md §13.2 — presence is the observation point Roadmap.md flags
  // for this: id is DEMONSTRABLY online right now (that's what got us
  // called), so any of its sessions still sitting at RK0 well past the
  // original handshake's own window is worth a human noticing. See
  // checkStuckX4DHSessions's own comment for what this does with that
  // signal — logging fires on every call regardless, but automatic
  // retry only ever fires on a genuine false→true transition, never on
  // routine re-confirmation of an already-known-online peer.
  checkStuckX4DHSessions(id, !wasOnline);
}

function pruneOnline() {
  const now = Date.now();
  for (const id of state.online) {
    if (!onlineTimestamps[id] || (now - onlineTimestamps[id]) > ONLINE_EXPIRY) {
      state.online.delete(id);
      clearDot(id);   // gui.js — fading-dot timestamp
      mlog.info(`○ GONE(prune)  ${pid(id)}`);
    }
  }
  renderContactList();
}
setInterval(pruneOnline, PRUNE_INTERVAL_MS);

// Device identity — local-only, never synced, never included in any
// backup/export. The raw seed is the durable secret; deviceId is just its
// derived public form, same shape as publicId (SHA-256[0:12]
// base64url via derivePublicId — reused directly, not reimplemented).
// Deliberately generated through the SAME curve family already in use
// for signing (ed25519.getPublicKey) rather than pulling in a new
// dependency. A future X25519 (DH) key for real per-device forward
// secrecy can be derived from this same seed later via the standard
// birational Ed25519↔X25519 conversion — no re-keying, no redistribution,
// no "deviceId v1 vs v2" when that work actually happens.
async function getOrCreateDeviceSeed() {
  const storageKey = DEVICE_KEY_STORAGE + "_" + state.publicId;
  const existing = localStorage.getItem(storageKey);
  if (existing) return base64ToRaw(existing);
  const seed = crypto.getRandomValues(new Uint8Array(32));
  localStorage.setItem(storageKey, rawToBase64(seed));
  mlog.info("DEVICE     new device identity generated");
  return seed;
}

// deviceId and endpointId (lib.js) are two SEPARATE derivations off the
// SAME seed — see deriveDeviceEndpointId's comment for why that separation
// matters. Split out from the old getOrCreateDeviceId so login can derive
// both from one seed fetch/generate rather than duplicating the
// get-or-create logic per derivation.
async function getOrCreateDeviceId(seed) {
  const publicKey = ed25519.getPublicKey(seed);
  return await derivePublicId(publicKey);
}

async function computeBackupFingerprint() {
  const enc  = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(JSON.stringify(serialiseContacts())));
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
// key MUST be the caller's ECDH-derived key for the specific sender
// (contact.encKey) — never state.encKey used blindly. Under the old
// symmetric-by-address scheme every sender encrypted with the recipient's
// own raw AES key, so decrypting with state.encKey always happened to
// work regardless of who sent it. That's no longer true: each pairwise
// ECDH secret is DIFFERENT per contact, so the caller must resolve which
// contact.encKey applies (self-targeted packets still work uniformly here,
// since state.contacts[state.publicId].encKey IS state.encKey — self-ECDH).
// This helper stays generic — it takes whatever key the caller resolves,
// legacy identity-level OR (as of this pass) an X4DH per-device wire key.
// See decryptIncomingMessage below for how app:message's receive path
// now resolves WHICH key to hand this.
async function decryptMessage(blob, key, aad) {
  // v missing = v0 (legacy unversioned), v:1 = AES-256-GCM explicit,
  // v:2 = v1 + envelope-bound (AAD) — see ENV_LABEL/envelopeAad in lib.js.
  // Passing an aad REQUIRES v:2 (no fallback to an unbound blob); without
  // one, a v:2 blob is refused (it couldn't decrypt without its binding anyway).
  if (blob.v !== undefined && blob.v > 2) throw new Error(`unsupported message version v${blob.v}`);
  if (aad) { if (blob.v !== 2) throw new Error(`message blob v${blob.v} lacks envelope binding`); }
  else if (blob.v === 2)       throw new Error("message blob v2 needs its envelope binding to decrypt");
  const params = { name: "AES-GCM", iv: new Uint8Array(blob.iv) };
  if (aad) params.additionalData = aad;
  const plain = await crypto.subtle.decrypt(params, key, new Uint8Array(blob.data));
  return JSON.parse(new TextDecoder().decode(plain));
}
function signBlob(blob){
  const bytes=new TextEncoder().encode(JSON.stringify(blob));
  const sig=ed25519.sign(bytes,state.keys.signingKeySeed);
  return Array.from(sig);
}

/* ══════════════════════════════════════════
   PACKET ENVELOPE — app:message, app:migrate, app:burn, app:sync
   These four carry { type, from, to, blob, sig } and used to sign only
   the blob. type/from/to are outside the ciphertext, so a relay could
   retype a packet (an ordinary legacy-key app:message re-labelled
   app:burn blocked a contact and wiped the conversation — reproduced
   against 0.5.6), reflect it back at its sender, or redirect it to another
   device. Now:
     - the signature covers { type, from, to, blob } (same convention the
       call/data/session/handshake packets already use — their `type` is
       inside the signed JSON, so a signature for one type can never verify
       as another);
     - the ciphertext is bound to [type, from, to] as AES-GCM AAD, so the
       same rewrite fails at decrypt and the packet is dropped.
   sealEnvelope() is the ONE place such a packet is built; receivers pass
   envelopeAad(msg.type, msg.from, msg.to) — built from the packet AS
   RECEIVED, never from anything inside the payload — to decryptMessage and
   check verifyEnvelope(msg, key). `to` is bare ("id") or compound
   ("id::endpointId"), exactly as sent.
══════════════════════════════════════════ */
function signEnvelope(type, from, to, blob) {
  return signBlob({ type, from, to, blob });
}
function verifyEnvelope(msg, contactSignPublicKey) {
  if (!msg.sig || !contactSignPublicKey) return false;
  return verifyBlob({ type: msg.type, from: msg.from, to: msg.to, blob: msg.blob }, msg.sig, contactSignPublicKey);
}
async function sealEnvelope(type, from, to, key, payload) {
  const blob = await encryptMessage(key, payload, envelopeAad(type, from, to));
  return { type, from, to, blob, sig: signEnvelope(type, from, to, blob) };
}

// Is this packet addressed to THIS device? A bare "id" means any device of
// the identity; "id::endpointId" additionally names one device — and the
// endpoint part used to be ignored by every receive handler (the relay
// routes on it, but a relay is exactly who can't be trusted to). Replaces
// the old bare-id comparison on `msg.to` at every handler.
function isAddressedToMe(to) {
  const { id, endpoint } = parseAddress(to);
  return id === state.publicId && (!endpoint || endpoint === state.endpointId);
}

function getLast(contactId, n = EXCHANGE_COUNT) { return selectRetainedMessages(state.contacts[contactId]?.messages || [], n); }

function pollBatchSize() {
  return Math.min(10, Math.max(3, Math.round(Object.keys(state.contacts).length * 0.1)));
}

function pollContacts() {
  const others = Object.keys(state.contacts)
    .filter(id => id !== state.publicId)
    .sort(() => Math.random() - 0.5)
    .slice(0, pollBatchSize() - 1);
  sendSignal({ type: "sig:announce", ids: [state.publicId, ...others] });
  mlog.debug(`POLL       queried ${1 + others.length} id(s)`);
}

let pollTimer = null;

function schedulePoll() {
  clearTimeout(pollTimer);
  const jitter = (Math.random() - 0.5) * POLL_JITTER_MS;
  pollTimer = setTimeout(() => { pollContacts(); schedulePoll(); }, POLL_INTERVAL_MS + jitter);
}

/* ══════════════════════════════════════════
   DELIVERY STATUS RECONCILIATION
   Pulled out of receiveMessage's inline flip so every mergeMessages()
   call site can re-run it after a merge, not just the live-receive path.
   A reaction (any emoji, or the null-emoji auto-ack — see protocol.md's
   Delivery Acknowledgement section) targeting one of OUR OWN outbound
   messages proves a real device decrypted+verified it, REGARDLESS of
   whether that reaction arrived live, via peer backup push, via
   self-sync restore/backup push, or via manual app:sync exchange —
   those are all just different transports for the same fact. Without
   this being callable from every merge site, a reaction that only ever
   reaches us through, say, a restore push (e.g. it landed on a different
   one of our own devices first) would never flip the sender's status
   here, even though the underlying proof is just as real.
   Idempotent — only touches messages not already "delivered", safe to
   call after every merge regardless of whether anything actually changed.
══════════════════════════════════════════ */
function reconcileDeliveryStatus(contact) {
  if (!contact?.messages?.length) return;
  const ackedTargets = new Set(
    contact.messages.filter(m => m.type === "reaction" && m.targetId).map(m => m.targetId)
  );
  for (const m of contact.messages) {
    if (m.from === state.publicId && m.status && m.status !== "delivered" && ackedTargets.has(m.id)) {
      m.status = "delivered";
    }
  }
}

/* ══════════════════════════════════════════
   MISSING-MESSAGE RECONCILIATION
   recordKnownDevice() (above) only strikes an n off a device's `missing`
   list when a message carrying that EXACT n arrives live — it has no
   visibility into messages that show up any other way. That misses a
   real case: a message that was missing via the live path can still
   turn up through a peer backup push, a self-sync restore, or a manual
   app:sync exchange, all of which merge into contact.messages WITHOUT
   ever touching the device registry. Call this after every such merge
   (same call sites as reconcileDeliveryStatus) so `missing` reflects
   what's ACTUALLY on disk, not just what arrived through one specific
   channel.
   Matching is by (deviceId, n) where the stored message has a deviceId
   (see receiveMessage) — for older messages saved before that field
   existed, falls back to matching by n alone against contact.publicId,
   which is imprecise for a contact running multiple devices but never
   wrong in the sense of clearing a genuinely-still-missing message: the
   message we matched against is real and present either way.
══════════════════════════════════════════ */
function reconcileMissingDevices(contact) {
  if (!contact?.publicId) return;
  const devices = state.knownDevices[contact.publicId];
  if (!devices) return;
  let changed = false;
  for (const [deviceId, info] of Object.entries(devices)) {
    if (!Array.isArray(info.missing) || !info.missing.length) continue;
    const present = new Set(
      (contact.messages || [])
        .filter(m => m.n != null && (m.deviceId ? m.deviceId === deviceId : true))
        .map(m => m.n)
    );
    const before = info.missing.length;
    info.missing = info.missing.filter(n => !present.has(n));
    if (info.missing.length !== before) changed = true;
  }
  if (changed) saveDeviceRegistry();
}

// user-facing: called from the banner's dismiss (✕) button — see
// buildMissingBanner in meshchat-gui.js. For the case reconciliation
// above CAN'T fix: a gap that's genuinely permanent (the sender's local
// retention is only the last 15 messages per contact — serialiseContacts()
// — and there's no wire-level backfill request yet, see Roadmap.md), so
// nothing will ever arrive to clear it automatically. This is explicitly
// "stop warning me," not "these messages were found" — the banner's title
// attribute says as much.
function dismissMissingWarning(contactId) {
  const devices = state.knownDevices[contactId];
  if (!devices) return;
  let changed = false;
  for (const info of Object.values(devices)) {
    if (Array.isArray(info.missing) && info.missing.length) { info.missing = []; changed = true; }
  }
  if (changed) {
    saveDeviceRegistry();
    mlog.info(`DEVICE     missing-message warning dismissed  contact=${pid(contactId)}`);
    if (state.currentChat === contactId) renderMessages();
  }
}

/* ══════════════════════════════════════════
   STORAGE
   Audio messages are stripped of their data
   before serialising — only a stub is kept so
   the conversation timeline stays intact.
   Raw audio lives in audioCache (memory only).
══════════════════════════════════════════ */
function serialiseContacts() {
  const out = {};
  for (const [id,c] of Object.entries(state.contacts))
    out[id] = { name: c.name, publicId: c.publicId, shareableKey: c.shareableKey,
                messages: selectRetainedMessages(c.messages, RETENTION_COUNT).map(m => m.type === "audio" ? {...m, data:null, expired:true} : m),
                blocked: c.blocked || false,
                lastStateChange: c.lastStateChange || 0,
                lastRelay:       c.lastRelay       || null,
                lastRelaySeen:   c.lastRelaySeen    || 0 };
  return out;
}

// Contacts-only variant for the CONTACT-path peer backup (sync:backup_push
// to someone other than ourselves) — deliberately a separate function, not
// a flag on serialiseContacts() above. Every other caller of
// serialiseContacts() (saveContacts' own local-storage write, self-sync's
// full push/mini-backup, exportBackup, computeBackupFingerprint) needs the
// real message history and must be completely unaffected by this — a
// shared function with a strip-messages flag would risk one of those call
// sites someday passing the wrong flag by accident. This one is only ever
// called from saveContactsBackup, for the blob handed to
// pushBackupToContacts' non-self branch.
//
// Why: a peer holding your backup is functionally a third party with an
// encrypted copy of your conversation history sitting on their device
// indefinitely (peerBackups is never expired or pruned) — useful for
// restoring your CONTACT LIST after a wipe, but message content never
// needed to ride along for that to work, and every message you've ever
// sent that contact was already visible to them anyway, encrypted with
// their own copy of the pairwise/X4DH key. Metadata a contact needs to
// restore your contact list — name, shareableKey, blocked, type,
// lastStateChange, lastRelay/lastRelaySeen — is unaffected; only messages
// is forced empty. mergeMessages(existing, []) is already a safe no-op on
// the receiving end, so no wire/receive-side change is needed elsewhere.
function serialiseContactsForPeers() {
  const out = {};
  for (const [id,c] of Object.entries(state.contacts))
    out[id] = { name: c.name, publicId: c.publicId, shareableKey: c.shareableKey,
                messages: [],
                blocked: c.blocked || false,
                lastStateChange: c.lastStateChange || 0,
                lastRelay:       c.lastRelay       || null,
                lastRelaySeen:   c.lastRelaySeen    || 0 };
  return out;
}

async function deserialiseContacts(raw){
  const out={};
  for(const[id,c]of Object.entries(raw)){
    const parts=c.shareableKey.split(".");
    const x25519PublicKey=base64ToRaw(parts[0]);
    const signPublicKey=parts.length>=2?base64ToRaw(parts[1]):null;
    // parts[2] is base64-encoded relay WSS — preserved as-is in shareableKey
    // encKey is no longer imported raw off the wire — it's derived fresh via
    // ECDH(ourX25519Seed, theirX25519PublicKey) every load. Works identically
    // for the self entry (id === state.publicId): X25519 against our own
    // public key is a well-defined DH operation, same result every device.
    // This remains the LEGACY/fallback key even after the X4DH wire-key
    // work below — nothing here changes.
    const encKey=await deriveSharedAesKey(state.x25519Seed,x25519PublicKey);
    out[id]={...c,encKey,x25519PublicKey,signPublicKey};
  }
  return out;
}

/* ══════════════════════════════════════════
   saveContacts() SERIALIZATION
   Without this, two overlapping calls (e.g. an outgoing send and an
   incoming auto-ack landing within the same tick of each other) race:
   each snapshots serialiseContacts() synchronously at call time, but the
   actual localStorage.setItem only lands after encryptObject's async
   crypto.subtle.encrypt + gzip finish. Nothing guarantees they finish in
   the order they started — whichever encryption happens to resolve
   SECOND wins the write, even if its snapshot was the OLDER, less
   complete one. Everything still looks correct live (the in-memory merge
   was always fine) — the loss is invisible until the next reload, which
   is exactly what made this hard to spot.
   Fix: a simple promise-chained mutex. Every call to saveContacts()
   queues behind whatever's currently in flight, so a snapshot is only
   ever taken (and only ever written) after the previous write has fully
   landed — out-of-order completion becomes structurally impossible
   rather than merely unlikely.
══════════════════════════════════════════ */
let _saveContactsChain = Promise.resolve();

function saveContacts() {
  const run = _saveContactsChain.then(async () => {
    if (!state.cryptoKey) return;
    try {
      const encrypted = await encryptObject(state.cryptoKey, serialiseContacts());
      localStorage.setItem(STORAGE_KEY + "_" + state.publicId, JSON.stringify(encrypted));
      return encrypted;
    } catch(e) {
      // previously an unhandled rejection here failed completely silently —
      // same failure shape as the race this function now prevents, just a
      // different trigger (crypto/storage error instead of ordering).
      mlog.err(`STORAGE    saveContacts failed: ${e.message}`);
      return undefined;
    }
  });
  // Chain continues regardless of this call's outcome — one failed save
  // must not permanently wedge every future save behind a rejected
  // promise. Caller still awaits `run` itself, so it observes success/
  // failure normally; only the QUEUE'S continuation is failure-proofed.
  _saveContactsChain = run.catch(() => {});
  return run;
}

let messagesSinceBackup = 0;

async function saveContactsBackup(force = false) {
  if (!state.cryptoKey) return;
  const encrypted = await saveContacts();   // full data — local storage only, unaffected by the peer-facing change below
  messagesSinceBackup++;
  if (!force && messagesSinceBackup < BACKUP_THRESHOLD) return;
  messagesSinceBackup = 0;
  // Contacts-only blob for the wire — see serialiseContactsForPeers' own
  // comment. Self-sync (pushBackupToContacts' id === state.publicId branch)
  // ignores this parameter entirely and builds its own full blob from
  // serialiseContacts() directly, so this only ever reaches other contacts.
  const peerBlob = await encryptObject(state.cryptoKey, serialiseContactsForPeers());
  pushBackupToContacts(peerBlob);
}

setInterval(() => {
  saveContactsBackup(true);
  for (const id of Object.keys(state.contacts)) {
    if (id !== state.publicId) sendRestoreRequest(id);
  }
}, BACKUP_INTERVAL_MS);

async function loadContacts() {
  try {
    if (!state.cryptoKey) { state.contacts = {}; return; }
    const raw = localStorage.getItem(STORAGE_KEY + "_" + state.publicId);
    if (!raw) {
      state.contacts = {};
      mlog.info("STORAGE    no local data — fresh start");
      return;
    }
    state.contacts = await deserialiseContacts(await decryptObject(state.cryptoKey, JSON.parse(raw)));
    const contactIds = Object.keys(state.contacts).filter(id => id !== state.publicId);
    mlog.info(`STORAGE    loaded ${Object.keys(state.contacts).length} contact(s)`);
    if (contactIds.length > 0) sessionFresh = false;
  } catch(e) {
    console.warn("storage load failed", e);
    mlog.err("STORAGE    load failed: " + e.message);
    state.contacts = {};
  }
}

function loadPeerBackups() {
  try {
    state.peerBackups = JSON.parse(localStorage.getItem(PEER_BACKUP_KEY + "_" + state.publicId) || "{}");
    mlog.debug(`STORAGE    peer backups loaded: ${Object.keys(state.peerBackups).length}`);
  } catch(e) { state.peerBackups = {}; }
}

function savePeerBackups() {
  try { localStorage.setItem(PEER_BACKUP_KEY + "_" + state.publicId, JSON.stringify(state.peerBackups)); }
  catch(e) {}
}

function loadPeerTokens() {
  try {
    state.peerTokens = JSON.parse(localStorage.getItem(PEER_TOKEN_KEY + "_" + state.publicId) || "{}");
    mlog.debug(`STORAGE    peer tokens loaded: ${Object.keys(state.peerTokens).length}`);
  } catch(e) { state.peerTokens = {}; }
}

function savePeerTokens() {
  try { localStorage.setItem(PEER_TOKEN_KEY + "_" + state.publicId, JSON.stringify(state.peerTokens)); }
  catch(e) {}
}

/* ══════════════════════════════════════════
   DEVICE REGISTRY — load / prune / save
   pruneDeviceRegistry() is the reusable trim step (cutoff + per-identity
   cap, see DEVICE_REGISTRY_CUTOFF_MS/MAX_DEVICES_PER_IDENTITY above).
   Split out of loadDeviceRegistry() so it can ALSO run periodically (see
   the setInterval below) — previously this only ever ran once, at
   login, which let a churny session badly overshoot the cap for hours
   before the next reload swept it back down.
   loadDeviceRegistry() still separately handles one-time SHAPE migration
   (bare-timestamp entries → { lastSeen, lastN }, missing[] backfill) —
   that's a load-time upgrade of old data, not a repeated retention
   policy, so it deliberately stays out of the periodic sweep.
══════════════════════════════════════════ */
function pruneDeviceRegistry() {
  const cutoff = Date.now() - DEVICE_REGISTRY_CUTOFF_MS;
  let changed = false;
  for (const identityId of Object.keys(state.knownDevices)) {
    const devs = state.knownDevices[identityId];
    let entries = Object.entries(devs).filter(([, v]) => v.lastSeen > cutoff);
    if (entries.length !== Object.keys(devs).length) changed = true;
    if (entries.length > MAX_DEVICES_PER_IDENTITY) {
      entries = entries.sort(([, a], [, b]) => b.lastSeen - a.lastSeen).slice(0, MAX_DEVICES_PER_IDENTITY);
      changed = true;
    }
    state.knownDevices[identityId] = Object.fromEntries(entries);
  }
  if (changed) saveDeviceRegistry();
  return changed;
}
// Periodic sweep — same "don't wait for a reload" reasoning as
// pruneOnline's own setInterval just above. 10 minutes is deliberately
// coarse: this is bookkeeping hygiene, not a correctness-critical path,
// and piggybacking on a tighter interval (e.g. PRUNE_INTERVAL_MS's 30s)
// would just mean re-scanning every identity's device map far more often
// than the underlying data could plausibly have changed.
setInterval(pruneDeviceRegistry, DEVICE_PRUNE_INTERVAL_MS);

function loadDeviceRegistry() {
  try {
    state.knownDevices = JSON.parse(localStorage.getItem(DEVICE_REGISTRY_KEY + "_" + state.publicId) || "{}");
    // one-time SHAPE migration only — retention (cutoff/cap) is now
    // pruneDeviceRegistry()'s job, called below and periodically thereafter.
    for (const identityId of Object.keys(state.knownDevices)) {
      const devs = state.knownDevices[identityId];
      // migrate pre-n entries: a bare lastSeen timestamp becomes
      // { lastSeen, lastN: 0 } — old data never had a counter to recover,
      // so it starts at 0 and gets corrected the next time this device
      // is actually seen sending something with an n on it.
      for (const devId of Object.keys(devs)) {
        if (typeof devs[devId] === "number") devs[devId] = { lastSeen: devs[devId], lastN: 0 };
        // migrate pre-`missing` entries too — an older registry entry
        // simply has no gap tracking yet; start empty rather than guess.
        if (devs[devId] && !Array.isArray(devs[devId].missing)) devs[devId].missing = [];
      }
    }
    pruneDeviceRegistry();
    saveDeviceRegistry();
    mlog.debug(`STORAGE    device registry loaded: ${Object.keys(state.knownDevices).length} identity(ies)`);
  } catch(e) { state.knownDevices = {}; }
}

function saveDeviceRegistry() {
  try { localStorage.setItem(DEVICE_REGISTRY_KEY + "_" + state.publicId, JSON.stringify(state.knownDevices)); }
  catch(e) {}
}

// shared by app:message receipt and the existing self-sync fingerprint
// tagging — local-only knowledge, never part of serialiseContacts()/backup.
// `n`, when provided, is the sender's per-(their device, us) send counter —
// see nextSendCounter() below for the mirror-image local-send side.
//
// Beyond bookkeeping, a gap (n arriving ahead of prevLastN+1) is now
// recorded into `missing` — the list of n's we know this device sent but
// haven't seen — so the UI can surface "message #N not received yet"
// (see renderMessages in meshchat-gui.js). This is purely a DISPLAY hint,
// not a resend queue: there is no wire-level backfill request yet (see
// Roadmap.md — folded into the future session-bootstrap/reset design
// pass rather than freelanced here). `missing` is capped at 50 entries
// since it exists to inform a person, not to be exhaustive.
// An out-of-order arrival (n <= prevLastN) clears that n from `missing`
// if it was recorded, since the "missing" message just showed up late.
function recordKnownDevice(identityId, deviceId, n, endpointId) {
  if (!identityId || !deviceId) return;
  if (!state.knownDevices[identityId]) state.knownDevices[identityId] = {};
  const existing = state.knownDevices[identityId][deviceId];
  const prevLastN = (existing && typeof existing === "object") ? (existing.lastN || 0) : 0;
  let missing = (existing && Array.isArray(existing.missing)) ? existing.missing.slice() : [];
  let lastN = prevLastN;
  if (typeof n === "number") {
    if (n > prevLastN + 1) {
      for (let g = prevLastN + 1; g < n; g++) if (!missing.includes(g)) missing.push(g);
      mlog.debug(`DEVICE     n gap  id=${pid(identityId)}  device=${pid(deviceId)}  expected=${prevLastN + 1}  got=${n}  missing=${missing.length}`);
    } else if (n <= prevLastN && missing.includes(n)) {
      missing = missing.filter(g => g !== n);
      mlog.debug(`DEVICE     n late-arrival, cleared from missing  id=${pid(identityId)}  device=${pid(deviceId)}  n=${n}`);
    }
    lastN = Math.max(prevLastN, n);
  }
  // endpointId is learned passively, the same way deviceId itself is — only
  // adopt an explicitly-provided value, so an omitted field never silently
  // blanks out what's already known. Older/other callers that don't pass it
  // (e.g. restore paths) leave whatever's already on file untouched.
  const prevRoutingId = (existing && typeof existing === "object") ? existing.endpointId : undefined;
  state.knownDevices[identityId][deviceId] = {
    lastSeen: Date.now(), lastN, missing: missing.slice(0, 50),
    endpointId: endpointId || prevRoutingId || null
  };
  saveDeviceRegistry();
  // X4DH.md §13.3 — every call here is a chance the endpointId
  // precondition just got satisfied for a device we haven't
  // bootstrapped a session with yet. No-op the overwhelming majority
  // of the time (session already exists, we're not the fixed
  // initiator, or no endpoint yet) — see maybeTriggerX4DHPropose's own
  // comment for the full guard chain.
  maybeTriggerX4DHPropose(identityId, deviceId);
  // …and the mirror image for the RESPONDER side: a propose we couldn't ack
  // because this device's endpoint wasn't known yet (the first-contact race)
  // can be completed the moment this call learned it. No-op unless a
  // pendingAck is parked on the session.
  maybeCompleteDeferredAck(identityId, deviceId);
}

function loadSendCounters() {
  try {
    state.sendCounters = JSON.parse(localStorage.getItem(SEND_COUNTER_KEY + "_" + state.publicId) || "{}");
    mlog.debug(`STORAGE    send counters loaded: ${Object.keys(state.sendCounters).length}`);
  } catch(e) { state.sendCounters = {}; }
}

function saveSendCounters() {
  try { localStorage.setItem(SEND_COUNTER_KEY + "_" + state.publicId, JSON.stringify(state.sendCounters)); }
  catch(e) {}
}

// Local-only, per (THIS device, contact) outbound sequence — never
// included in serialiseContacts()/backups, same tier as the device seed
// itself. Deliberately not synced: two devices sharing one identity each
// keep their own independent counter, since there is no live, authoritative
// shared crypto state to arbitrate "whose turn" it is between them (see
// chat — this is the fork double-ratchet readiness has to respect here).
// Counts every outbound app:message payload (text/audio/image) to this
// contact regardless of relay-vs-signal delivery path — it tracks logical
// send order, not delivery success. Reactions are deliberately excluded.
// Bookkeeping only for now: nothing yet consumes `n` as a real chain
// position.
function nextSendCounter(contactId) {
  const n = (state.sendCounters[contactId] || 0) + 1;
  state.sendCounters[contactId] = n;
  saveSendCounters();
  return n;
}

// getAckPointer(contactId) — freshest usable (deviceId, n) pointer for
// contactId's conversation, or null if none exists yet.
//
// REWRITTEN (0.4.9) — the previous version read state.knownDevices and
// picked whichever of the CONTACT's devices had the largest lastSeen.
// That looked sound (it even excluded lastN:0 placeholders) but missed a
// sharper version of the same problem it was already trying to guard
// against: lastSeen is bumped by EVERY incoming packet from a device,
// including a bare RECEIVED-ack reaction (deviceId present, no n) — and
// since reactions are now fanned to every known device of a contact (see
// sendFannedX4DH below), a contact running two-plus devices means BOTH ack
// every message you send, independently, in whatever order their acks
// happen to race in. lastSeen stopped meaning "which device am I
// actually talking to" the moment that became true — it started meaning
// "whichever of this contact's devices most recently won an ack race,"
// pure noise with respect to conversational relevance. A real message
// several minutes old could out-rank one from seconds ago purely because
// its device's ack landed a few milliseconds later.
//
// It also never considered YOUR OWN last sent message at all — only the
// contact's devices were ever candidates — so a run of several outgoing
// messages with no reply in between would each independently point back
// at the same stale contact message instead of chaining onto each other.
//
// Fix: stop consulting the device registry for this. Look directly at
// contactId's own message list and take the single most recent (ts)
// entry that carries a real (deviceId, n) pair, EXCLUDING reactions
// (they never carry n, by design — see nextSendCounter) — regardless of
// whether it was sent by the contact or by us. ts is immutable content,
// set once at compose time; unlike lastSeen it can't be perturbed by
// unrelated later traffic. This requires outgoing messages to stamp
// their own deviceId on the LOCALLY stored copy too (previously only the
// wire payload got one, for the recipient's benefit) — see the four
// send functions below, each now doing so.
//
// Tiebreak on an exact ts collision: id string compare, same stable
// secondary key mergeMessages' own baseline sort already uses, so this
// and that sort agree on ordering for the (rare) exact-millisecond case.
function getAckPointer(contactId) {
  const messages = state.contacts[contactId]?.messages;
  if (!messages || !messages.length) return null;

  let best = null;
  for (const m of messages) {
    if (m.type === "reaction" || !m.deviceId || m.n == null) continue;
    if (!best || m.ts > best.ts || (m.ts === best.ts && m.id > best.id)) best = m;
  }
  return best ? { ackDeviceId: best.deviceId, ackN: best.n } : null;
}

/* ══════════════════════════════════════════
   CONTACT-FACING PER-DEVICE FANOUT
   resolveDeviceTargets(contactId) splits a contact's known devices into
   "targeted" (endpointId known AND seen within FANOUT_STALE_MS) and a
   single "needsBroadcast" flag: true whenever at least one known device
   is unresolved (no endpointId on file yet — an older client, or one
   that hasn't sent us anything this session) OR stale, OR there are no
   known devices at all (a fresh contact — today's only case, unchanged).
   Staleness never excludes a device — it only demotes it from "gets its
   own targeted send" to "gets the broadcast fallback like everyone
   else." Nothing is ever silently dropped by this function.

   This ADDRESSING split (targeted vs broadcast, who gets their own copy
   at all) is unchanged by the X4DH wire-key work below — what changed is
   ENCRYPTION: sendFannedX4DH (further down) now picks a per-device key
   for each TARGETED entry this function returns, rather than reusing one
   shared ciphertext across all of them the way the old sendFanned did.
══════════════════════════════════════════ */
const FANOUT_STALE_MS = 7 * 24 * 60 * 60 * 1000;   // 7 days — deliberately its own, shorter window than DEVICE_REGISTRY_CUTOFF_MS's 30-day retention (see that constant's comment for why the two don't need to match)

function resolveDeviceTargets(contactId) {
  const devices = state.knownDevices[contactId] || {};
  // Self-fanout (contactId === our own identity, e.g. sendSelfSync or a
  // self-chat message) must never target THIS device: it's in our own
  // registry (login calls recordKnownDevice(state.publicId, state.deviceId))
  // but with no endpointId, so left in it would read as "unresolved" forever
  // and force a legacy-key broadcast on every single self-send — and would
  // be a pointless echo to ourselves once an endpointId ever did get filed.
  // Identical to plain Object.entries() for every non-self contact.
  const entries = Object.entries(devices)
    .filter(([deviceId]) => !(contactId === state.publicId && deviceId === state.deviceId));
  const now = Date.now();

  const targeted = [];
  let needsBroadcast = entries.length === 0;   // fresh contact (or, for self, no sibling known yet)

  for (const [deviceId, info] of entries) {
    const isStale = (now - (info.lastSeen || 0)) > FANOUT_STALE_MS;
    if (info.endpointId && !isStale) {
      targeted.push({ deviceId, endpointId: info.endpointId });
    } else {
      needsBroadcast = true;   // unresolved OR stale — falls back, not dropped
    }
  }
  // knownCount — how many devices (excluding our own, in the self case) we
  // actually have on file. Lets a caller tell "nothing known at all"
  // (needsBroadcast true because entries is empty) apart from "known but
  // unresolved/stale" (needsBroadcast true because of a fallback) —
  // sendSelfSync needs exactly that distinction, ordinary fanout doesn't.
  return { targeted, needsBroadcast, knownCount: entries.length };
}

/* ══════════════════════════════════════════
   X4DH — SESSION ESTABLISHMENT (see X4DH.md)
   Root-key establishment, automatic bootstrap/retry, AND (as of this
   pass) the actual wire-message key used for real app:message traffic
   once a device pair has a session. See the design discussion this
   pass came out of for the full reasoning; summary of what's live now:
     - X4DH.md §3-§7: RK0/RK1 derivation, session:propose/session:ack
     - §13.1/§13.3: fixed initiator, passive endpoint-discovery trigger
     - §13.2 + Roadmap's automatic-retry pass: stuck-at-RK0 detection,
       a bounded (10-attempt) auto-retry gated on genuine online-
       transitions, re-arming on the next transition after exhaustion
     - THIS PASS: the session's root key (RK0 OR RK1 — either stage is
       eligible; see the design discussion for why RK0 was accepted
       despite its narrower forward-secrecy property, X4DH.md §10) is
       now used to derive a real AES-256-GCM key per (contact, device)
       pair, which sendFannedX4DH/decryptIncomingMessage use in place of
       the old identity-level static key for any device that has one.
       Deliberately NOT a ratchet — the derived key is static per session,
       renegotiated only when the underlying session itself resets (the
       existing reactive stuck-detection retry, nothing new added for
       this pass — periodic/count-based rotation was explicitly deferred).
       A device with no session yet (or one that never bootstraps one)
       falls back to the legacy identity-level key exactly as before —
       this is graceful degradation, not a hard cutover.
══════════════════════════════════════════ */

// X4DH.md §13.1 — fixed initiator per pair, eliminating proposal glare
// structurally rather than detecting/resolving it after the fact. Lower
// publicId always initiates, permanently, for both first bootstrap and
// any later reset. Self-sessions (contactId === state.publicId) can't
// use publicId to break the tie — both sides ARE the same identity — so
// this falls through to comparing deviceId instead, same permanence
// rule, decided once per device pair.
function isFixedInitiator(contactId, theirDeviceId) {
  if (contactId === state.publicId) return state.deviceId < theirDeviceId;
  return state.publicId < contactId;
}

// X4DH.md §7.1 — Alice cannot discard EK_A_priv the instant
// session:propose is sent; she needs it if/when session:ack arrives, to
// compute DH4. This map holds exactly that, in memory only — same
// sensitivity tier as the device seed itself, NEVER written to
// localStorage under any key. Keyed by contactId + the SPECIFIC target
// device's deviceId + sessionEpoch, since a contact can have several
// devices each mid-handshake with sessionEpochs of their own.
//
// X4DH_PROPOSAL_TIMEOUT_MS bounds how long a proposal stays "waiting for
// a live ack" before its ephemeral is discarded and the session simply
// stays at RK0 for that attempt (§7.1). This is NOT a "give up on ever
// talking to this device" timeout — it only governs the narrow window
// for the OPPORTUNISTIC live upgrade; a genuinely offline device still
// receives (and can adopt) the buffered propose whenever it reconnects,
// same as any other buffered packet — it just won't get the DH3/DH4
// upgrade unless a fresh propose is sent while both sides are actually
// online together. 60s mirrors BACKUP_OFFER_TTL's existing "how long is
// a live handshake still fresh" precedent in this file.
const pendingX4DHProposals = new Map();   // "contactId:theirDeviceId:sessionEpoch" -> { ekPriv, createdAt, timeoutHandle }

function pendingX4DHKey(contactId, theirDeviceId, sessionEpoch) {
  return `${contactId}:${theirDeviceId}:${sessionEpoch}`;
}

// Per-entry setTimeout, NOT a shared periodic sweep — confirmed live on
// meshdev that a single setInterval(..., X4DH_PROPOSAL_TIMEOUT_MS)
// started once at page load has no relationship to any individual
// entry's own creation time: a proposal created partway through the
// interval's current cycle survives past that cycle's tick (still under
// the threshold at that check) and isn't re-checked until the NEXT tick
// a full period later — observed letting an ack land ~94s after a
// proposal meant to expire at 60s complete normally. Tying the timer to
// the entry itself makes the deadline exact regardless of when in any
// shared schedule it happens to fall.
function schedulePendingX4DHExpiry(key) {
  return setTimeout(() => {
    if (pendingX4DHProposals.delete(key)) {
      mlog.debug(`X4DH       proposal expired, ephemeral discarded  key=${key}`);
    }
  }, X4DH_PROPOSAL_TIMEOUT_MS);
}

/* ── session storage ──
   meshchat_x4dh_sessions_v1_<publicId> — local-only, identity-scoped,
   NEVER included in serialiseContacts()/backups/exports, same tier as
   the device seed and send counters. Unlike those, though, the VALUE
   stored here (a derived root key) is genuine session key material
   rather than bookkeeping — so unlike the plaintext device registry/
   send-counter storage, this is encrypted at rest with state.cryptoKey
   (the same key protecting contacts/messages), via the existing
   encryptObject/decryptObject helpers.

   Shape:
   {
     "<contactId>": {
       "<theirDeviceId>": {
         sessionEpoch, stage: "rk0"|"rk1", rootKey (base64),
         initiator, establishedAt, upgradedAt,
         retryAttempts, retryExhaustedAt, lastRetryAt
       }
     }
   }
── */
async function loadX4DHSessions() {
  try {
    if (!state.cryptoKey) { state.x4dhSessions = {}; return; }
    const raw = localStorage.getItem(X4DH_SESSION_KEY + "_" + state.publicId);
    if (!raw) { state.x4dhSessions = {}; return; }
    state.x4dhSessions = await decryptObject(state.cryptoKey, JSON.parse(raw));
    mlog.debug(`STORAGE    X4DH sessions loaded: ${Object.keys(state.x4dhSessions).length} contact(s)`);
  } catch(e) {
    mlog.warn(`STORAGE    X4DH session load failed: ${e.message}`);
    state.x4dhSessions = {};
  }
}

async function saveX4DHSessions() {
  if (!state.cryptoKey) return;
  try {
    const encrypted = await encryptObject(state.cryptoKey, state.x4dhSessions);
    localStorage.setItem(X4DH_SESSION_KEY + "_" + state.publicId, JSON.stringify(encrypted));
  } catch(e) {
    mlog.err(`STORAGE    X4DH session save failed: ${e.message}`);
  }
}

function getX4DHSession(contactId, theirDeviceId) {
  return state.x4dhSessions?.[contactId]?.[theirDeviceId] || null;
}

// storeX4DHSessionRK0 fully replaces the session object on every propose
// (both a first-ever bootstrap AND a later retry — see retryX4DHPropose,
// which is just sendX4DHPropose called again). retryAttempts/
// retryExhaustedAt/lastRetryAt are carried forward from whatever was
// already on file rather than reset here — they're per-(contact,device)
// budget bookkeeping, not per-epoch, so a retry that successfully
// re-establishes RK0 must NOT silently zero its own attempt count. A
// brand-new device pair simply has nothing to carry forward (existing
// is undefined), so it starts clean.
async function storeX4DHSessionRK0(contactId, theirDeviceId, sessionEpoch, rk0Bytes, initiator, proposeTs) {
  if (!state.x4dhSessions[contactId]) state.x4dhSessions[contactId] = {};
  const existing = state.x4dhSessions[contactId][theirDeviceId];
  // A reset/retry replaces the whole session. Packets the OTHER side already
  // sent under the old generation(s) are still in flight — keep those roots
  // as decrypt-only for X4DH_RETIRED_GRACE_MS instead of discarding them.
  if (existing) {
    retireX4DHRoot(contactId, theirDeviceId, existing.rootKey);
    retireX4DHRoot(contactId, theirDeviceId, existing.rk0Root);
  }
  state.x4dhSessions[contactId][theirDeviceId] = {
    // proposeTs — the ORIGINATING session:propose packet's own signed
    // `ts` field (the sender's clock), kept separate from establishedAt
    // below (OUR OWN Date.now() at storage time, a different clock
    // entirely) — see handleX4DHPropose's stale-propose guard (X4DH.md
    // §13.2), which deliberately compares sender-clock-to-sender-clock
    // rather than sender-clock-to-our-clock, so ordinary cross-device
    // clock skew can never masquerade as a replay. Defaults to our own
    // clock when the caller is the initiator side (sendX4DHPropose
    // storing the propose WE just sent — "the sender's clock" and "our
    // clock" are the same thing there); the receiving side
    // (handleX4DHPropose) always passes the real msg.ts explicitly.
    sessionEpoch, stage: "rk0", rootKey: rawToBase64(rk0Bytes),
    initiator, establishedAt: Date.now(), upgradedAt: null,
    proposeTs: proposeTs ?? Date.now(),
    // Retry-budget fields (Roadmap.md's automatic-retry design pass) —
    // per-(contact,device), not per-epoch. Carried forward across every
    // overwrite of this object, including a retry's own fresh RK0.
    retryAttempts:    existing?.retryAttempts    || 0,
    retryExhaustedAt: existing?.retryExhaustedAt || null,
    lastRetryAt:      existing?.lastRetryAt      || null,
  };
  // (wire keys are cached per ROOT now — nothing to evict here, see x4dhWireKeyByRoot)
  await saveX4DHSessions();
  mlog.info(`X4DH       RK0 established  ${pid(contactId, { deviceId: theirDeviceId })}  epoch=${pid(sessionEpoch)}`);
}

// Guards against upgrading the wrong session — if a session has already
// moved on (a newer propose/reset landed since this ack's sessionEpoch
// was issued), this ack is stale and must not regress it. Full
// staleness/replay hardening beyond this single check is X4DH.md §13.2,
// deliberately deferred past this pass.
// sendStage — which root WE encrypt under from now on (see the key-generation
// block below): "rk1" for the initiator (the ack was built from RK1, so the
// responder provably has it), "rk0" for the responder (it has no proof yet
// that the initiator received the ack — it keeps sending under RK0, which
// the initiator certainly holds, until a message arrives under RK1).
async function upgradeX4DHSessionToRK1(contactId, theirDeviceId, sessionEpoch, rk1Bytes, sendStage = "rk1") {
  const existing = getX4DHSession(contactId, theirDeviceId);
  if (!existing || existing.sessionEpoch !== sessionEpoch) {
    mlog.warn(`X4DH       stale upgrade attempt — no matching rk0 session, dropped  ${pid(contactId, { deviceId: theirDeviceId })}  epoch=${pid(sessionEpoch)}`);
    return false;
  }
  if (existing.stage === "rk0") existing.rk0Root = existing.rootKey;   // RK0 stays usable (decrypt always; send too while sendStage is "rk0")
  existing.stage      = "rk1";
  existing.rootKey    = rawToBase64(rk1Bytes);
  existing.sendStage  = sendStage;
  existing.upgradedAt = Date.now();
  delete existing.pendingAck;   // nothing left to defer — see maybeCompleteDeferredAck
  // A session that reaches RK1 isn't stuck anymore — clear whatever
  // retry bookkeeping it was carrying so a FUTURE unrelated episode of
  // this same device pair getting stuck (post-reset, down the line)
  // starts with a clean budget rather than inheriting an old exhaustion.
  existing.retryAttempts    = 0;
  existing.retryExhaustedAt = null;
  await saveX4DHSessions();
  mlog.info(`X4DH       RK1 upgrade complete  ${pid(contactId, { deviceId: theirDeviceId })}  epoch=${pid(sessionEpoch)}`);
  return true;
}

/* ── wire-message keys: SEND vs DECRYPT, and key generations ──
   Pass 1 derived ONE key per (contact, device) from the session's current
   root and used it for everything. That lost packets whenever the two sides
   disagreed, for a moment, about which root was current:
     - the responder upgrades to RK1 BEFORE its ack is delivered, so the
       initiator's RK0-keyed messages (sent meanwhile) were undecryptable,
       and the responder's RK1-keyed ones were undecryptable to the
       initiator (still at RK0);
     - a lost or late ack (the initiator drops its ephemeral after 60s)
       left the pair permanently desynced until the stuck-retry;
     - a reset replaced the session wholesale, so anything the peer had
       already sent under the old keys was lost.
   Rule now: SEND under the newest root the peer has demonstrably reached,
   DECRYPT under every generation still alive.
     session.rootKey  — newest root (RK1 once upgraded, else RK0)
     session.rk0Root  — RK0, retained after the upgrade until the peer is
                        confirmed to hold RK1 (persisted with the session,
                        encrypted at rest like everything in it)
     session.sendStage— "rk0" | "rk1": which of the two we encrypt under
                        (absent on a pre-0.5.9 record = its current stage)
   The initiator sends under RK1 as soon as the ack lands (the ack was built
   from RK1). The responder keeps sending under RK0 until a VERIFIED message
   from that device decrypts under RK1 — proof the initiator upgraded —
   then switches (confirmX4DHPeerKey) and retires RK0. A lost ack therefore
   no longer desyncs anything: both sides simply stay on RK0, which both
   hold, until the retry.
   Roots that are replaced (a reset) or retired (RK0 after confirmation) go
   to x4dhRetired for X4DH_RETIRED_GRACE_MS: decrypt-only, memory-only —
   never persisted, so a reload drops them (forward secrecy over
   in-flight-across-a-reload packets). Wire keys are cached by ROOT CONTENT
   (x4dhWireKeyByRoot), so a cache hit can never be stale; the entry is
   evicted when its root's grace ends.
── */
const X4DH_RETIRED_GRACE_MS = 120_000;
const x4dhWireKeyByRoot = new Map();   // root (base64) -> CryptoKey (AES-256-GCM) — memory only
const x4dhRetired       = new Map();   // "contactId:deviceId" -> [{ rootB64, retiredAt }] — memory only

async function wireKeyForRoot(rootB64) {
  let k = x4dhWireKeyByRoot.get(rootB64);
  if (!k) { k = await deriveX4DHWireKey(base64ToRaw(rootB64)); x4dhWireKeyByRoot.set(rootB64, k); }
  return k;
}

function retireX4DHRoot(contactId, theirDeviceId, rootB64) {
  if (!rootB64) return;
  const key = `${contactId}:${theirDeviceId}`;
  const list = x4dhRetired.get(key) || [];
  if (!list.some(r => r.rootB64 === rootB64)) list.push({ rootB64, retiredAt: Date.now() });
  x4dhRetired.set(key, list);
}

function purgeRetiredX4DHRoots() {
  const now = Date.now();
  for (const [key, list] of x4dhRetired) {
    const keep = list.filter(r => now - r.retiredAt <= X4DH_RETIRED_GRACE_MS);
    for (const r of list) if (!keep.includes(r)) x4dhWireKeyByRoot.delete(r.rootB64);
    if (keep.length) x4dhRetired.set(key, keep); else x4dhRetired.delete(key);
  }
}
setInterval(purgeRetiredX4DHRoots, 30_000);   // so a retired key doesn't outlive its grace just because nothing decrypted lately

// the root WE encrypt under for this session
function x4dhSendRoot(s) {
  return (s.stage === "rk1" && s.sendStage === "rk0" && s.rk0Root) ? s.rk0Root : s.rootKey;
}

// getOrDeriveWireKey(contactId, theirDeviceId) — the key to ENCRYPT under
// for that device pair (null if no session). Decrypting uses
// getDecryptWireKeys below, never this.
async function getOrDeriveWireKey(contactId, theirDeviceId) {
  const session = getX4DHSession(contactId, theirDeviceId);
  if (!session) return null;
  return wireKeyForRoot(x4dhSendRoot(session));
}

// Every key a packet from this device could legitimately be under, most
// likely first: the current root, the retained RK0, then recently retired
// roots (newest first). label tells the caller which one matched —
// "current" is what confirmX4DHPeerKey keys off.
async function getDecryptWireKeys(contactId, theirDeviceId) {
  purgeRetiredX4DHRoots();
  const out = [], seen = new Set();
  const add = async (rootB64, label) => {
    if (!rootB64 || seen.has(rootB64)) return;
    seen.add(rootB64);
    out.push({ key: await wireKeyForRoot(rootB64), label });
  };
  const s = getX4DHSession(contactId, theirDeviceId);
  if (s) { await add(s.rootKey, "current"); await add(s.rk0Root, "prev-rk0"); }
  for (const r of [...(x4dhRetired.get(`${contactId}:${theirDeviceId}`) || [])].reverse()) await add(r.rootB64, "retired");
  return out;
}

// A verified message from this device just decrypted under our CURRENT RK1:
// it provably holds RK1. Switch to sending under RK1 (responder) and retire
// the retained RK0 (both sides) into the decrypt-only grace.
function confirmX4DHPeerKey(contactId, theirDeviceId) {
  const s = getX4DHSession(contactId, theirDeviceId);
  if (!s || s.stage !== "rk1") return;
  const switching = s.sendStage === "rk0";
  if (!switching && !s.rk0Root) return;
  if (s.rk0Root) { retireX4DHRoot(contactId, theirDeviceId, s.rk0Root); delete s.rk0Root; }
  s.sendStage = "rk1";
  saveX4DHSessions();
  mlog.info(`X4DH       peer confirmed RK1 — ${switching ? "now sending under RK1, " : ""}RK0 retired (decrypt-only grace ${X4DH_RETIRED_GRACE_MS / 1000}s)  ${pid(contactId, { deviceId: theirDeviceId })}`);
}

/* ── packet signing ──
   session:propose / session:ack carry no blob — ekPub is a public key,
   not secret, so nothing here needs encryption; the signature is what
   makes it trustworthy. Mandatory signature, same trust tier as
   app:migrate / app:burn / the call and data signaling groups — this
   drives crypto session state, not just display, so an unsigned or
   invalid packet is dropped outright rather than flagged and shown.
── */
function signX4DHPacket(obj) {
  const { type, from, to, sessionEpoch, ekPub, deviceId, ts } = obj;
  return signBlob({ type, from, to, sessionEpoch, ekPub, deviceId: deviceId || null, ts });
}
function verifyX4DHPacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, sessionEpoch, ekPub, deviceId, ts } = obj;
  return verifyBlob({ type, from, to, sessionEpoch, ekPub, deviceId: deviceId || null, ts }, obj.sig, contactSignPublicKey);
}

/* ── automatic trigger (X4DH.md §13.3) ──
   Passive discovery, not a poll: this piggybacks on recordKnownDevice()
   rather than scanning contacts on a timer, because §13.3's whole point
   is that the precondition (theirDeviceId's endpointId known) already
   gets satisfied for free by ordinary traffic — there is no dedicated
   discovery packet to wait on, so there's nothing to poll for either.
   Every call to recordKnownDevice() re-checks whether IT just satisfied
   the precondition for a device we haven't bootstrapped with yet.

   Covers self-pairs too (isFixedInitiator's deviceId tiebreak, §13.1) —
   recordKnownDevice() gets called for self the same passive way it does
   for contacts, mainly via the self-sync backup accept/push handlers.

   x4dhProposeInFlight guards a real race, not a theoretical one:
   recordKnownDevice() can fire twice in quick succession for the same
   device (e.g. two messages arriving back to back), and sendX4DHPropose
   doesn't actually WRITE the new session into state.x4dhSessions until
   after its own await (ephemeral generation + HKDF) completes — so two
   back-to-back calls here could both see "no session yet" and both
   fire, generating two different ephemerals toward the same device. The
   guard is populated synchronously the instant this function decides to
   fire, closing the window before either proposal's own async work has
   a chance to run.
── */
const x4dhProposeInFlight = new Set();   // "contactId:theirDeviceId" — see comment above

function maybeTriggerX4DHPropose(contactId, theirDeviceId) {
  if (!theirDeviceId) return;
  // Only real exclusion left: never propose toward our OWN current
  // device. recordKnownDevice(state.publicId, state.deviceId) fires at
  // login (see getOrCreateDeviceSeed's call site), which would
  // otherwise reach every check below — isFixedInitiator's self-
  // tiebreak treats an exact deviceId match as "not lower"
  // (state.deviceId < state.deviceId is false), so this happens to be
  // safe by coincidence already, but it's cheap enough to make
  // explicit rather than lean on that coincidence holding forever.
  if (contactId === state.publicId && theirDeviceId === state.deviceId) return;
  const contact = state.contacts[contactId];
  if (!contact || contact.blocked || !contact.x25519PublicKey) return;
  // Every bail below is mlog.debug — console-only (see mlog's own
  // definition), deliberately not the in-page 20-line ring buffer.
  // This runs on EVERY recordKnownDevice() call, i.e. every message
  // received from every contact — logging these at info level would
  // drown the in-page log in "skipped" lines for the overwhelmingly
  // common case (a session already exists, or we're not the
  // initiator). Check the browser console, not the in-page widget,
  // when tracing why a specific device pair isn't proposing.
  if (!isFixedInitiator(contactId, theirDeviceId)) {
    mlog.debug(`X4DH       trigger skipped — not fixed initiator  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return;
  }
  const existingSession = getX4DHSession(contactId, theirDeviceId);
  if (existingSession) {
    mlog.debug(`X4DH       trigger skipped — session already exists (stage=${existingSession.stage})  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return;
  }
  const theirEndpoint = state.knownDevices[contactId]?.[theirDeviceId]?.endpointId;
  if (!theirEndpoint) {
    mlog.debug(`X4DH       trigger skipped — no known endpoint yet  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return;
  }

  const key = `${contactId}:${theirDeviceId}`;
  if (x4dhProposeInFlight.has(key)) {
    mlog.debug(`X4DH       trigger skipped — already in flight  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return;
  }
  x4dhProposeInFlight.add(key);
  mlog.debug(`X4DH       trigger firing  ${pid(contactId, { deviceId: theirDeviceId, endpointId: theirEndpoint })}`);
  sendX4DHPropose(contactId, theirDeviceId).finally(() => x4dhProposeInFlight.delete(key));
}

/* ── stuck-at-RK0 detection (X4DH.md §13.2) ──
   Logging is unconditional (subject only to its own cooldown, below);
   AUTOMATIC RETRY is gated separately, on genuine online-transitions
   only — see maybeAutoRetryX4DH. "Stuck" needs a real signal, not just
   elapsed time — a session sitting at RK0 because the OTHER side has
   simply been offline the whole time is completely normal (that's the
   entire point of the async 2DH bootstrap, X4DH.md §5). The signal used
   here is presence: checkStuckX4DHSessions only ever runs from inside
   markOnline(), i.e. only when id has JUST been confirmed online.
   "Stuck" is then just "online right now, AND still at RK0 well past
   the point the original handshake attempt could still be waiting on
   its own."

   Covers both stuck shapes, distinguished by session.initiator:
     - initiator === true  — we sent session:propose and never got
       session:ack back. This is the ONLY shape maybeAutoRetryX4DH ever
       acts on.
     - initiator === false — we received a propose but didn't know the
       sender's endpointId yet. Re-flagging this here on every
       subsequent online sighting is genuinely useful — nothing else
       ever revisits that decision.

   Threshold is 2× X4DH_PROPOSAL_TIMEOUT_MS, not 1×: at 1× the
   pendingX4DHProposals entry has JUST expired — doubling it gives
   clean separation from that boundary rather than racing it.
── */
const X4DH_STUCK_RK0_THRESHOLD_MS = 2 * X4DH_PROPOSAL_TIMEOUT_MS;   // 120s — see comment above for why 2×, not 1×
const X4DH_STUCK_LOG_COOLDOWN_MS  = 5 * 60 * 1000;                  // don't re-flag the same stuck session more than once per 5 min
const _lastStuckX4DHFlag = new Map();   // "contactId:theirDeviceId" -> last-flagged timestamp

// Retry budget — Roadmap.md's "cap attempts (~10), gated on discrete
// online-transition events, not elapsed time." See maybeAutoRetryX4DH.
const MAX_X4DH_RETRY_ATTEMPTS = 10;

function checkStuckX4DHSessions(id, isTransition = false) {
  const devices = state.x4dhSessions[id];
  if (!devices) return;
  const now = Date.now();
  for (const [deviceId, session] of Object.entries(devices)) {
    if (session.stage !== "rk0") continue;   // already upgraded, or a shape this doesn't need to care about
    const stuckForMs = now - (session.establishedAt || 0);
    if (stuckForMs < X4DH_STUCK_RK0_THRESHOLD_MS) continue;   // still within the original handshake's own window — not suspicious yet

    const key = `${id}:${deviceId}`;
    const lastFlagged = _lastStuckX4DHFlag.get(key);
    if (!lastFlagged || (now - lastFlagged) >= X4DH_STUCK_LOG_COOLDOWN_MS) {
      _lastStuckX4DHFlag.set(key, now);
      const role = session.initiator
        ? "we proposed, never got session:ack back"
        : "we received a propose but never sent our own ack (endpoint unknown at the time)";
      mlog.warn(`X4DH       stuck at RK0  ${pid(id, { deviceId })}  epoch=${pid(session.sessionEpoch)}  stuck_for=${Math.round(stuckForMs/1000)}s  (${role})`);
    }

    // Retry is gated on the transition itself, independent of the log
    // cooldown just above — a peer that's been online the whole time
    // doesn't get repeated retries just because five minutes passed and
    // the log line fired again; a peer that drops and reconnects gets a
    // fresh shot immediately even if we only just logged the stuck state
    // moments before disconnecting.
    if (isTransition) maybeAutoRetryX4DH(id, deviceId, session);
  }
}

/* ── automatic retry, gated on online-transitions (Roadmap.md) ──
   Only ever called from checkStuckX4DHSessions on a genuine false→true
   presence edge for the contact. Responder-side stuck sessions
   (session.initiator === false) are deliberately left untouched — there
   is nothing THIS device can do about that shape; the fix is the OTHER
   side re-proposing, not something we can drive from here.

   Budget accounting: retryAttempts counts REAL fired retries (a
   successful call into retryX4DHPropose), not attempts blocked by
   retryX4DHPropose's own internal refusal (no session / wrong stage /
   not the fixed initiator) — a refusal there means nothing was actually
   sent, so it doesn't cost anything from this budget. Boundary: attempts
   0 through MAX_X4DH_RETRY_ATTEMPTS-1 (10 total) each fire a real retry
   and bump the counter to match; the check that runs AFTER the 10th
   successful retry (i.e. attempts already at 10) is what flips to
   exhausted — the 10th attempt itself is not suppressed.

   Re-arm rule: a transition arriving while retryExhaustedAt is set is
   itself the re-arm event — it clears exhaustion and immediately spends
   the first attempt of the new budget in this same call.
── */
async function maybeAutoRetryX4DH(contactId, theirDeviceId, session) {
  if (!session.initiator) return;

  if (session.retryExhaustedAt) {
    mlog.info(`X4DH       auto-retry re-armed by online-transition  ${pid(contactId, { deviceId: theirDeviceId })} — budget reset`);
    session.retryAttempts    = 0;
    session.retryExhaustedAt = null;
  }

  const attempts = session.retryAttempts || 0;
  if (attempts >= MAX_X4DH_RETRY_ATTEMPTS) {
    if (!session.retryExhaustedAt) {
      session.retryExhaustedAt = Date.now();
      await saveX4DHSessions();
      mlog.warn(`X4DH       stuck at RK0, retries exhausted (${attempts}x)  ${pid(contactId, { deviceId: theirDeviceId })} — will retry again after this peer's next reconnect`);
    }
    return;
  }

  mlog.info(`X4DH       auto-retry firing (attempt ${attempts + 1}/${MAX_X4DH_RETRY_ATTEMPTS})  ${pid(contactId, { deviceId: theirDeviceId })}`);
  const ok = await retryX4DHPropose(contactId, theirDeviceId);
  if (!ok) return;   // retryX4DHPropose already logs its own refusal reason — no budget spent

  // retryX4DHPropose → sendX4DHPropose → storeX4DHSessionRK0 has already
  // replaced the session object by this point (preserving retryAttempts/
  // retryExhaustedAt per storeX4DHSessionRK0's own carry-forward) — bump
  // the counter on the FRESH object via a fresh lookup, not the stale
  // `session` reference this function was called with.
  const updated = getX4DHSession(contactId, theirDeviceId);
  if (updated) {
    updated.retryAttempts = attempts + 1;
    updated.lastRetryAt   = Date.now();
    await saveX4DHSessions();
  }
}

/* ── x4dhDebug — console-only, not wired into any UI or automatic path.
   Exists purely to let retry-budget logic (and, later, the epoch-guard
   replay test flagged in Roadmap.md) be exercised without waiting on
   real handshake timing. ── */
window.x4dhDebug = {
  // console.table dump across every contact/device this identity has an
  // X4DH session with — stage, age, initiator role, retry bookkeeping.
  list() {
    const rows = [];
    for (const [contactId, devices] of Object.entries(state.x4dhSessions)) {
      for (const [deviceId, s] of Object.entries(devices)) {
        rows.push({
          contact: pid(contactId), device: pid(deviceId),
          stage: s.stage, initiator: s.initiator,
          ageSec: Math.round((Date.now() - (s.establishedAt || 0)) / 1000),
          retryAttempts: s.retryAttempts || 0,
          exhausted: !!s.retryExhaustedAt,
          deferredAck: !!s.pendingAck,
          sendStage: s.sendStage || s.stage, rk0Kept: !!s.rk0Root,
          epoch: pid(s.sessionEpoch),
        });
      }
    }
    console.table(rows);
    return rows;
  },
  // Thin wrapper over the existing manual helper — uncapped, unaffected
  // by the retry budget above (that budget only gates the AUTOMATIC
  // caller, maybeAutoRetryX4DH).
  retry(contactId, theirDeviceId) {
    return retryX4DHPropose(contactId, theirDeviceId);
  },
  // Manufactures a session sitting at RK0, stuck_for comfortably past
  // X4DH_STUCK_RK0_THRESHOLD_MS, with a chosen starting retryAttempts/
  // exhausted state. Deliberately does NOT fake
  // state.knownDevices[contactId][theirDeviceId].endpointId or override
  // isFixedInitiator's real comparison — both are read live from actual
  // identity material by sendX4DHPropose/retryX4DHPropose. Run
  // x4dhDebug.check() against the SAME pair first to confirm both
  // preconditions actually hold before expecting a retry to fire.
  forceStuck(contactId, theirDeviceId, { retryAttempts = 0, exhausted = false } = {}) {
    if (!state.x4dhSessions[contactId]) state.x4dhSessions[contactId] = {};
    state.x4dhSessions[contactId][theirDeviceId] = {
      sessionEpoch: crypto.randomUUID(), stage: "rk0",
      rootKey: rawToBase64(crypto.getRandomValues(new Uint8Array(32))),
      initiator: true,
      establishedAt: Date.now() - (X4DH_STUCK_RK0_THRESHOLD_MS + 5000),
      upgradedAt: null, proposeTs: Date.now() - (X4DH_STUCK_RK0_THRESHOLD_MS + 5000),
      retryAttempts, retryExhaustedAt: exhausted ? Date.now() : null,
      lastRetryAt: null,
    };
    saveX4DHSessions();
    mlog.info(`X4DH       forceStuck  ${pid(contactId, { deviceId: theirDeviceId })}  retryAttempts=${retryAttempts}  exhausted=${exhausted}`);
  },
  // Drives checkStuckX4DHSessions directly with isTransition=true,
  // without needing a real presence signal to arrive first.
  simulateTransition(contactId) {
    checkStuckX4DHSessions(contactId, true);
  },
  // Diagnostic: surfaces the actual live preconditions retryX4DHPropose/
  // sendX4DHPropose will check, in one call.
  check(contactId, theirDeviceId) {
    const result = {
      isFixedInitiator: isFixedInitiator(contactId, theirDeviceId),
      endpointKnown: state.knownDevices[contactId]?.[theirDeviceId]?.endpointId || null,
      session: getX4DHSession(contactId, theirDeviceId),
    };
    console.table([result]);
    return result;
  },
};

/* ── send side ──
   sendX4DHPropose(contactId, theirDeviceId) — X4DH.md §3/§4. Only ever
   valid to call when isFixedInitiator(contactId, theirDeviceId) is true;
   the automatic trigger (maybeTriggerX4DHPropose, above) is responsible
   for that decision, but this function re-checks and refuses rather
   than trusting every future call site to get it right.

   Requires theirDeviceId's endpointId already on file (§13.3's
   precondition — learned passively the same way ordinary message
   fanout already learns it). If it isn't known yet, there's no compound
   address to propose to, and this bails rather than guessing at a
   broadcast form session:propose deliberately has no meaning for (see
   server.py — a bare `to` is rejected outright for this type).
── */
async function sendX4DHPropose(contactId, theirDeviceId) {
  const contact = state.contacts[contactId];
  if (!contact || contact.blocked || !contact.x25519PublicKey) return false;
  if (!isFixedInitiator(contactId, theirDeviceId)) {
    mlog.warn(`X4DH       refusing to propose — not the fixed initiator  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return false;
  }
  const theirEndpoint = state.knownDevices[contactId]?.[theirDeviceId]?.endpointId;
  if (!theirEndpoint) {
    mlog.debug(`X4DH       propose deferred — no known endpoint yet  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return false;
  }

  const { priv: ekPriv, pub: ekPub } = generateX25519Ephemeral();
  const dh1 = x25519.getSharedSecret(state.x25519Seed, contact.x25519PublicKey);
  const dh2 = x25519.getSharedSecret(ekPriv, contact.x25519PublicKey);
  const rk0 = await deriveX4DHRootStage1(dh1, dh2);

  const sessionEpoch = crypto.randomUUID();
  const proposeTs    = Date.now();   // one value, used for both storage and the outgoing packet's signed `ts` — see storeX4DHSessionRK0's own comment
  const pendingKey   = pendingX4DHKey(contactId, theirDeviceId, sessionEpoch);
  pendingX4DHProposals.set(pendingKey, {
    ekPriv, createdAt: Date.now(), timeoutHandle: schedulePendingX4DHExpiry(pendingKey),
  });
  await storeX4DHSessionRK0(contactId, theirDeviceId, sessionEpoch, rk0, true, proposeTs);

  const obj = {
    type: "session:propose", from: state.publicId, to: buildAddress(contactId, theirEndpoint),
    sessionEpoch, ekPub: Array.from(ekPub), deviceId: state.deviceId, ts: proposeTs,
  };
  obj.sig = signX4DHPacket(obj);
  const viaRelay = sendToRelay(contactId, obj, true);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ X4DH_PROPOSE to   ${pid(contactId, { deviceId: theirDeviceId, endpointId: theirEndpoint })}  epoch=${pid(sessionEpoch)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
  return true;
}

/* ── receive side ──
   handleX4DHPropose(msg) — X4DH.md §6/§7. Always replies immediately.
   Per §6.1/§7.1, the receiving side computes RK0 too before folding in
   DH3/DH4 — cheap (two ECDH calls with material already in hand), not
   skippable under the incremental construction this project settled on.

   Reprocessing the SAME propose twice is a real, confirmed-live-on-
   meshdev desync risk, not a theoretical one: session:propose is
   durably buffered even when live delivery succeeds (same class as
   app:migrate/app:burn), so a brief reconnect shortly after can re-flush
   an already-handled propose. Guarded here the same way the backup/
   restore handshake family already guards against its own near-
   simultaneous redelivery: isDuplicateInbound/DEDUP_WINDOW_MS.
── */
async function handleX4DHPropose(msg) {
  if (!msg.from || !msg.to || !msg.sessionEpoch || !msg.ekPub || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked || !contact.x25519PublicKey) return;
  if (isDuplicateInbound(`x4dh_propose:${msg.from}:${msg.deviceId}:${msg.sessionEpoch}`)) {
    mlog.debug(`← X4DH_PROPOSE from ${pid(msg.from, { deviceId: msg.deviceId })} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  if (!verifyX4DHPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← X4DH_PROPOSE from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  const theirDeviceId = msg.deviceId;
  // §13.1 — a propose from a sender who should never have been the
  // initiator toward us is either a bug or something probing the
  // structural glare-elimination rule. Reject rather than silently
  // playing along.
  if (theirDeviceId && isFixedInitiator(msg.from, theirDeviceId)) {
    mlog.warn(`← X4DH_PROPOSE from ${pid(msg.from, { deviceId: theirDeviceId })} — sender is not the fixed initiator for this pair, dropped`);
    return;
  }
  markOnline(msg.from);

  // X4DH.md §13.2 — refuse a propose that isn't STRICTLY newer than
  // whatever we already adopted for this device.
  const existingSession = getX4DHSession(msg.from, theirDeviceId);
  if (existingSession && existingSession.proposeTs != null && msg.ts <= existingSession.proposeTs) {
    mlog.warn(`← X4DH_PROPOSE from ${pid(msg.from, { deviceId: theirDeviceId })} — stale (ts=${msg.ts} <= existing proposeTs=${existingSession.proposeTs}), refusing to regress session (stage=${existingSession.stage}), dropped`);
    return;
  }

  const ekAPub = new Uint8Array(msg.ekPub);
  const dh1 = x25519.getSharedSecret(state.x25519Seed, contact.x25519PublicKey);
  const dh2 = x25519.getSharedSecret(state.x25519Seed, ekAPub);
  const rk0 = await deriveX4DHRootStage1(dh1, dh2);
  await storeX4DHSessionRK0(msg.from, theirDeviceId, msg.sessionEpoch, rk0, false, msg.ts);

  const theirEndpoint = state.knownDevices[msg.from]?.[theirDeviceId]?.endpointId;
  if (!theirEndpoint) {
    // NOT a "can't happen" — it is the ordinary first-contact race. The
    // initiator proposes the moment it learns OUR endpoint (from our first
    // message to it); the only thing that would tell US its endpoint is its
    // delivery ack, which follows that propose, so the propose can win the
    // race to the relay. §13.3's "already known by now" only holds when the
    // initiator happened to message us first. We can't address a
    // session:ack without a compound `to`, so instead of giving up (the old
    // behaviour left BOTH sides at RK0 until the stuck-retry fired, minutes
    // later) the verified propose is parked on the RK0 session as
    // `pendingAck`, and recordKnownDevice -> maybeCompleteDeferredAck
    // finishes the handshake the moment the endpoint is learned. Everything
    // needed to finish is already on the session (rootKey = RK0) plus the
    // initiator's ephemeral PUBLIC key stored here, so nothing secret is
    // added to what is persisted. Only honoured for X4DH_DEFERRED_ACK_WINDOW_MS.
    // The check above and this set happen in ONE synchronous stretch (no await
    // between them), so an endpoint learned by another handler can't slip
    // into the gap — it either shows up in the lookup above or finds
    // pendingAck already set.
    const session = getX4DHSession(msg.from, theirDeviceId);
    if (session && session.sessionEpoch === msg.sessionEpoch) {
      session.pendingAck = { ekPub: rawToBase64(ekAPub), receivedAt: Date.now() };
      await saveX4DHSessions();
      mlog.info(`← X4DH_PROPOSE from ${pid(msg.from, { deviceId: theirDeviceId })} — endpoint not known yet, ack deferred (up to ${X4DH_DEFERRED_ACK_WINDOW_MS / 1000}s) — session stays at RK0 meanwhile`);
    }
    return;
  }
  await completeX4DHAck(msg.from, theirDeviceId, theirEndpoint, msg.sessionEpoch, ekAPub, rk0);
}

/* ── deferred ack (the first-contact race) ──
   completeX4DHAck is the responder's whole second half — DH3/DH4, upgrade
   to RK1, send session:ack — pulled out of handleX4DHPropose so the direct
   path (endpoint already known) and the deferred path (endpoint learned
   later, maybeCompleteDeferredAck) are the SAME code.

   Upgrades only if the session is STILL the one this propose created
   (upgradeX4DHSessionToRK1's epoch match). If a newer propose replaced it
   during the awaits above, nothing is acked: acking a superseded epoch
   would leave the initiator holding an RK1 we no longer have. (The old
   inline code ignored upgrade's return value and acked regardless.)

   WINDOW. The initiator discards its ephemeral private key after
   X4DH_PROPOSAL_TIMEOUT_MS (60s) and we move to RK1 BEFORE the ack is
   delivered, so a late ack would leave us at RK1 and it at RK0 — each side
   unable to decrypt the other. A deferred ack is therefore only completed
   within X4DH_DEFERRED_ACK_WINDOW_MS (30s) of receiving the propose — half
   the initiator's lifetime, leaving room for transit. Past that we stay at
   RK0 and the existing stuck-retry repairs it, exactly as before this
   change. The real race closes in milliseconds, so the window is only a
   backstop. Must stay well below X4DH_PROPOSAL_TIMEOUT_MS. */
const X4DH_DEFERRED_ACK_WINDOW_MS = 30_000;
const x4dhAckInFlight = new Set();   // "contactId:theirDeviceId" — one completion at a time per device

async function completeX4DHAck(contactId, theirDeviceId, theirEndpoint, sessionEpoch, ekAPub, rk0) {
  const contact = state.contacts[contactId];
  if (!contact || contact.blocked || !contact.x25519PublicKey) return false;

  const { priv: ekBPriv, pub: ekBPub } = generateX25519Ephemeral();
  const dh3 = x25519.getSharedSecret(ekBPriv, contact.x25519PublicKey);
  const dh4 = x25519.getSharedSecret(ekBPriv, ekAPub);
  const rk1 = await deriveX4DHRootStage2(rk0, dh3, dh4);
  if (!(await upgradeX4DHSessionToRK1(contactId, theirDeviceId, sessionEpoch, rk1, "rk0"))) return false;

  const ackObj = {
    type: "session:ack", from: state.publicId, to: buildAddress(contactId, theirEndpoint),
    sessionEpoch, ekPub: Array.from(ekBPub), deviceId: state.deviceId, ts: Date.now(),
  };
  ackObj.sig = signX4DHPacket(ackObj);
  const viaRelay = sendToRelay(contactId, ackObj, true);
  if (!viaRelay) sendSignal(ackObj);
  mlog.info(`→ X4DH_ACK     to   ${pid(contactId, { deviceId: theirDeviceId, endpointId: theirEndpoint })}  epoch=${pid(sessionEpoch)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
  return true;
}

// Called from recordKnownDevice on EVERY observation of a device — so a
// no-op the overwhelming majority of the time (no pendingAck). Fires when
// the endpoint that was missing at propose time has now been learned.
function maybeCompleteDeferredAck(contactId, theirDeviceId) {
  if (!theirDeviceId) return;
  const session = getX4DHSession(contactId, theirDeviceId);
  const pending = session?.pendingAck;
  if (!pending) return;
  const key = `${contactId}:${theirDeviceId}`;
  if (x4dhAckInFlight.has(key)) return;
  const theirEndpoint = state.knownDevices[contactId]?.[theirDeviceId]?.endpointId;
  if (!theirEndpoint) return;   // still unknown — keep waiting

  const ageMs = Date.now() - pending.receivedAt;
  if (session.stage !== "rk0" || session.initiator || ageMs > X4DH_DEFERRED_ACK_WINDOW_MS) {
    delete session.pendingAck;
    saveX4DHSessions();
    mlog.info(ageMs > X4DH_DEFERRED_ACK_WINDOW_MS
      ? `X4DH       deferred ack window expired (${Math.round(ageMs / 1000)}s > ${X4DH_DEFERRED_ACK_WINDOW_MS / 1000}s) — staying at RK0 until the initiator retries  ${pid(contactId, { deviceId: theirDeviceId })}`
      : `X4DH       deferred ack dropped — session no longer a pending responder RK0  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return;
  }

  x4dhAckInFlight.add(key);
  const epoch = session.sessionEpoch;
  (async () => {
    try {
      const ekAPub = base64ToRaw(pending.ekPub);
      const rk0    = base64ToRaw(session.rootKey);   // stage is rk0 (checked above), so this IS RK0
      mlog.info(`X4DH       endpoint learned — completing deferred ack  ${pid(contactId, { deviceId: theirDeviceId, endpointId: theirEndpoint })}  epoch=${pid(epoch)}  after=${Math.round(ageMs)}ms`);
      await completeX4DHAck(contactId, theirDeviceId, theirEndpoint, epoch, ekAPub, rk0);
    } catch(e) {
      mlog.warn(`X4DH       deferred ack failed: ${e.message}  ${pid(contactId, { deviceId: theirDeviceId })}`);
    } finally {
      x4dhAckInFlight.delete(key);
      // a newer propose may have parked ITS pendingAck while we were busy
      const s = getX4DHSession(contactId, theirDeviceId);
      if (s?.pendingAck && s.sessionEpoch !== epoch) maybeCompleteDeferredAck(contactId, theirDeviceId);
    }
  })();
}

// handleX4DHAck(msg) — X4DH.md §6/§7.1. Looks up the pending proposal
// this ack answers; a miss means stale/duplicate/already-upgraded/
// timed-out and is dropped rather than guessed at.
async function handleX4DHAck(msg) {
  if (!msg.from || !msg.to || !msg.sessionEpoch || !msg.ekPub || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked || !contact.x25519PublicKey) return;
  if (!verifyX4DHPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← X4DH_ACK     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  markOnline(msg.from);

  const theirDeviceId = msg.deviceId;
  const key     = pendingX4DHKey(msg.from, theirDeviceId, msg.sessionEpoch);
  const pending = pendingX4DHProposals.get(key);
  if (!pending) {
    mlog.debug(`← X4DH_ACK     from ${pid(msg.from, { deviceId: theirDeviceId })} — no matching pending proposal, dropped`);
    return;
  }

  const session = getX4DHSession(msg.from, theirDeviceId);
  if (!session || session.sessionEpoch !== msg.sessionEpoch) {
    mlog.warn(`← X4DH_ACK     from ${pid(msg.from, { deviceId: theirDeviceId })} — no matching rk0 session on file, dropped`);
    clearTimeout(pending.timeoutHandle);
    pendingX4DHProposals.delete(key);
    return;
  }

  const ekBPub = new Uint8Array(msg.ekPub);
  const dh3    = x25519.getSharedSecret(state.x25519Seed, ekBPub);
  const dh4    = x25519.getSharedSecret(pending.ekPriv, ekBPub);
  const rk0    = base64ToRaw(session.rootKey);
  const rk1    = await deriveX4DHRootStage2(rk0, dh3, dh4);
  await upgradeX4DHSessionToRK1(msg.from, theirDeviceId, msg.sessionEpoch, rk1);

  // Ephemeral private key's job is done — discard it now rather than
  // waiting for its scheduled expiry.
  clearTimeout(pending.timeoutHandle);
  pendingX4DHProposals.delete(key);
  mlog.info(`← X4DH_ACK     from ${pid(msg.from, { deviceId: theirDeviceId })}  epoch=${pid(msg.sessionEpoch)} — session upgraded to RK1`);
}

// retryX4DHPropose(contactId, theirDeviceId) — Roadmap.md's "session
// bootstrap and session reset are the same mechanism" framing: this is
// just sendX4DHPropose called a second time, with a guard in front
// refusing anything that isn't a genuinely stuck initiator-side RK0
// session. Uncapped and manual — the retry BUDGET (MAX_X4DH_RETRY_
// ATTEMPTS) lives entirely in maybeAutoRetryX4DH, the automatic caller;
// this function itself has no memory of how many times it's been
// called and never refuses on that basis.
async function retryX4DHPropose(contactId, theirDeviceId) {
  const session = getX4DHSession(contactId, theirDeviceId);
  if (!session) {
    mlog.warn(`X4DH       retry refused — no session on file  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return false;
  }
  if (session.stage !== "rk0") {
    mlog.warn(`X4DH       retry refused — session not at rk0 (stage=${session.stage})  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return false;
  }
  if (!isFixedInitiator(contactId, theirDeviceId)) {
    mlog.warn(`X4DH       retry refused — not the fixed initiator  ${pid(contactId, { deviceId: theirDeviceId })}`);
    return false;
  }
  mlog.info(`X4DH       retrying propose  ${pid(contactId, { deviceId: theirDeviceId })}  (was stuck at epoch=${pid(session.sessionEpoch)})`);
  return sendX4DHPropose(contactId, theirDeviceId);
}

/* ══════════════════════════════════════════
   PER-DEVICE FANOUT — X4DH-AWARE SEND (this pass)
   Replaces the old "encrypt once, sendFanned(obj)" pattern that used to
   live here — every ordinary message-send path (text/audio/image/
   reaction/system call notice) now goes through this instead. Reuses
   resolveDeviceTargets' existing targeted/broadcast split UNCHANGED —
   only what happens to EACH targeted device is new: a device with ANY
   X4DH session on file (rk0 or rk1 — see the design discussion this
   pass came out of for why rk0 is included) gets its OWN ciphertext,
   encrypted with that device's own wire key (getOrDeriveWireKey),
   addressed directly. A device with no session yet falls back to the
   legacy identity-level contact.encKey — still addressed directly if
   its endpoint is known, so per-device ROUTING is unaffected either
   way; only KEY SELECTION is new, and only once a session exists.

   The broadcast fallback (bare `to`, unresolved/no-known-devices case)
   always uses the legacy key — there's no single device to derive an
   X4DH key FOR when addressing "every live session under this identity"
   at once, so this path is unchanged from before X4DH existed.

   blob/sig now legitimately DIFFER per destination (unlike the old
   sendFanned, where one blob/sig pair was reused verbatim everywhere)
   — this is the actual point of moving to per-device keys, not an
   oversight. Callers cache only fanned.envelopes[0] in packetCache for
   the ⓘ inspector — the payload is identical across every copy, so one
   representative envelope is enough to inspect wire shape/sig format;
   showing all N per-device ciphertexts wasn't judged worth the extra
   UI complexity for a debug feature.
══════════════════════════════════════════ */
async function sendFannedX4DH(contactId, payload) {
  const contact = state.contacts[contactId];
  const { targeted, needsBroadcast } = resolveDeviceTargets(contactId);
  let sent = false;
  let x4dhCount = 0, legacyCount = 0;
  const envelopes = [];

  for (const { deviceId, endpointId } of targeted) {
    const wireKey = await getOrDeriveWireKey(contactId, deviceId);
    const key = wireKey || contact.encKey;
    const obj = await sealEnvelope("app:message", state.publicId, buildAddress(contactId, endpointId), key, payload);
    const viaRelay = sendToRelay(contactId, obj, true);
    if (!viaRelay) sendSignal(obj);
    sent = sent || viaRelay || state.ws?.readyState === WebSocket.OPEN;
    if (wireKey) x4dhCount++; else legacyCount++;
    envelopes.push(obj);
  }

  if (needsBroadcast) {
    const obj = await sealEnvelope("app:message", state.publicId, contactId, contact.encKey, payload);
    const viaRelay = sendToRelay(contactId, obj, true);
    if (!viaRelay) sendSignal(obj);
    sent = sent || viaRelay || state.ws?.readyState === WebSocket.OPEN;
    legacyCount++;
    envelopes.push(obj);
  }

  return { sent, targetedCount: targeted.length, broadcastSent: needsBroadcast, x4dhCount, legacyCount, envelopes };
}

/* ══════════════════════════════════════════
   PEER BACKUP DISTRIBUTION
   Protocol (non-self peers):
     1. sender → backup_offer  { from, to, size, ts, sig }
     2. receiver → backup_accept { from, to, ts, sig } (only if willing)
     3. sender → backup_push   { from, to, blob, ts, sig }
   Self-sync skips the offer step (always accepted) and is unaffected by
   anything below — its `from` stays bare state.publicId, unchanged.
   Constrained peers (C64 etc.) can simply never
   send backup_accept and they will never receive blobs.

   As of this pass, the blob offered/pushed to a non-self peer carries
   CONTACTS ONLY — messages: [] on every entry (serialiseContactsForPeers,
   see its own comment). Self-sync's own blob (below, id === state.publicId)
   is untouched and still carries full history. A contact restoring after
   a wipe recovers their contact list from whichever peers still hold a
   copy of them; recovering message HISTORY still relies on the other
   half of each conversation existing on the contact's own device (manual
   SYNC, or normal delivery), same as it always has for a brand-new device
   with nothing local yet.

   `from` on these three types carries our own compound "id::endpointId"
   address (buildAddress) — the ONE deliberate exception to "from always
   stays bare" (see ADDR_SEP's own comment in meshchat-lib.js and
   protocol.md's Compound Addressing section for the general rule this
   departs from). Every other packet type in the app is unaffected.

   Why here specifically: self-sync can wrap deviceId/endpointId inside
   its blob because sender and recipient share one key (same identity).
   app:message can do the same because by the time a message exists, the
   pairwise ECDH key already works. backup_offer has neither guarantee —
   it may be reaching a contact who hasn't added the sender back yet, so
   there may be no shared key material at all. Plaintext-on-the-address is
   the only channel guaranteed to reach a genuinely fresh/not-yet-mutual
   recipient, so that's what carries it here, same tier of exposure the
   relay's own auth-time endpoint_id already has.

   Signed regardless — every send below is signed with the identity's
   Ed25519 key (signHandshakePacket), even though verification is only ever
   POSSIBLE once the recipient already has this sender as a contact (needs
   their signPublicKey, same precondition encryption already has here).
   An unverifiable packet (no sig, or sender unknown) is processed exactly
   as this handshake always has been — bootstrap must keep working. Only
   an ACTIVELY WRONG signature (sig present, sender's key on file, doesn't
   check out — i.e. tampered in transit by the untrusted relay) is treated
   as tampering and dropped, logged either way.

   NOTE: self-sync/backup traffic is deliberately OUT OF SCOPE for the
   X4DH wire-key work above — it stays on state.cryptoKey (the backup
   key) exactly as before. That's a different key hierarchy protecting
   different content (encrypted contact-store snapshots, not live
   message transit) and was never part of what this pass touches.

   Reused (not backup-specific despite the name history) by sync:restore_ack
   and sync:restore_push — both reachable from a non-mutual/unknown sender
   too, via sig:seen's fresh-device bootstrap ping (see handleSignal), so
   they need this exact same soft stance. sync:restore_req is the one
   sibling type that does NOT use this pair — see signRestorePacket below,
   which is deliberately stricter because that type can only ever be
   decrypted by an already-mutual contact in the first place.
══════════════════════════════════════════ */

// `ek` (step 4 — one-shot restore-push wrap, see pendingRestoreEk below)
// is included in the signed set ONLY when the object being signed
// actually carries one. A packet with no `ek` field produces the exact
// same signed payload as before this pass — old clients, and new clients
// that simply aren't using the wrap this round, stay byte-for-byte
// compatible in both signing directions. Only two same-version parties,
// both including `ek`, need to agree on the signed shape — which they do,
// by construction, since both run this same function.
function signHandshakePacket(obj) {
  const { type, from, to, size, ts, blob, ek } = obj;
  const payload = { type, from, to, size: size ?? null, ts, blob: blob || null };
  if (ek !== undefined) payload.ek = ek;
  return signBlob(payload);
}
function verifyHandshakePacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, size, ts, blob, ek } = obj;
  const payload = { type, from, to, size: size ?? null, ts, blob: blob || null };
  if (ek !== undefined) payload.ek = ek;
  return verifyBlob(payload, obj.sig, contactSignPublicKey);
}

// Tracks which peers we have a pending offer waiting for accept. Bare
// identity, deliberately NOT per-device — the blob offered is the same
// regardless of which of that identity's devices ends up accepting it,
// so there's nothing device-specific to key on at OFFER time. What used
// to matter (and was the bug) is what happens on ACCEPT: see
// handleBackupAccept's own comment on why this entry now survives past
// the first accept it satisfies, for the rest of its TTL.
const pendingBackupOffer = {};   // id → { blob, ts }

/* ══════════════════════════════════════════
   SELF-SYNC BACKUP — key resolution + discovery hello
   The self branch of the backup handshake used to encrypt everything under
   state.cryptoKey, the passphrase-derived backup key: deterministic, so
   recorded traffic plus a later passphrase compromise exposes every full
   push and ack ever sent. It now rides the X4DH self-sessions instead
   (see pushBackupToContacts' self branch for the sending rules).

   decryptSelfBackupBlob mirrors decryptIncomingMessage: the blob carries
   no key hint (deviceId is inside it, by design), so every self-session
   wire key is tried, newest session first, then the backup key last. A
   wrong-key attempt fails cleanly on AES-GCM's tag, so this is a handful
   of rejected decrypts at worst, never a false positive. Returns
   wireDeviceId = the sibling whose session key worked, or null if it was
   the backup key. Throws if every candidate fails.
══════════════════════════════════════════ */
const isIdLike = (s) => typeof s === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(s);

const SELF_HELLO_COOLDOWN_MS = 60_000;   // discovery hello is tiny, but backup cycles fire on every couple of messages — don't spam siblings with acks
let   lastSelfHelloSent      = 0;

async function decryptSelfBackupBlob(blob, aad) {
  const sessions   = state.x4dhSessions[state.publicId] || {};
  const candidates = Object.entries(sessions)
    .sort(([, a], [, b]) => (b.establishedAt || 0) - (a.establishedAt || 0));
  for (const [theirDeviceId] of candidates) {
    for (const { key, label } of await getDecryptWireKeys(state.publicId, theirDeviceId)) {
      try {
        const plain = await decryptObject(key, blob, aad);
        // self blobs carry no signature, but AES-GCM success under RK1 is the
        // same proof of possession — see confirmX4DHPeerKey
        if (label === "current") confirmX4DHPeerKey(state.publicId, theirDeviceId);
        return { plain, wireDeviceId: theirDeviceId };
      } catch(e) { /* wrong key — try the next generation / sibling */ }
    }
  }
  return { plain: await decryptObject(state.cryptoKey, blob, aad), wireDeviceId: null };
}

// Receive side of the discovery hello. Learns the sibling (which can
// trigger X4DH bootstrap via recordKnownDevice) and answers with a small
// targeted ack. Under a session key — and with our fingerprint — if we
// already hold a session with that device; otherwise a content-free ack
// (deviceId + endpointId only) under the backup key.
async function handleSelfHello(plain) {
  if (plain.deviceId === state.deviceId) return;   // own echo
  if (isDuplicateInbound(`self_hello:${plain.deviceId}`)) {
    mlog.debug(`← BACKUP_HELLO from self  ${pid(state.publicId, { deviceId: plain.deviceId })} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  const helloEndpoint = isIdLike(plain.endpointId) ? plain.endpointId : undefined;
  mlog.info(`← BACKUP_HELLO from self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: helloEndpoint })}`);
  recordKnownDevice(state.publicId, plain.deviceId, undefined, helloEndpoint);

  const sessionKey = await getOrDeriveWireKey(state.publicId, plain.deviceId);
  const ackPayload = { deviceId: state.deviceId, endpointId: state.endpointId };
  if (sessionKey) ackPayload.fingerprint = await computeBackupFingerprint();
  const ackTo   = buildAddress(state.publicId, helloEndpoint);
  const ackBlob = await encryptObject(sessionKey || state.cryptoKey, ackPayload, envelopeAad("sync:backup_accept", state.publicId, ackTo));
  sendSignal({ type: "sync:backup_accept", from: state.publicId, to: ackTo, blob: ackBlob });
  mlog.debug(`→ BACKUP_ACK   to self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: helloEndpoint })} — ${sessionKey ? "session key, with fingerprint" : "content-free"}`);
}

async function pushBackupToContacts(blob) {
  for (const id of Object.keys(state.contacts)) {
	const contact = state.contacts[id];
    const onOwnRelay = state.online.has(id) && 
	  (!contact.lastRelay || contact.lastRelay === state.contacts[state.publicId]?.lastRelay);
	const hasOpenRelay = contact.lastRelay && 
	  relayConns[relayHostname(contact.lastRelay)]?.outbound;
	if (!onOwnRelay && !hasOpenRelay) continue;

	if (id === state.publicId) {
		// self-sync: no negotiation needed, push directly — but NEVER under the
		// deterministic backup key alone. A full push carries serialiseContacts()
		// (contacts + recent messages), and recorded traffic plus a later
		// passphrase compromise would hand all of it over. So:
		//
		//   - A sibling we know (fresh, endpointId on file) AND hold an X4DH
		//     self-session with gets a TARGETED full push encrypted under that
		//     session's wire key (getOrDeriveWireKey) — the same per-device key
		//     app:message already rides. Skipped when its fingerprint (learned
		//     from an ack) already matches ours.
		//   - Anything we can't do that for — no sibling known yet, one whose
		//     endpointId is unknown or stale, or one with no session yet — gets
		//     a content-free discovery HELLO instead: { deviceId, endpointId,
		//     hello:true } under the backup key, broadcast to our own identity.
		//     No contacts, no fingerprint. The hello's only job is to let
		//     siblings learn this device (recordKnownDevice), which is what
		//     bootstraps the X4DH self-session the next push rides.
		//
		// Cost of this: a brand-new sibling gets contacts from the next push
		// after its session exists, not instantly. (A genuinely wiped device
		// still restores immediately via the wrapped restore_ack/restore_push
		// path, which is unaffected.) The hello still exposes the
		// deviceId<->endpointId link to anyone holding recorded traffic plus
		// the passphrase — metadata only, accepted for the discovery step.
		try {
			const fingerprint = await computeBackupFingerprint();
			const { targeted, needsBroadcast } = resolveDeviceTargets(state.publicId);
			let sent = 0, current = 0, noSession = 0;
			let selfPayload = null;

			for (const { deviceId: devId, endpointId: devEndpoint } of targeted) {
				if (state.knownDeviceFingerprints[devId] === fingerprint) { current++; continue; }
				const wireKey = await getOrDeriveWireKey(state.publicId, devId);
				if (!wireKey) { noSession++; continue; }
				// deviceId/endpointId/fingerprint ride INSIDE the encrypted blob, never
				// as outer envelope fields (an unsigned outer field is silently
				// rewritable by the relay). Self-sync backup packets carry no `sig`,
				// so this is tamper-EVIDENCE (AES-GCM) rather than the sender
				// authentication app:message's Ed25519 signature provides.
				if (!selfPayload) selfPayload = {
					deviceId: state.deviceId, endpointId: state.endpointId, fingerprint,
					contacts: serialiseContacts(),
				};
				const pushTo = buildAddress(id, devEndpoint);
				const blob = await encryptObject(wireKey, selfPayload, envelopeAad("sync:backup_push", state.publicId, pushTo));
				sendSignal({ type: "sync:backup_push", from: state.publicId, to: pushTo, blob });
				sent++;
				mlog.info(`→ BACKUP_PUSH  to self — targeted, session key  ${pid(state.publicId, { deviceId: devId, endpointId: devEndpoint })}`);
			}

			const wantsHello = needsBroadcast || noSession > 0;
			if (wantsHello && (Date.now() - lastSelfHelloSent) > SELF_HELLO_COOLDOWN_MS) {
				lastSelfHelloSent = Date.now();
				const helloBlob = await encryptObject(state.cryptoKey, {
					deviceId: state.deviceId, endpointId: state.endpointId, hello: true,
				}, envelopeAad("sync:backup_push", state.publicId, id));
				sendSignal({ type: "sync:backup_push", from: state.publicId, to: id, blob: helloBlob });
				mlog.info(`→ BACKUP_PUSH  to self — content-free hello  (${needsBroadcast ? "device(s) unknown/unresolved/stale" : ""}${needsBroadcast && noSession ? ", " : ""}${noSession ? noSession + " without a session yet" : ""})`);
			}
			if (!sent && !wantsHello) {
				mlog.debug(`→ BACKUP_PUSH  to self — nothing to send (${current} sibling(s) already current)`);
			}
		} catch(e) {
			mlog.warn(`→ BACKUP_PUSH  to self — failed: ${e.message}`);
		}
		continue;
    }

    // estimate wire size before sending
    const size = JSON.stringify(blob).length;
    const offerTs = Date.now();
    pendingBackupOffer[id] = { blob, ts: offerTs };
    const offerObj = { type: "sync:backup_offer", from: buildAddress(state.publicId, state.endpointId), to: id, size, ts: offerTs };
    offerObj.sig = signHandshakePacket(offerObj);
    sendSignal(offerObj);
    mlog.info(`→ BACKUP_OFFER to   ${pid(id)}  size=${size}`);
  }
}

// replyAddress(fromId, fromEndpoint, verified) — where a REPLY in the
// backup/restore handshake family should be addressed.
//
// These handshakes open with a packet addressed to a bare identity, which
// the relay fans out to every live session under it. Everything that
// answers it used to be addressed bare too, so with two devices under one
// identity every reply also fanned out — and each reply is wrapped for ONE
// specific one-shot ephemeral, so the copy landing on the wrong device (or
// arriving at a slot keyed for a different device) could never unwrap.
// The opening packet's `from` already names the exact device that sent it
// ("id::endpointId"), so once its signature has verified, answer that one
// device only: one packet in, one reply out, one matching ephemeral.
//
// Falls back to the bare identity when the sender's endpoint is unknown
// (older client) or the packet couldn't be verified (fresh/not-yet-mutual
// sender) — an unverified endpoint suffix isn't trusted for anything, same
// rule the log annotation already follows. Bare fallback keeps bootstrap
// working exactly as before; multiple responders are unavoidable there, and
// pendingEkCandidates' broad search is what covers that case.
function replyAddress(fromId, fromEndpoint, verified) {
  return (verified && fromEndpoint) ? buildAddress(fromId, fromEndpoint) : fromId;
}

async function handleBackupOffer(msg) {
  if (!msg.from || !msg.size || !isAddressedToMe(msg.to)) return;
  const { id: fromId, endpoint: fromEndpoint } = parseAddress(msg.from);
  if (!fromId) { mlog.warn(`← BACKUP_OFFER  bad 'from' address, dropped`); return; }
  if (state.contacts[fromId]?.blocked) return;

  // Verification is only possible once we already have this sender as a
  // contact (their signPublicKey) — a genuinely fresh/not-yet-mutual
  // sender can still reach us here, same as this handshake has always
  // allowed. Only an ACTIVE verification failure (sig present, key on
  // file, doesn't check out) is treated as tampering and dropped.
  const contact    = state.contacts[fromId];
  const verifiable = !!(msg.sig && contact?.signPublicKey);
  const verified   = verifiable && verifyHandshakePacket(msg, contact.signPublicKey);
  if (verifiable && !verified) {
    mlog.warn(`← BACKUP_OFFER from ${pid(fromId)} — signature invalid, dropped`);
    return;
  }

  // Second trigger for the cross-relay bootstrap — see
  // pingRestoreIfFreshStranger. A fresh device accepts this offer from a
  // stranger and then drops the push (nothing to store it under); the offer
  // is still useful as proof the holder is reachable, so ping before the
  // dedup below can suppress anything.
  if (!contact) pingRestoreIfFreshStranger(fromId, "backup_offer");

  // Dedup AFTER verification, keyed on the sender's endpoint once verified.
  // Accepts are now targeted at the one device that offered (see
  // replyAddress), so a second, genuinely distinct sibling device offering
  // within the same few seconds MUST get its own accept — an identity-level
  // key here would swallow it as a "duplicate" and that device would never
  // receive an accept at all (before targeting, the first device's
  // broadcast accept happened to cover it by accident).
  const offerDedupKey = `backup_offer:${fromId}${verified && fromEndpoint ? ":" + fromEndpoint : ""}`;
  if (isDuplicateInbound(offerDedupKey)) {
    mlog.debug(`← BACKUP_OFFER from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  markOnline(fromId);

  // accept unconditionally — a constrained peer would simply not implement this handler
  mlog.info(`← BACKUP_OFFER from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})}  size=${msg.size}  sig:${verified ? "✓" : "·"} — accepting`);
  const acceptTs  = Date.now();
  const acceptObj = { type: "sync:backup_accept", from: buildAddress(state.publicId, state.endpointId), to: replyAddress(fromId, fromEndpoint, verified), ts: acceptTs };
  if (verified) attachBackupEk(acceptObj, fromId, fromEndpoint);
  acceptObj.sig = signHandshakePacket(acceptObj);
  sendSignal(acceptObj);
}

async function handleBackupAccept(msg) {
  if (!msg.from || !isAddressedToMe(msg.to)) return;
  const { id: fromId, endpoint: fromEndpoint } = parseAddress(msg.from);
  if (!fromId) return;
  markOnline(fromId);   // covers both branches below — self-sync's own `from` is always bare, so fromId === msg.from there

  // device-fingerprint ack (self-sync freshness tracking) — disambiguated
  // from the normal contact-offer accept by the presence of `blob`, which
  // the regular contact handshake (handleBackupOffer's reply, just above)
  // never sets. deviceId/endpointId/fingerprint no longer appear as outer
  // fields at all — see the push side's comment for why — so blob presence
  // is the only signal left to branch on here.
  if (msg.blob) {
    try {
      // Same key resolution as the push side: session keys first, backup key
      // last. A content-free ack (reply to a discovery hello, sent before a
      // session exists) simply carries no fingerprint.
      const { plain, wireDeviceId } = await decryptSelfBackupBlob(msg.blob, envelopeAad(msg.type, msg.from, msg.to));
      if (!plain?.deviceId || plain.deviceId === state.deviceId) return;  // malformed, or own echo (shouldn't happen)
      if (!isIdLike(plain.deviceId)) return;
      if (wireDeviceId && plain.deviceId !== wireDeviceId) {
        mlog.warn(`← BACKUP_ACK   from self — decrypted under ${pid(wireDeviceId)}'s session key but payload claims deviceId=${pid(plain.deviceId)}, dropped`);
        return;
      }
      // Self-sync carries no signature to verify (see protocol.md), so
      // deviceId — trustworthy the moment decrypt succeeds, since decrypt
      // itself requires a key only this identity's own devices hold — is
      // what dedup keys on here instead of an endpoint.
      // Keyed on whether the ack carries a fingerprint: a content-free ack
      // (reply to a discovery hello) must not shadow a real fingerprint ack
      // arriving moments later from the same sibling, or we'd lose the
      // "this device is current" fact and re-push for nothing.
      if (isDuplicateInbound(`backup_accept_self:${plain.deviceId}${plain.fingerprint ? "" : ":nofp"}`)) {
        mlog.debug(`← BACKUP_ACK   from self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: plain.endpointId })} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
        return;
      }
      const ackEndpoint = isIdLike(plain.endpointId) ? plain.endpointId : undefined;
      // Always learn the sibling — this is what lets a content-free hello
      // bootstrap a self X4DH session (recordKnownDevice → maybeTriggerX4DHPropose).
      recordKnownDevice(state.publicId, plain.deviceId, undefined, ackEndpoint);
      if (plain.fingerprint) {
        state.knownDeviceFingerprints[plain.deviceId] = plain.fingerprint;
        mlog.debug(`← BACKUP_ACK   from self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: ackEndpoint })} — fingerprint recorded${wireDeviceId ? "  (session key)" : ""}`);
      } else {
        mlog.debug(`← BACKUP_ACK   from self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: ackEndpoint })} — content-free ack, device learned`);
      }
    } catch(e) {
      mlog.warn(`← BACKUP_ACK   decrypt failed`);
    }
    return;
  }

  // plain contact-offer accept — from here down mirrors handleBackupOffer's
  // verification stance exactly: unverifiable (no sig / sender not yet a
  // contact) proceeds as this handshake always has; an ACTIVE verification
  // failure is dropped.
  const contact    = state.contacts[fromId];
  const verifiable = !!(msg.sig && contact?.signPublicKey);
  const verified   = verifiable && verifyHandshakePacket(msg, contact.signPublicKey);
  // Endpoint-aware once verified — otherwise a second of the sender's own
  // devices genuinely accepting within the same few seconds would collapse
  // into one identity-level dedup slot and get silently swallowed as a
  // "duplicate" of the first, the same cross-device suppression bug the
  // restore-cooldown split fixed. Falls back to bare fromId when
  // unverified, same tier as everywhere else in this handshake family.
  const dedupKey = `backup_accept:${fromId}${verified && fromEndpoint ? ":" + fromEndpoint : ""}`;
  if (isDuplicateInbound(dedupKey)) {
    mlog.debug(`BACKUP_ACCEPT  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  if (verifiable && !verified) {
    mlog.warn(`BACKUP_ACCEPT  from ${pid(fromId)} — signature invalid, dropped`);
    return;
  }

  const pending = pendingBackupOffer[fromId];
  if (!pending) {
    mlog.debug(`BACKUP_ACCEPT  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — no pending offer, ignored`);
    return;
  }
  // honour TTL — don't send a stale blob
  if (Date.now() - pending.ts > BACKUP_OFFER_TTL) {
    delete pendingBackupOffer[fromId];
    mlog.warn(`BACKUP_ACCEPT  from ${pid(fromId)} — offer expired, ignored`);
    return;
  }
  // Wrap (same one-shot ephemeral mechanism as the restore-push wrap —
  // see pendingBackupEk above). Only when the OFFER's ack verified and
  // carried an ephemeral (handleBackupOffer only attaches one when
  // `verified` there was true, so msg.ek here already implies that —
  // this re-check just keeps the gate explicit and self-contained rather
  // than relying on the sender having done the right thing). Wrap
  // failure falls back to sending the plain blob rather than dropping it
  // — the recipient still needs their backup stored, and unwrapped is
  // exactly today's behavior, not a downgrade below anything working now.
  let outBlob = pending.blob, ek = null;
  if (verified && msg.ek) {
    try {
      const theirEk = new Uint8Array(msg.ek);
      const { priv, pub } = generateX25519Ephemeral();
      const shared  = x25519.getSharedSecret(priv, theirEk);
      const wrapKey = await deriveEphemeralWrapKey(shared);
      outBlob = await encryptObject(wrapKey, pending.blob);
      ek = Array.from(pub);
    } catch(e) {
      mlog.warn(`BACKUP_PUSH    wrap failed for ${pid(fromId)}, sending unwrapped: ${e.message}`);
      outBlob = pending.blob; ek = null;
    }
  }
  // Deliberately NOT deleted here anymore. backup_offer's `to` is a bare
  // identity, so it broadcasts to every live session under it — an
  // identity running two-plus devices legitimately produces two-plus
  // independent accepts in reply to the ONE offer, each with its own ek.
  // Consuming pendingBackupOffer[fromId] on the first accept meant only
  // ONE of those devices ever got a push generated for it at all; the
  // rest found nothing here (a debug-only "no pending offer, ignored"
  // line above) and simply never received a working backup — no crash,
  // just a device that silently never got backed up until some later
  // offer cycle happened to have it accept first instead. The blob itself
  // (`pending.blob`) is identical no matter which device accepts, so
  // there's no correctness reason to serve only one; each accept within
  // the TTL window above now gets its own push, wrapped with THAT
  // accept's own ek. The entry is cleared only by the expiry check above
  // once BACKUP_OFFER_TTL has genuinely passed, or implicitly replaced
  // the next time pushBackupToContacts sends a fresh offer.
  const pushTs  = Date.now();
  const pushObj = { type: "sync:backup_push", from: buildAddress(state.publicId, state.endpointId), to: replyAddress(fromId, fromEndpoint, verified), blob: outBlob, ts: pushTs };
  if (ek) pushObj.ek = ek;
  pushObj.sig = signHandshakePacket(pushObj);
  sendSignal(pushObj);
  mlog.info(`→ BACKUP_PUSH  to   ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})}  sig:${verified ? "✓" : "·"} — accepted${ek ? "  +wrap" : ""}`);
}

async function handleBackupPush(msg) {
  if (!msg.from || !msg.blob || !isAddressedToMe(msg.to)) return;
  const { id: fromId, endpoint: fromEndpoint } = parseAddress(msg.from);
  if (!fromId) return;
  if (state.contacts[fromId]?.blocked) return;
  markOnline(fromId);   // self-sync's own `from` is always bare, so fromId === msg.from there

	if (fromId === state.publicId) {
		try {
		  // Key resolution: any X4DH self-session wire key first, backup key
		  // last — see decryptSelfBackupBlob. wireDeviceId is set only when a
		  // session key was the one that worked.
		  const { plain, wireDeviceId } = await decryptSelfBackupBlob(msg.blob, envelopeAad(msg.type, msg.from, msg.to));
		  if (typeof plain !== "object" || plain === null || Array.isArray(plain)) return;

		  // Content-free discovery hello — { deviceId, endpointId, hello:true },
		  // no contacts, no fingerprint. See pushBackupToContacts' self branch.
		  // A genuine contacts map can never be mistaken for this: its keys are
		  // publicIds, and `contacts` must be absent.
		  if (plain.hello === true && isIdLike(plain.deviceId) && !plain.contacts) {
			await handleSelfHello(plain);
			return;
		  }

		  // Two self-push shapes share this handler: the periodic full-
		  // backup push, wrapped as { deviceId, endpointId, fingerprint,
		  // contacts } (see pushBackupToContacts) — and the RETIRED pushMiniBackup's (still
		  // accepted here so older clients' pushes keep working)
		  // slim single-contact push, still a bare { contactId: {...} }
		  // map with no deviceId/fingerprint at all, since it never
		  // participated in the fingerprint-tracking dance. Disambiguated
		  // by a string deviceId alongside an object contacts — never
		  // ambiguous with a genuine contacts map, whose top-level keys
		  // are publicIds, never the literal string "deviceId".
		  const isWrapped   = typeof plain.deviceId === "string" && typeof plain.contacts === "object";
		  const contactsMap = isWrapped ? plain.contacts : plain;

		  // own-echo guard — only ever meaningful for the wrapped shape; a
		  // mini-backup carries no deviceId to compare and was never
		  // subject to this guard even before deviceId moved inside the blob.
		  if (isWrapped && plain.deviceId === state.deviceId) return;

		  // Same cross-check receiveMessage does: a decrypt under a specific
		  // sibling's session key can only have been produced by that device
		  // pair, so the payload's own deviceId claim must agree.
		  if (isWrapped && wireDeviceId && plain.deviceId !== wireDeviceId) {
			mlog.warn(`← BACKUP_PUSH  from self — decrypted under ${pid(wireDeviceId)}'s session key but payload claims deviceId=${pid(plain.deviceId)}, dropped`);
			return;
		  }
		  // A full push under the static backup key is what a pre-0.5.7 sibling
		  // sent. Those can no longer arrive here (self blobs are envelope-bound
		  // since 0.5.7), so this only fires for a modified client — logged, not dropped.
		  if (isWrapped && !wireDeviceId) {
			mlog.info(`← BACKUP_PUSH  from self — full push under static backup key (legacy sender)`);
		  }

		  // Dedup on deviceId, same reasoning as handleBackupAccept's self
		  // branch — no signature on self-sync traffic to key an endpoint
		  // check off, but decrypt succeeding already proves it's genuinely
		  // one of our own devices. Skipped for a mini-backup (isWrapped
		  // false): no deviceId to key on there, and re-merging the same
		  // slim single-contact push twice is a harmless no-op anyway.
		  if (isWrapped && isDuplicateInbound(`backup_push_self:${plain.deviceId}`)) {
			mlog.debug(`← BACKUP_PUSH  from self  ${pid(state.publicId, { deviceId: plain.deviceId, endpointId: plain.endpointId })} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
			return;
		  }

		  const restored      = await deserialiseContacts(contactsMap);
		  const prevSelfRelay = state.contacts[state.publicId]?.lastRelay;
		  for (const [id, contact] of Object.entries(restored)) {
			if (!state.contacts[id]) state.contacts[id] = contact;
			else {
			  mergeContactMeta(state.contacts[id], contact);
			  state.contacts[id].messages = mergeMessages(state.contacts[id].messages, contact.messages);
			  reconcileDeliveryStatus(state.contacts[id]);
			  reconcileMissingDevices(state.contacts[id]);
			}
		  }
		  await saveContacts();
		  renderContactList();
		  if (state.currentChat) renderMessages();
		  mlog.info(`← BACKUP_PUSH  from self  ${isWrapped ? pid(state.publicId, { deviceId: plain.deviceId, endpointId: plain.endpointId }) : pid(state.publicId)} — merged other-me`);
		  if (state.contacts[state.publicId]?.lastRelay !== prevSelfRelay) {
			mlog.info(`BACKUP_PUSH    self relay changed via other device — rebooting signal`);
			rebootSignal();
		  }

		  if (!isWrapped) return;   // mini-backup — no fingerprint tracking, no ack, done here

		  // record sender's fingerprint, then ack back with our own post-merge
		  // fingerprint — reuses backup_accept's shape, disambiguated (on the
		  // receiving end, in handleBackupAccept) by the presence of `blob`,
		  // which the normal contact handshake never sets.
		  if (plain.fingerprint) {
			state.knownDeviceFingerprints[plain.deviceId] = plain.fingerprint;
			recordKnownDevice(state.publicId, plain.deviceId, undefined, plain.endpointId);
		  }
		  const ownFingerprint = await computeBackupFingerprint();
		  // plain.endpointId just arrived on this very push — target the
		  // ack straight back to the device that sent it when we have
		  // it, rather than broadcasting a small ack to every live
		  // self-session. Falls back to broadcast if this particular
		  // push came from an endpointId-less sender (older client).
		  // deviceId/endpointId/fingerprint ride inside the ack's own
		  // small encrypted blob, same reasoning as the push above — the
		  // `to` address's optional "::endpointId" unit stays outside
		  // since the relay genuinely needs it to route.
		  // Ack under the same class of key the push arrived under: a session
		  // key when the sender used one, the backup key otherwise (an older
		  // sender can only decrypt that).
		  const ackKey  = wireDeviceId ? await getOrDeriveWireKey(state.publicId, wireDeviceId) : null;
		  const ackTo   = buildAddress(state.publicId, plain.endpointId);
		  const ackBlob = await encryptObject(ackKey || state.cryptoKey, {
			  deviceId: state.deviceId, endpointId: state.endpointId, fingerprint: ownFingerprint,
		  }, envelopeAad("sync:backup_accept", state.publicId, ackTo));
		  sendSignal({ type: "sync:backup_accept", from: state.publicId, to: ackTo, blob: ackBlob });
		  mlog.debug(`→ BACKUP_ACK   to self  ${plain.endpointId ? pid(state.publicId, { deviceId: plain.deviceId, endpointId: plain.endpointId }) : pid(state.publicId)} — fingerprint ${ownFingerprint}${plain.endpointId ? "" : "  (broadcast — sender endpoint unknown)"}`);
		} catch(e) {
		  mlog.warn(`← BACKUP_PUSH  from self — decrypt failed`);
		}
		return;
	}

  if (!state.contacts[fromId]) {
    mlog.warn(`← BACKUP_PUSH  from ${pid(fromId)} — unknown contact, dropped`);
    return;
  }

  // Same verification stance as handleBackupOffer/handleBackupAccept:
  // unverifiable (no sig, or we somehow have no signPublicKey on file
  // despite having a contact record) proceeds as always; an ACTIVE
  // verification failure — sig present, key on file, doesn't check out —
  // is treated as tampering and dropped.
  const contact    = state.contacts[fromId];
  const verifiable = !!(msg.sig && contact.signPublicKey);
  const verified   = verifiable && verifyHandshakePacket(msg, contact.signPublicKey);
  // Endpoint-aware once verified — see handleBackupAccept's dedupKey
  // comment for why bare fromId alone would risk swallowing a second,
  // genuinely distinct sibling device's push.
  const dedupKey = `backup_push:${fromId}${verified && fromEndpoint ? ":" + fromEndpoint : ""}${ekDedupTag(msg.ek)}`;
  if (isDuplicateInbound(dedupKey)) {
    mlog.debug(`← BACKUP_PUSH  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  if (verifiable && !verified) {
    mlog.warn(`← BACKUP_PUSH  from ${pid(fromId)} — signature invalid, dropped`);
    return;
  }

  // Unwrap — same one-shot mechanism as the restore-push wrap. What ends
  // up in peerBackups is always the PLAIN inner blob, exactly as before
  // this pass: the wrap is transport-only and never touches what's kept
  // at rest (peerBackups is itself still an opaque blob to us regardless,
  // encrypted under the SENDER's own key — this unwrap only strips the
  // outer transport layer we're able to see, not the inner one we can't).
  let storedBlob = msg.blob;
  const viaWrap = !!msg.ek;
  if (viaWrap) {
    // Trial-decrypt against every live candidate for this slot (device-
    // specific ones first, only meaningful once verified, then the bare-
    // identity fallback ones) — see this map's own header comment for
    // why a single stored ephemeral isn't enough: more than one sibling
    // can legitimately answer the same accept, each with its own ek.
    // AES-GCM's auth tag fails a wrong candidate cleanly, so this costs
    // at most a handful of failed attempts, never a false positive. A
    // successful match is deliberately NOT removed here — see the header
    // comment's note on why a matched candidate must stay usable for
    // whatever OTHER reply is still in flight to the same broadcast ack.
    const candidates = pendingEkCandidates(pendingBackupEk, fromId, verified ? fromEndpoint : null);
    if (!candidates.length) {
      mlog.warn(`← BACKUP_PUSH  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — wrap present but no pending ephemeral for ${pid(fromId)}, dropped`);
      return;
    }
    const theirEk = new Uint8Array(msg.ek);
    let matched = false;
    for (const candidate of candidates) {
      try {
        const shared  = x25519.getSharedSecret(candidate.priv, theirEk);
        const wrapKey = await deriveEphemeralWrapKey(shared);
        storedBlob = await decryptObject(wrapKey, msg.blob);
        matched = true;
        break;
      } catch(e) { /* wrong candidate — try the next one */ }
    }
    if (!matched) {
      mlog.warn(`← BACKUP_PUSH  from ${pid(fromId)} — unwrap failed against ${candidates.length} candidate(s), dropped`);
      return;
    }
  }

  state.peerBackups[fromId] = storedBlob;
  savePeerBackups();
  mlog.info(`← BACKUP_PUSH  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})}  sig:${verified ? "✓" : "·"} — stored${viaWrap ? "  +wrap" : ""}`);

  // token exchange — one time only
  if (!state.peerTokens[fromId]) {
    // Remember that WE asked — handleTokenResponse only accepts a token
    // that answers a request still in flight (see TOKEN_REQ_TTL_MS).
    pendingTokenReq.set(fromId, Date.now());
    sendSignal({ type: "sync:token_req", from: state.publicId, to: fromId });
    mlog.info(`→ TOKEN_REQ    to   ${pid(fromId)} — no token yet`);
  }
}

/* ══════════════════════════════════════════
   RESTORE TOKEN — hygiene pass (step 1 of making the token "proper")
   What a token is: a small record ALICE seals under her own backup key
   and hands to Bob when he stores her backup. Only her passphrase-derived
   key can open it, so opening it later proves "I issued this" without
   any signature. What's inside is Bob's shareableKey as Alice knows it —
   i.e. everything needed to rebuild Bob (X25519 key, signing key, relay).

   This pass changes only how tokens are ISSUED, STORED and CHECKED. It
   does not change what a restore does with one (that's the later
   bootstrap step). Three fixes:
     1. token_resp is now signed, and only accepted from a known contact
        while a token_req of ours is still in flight. Before, ANY authed
        sender could plant a junk token; handleTokenResponse keeps only
        the first token per sender, so a planted one stuck forever and
        Alice then dropped every restore_req Bob sent with it (silent,
        permanent, and worse than having no token at all).
     2. Issued tokens carry { v: 2, shareableKey } only. `name` was
        Alice's private label for Bob and `date` was never read by
        anything — both just leaked into an outer plaintext field. Old
        tokens (with name/date) still validate: only shareableKey is read.
     3. A token only counts if the key inside it derives to msg.from
        (tokenBoundId). Before, any token Alice ever issued to anyone was
        accepted from anyone who held the bytes. And a bad token no
        longer aborts the restore for a known contact — it is treated as
        no token (see handleRestoreRequest).
══════════════════════════════════════════ */
const TOKEN_REQ_TTL_MS = 60_000;      // how long a token_req of ours stays "in flight" for handleTokenResponse
const pendingTokenReq  = new Map();   // contactId → timestamp of our outstanding token_req

// Same shape/pattern as signRestorePacket. `token` is the sealed { v, iv, data }
// object itself — the ciphertext is INSIDE the signature, so a relay can't
// swap it. Old clients send no sig/ts at all; those fail verification and
// are ignored (restore still works between that pair, just without a token).
function signTokenPacket(obj) {
  const { type, from, to, ts, token } = obj;
  return signBlob({ type, from, to, ts, token: token || null });
}
function verifyTokenPacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, ts, token } = obj;
  return verifyBlob({ type, from, to, ts, token: token || null }, obj.sig, contactSignPublicKey);
}

// Derives the publicId of whoever a decrypted token was issued FOR, from
// the two public keys inside its shareableKey — the same derivation
// addContact uses. Throws on anything malformed; callers catch and treat
// that as "no usable token".
async function tokenBoundId(tokenPlain) {
  const key = tokenPlain?.shareableKey;
  if (typeof key !== "string") throw new Error("missing shareableKey");
  const parts = key.split(".");
  if (parts.length < 2) throw new Error("malformed shareableKey");
  const x25519PublicKey = base64ToRaw(parts[0]);
  const signPublicKey   = base64ToRaw(parts[1]);
  if (x25519PublicKey.length !== 32 || signPublicKey.length !== 32) throw new Error("bad key length");
  return deriveIdentityPublicId(x25519PublicKey, signPublicKey);
}

async function handleTokenRequest(msg) {
  if (!msg.from || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  mlog.info(`← TOKEN_REQ    from ${pid(msg.from)} — generating token`);
  const token = await encryptObject(state.cryptoKey, { v: 2, shareableKey: contact.shareableKey });
  const tokenRespObj = { type: "sync:token_resp", from: state.publicId, to: msg.from, ts: Date.now(), token };
  tokenRespObj.sig = signTokenPacket(tokenRespObj);
  const viaRelayResp = sendToRelay(msg.from, tokenRespObj, false);
  if (!viaRelayResp) sendSignal(tokenRespObj);
  mlog.info(`→ TOKEN_RESP   to   ${pid(msg.from)}  via=${viaRelayResp ? "relay" : "signal(fallback)"}`);
}

async function handleTokenResponse(msg) {
  if (!msg.from || !msg.token || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) {
    mlog.warn(`← TOKEN_RESP   from ${pid(msg.from)} — not a contact, ignored`);
    return;
  }
  const askedAt = pendingTokenReq.get(msg.from);
  if (!askedAt || (Date.now() - askedAt) > TOKEN_REQ_TTL_MS) {
    mlog.warn(`← TOKEN_RESP   from ${pid(msg.from)} — unsolicited (no token_req in flight), ignored`);
    return;
  }
  if (!verifyTokenPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← TOKEN_RESP   from ${pid(msg.from)} — signature missing or invalid, ignored`);
    return;
  }
  pendingTokenReq.delete(msg.from);
  if (state.peerTokens[msg.from]) {
    mlog.debug(`TOKEN_RESP     from ${pid(msg.from)} — already have token, ignored`);
    return;
  }
  state.peerTokens[msg.from] = msg.token;
  savePeerTokens();
  mlog.info(`← TOKEN_RESP   from ${pid(msg.from)}  sig:✓ — stored`);
}
/* ══════════════════════════════════════════
   RESTORE PUSH WRAP — ephemeral (step 4 of the restore-token work)
   Protects the inner passphrase-encrypted backup blob against a passive
   wire recording that's later paired with a leaked passphrase. The inner
   blob is untouched — still exactly what it always was (AES-GCM under
   state.cryptoKey, the thing restore-from-nothing needs to stay
   decryptable by passphrase alone) — this adds a SECOND layer around it,
   keyed by a fresh X25519 ephemeral-to-ephemeral DH generated per
   exchange and never written to disk. Recording the wrapped wire bytes
   and later learning the passphrase does not recover them — the
   ephemeral private keys are gone the moment they expire.

   Sequencing: whoever SENDS a restore_ack (sendRestoreAckPing, or the
   reply built in handleRestoreRequest) attaches a fresh ephemeral public
   key as `ek` and holds the matching private key here, keyed by the
   ack's addressee — when the addressee's specific device is already
   known (attachRestoreEk's endpointId param), keyed by that device too,
   not just the bare identity. Whoever RECEIVES that ack (handleRestoreAck,
   peer branch) only wraps when the ack's signature VERIFIED — an `ek`
   riding on an unverifiable ack could be a relay's own swapped-in key,
   the same reasoning step 3 already applies to attaching the token — and
   generates its OWN fresh ephemeral to compute the shared secret,
   attaching that ephemeral's public half to the push as its own `ek`.

   THREE independent races were found live against this mechanism, all
   the same underlying shape — a bare `to` broadcasts to every live
   session under an identity, so "one ack" or "one attach" is never
   actually one-to-one once more than one device (or more than one of
   OUR OWN code paths targeting the same identity) is involved — fixed
   incrementally, each fix exposing the next:
     1. Two attaches for the SAME identity racing to overwrite one
        shared slot (two of a contact's devices each independently
        triggering their own restore_req/ack round trip toward us).
        Fixed by keying attaches by device when the device is known.
     2. One ack drawing MULTIPLE independent, individually-valid pushes
        (one per replying device) against what was still only one stored
        ephemeral, consumed — and thus gone — after the first of them.
        Fixed by no longer deleting a slot's entry on a successful match.
     3. The same failure shape as #1, but between our OWN two attach call
        sites (sendRestoreAckPing and handleRestoreRequest) landing on
        the same bare-identity fallback slot when the target device's
        endpoint wasn't yet known to either of them. Fixed by letting a
        slot hold a LIST of live ephemerals rather than exactly one, so
        two attaches to the same slot coexist instead of one clobbering
        the other — the consuming side trial-decrypts every candidate
        currently in the slot (newest first), the same pattern this
        codebase already uses for X4DH wire-key resolution (see
        decryptIncomingMessage): a wrong candidate fails cleanly and
        immediately against AES-GCM's auth tag, so trying a handful
        costs nothing but a few failed decrypts, never a false positive.

   Landing #3's list naively also re-added a version of #2's bug: the
   first version of this trial-decrypt loop still removed whichever
   candidate matched, on the theory that a "used" ephemeral was done.
   It isn't — a single attach's ephemeral is exactly what #2 already
   established can legitimately answer MORE than one incoming push (one
   ack broadcasting to N devices, each pairing our one stored priv with
   their OWN distinct ephemeral via ordinary, repeatable X25519 DH) — so
   removing it after the first match reintroduced #2's exact symptom
   one level down: the first of two replies to consume a shared, freshly-
   listed candidate left nothing for the second. A candidate is now
   NEVER removed for having matched — matching costs it nothing. The
   only way anything is ever removed is its own timeout
   (RESTORE_EK_TIMEOUT_MS/BACKUP_EK_TIMEOUT_MS) genuinely elapsing with
   no one having claimed it by then.

   Deliberately NOT an X4DH session: a just-wiped device has a brand-new
   deviceId and can't have bootstrapped a real session for this pair yet,
   and this only ever needs to protect the handful of exchanges one ack
   can legitimately draw, not stand up a reusable session. Timeout
   mirrors X4DH_PROPOSAL_TIMEOUT_MS/BACKUP_OFFER_TTL — restore_ack/
   restore_push are already live-only (never durably buffered — see
   protocol.md), so if a push doesn't arrive within this window it isn't
   coming via this round trip at all; the next poll cycle simply
   generates a fresh ack with a fresh ek.
══════════════════════════════════════════ */
const RESTORE_EK_TIMEOUT_MS = 60_000;
// slotKey -> Array<{ priv, timeoutHandle }>. A slot holds every currently
// live ephemeral generated for it, not just the most recent one — see
// this section's header comment for the three races that made a single
// slot-per-key insufficient. pendingEkSlotKey below computes the key
// (identity, or identity+ADDR_SEP+endpointId when a specific device is
// known); attachRestoreEk/attachBackupEk always push via appendPendingEk,
// never overwrite. Entries are read-only from the consuming side's point
// of view — see pendingEkCandidates — and removed only by their own
// timeout, never for having matched a push.
const pendingRestoreEk = new Map();

// Shared by pendingRestoreEk and pendingBackupEk (see that map's own
// comment for why the two maps themselves stay separate) — purely a key-
// shaping helper, no state of its own. Mirrors buildAddress's own
// "compound when a unit is known, bare otherwise" shape, reusing ADDR_SEP
// so a slot key reads the same way a wire "id::endpointId" address does.
function pendingEkSlotKey(targetId, endpointId) {
  return endpointId ? `${targetId}${ADDR_SEP}${endpointId}` : targetId;
}

// pendingEkCandidates(map, targetId, endpointId) — every entry currently
// worth trying against an incoming push, newest first, the device-
// specific slot's entries before the bare-identity fallback slot's (only
// meaningful once the responder's own signature has verified — see each
// call site). Read-only in the fullest sense: it never removes anything,
// and neither does a caller that successfully decrypts against one of
// these candidates — see this section's header comment for why a match
// must not consume the entry. The only removal path is a candidate's own
// timeout (appendPendingEk's setTimeout), completely independent of
// whether, or how many times, it was ever successfully used first.
function pendingEkCandidates(map, targetId, endpointId) {
  const specificKey = endpointId ? pendingEkSlotKey(targetId, endpointId) : null;
  const specific    = specificKey ? (map.get(specificKey) || []) : [];
  const bare        = map.get(targetId) || [];
  // Safety net: every OTHER slot held for this identity (other devices'
  // endpoints). Replies are now addressed one-to-one (replyAddress), so a
  // push normally lands in exactly its own slot — but the bare-addressed
  // bootstrap ping still draws replies from any of a peer's devices, and a
  // slot mismatch must never cost a valid push. Trial decryption against an
  // extra candidate or two is free: AES-GCM fails a wrong key cleanly, never
  // a false positive.
  const prefix = targetId + ADDR_SEP;
  const others = [];
  for (const [key, list] of map) {
    if (key === specificKey || !key.startsWith(prefix)) continue;
    others.push(...[...list].reverse());
  }
  return [...[...specific].reverse(), ...[...bare].reverse(), ...others];
}

// appendPendingEk(map, key, targetId, endpointId, timeoutMs, label) —
// shared by attachRestoreEk/attachBackupEk: push a fresh candidate onto
// whichever slot `key` names, scheduling its own independent expiry.
// Never touches any OTHER candidate already sitting in that slot or any
// other slot. Returns the fresh ephemeral's public half for the caller
// to attach to its outgoing packet.
function appendPendingEk(map, key, targetId, endpointId, timeoutMs, label) {
  const { priv, pub } = generateX25519Ephemeral();
  const entry = { priv };
  entry.timeoutHandle = setTimeout(() => {
    const list = map.get(key);
    if (!list) return;
    const idx = list.indexOf(entry);
    if (idx === -1) return;
    list.splice(idx, 1);
    if (list.length === 0) map.delete(key);
    mlog.debug(`${label} ephemeral expired  id=${pid(targetId, endpointId ? { endpointId } : {})}`);
  }, timeoutMs);
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(entry);
  return pub;
}

// endpointId (optional): the specific device we expect to answer with a
// push, when already known (handleRestoreRequest has plain.deviceId from
// the decrypted request and can resolve its endpoint via knownDevices;
// sendRestoreAckPing's broadcast ping has no device to name at all, since
// sig:seen only ever identifies the identity, never a device — it keeps
// using the bare-identity slot).
function attachRestoreEk(obj, targetId, endpointId) {
  const key = pendingEkSlotKey(targetId, endpointId);
  const pub = appendPendingEk(pendingRestoreEk, key, targetId, endpointId, RESTORE_EK_TIMEOUT_MS, "RESTORE_EK");
  obj.ek = Array.from(pub);
}
// Same one-shot-ephemeral shape as attachRestoreEk/pendingRestoreEk just
// above, for the contact BACKUP handshake instead of restore. Kept as a
// genuinely separate map/constant rather than sharing pendingRestoreEk —
// a contact could plausibly be mid-restore and mid-backup-exchange at the
// same time, and the two flows have no reason to be able to clobber each
// other's pending ephemeral. backup_offer's `from` is compound already,
// so handleBackupOffer always has an endpointId to pass.
const BACKUP_EK_TIMEOUT_MS = 60_000;   // same "live-only, self-healing" reasoning as RESTORE_EK_TIMEOUT_MS — backup_offer/accept/push are never durably buffered either
const pendingBackupEk = new Map();     // slotKey (see pendingEkSlotKey) -> Array<{ priv, timeoutHandle }>

function attachBackupEk(obj, targetId, endpointId) {
  const key = pendingEkSlotKey(targetId, endpointId);
  const pub = appendPendingEk(pendingBackupEk, key, targetId, endpointId, BACKUP_EK_TIMEOUT_MS, "BACKUP_EK");
  obj.ek = Array.from(pub);
}
/* ══════════════════════════════════════════
   RESTORE_REQ — mandatory signature, unlike the handshake pair above
   restore_req is fundamentally different from backup_offer/restore_ack/
   restore_push: it can ONLY ever be successfully processed by a recipient
   who already has the sender as a mutual contact — decrypting it requires
   contact.encKey, and handleRestoreRequest returns immediately if that
   contact doesn't exist (see its own comment on why: the old symmetric-
   key scheme let ANY sender decrypt-with-our-own-key; real ECDH closed
   that, on purpose). A contact's signPublicKey is populated the instant
   they're added — straight from the shareable address, no prior message
   exchange needed — so by the time this handler would reach a signature
   check, verification is ALWAYS possible. No fresh-client leniency is
   warranted here the way it is for the other three; missing or invalid
   is simply dropped, same tier as app:migrate/call:*.
══════════════════════════════════════════ */
function signRestorePacket(obj) {
  const { type, from, to, ts, blob } = obj;
  return signBlob({ type, from, to, ts, blob: blob || null });
}
function verifyRestorePacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, ts, blob } = obj;
  return verifyBlob({ type, from, to, ts, blob: blob || null }, obj.sig, contactSignPublicKey);
}

const pendingRestoreRequest = new Set();

// Shared by sig:seen's three bootstrap-ping call sites below (self, known
// contact, and — deliberately — a completely unknown id too, in case a
// fresh device with no local data at all happens to be talking to a
// stranger who was actually a contact on a prior device). Same soft
// verification stance as the rest of this handshake pair: signed
// unconditionally, verified only when the recipient already has us on
// file.
const lastRestoreAckPingSent = {};
const RESTORE_ACK_PING_COOLDOWN = 60_000; // much shorter than RESTORE_COOLDOWN — this is just "don't spam," not "don't restore"

function canSendRestoreAckPing(id) {
  const last = lastRestoreAckPingSent[id];
  return !last || (Date.now() - last) > RESTORE_ACK_PING_COOLDOWN;
}

function sendRestoreAckPing(toId) {
  if (!canSendRestoreAckPing(toId)) return;
  lastRestoreAckPingSent[toId] = Date.now();
  const ts  = Date.now();
  const obj = { type: "sync:restore_ack", from: buildAddress(state.publicId, state.endpointId), to: toId, ts };
  attachRestoreEk(obj, toId);
  obj.sig = signHandshakePacket(obj);
  sendSignal(obj);
}

// Cross-relay bootstrap trigger. sig:seen is the ONLY thing that normally
// makes a fresh device say hi (sendRestoreAckPing), and sig:seen is relay-
// local: a holder living on ANOTHER relay announces to its own relay, which
// has never heard of us, so no sig:seen ever reaches us. What does reach us
// is the holder's OUTBOUND connection to our relay, which delivers its
// restore_req / backup_offer straight to this socket (the holder's relay
// conn registers there under its own id). Seeing an unknown sender arrive
// that way while we're fresh is the same fact sig:seen would have told us,
// so it gets the same answer: the ping, which is what draws the token and
// the wrapped restore_push.
//
// Gated on sessionFresh (a device that already has contacts waits for the
// normal poll/restore cadence instead — and cannot be made to emit pings by
// strangers) and on the sender not being ourselves. Called from two sites
// because either packet can be the one that arrives (restore_req is skipped
// by the holder's own cooldown, backup_offer is not); sendRestoreAckPing's
// own 60s per-id cooldown makes the second call a no-op.
function pingRestoreIfFreshStranger(fromId, via) {
  if (!sessionFresh || !fromId || fromId === state.publicId || state.contacts[fromId]) return;
  if (!canSendRestoreAckPing(fromId)) return;
  sendRestoreAckPing(fromId);
  mlog.info(`→ RESTORE_ACK  to   ${pid(fromId)} — fresh, unknown sender reached us directly (${via}) — asking for peer backup`);
}

async function sendRestoreRequest(id) {
  const contact = state.contacts[id];
  if (!contact || contact.blocked) return;
  if (pendingRestoreRequest.has(id)) {
    mlog.debug(`RESTORE_REQ already pending  to ${pid(id)}`);
    return;
  }
  if (!canSendRestoreRequest(id)) {
    mlog.debug(`RESTORE_REQ skipped cooldown  to ${pid(id)}`);
    return;
  }
  pendingRestoreRequest.add(id);
  const blob = await encryptObject(contact.encKey, {
    publicId_A:    state.publicId,
    publicId_B:    id,
    wss:           state.contacts[state.publicId]?.lastRelay || null,
    signPublicKey: rawToBase64(state.contacts[state.publicId]?.signPublicKey),
	deviceId:      state.deviceId,
  });
  const token = state.peerTokens[id] || null;
  const ts = Date.now();
  const reqObj = { type: "sync:restore_req", from: state.publicId, to: id, blob, ts, ...(token ? { token } : {}) };
  reqObj.sig = signRestorePacket(reqObj);
  const viaRelay = sendToRelay(id, reqObj, true);
  if (!viaRelay) sendSignal(reqObj);
  mlog.info(`→ RESTORE_REQ  to   ${pid(id)}${token ? "  +token" : ""}  via=${viaRelay ? "relay" : "signal(fallback)"}`);  
 
}

/* ── RELAY-HINT TIMESTAMPS ──
   updateRelay (meshchat-lib.js) adopts a relay only when its ts is newer
   than contact.lastRelaySeen, and then PINS lastRelaySeen to that ts. The
   ts that reaches it is chosen by the sender (a message's plain.ts, a
   migrate notice's plain.ts) or, for a replayed restore_req, by whoever
   replays it — and the receiver's own clock plays no part. A hint stamped
   in the future therefore wins once and then outranks every genuine
   later notice (a real MIGRATE would be "not newer, ignored") until the
   real clock catches up. A sender with a fast clock does this by
   accident; a hostile one can do it deliberately.
   Clamping to the receiver's now closes that without touching the
   ordering rule itself: a hint can still never be older than what we
   hold, it just can't claim to be from the future.
   Non-numeric / missing ts deliberately passes through as NaN rather than
   being defaulted to now — updateRelay treats NaN as 0 and ignores it, so
   a notice with no usable timestamp can't manufacture freshness for
   itself. */
function clampRelayTs(ts, now = Date.now()) {
  return Math.min(ts, now);
}

async function handleRestoreRequest(msg) {
  if (!msg.from || !msg.blob || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact) {
    // Under the old symmetric-by-address scheme, ANY sender could produce
    // a blob decryptable with our own key — no need to have added them
    // back. That was exactly the bug this whole pass fixed. With real
    // ECDH, decrypting genuinely requires their X25519 public key on
    // file, i.e. we must already have them as a contact. sendRestoreRequest
    // is only ever invoked for ids already in state.contacts on the
    // sending side, so this isn't a new practical limitation — just
    // enforced by the crypto now instead of a policy check after decrypt.
    //
    // The request itself still can't be served — but when we're fresh, its
    // arrival is the cross-relay equivalent of sig:seen (see
    // pingRestoreIfFreshStranger), so answer with the bootstrap ping.
    pingRestoreIfFreshStranger(msg.from, "restore_req");
    mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — unknown contact, can't decrypt, dropped`);
    return;
  }
  if (!verifyRestorePacket(msg, contact.signPublicKey)) {
    mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  let plain;
  try {
    plain = await decryptObject(contact.encKey, msg.blob);
// ID_A mismatch
if (plain.publicId_A !== msg.from) {
  mlog.warn(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — ID_A mismatch, dropped`);
  return;
}
if (plain.publicId_B !== state.publicId) {
  mlog.warn(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — ID_B mismatch, dropped`);
  return;
}
  } catch(e) {
    mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — decrypt failed, dropped`);
    return;
  }

// blocked
if (contact.blocked) {
  mlog.info(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — blocked, ignored`);
  return;
}
  
  if (plain.deviceId) recordKnownDevice(msg.from, plain.deviceId);

  if (!canServeRestoreRequest(msg.from, plain.deviceId)) {
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — cooldown, no ack`);
    return;
  }

  const fresh = Object.keys(state.contacts).length <= 1;

  // Token check. A token only counts if it is BOUND to this sender: the key
  // inside it (issued by us, sealed under our own backup key) must derive
  // to msg.from. Previously any token we'd ever issued was accepted from
  // whoever presented the bytes, and a token that failed to open aborted
  // the whole request — which, combined with the unsigned token_resp,
  // let a planted junk token silently kill a contact's restore path.
  // Now a bad/mismatched token is simply "no token": a known contact still
  // falls through to the ack below (the request itself is already
  // signature-verified and ECDH-decrypted, which is what actually
  // authenticates them), and only the `fresh` branch still needs a valid one.
  let tokenOk = false;
  if (msg.token) {
    try {
      const tokenPlain = await decryptObject(state.cryptoKey, msg.token);
      const boundId    = await tokenBoundId(tokenPlain);
      if (boundId !== msg.from) throw new Error("token was not issued for this sender");
      tokenOk = true;
      mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — token valid ✓ (bound)`);
    } catch(e) {
      mlog.warn(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — token ignored (${e.message})`);
    }
  }

  if (tokenOk) {
    // update contact with wss and signPublicKey from blob if we know them
    // (unchanged from before this pass — deliberately not touched here)
    if (state.contacts[msg.from]) {
      // Stamped with the request's own SIGNED ts (verifyRestorePacket covers
      // it), not Date.now(). restore_req is live-only but never freshness-
      // checked, so a malicious relay can replay an old genuine request at
      // any later time; stamping "now" turned that replay into a fresh,
      // validly-timestamped relay hint that outranks the contact's real
      // newer migrate. The signed ts means a replay carries its ORIGINAL
      // age, so updateRelay's newer-than guard rejects it. Clamped so a
      // sender-chosen future ts can't pin lastRelaySeen either.
      if (plain.wss) updateRelay(state.contacts[msg.from], plain.wss, clampRelayTs(msg.ts));
      if (plain.signPublicKey) {
        state.contacts[msg.from].signPublicKey = base64ToRaw(plain.signPublicKey);
      }
    }
  } else if (fresh) {
    // fresh client, no valid token
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — fresh client, no valid token, ignored`);
    return;
  }
  // else: no token, not fresh — an already-known contact re-requesting
  // without a token. Nothing further to validate; falls through to the
  // ack below same as the token-valid path does.

  // send ack — cross domain if we have their wss
  const ackTs  = Date.now();
  // plain.deviceId names exactly which of msg.from's devices sent THIS
  // request. restore_req itself carries no endpoint, but if we already know
  // one for that device from earlier traffic, answer that device ONLY — the
  // ack's ephemeral slot is keyed by that same endpoint (attachRestoreEk
  // below), so ack addressing and slot keying now agree. Before this, the
  // ack went to the bare identity: a sibling device also received it and
  // pushed a perfectly valid wrapped reply that found no slot at its own
  // endpoint ("wrap present but no pending ephemeral"). Endpoint unknown
  // -> bare ack + bare slot, as before.
  const knownDeviceEndpoint = plain.deviceId ? state.knownDevices[msg.from]?.[plain.deviceId]?.endpointId : null;
  const ackObj = { type: "sync:restore_ack", from: buildAddress(state.publicId, state.endpointId), to: knownDeviceEndpoint ? buildAddress(msg.from, knownDeviceEndpoint) : msg.from, ts: ackTs };
  // plain.deviceId names exactly which of msg.from's devices sent THIS
  // request — restore_req itself carries no endpoint (see protocol.md),
  // but if we already know one for that device from earlier traffic
  // (recordKnownDevice above only just recorded deviceId, not endpoint),
  // scope this ack's ephemeral to that specific device rather than the
  // bare identity. Two devices of the same contact requesting at once
  // then get their own slot each, instead of racing to overwrite one
  // shared per-identity ephemeral (see attachRestoreEk's own comment).
  attachRestoreEk(ackObj, msg.from, knownDeviceEndpoint);
  ackObj.sig = signHandshakePacket(ackObj);
  const senderWss = plain.wss || state.contacts[msg.from]?.lastRelay || null;
  let ackSent = false;
  if (senderWss) {
    const entry = getOrOpenRelayConn(senderWss, true);
    if (entry) {
      const raw = JSON.stringify(ackObj);
      if (entry.ready && entry.ws?.readyState === WebSocket.OPEN) {
        entry.ws.send(raw); ackSent = true;
      } else if (!entry.ready) {
        entry.queue.push(raw); ackSent = true;
      }
    }
  }
  if (!ackSent) sendSignal(ackObj);
  markRestoreRequestServed(msg.from, plain.deviceId);
  mlog.info(`← RESTORE_REQ  from ${pid(msg.from, plain.deviceId ? { deviceId: plain.deviceId } : {})} — ack sent  via=${ackSent ? "relay(" + senderWss + ")" : "signal(fallback)"}`);
}

async function handleRestoreAck(msg) {
  if (!msg.from || !msg.to) return;
  if (!isAddressedToMe(msg.to)) return;
  const { id: fromId, endpoint: fromEndpoint } = parseAddress(msg.from);
  if (!fromId) return;
  markOnline(fromId);

  // Same soft stance as backup_offer/accept/push: this ack is reachable
  // from a non-mutual/unknown sender too (sig:seen's fresh-device
  // bootstrap ping, see sendRestoreAckPing), so verification is only ever
  // possible once we already have the sender as a contact. Drop only on
  // an ACTIVE failure; unverifiable proceeds exactly as this has always
  // worked. deviceId is deliberately no longer read from an outer field
  // here at all (see the compound-from note on the send side) — there is
  // no safe way to learn it on this specific path, so it simply isn't
  // learned here; recordKnownDevice still gets fed via every other path
  // that DOES have a safe channel for it (app:message, self-sync).
  const contact    = state.contacts[fromId];
  const verifiable = !!(msg.sig && contact?.signPublicKey);
  const verified   = verifiable && verifyHandshakePacket(msg, contact.signPublicKey);
  // Endpoint-aware once verified, same reasoning as the backup handshake
  // pair's dedup keys above — a second of the sender's own devices acking
  // within the same few seconds is a genuinely distinct, real ack, not a
  // duplicate of the first.
  const dedupKey = `restore_ack:${fromId}${verified && fromEndpoint ? ":" + fromEndpoint : ""}`;
  if (isDuplicateInbound(dedupKey)) {
    mlog.debug(`← RESTORE_ACK  from ${pid(fromId, verified ? { endpointId: fromEndpoint } : {})} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }
  if (verifiable && !verified) {
    mlog.warn(`← RESTORE_ACK  from ${pid(fromId)} — signature invalid, dropped`);
    return;
  }
  const fromDisp = pid(fromId, verified ? { endpointId: fromEndpoint } : {});

  if (fromId === state.publicId) {
    // Self restore_push carries serialiseContacts() — FULL message history,
    // unlike the contact-path push below (contacts only). It is therefore the
    // most valuable thing in this handshake family to keep off the wire in a
    // form a recorded capture + later passphrase leak could open. Same one-shot
    // ephemeral wrap as the peer branch: the ping we receive (sendRestoreAckPing)
    // already attached an `ek` and the asking device already holds the matching
    // private half in pendingRestoreEk — this branch just never used it before.
    //
    // Self-specific: `verified` is effectively always true here. The ack is signed
    // by a device of OUR OWN identity, and our self contact always carries
    // signPublicKey (derived at login, even on a freshly wiped device), so the
    // "unverifiable fresh sender" case that forces the peer branch to be lenient
    // does not exist for self. An ack that fails verification was already dropped
    // above, and `ek` is inside the signed set, so a relay cannot strip or swap it
    // without that check failing.
    //
    // Wrap failure (malformed ek) falls back to the plain backup-key blob, same as
    // the peer branch — the asking device still needs its data.
    const pushTs    = Date.now();
    const freshBlob = await encryptObject(state.cryptoKey, serialiseContacts());
    let outBlob = freshBlob, ek = null;
    if (verified && msg.ek) {
      try {
        const theirEk = new Uint8Array(msg.ek);
        const { priv, pub } = generateX25519Ephemeral();
        const shared  = x25519.getSharedSecret(priv, theirEk);
        const wrapKey = await deriveEphemeralWrapKey(shared);
        outBlob = await encryptObject(wrapKey, freshBlob);
        ek = Array.from(pub);
      } catch(e) {
        mlog.warn(`RESTORE_PUSH   wrap failed for self ${fromDisp}, sending unwrapped: ${e.message}`);
        outBlob = freshBlob; ek = null;
      }
    }
    const pushObj   = { type: "sync:restore_push", from: buildAddress(state.publicId, state.endpointId), to: replyAddress(fromId, fromEndpoint, verified), blob: outBlob, ts: pushTs };
    if (ek) pushObj.ek = ek;   // must be set BEFORE signing — signHandshakePacket includes ek in the signed set when present
    pushObj.sig = signHandshakePacket(pushObj);
    sendSignal(pushObj);
    mlog.info(`← RESTORE_ACK  from self  ${fromDisp} — sending fresh data${ek ? "  +wrap" : ""}`);
    return;
  }

  const backup = state.peerBackups[fromId];
  if (!backup) {
    mlog.info(`← RESTORE_ACK  from ${fromDisp} — no backup stored, nothing sent`);
    return;
  }
  // Wrap (step 4). Only when the ack's signature VERIFIED and it carried an
  // ephemeral — see the pendingRestoreEk section above for why both sides
  // of that gate matter. Wrap failure (malformed ek, etc.) falls back to
  // sending the backup unwrapped rather than dropping it silently — the
  // recipient still needs their data, and an unwrapped push is exactly
  // today's behavior, not a downgrade below anything that currently works.
  let outBlob = backup, ek = null;
  if (verified && msg.ek) {
    try {
      const theirEk = new Uint8Array(msg.ek);
      const { priv, pub } = generateX25519Ephemeral();
      const shared  = x25519.getSharedSecret(priv, theirEk);
      const wrapKey = await deriveEphemeralWrapKey(shared);
      outBlob = await encryptObject(wrapKey, backup);
      ek = Array.from(pub);
    } catch(e) {
      mlog.warn(`RESTORE_PUSH   wrap failed for ${fromDisp}, sending unwrapped: ${e.message}`);
      outBlob = backup; ek = null;
    }
  }
  // Token attach (step 3). Only when the ack's signature VERIFIED: the token
  // is a sealed record only the ack sender can open, so it's only worth
  // handing to someone we've just confirmed is that identity — never to an
  // unsigned/unverifiable ack. It rides as an outer field and is
  // deliberately NOT part of signHandshakePacket's signed set: adding it
  // there would make older clients that already know this sender compute a
  // different signature and drop the push. Stripping it in transit only
  // downgrades the receiver to today's unverified path; it can't forge one
  // (the receiver binds the token's key to `from` and verifies the push
  // signature with it — see handleRestorePush).
  const token = verified ? state.peerTokens[fromId] : null;
  mlog.info(`← RESTORE_ACK  from ${fromDisp} — sending restore_push${token ? "  +token" : ""}${ek ? "  +wrap" : ""}`);
  const pushTs  = Date.now();
  const pushObj = { type: "sync:restore_push", from: buildAddress(state.publicId, state.endpointId), to: replyAddress(fromId, fromEndpoint, verified), blob: outBlob, ts: pushTs };
  if (ek) pushObj.ek = ek;
  pushObj.sig = signHandshakePacket(pushObj);
  if (token) pushObj.token = token;
  sendSignal(pushObj);
}

async function handleRestorePush(msg) {
  if (!msg.from || !msg.blob || !isAddressedToMe(msg.to)) return;
  const { id: fromId, endpoint: fromEndpoint } = parseAddress(msg.from);
  if (!fromId) return;
  markOnline(fromId);

  // Verify BEFORE the cooldown check (reordered — used to run after).
  // The cooldown below is endpoint-keyed once verified (see
  // canAcceptRestorePush), and fromEndpoint isn't safe to key anything on
  // until the signature backing it actually checks out. Same soft stance
  // as the rest of this handshake: unverifiable (no sig, or sender not
  // yet a contact) proceeds exactly as this has always worked; only an
  // ACTIVE verification failure is dropped.
  const contact = state.contacts[fromId];
  // Token path (step 3): a device that has lost its contacts can't verify
  // this push — it has no signPublicKey for the sender. If the holder
  // attached the token WE issued for them, opening it (passphrase key only)
  // gives us that key: the sender's shareableKey, sealed by us earlier. The
  // key must derive to `from` (tokenBoundId) or the token is ignored, and the
  // push signature is then verified with the key from the token. When we
  // already know the sender we keep using the contact's key as before —
  // the token adds nothing there.
  let verifyKey = contact?.signPublicKey || null;
  let viaToken  = false;
  if (!verifyKey && msg.token) {
    try {
      const tokenPlain = await decryptObject(state.cryptoKey, msg.token);
      const boundId    = await tokenBoundId(tokenPlain);
      if (boundId !== fromId) throw new Error("token was not issued for this sender");
      verifyKey = base64ToRaw(tokenPlain.shareableKey.split(".")[1]);
      viaToken  = true;
    } catch(e) {
      mlog.warn(`← RESTORE_PUSH from ${pid(fromId)} — token ignored (${e.message})`);
    }
  }
  const verifiable = !!(msg.sig && verifyKey);
  const verified   = verifiable && verifyHandshakePacket(msg, verifyKey);
  if (verifiable && !verified) {
    mlog.warn(`← RESTORE_PUSH from ${pid(fromId)} — signature invalid${viaToken ? " (via token)" : ""}, dropped`);
    return;
  }
  if (viaToken && !verified) {
    // token opened fine but the push carried no signature — nothing to
    // verify, so this is exactly today's unverified path.
    mlog.info(`← RESTORE_PUSH from ${pid(fromId)} — token ✓ bound, but push unsigned — unverified`);
  }
  const fromDisp = pid(fromId, verified ? { endpointId: fromEndpoint } : {});
  // Only trust the endpoint suffix for cooldown-keying once signed+verified
  // — an unverified sender collapses to the identity-level fallback, same
  // tier canServeRestoreRequest/canAcceptRestorePush apply elsewhere.
  const cooldownEndpoint = verified ? fromEndpoint : null;

  // Dedup first, before the (much longer) accept-cooldown gate — cheapest,
  // most content-independent check goes first, same ordering principle
  // backup_offer's original dedup already established. Reuses
  // cooldownEndpoint rather than computing a separate key.
  const dedupKey = `restore_push:${fromId}${cooldownEndpoint ? ":" + cooldownEndpoint : ""}${ekDedupTag(msg.ek)}`;
  if (isDuplicateInbound(dedupKey)) {
    mlog.debug(`← RESTORE_PUSH from ${fromDisp} — duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
    return;
  }

  if (!canAcceptRestorePush(fromId, cooldownEndpoint)) {
    mlog.info(`← RESTORE_PUSH from ${fromDisp} — cooldown, ignored`);
    return;
  }

  try {
    // Unwrap (step 4), before the inner passphrase-key decrypt. `ek`
    // present means the sender wrapped the backup under a one-shot
    // ephemeral DH — see the pendingRestoreEk section above. A pending
    // entry only exists if WE sent them an ack with our own ephemeral
    // (sendRestoreAckPing / handleRestoreRequest's reply ack); anything
    // else (no entry, or the unwrap itself failing) is dropped outright
    // rather than falling through to the inner decrypt with the still-
    // wrapped ciphertext, which would just fail there anyway with a less
    // specific log line.
    let innerBlob = msg.blob;
    const viaWrap = !!msg.ek;
    if (viaWrap) {
      // Trial-decrypt against every live candidate for this slot (device-
      // specific ones first, reusing cooldownEndpoint — already verified-
      // gated above — then the bare-identity fallback ones) — see this
      // map's own header comment for why a single stored ephemeral isn't
      // enough: one ack broadcasts to every live session under an
      // identity, so more than one of a contact's devices can legitimately
      // answer it, each with its own fresh ephemeral. AES-GCM's auth tag
      // fails a wrong candidate cleanly, so this costs at most a handful
      // of failed attempts, never a false positive. A successful match is
      // deliberately NOT removed here — see the header comment's note on
      // why a matched candidate must stay usable for whatever OTHER reply
      // is still in flight to the same broadcast ack.
      const candidates = pendingEkCandidates(pendingRestoreEk, fromId, cooldownEndpoint);
      if (!candidates.length) {
        mlog.warn(`← RESTORE_PUSH from ${fromDisp} — wrap present but no pending ephemeral for ${pid(fromId)}, dropped`);
        return;
      }
      const theirEk = new Uint8Array(msg.ek);
      let matched = false;
      for (const candidate of candidates) {
        try {
          const shared  = x25519.getSharedSecret(candidate.priv, theirEk);
          const wrapKey = await deriveEphemeralWrapKey(shared);
          innerBlob = await decryptObject(wrapKey, msg.blob);
          matched = true;
          break;
        } catch(e) { /* wrong candidate — try the next one */ }
      }
      if (!matched) {
        mlog.warn(`← RESTORE_PUSH from ${fromDisp} — unwrap failed against ${candidates.length} candidate(s), dropped`);
        return;
      }
    }
    const plain = await decryptObject(state.cryptoKey, innerBlob);
    if (typeof plain !== "object" || Array.isArray(plain)) {
      mlog.warn(`← RESTORE_PUSH from ${fromDisp} — bad structure, dropped`);
      return;
    }
    const restored      = await deserialiseContacts(plain);
    const prevSelfRelay = state.contacts[state.publicId]?.lastRelay;
    let added = 0, msgsMerged = 0;
    for (const [id, contact] of Object.entries(restored)) {
      if (!state.contacts[id]) {
        state.contacts[id] = contact;
        state.contacts[id].lastRelaySeen = 0;
        added++;
      }
      else {
        mergeContactMeta(state.contacts[id], contact);
        const before = state.contacts[id].messages.length;
        state.contacts[id].messages = mergeMessages(state.contacts[id].messages, contact.messages);
        reconcileDeliveryStatus(state.contacts[id]);
        reconcileMissingDevices(state.contacts[id]);
        msgsMerged += state.contacts[id].messages.length - before;
      }
    }
    markRestorePushAccepted(fromId, cooldownEndpoint);
    markRestoreRequestFulfilled(fromId);
    sessionFresh = false;
    await saveContacts();
    renderContactList();
	if (state.currentChat) renderMessages();
    mlog.info(`← RESTORE_PUSH from ${fromDisp} — +${added} contacts  +${msgsMerged} msgs  sig:${verified ? (viaToken ? "✓ (via token)" : "✓") : "·"}${viaWrap ? "  +wrap" : ""}`);
    setSyncStatus("restored from network ✓");
    if (state.contacts[state.publicId]?.lastRelay !== prevSelfRelay) {
      mlog.info(`RESTORE_PUSH   self relay changed via other device — rebooting signal`);
      rebootSignal();
    }
  } catch(e) {
    mlog.warn(`← RESTORE_PUSH from ${fromDisp} — decrypt failed, dropped`);
  }
}

/* ══════════════════════════════════════════
   MSG EXCHANGE (manual SYNC button)
══════════════════════════════════════════ */
/* Same protection tier as app:migrate: the batch is encrypted under the
   pairwise key (contact.encKey) and the ciphertext is signed, with
   verification MANDATORY on receive. Before this, the packet carried
   `msgs` as plain JSON with no signature at all — the relay could read the
   text and could forge `from` to inject messages into any conversation.

   Deliberately the legacy identity-level key, not an X4DH wire key: SYNC is
   addressed to the contact (bare `to`, every live session answers), not to
   one device pair, so there is no single session to derive a key against —
   same reasoning that keeps app:migrate/app:burn/call:* off X4DH.

   Everything that used to ride as an unsigned outer field (`reply`, and the
   `from`/`to` pair) now lives INSIDE the encrypted+signed payload, and
   receive checks them against the envelope: an outer field is silently
   rewritable by an untrusted relay, and with a pairwise-symmetric key a
   captured packet could otherwise be reflected back at its own sender.

   syncId ties a reply to the request that caused it. A reply is accepted
   only while a request of OURS to that same contact is still pending
   (SYNC_PENDING_TTL_MS) — no clocks involved, so cross-device skew can't
   matter. A matching reply is deliberately NOT consumed: the request is a
   broadcast, so several of the contact's devices can each legitimately
   answer it, and merging the same batch twice is a no-op anyway.

   Old clients send plaintext `msgs` with no blob; those are dropped. Hard
   cutover, same stance as the other recent wire changes — the only real
   consequence is that SYNC between a new and an old client does nothing.

   EPHEMERAL WRAP (the messages themselves). The pairwise key above is
   static-static ECDH — deterministic — so a recorded batch plus a later
   identity-key compromise would expose every message text in it. The
   message batch therefore never rides under that key alone:
     - the REQUEST carries no messages at all, only a fresh X25519 ephemeral
       public key `ek` (inside the encrypted+signed payload, so a relay can
       neither strip nor swap it);
     - the REPLY carries its own fresh ephemeral `ek` plus `wrapped` — the
       batch encrypted under HKDF(X25519(replier ephemeral, requester
       ephemeral)). The requester's ephemeral private half lives only in
       pendingSyncs, in memory, until SYNC_PENDING_TTL_MS expires.
   Same one-shot ephemeral-to-ephemeral construction (and the same
   deriveEphemeralWrapKey) as the restore/backup push wraps. The outer
   pairwise layer stays: it is what authenticates and binds from/to/syncId.
   Consequence: SYNC is one-directional — the side that presses SYNC
   receives the other side's recent messages; it no longer also pushes its
   own. Press it on both sides for a two-way exchange. A request with no
   valid `ek` is dropped (hard cutover, no unwrapped fallback). */
const MAX_SYNC_MSGS        = 50;       // inbound cap per batch — EXCHANGE_COUNT is 10, this is just a sanity ceiling
const SYNC_PENDING_TTL_MS  = 60_000;   // how long a reply to our own request stays acceptable
const pendingSyncs = new Map();        // syncId -> { contactId, createdAt, ekPriv } — ekPriv is memory-only, same tier as pendingX4DHProposals

const validSyncEk = (ek) => Array.isArray(ek) && ek.length === 32 && ek.every(b => Number.isInteger(b) && b >= 0 && b <= 255);

// request: { syncId, reply:false, ek }
// reply:   { syncId, reply:true,  ek, wrapped }   (wrapped = encryptObject(ephemeralWrapKey, msgs))
async function buildSyncPacket(contact, { syncId, reply, ek, wrapped }) {
  const payload = { from: state.publicId, to: contact.publicId, syncId, reply, ek };
  if (wrapped) payload.wrapped = wrapped;
  return sealEnvelope("app:sync", state.publicId, contact.publicId, contact.encKey, payload);
}

// Whitelisted field copy, never a spread — same discipline as
// handleSelfSync. The batch is signed by the contact, but the contact is
// still only a peer: local-only fields (ackTrusted, status) must never ride
// in from the wire, and a malformed entry must not poison the conversation.
// Messages already on file are skipped rather than merged over: mergeMessages
// resolves a same-id collision by ts with the incoming copy winning a tie, so
// a synced copy of our own message would replace the local object and lose
// its delivery status. Reactions are the exception — same id across states,
// newer ts must win, which mergeMessages already does.
function sanitizeSyncedMessages(raw, peerId, existing) {
  if (!Array.isArray(raw)) return [];
  const have = new Set((existing || []).map(m => m.id));
  const out  = [];
  for (const m of raw.slice(0, MAX_SYNC_MSGS)) {
    if (!m || typeof m.id !== "string" || m.id.length > 64 || !Number.isFinite(m.ts)) continue;
    if (m.from !== peerId && m.from !== state.publicId) continue;   // only the two parties of THIS conversation
    const t = m.type || "text";
    if (t !== "reaction" && have.has(m.id)) continue;
    const o = { id: m.id, from: m.from, ts: m.ts, valid: m.valid !== false };
    if (t === "text") {
      if (typeof m.text !== "string") continue;
      o.text = m.text;
    } else if (t === "audio" || t === "image") {
      o.type = t;
      o.mimeType = typeof m.mimeType === "string" ? m.mimeType : null;
    } else if (t === "reaction") {
      if (typeof m.targetId !== "string") continue;
      o.type = "reaction"; o.targetId = m.targetId;
      o.emoji = typeof m.emoji === "string" ? m.emoji : null;
    } else if (t === "system") {
      if (typeof m.text !== "string") continue;
      o.type = "system"; o.kind = typeof m.kind === "string" ? m.kind : null; o.text = m.text;
    } else continue;
    if (typeof m.deviceId === "string") o.deviceId = m.deviceId;
    if (Number.isFinite(m.n)) o.n = m.n;
    if (typeof m.ackDeviceId === "string" && Number.isFinite(m.ackN)) { o.ackDeviceId = m.ackDeviceId; o.ackN = m.ackN; }
    out.push(o);
  }
  return out;
}

async function initiateExchange(contactId) {
  if (!state.online.has(contactId)) {
    setSyncStatus("contact offline");
    mlog.info(`\u2192 SYNC         to   ${pid(contactId)} \u2014 offline, aborted`);
    return;
  }
  const contact = state.contacts[contactId];
  if (!contact || contact.blocked || !contact.encKey) return;
  const syncId = crypto.randomUUID();
  const now = Date.now();
  for (const [id, p] of pendingSyncs) if (now - p.createdAt > SYNC_PENDING_TTL_MS) pendingSyncs.delete(id);   // no leak across a long session
  const { priv: ekPriv, pub: ekPub } = generateX25519Ephemeral();
  pendingSyncs.set(syncId, { contactId, createdAt: now, ekPriv });
  // Exact deadline per entry (same reasoning as schedulePendingX4DHExpiry):
  // the lazy sweep above only runs on the NEXT sync, which could leave a
  // private key sitting in memory long after its window closed.
  setTimeout(() => pendingSyncs.delete(syncId), SYNC_PENDING_TTL_MS);
  try {
    sendSignal(await buildSyncPacket(contact, { syncId, reply: false, ek: Array.from(ekPub) }));
    mlog.info(`\u2192 SYNC         to   ${pid(contactId)}  id=${pid(syncId)}`);
    setSyncStatus("syncing\u2026");
  } catch(e) {
    pendingSyncs.delete(syncId);
    mlog.err(`\u2192 SYNC         to   ${pid(contactId)} \u2014 send failed: ${e.message}`);
    setSyncStatus("sync failed");
  }
}

async function handleMsgExchange(msg) {
  if (!msg.from || !msg.to || !isAddressedToMe(msg.to)) return;
  if (!msg.blob) {
    mlog.warn(`\u2190 SYNC         from ${pid(msg.from)} \u2014 no encrypted blob (legacy plaintext sync), dropped`);
    return;
  }
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked || msg.from === state.publicId) return;

  // Signature first (cheap, and nothing below is worth doing for a forgery).
  // Mandatory, same tier as app:migrate — a missing or invalid one is dropped,
  // never flagged-and-shown, because this packet writes into the conversation.
  if (!verifyEnvelope(msg, contact.signPublicKey)) {
    mlog.warn(`\u2190 SYNC         from ${pid(msg.from)} \u2014 signature missing or invalid, dropped`);
    return;
  }
  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey, envelopeAad(msg.type, msg.from, msg.to)); }
  catch(e) { mlog.warn(`\u2190 SYNC         from ${pid(msg.from)} \u2014 decrypt failed, dropped`); return; }

  // Envelope fields are unsigned and relay-rewritable; the payload copies are
  // authoritative. A mismatch means reflection/redirection, not a normal case.
  if (plain.from !== msg.from || plain.to !== state.publicId
      || typeof plain.syncId !== "string" || plain.syncId.length > 64 || typeof plain.reply !== "boolean") {
    mlog.warn(`\u2190 SYNC         from ${pid(msg.from)} \u2014 payload/envelope mismatch, dropped`);
    return;
  }
  markOnline(msg.from);   // only now \u2014 handleSignal used to do this before any verification

  if (!plain.reply) {
    if (!validSyncEk(plain.ek)) {
      mlog.warn(`\u2190 SYNC_REQ     from ${pid(msg.from)} \u2014 no valid ephemeral key (legacy sync request), dropped`);
      return;
    }
    if (isDuplicateInbound(`app_sync:${msg.from}:${plain.syncId}`)) {
      mlog.debug(`\u2190 SYNC_REQ     from ${pid(msg.from)} \u2014 duplicate within ${DEDUP_WINDOW_MS}ms, suppressed`);
      return;
    }
    mlog.info(`\u2190 SYNC_REQ     from ${pid(msg.from)}  id=${pid(plain.syncId)} \u2014 replying (wrapped)`);
    try {
      const { priv, pub } = generateX25519Ephemeral();
      const wrapKey = await deriveEphemeralWrapKey(x25519.getSharedSecret(priv, new Uint8Array(plain.ek)));
      const wrapped = await encryptObject(wrapKey, getLast(msg.from));
      sendSignal(await buildSyncPacket(contact, { syncId: plain.syncId, reply: true, ek: Array.from(pub), wrapped }));
    } catch(e) {
      mlog.warn(`\u2192 SYNC_REPLY   to   ${pid(msg.from)} \u2014 send failed: ${e.message}`);
    }
    return;   // the request carries no messages — nothing to merge on this side
  }

  const pending = pendingSyncs.get(plain.syncId);
  if (!pending || pending.contactId !== msg.from || (Date.now() - pending.createdAt) > SYNC_PENDING_TTL_MS) {
    mlog.debug(`\u2190 SYNC_REPLY   from ${pid(msg.from)} \u2014 no matching pending request, ignored`);
    return;
  }
  if (!validSyncEk(plain.ek) || !plain.wrapped || typeof plain.wrapped !== "object") {
    mlog.warn(`\u2190 SYNC_REPLY   from ${pid(msg.from)} \u2014 missing ephemeral key or wrapped batch, dropped`);
    return;
  }
  // Trial-free: this reply answers a request whose ephemeral WE hold. A
  // second device of the contact answering the same broadcast request
  // brings its own ek and unwraps against the same pending ekPriv, which
  // is why the pending entry is not consumed here.
  let msgs;
  try {
    const wrapKey = await deriveEphemeralWrapKey(x25519.getSharedSecret(pending.ekPriv, new Uint8Array(plain.ek)));
    msgs = await decryptObject(wrapKey, plain.wrapped);
  } catch(e) {
    mlog.warn(`\u2190 SYNC_REPLY   from ${pid(msg.from)} \u2014 unwrap failed, dropped`);
    return;
  }

  const incoming = sanitizeSyncedMessages(msgs, msg.from, contact.messages);
  const before = contact.messages.length;
  contact.messages = mergeMessages(contact.messages, incoming);
  reconcileDeliveryStatus(contact);
  reconcileMissingDevices(contact);
  const added = contact.messages.length - before;
  mlog.info(`\u2190 SYNC_REPLY   from ${pid(msg.from)} \u2014 +${added} msgs  +wrap`);
  setSyncStatus("synced with " + contact.name + " \u2713");
  await saveContacts();
  if (state.currentChat === msg.from) renderMessages();
}

/* ══════════════════════════════════════════
   WEBSOCKET
══════════════════════════════════════════ */
/* ══════════════════════════════════════════
   AUTH STATE
   authStep: "idle" | "await_challenge" | "await_ok" | "done"
   After "done" the usual post-connect flow runs. `auth` is the
   createRelayAuth() helper for the CURRENT socket only (see below).
══════════════════════════════════════════ */
const authState = { step: "idle", auth: null };

// SIGNAL_URL is the bootstrap default — used only when we have no local
// truth yet (fresh identity, first load on this origin). Once me.lastRelay
// exists, it's the actual connection target — same "local storage wins"
// rule as sig:relay_info. Computed fresh on every call so an edited
// lastRelay takes effect on the very next connect, not just on reload.
function getSignalUrl() {
  const me = state.contacts[state.publicId];
  return me?.lastRelay || SIGNAL_URL;
}

function connectSignal() {
  const url = getSignalUrl();
  const ws  = new WebSocket(url);
  state.ws  = ws;
  ws.onopen = () => {
    mlog.info(`WS         connected  ${url}`);
    authState.step = "idle";
    startAuth(url);   // url = what THIS socket dialed — the relay host the proof gets bound to
  };
  ws.onclose = () => {
    // stale guard — if state.ws has already moved on to a newer connection
    // (e.g. a deliberate reboot after editing our own relay), this close
    // event belongs to the socket we just replaced. Don't double-reconnect.
    if (state.ws !== ws) {
      mlog.debug("WS         stale close ignored (already reconnected)");
      return;
    }
    setConnected(false);
    authState.step = "idle";
    mlog.warn("WS         disconnected — retrying in 3s");
    setTimeout(connectSignal, WS_RECONNECT_MS);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => { try { handleSignal(JSON.parse(evt.data)); } catch(e) {} };
}

// Deliberate reconnect — used when our own lastRelay changes (manual edit
// or, later, an actual migration commit) and we need the live signal
// session to follow it immediately rather than wait for the next natural
// reconnect cycle. Closes the current socket and opens a fresh one right
// away; the stale guard above stops the old socket's onclose from also
// scheduling a redundant reconnect a few seconds later.
function rebootSignal() {
  mlog.info("WS         reboot — relay changed, reconnecting now");
  state.ws?.close(1000, "reboot");
  connectSignal();
}

/* ══════════════════════════════════════════
   RELAY AUTH — one helper for every handshake
   Used by all four places that authenticate to a relay: the main signal
   socket (startAuth), outbound contact relays (getOrOpenRelayConn), the
   MIGRATE test probe (testRelayConnection) and the old-relay drain
   (drainOldRelay). Each used to carry its own copy of
   "ed25519.sign(nonce)" over whatever bytes the relay sent.

   What the proof signs, and why, is documented at buildAuthMessage
   (meshchat-lib.js). The two properties that matter for call sites:
     - the relay host comes from `url` — the URL this socket was opened
       with — never from anything in the challenge;
     - proof() refuses any challenge that isn't exactly AUTH_NONCE_LEN
       bytes, so a relay can't pick what we sign. It THROWS on a bad
       challenge; every caller treats that as a failed handshake and
       drops the connection.
   endpointId / noReceive are part of what's signed, so they're fixed at
   construction and the same values go out in init().
══════════════════════════════════════════ */
function createRelayAuth(url, { endpointId = null, noReceive = false } = {}) {
  const host       = authHostFromUrl(url);
  const parts      = state.shareableKey.split(".");
  const x25519Pub  = base64ToRaw(parts[0]);
  const ed25519Pub = base64ToRaw(parts[1]);
  return {
    host,
    init() {
      const o = {
        type: "sig:auth_init", auth_v: AUTH_VERSION,
        x25519_pub: Array.from(x25519Pub), ed25519_pub: Array.from(ed25519Pub),
      };
      if (endpointId) o.endpoint_id = endpointId;
      if (noReceive)  o.no_receive  = true;
      return o;
    },
    proof(challenge) {
      if (!host) throw new Error("cannot derive relay host from url");
      const nonce = challenge?.nonce;
      if (!Array.isArray(nonce) || nonce.length !== AUTH_NONCE_LEN
          || !nonce.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) {
        throw new Error(`challenge nonce must be exactly ${AUTH_NONCE_LEN} bytes`);
      }
      const message = buildAuthMessage(host, Uint8Array.from(nonce), x25519Pub, ed25519Pub, endpointId, noReceive);
      return { type: "sig:auth_proof", sig: Array.from(ed25519.sign(message, state.keys.signingKeySeed)) };
    },
  };
}

function startAuth(url) {
  authState.auth = createRelayAuth(url, { endpointId: state.endpointId });
  authState.step = "await_challenge";
  state.ws.send(JSON.stringify(authState.auth.init()));
  mlog.info(`AUTH       init  ${pid(state.publicId, { endpointId: state.endpointId })}  host=${authState.auth.host}`);
}

// Possession proof: a signature over the domain-separated auth message
// (see createRelayAuth), not over the raw nonce. Only answered while WE are
// waiting for a challenge on the main socket — a stray challenge at any
// other time is not something to sign.
function handleAuthChallenge(msg) {
  if (authState.step !== "await_challenge" || !authState.auth) {
    mlog.warn(`AUTH       unexpected challenge (step=${authState.step}) — ignored`);
    return;
  }
  try {
    state.ws.send(JSON.stringify(authState.auth.proof(msg)));
    authState.step = "await_ok";
    mlog.info("AUTH       proof sent");
  } catch(e) {
    mlog.err(`AUTH       sign refused: ${e.message} — dropping connection`);
    try { state.ws.close(1008, "bad challenge"); } catch(_) {}
  }
}

function handleAuthOk(msg) {
  if (authState.step !== "await_ok") {
    mlog.warn(`AUTH       unexpected auth_ok (step=${authState.step}) — ignored`);
    return;
  }
  // The relay derives public_id from the keys we presented. Anything else
  // means it didn't authenticate the identity we think it did.
  if (msg.public_id !== state.publicId) {
    mlog.err(`AUTH       auth_ok for a different id (${pid(msg.public_id)} != ${pid(state.publicId)}) — dropping connection`);
    try { state.ws.close(1008, "id mismatch"); } catch(_) {}
    return;
  }
  mlog.info(`AUTH OK    id=${pid(msg.public_id)}`);

  // fully authenticated, run post-connect flow
  authState.step = "done";
  setConnected(true);
  state.ws.send(JSON.stringify({ type: "sig:relay_req" }));
  pollContacts();
  schedulePoll();
}

const AUTH_FAIL_HINTS = {
  auth_version:         "relay and client speak different auth versions — update both",
  relay_not_configured: "this relay has no valid RELAY_WSS_URL set and refuses to authenticate anyone",
  proof_invalid:        "signature rejected — the relay doesn't recognise the host we dialed (RELAY_WSS_URL / RELAY_AUTH_HOSTS), or relay/client versions differ",
};

function handleAuthFail(msg) {
  if (authState.step === "done") {
    mlog.debug(`RELAY      remote rejected unauthenticated traffic  reason=${msg.reason}`);
    return;
  }
  const hint = AUTH_FAIL_HINTS[msg.reason];
  mlog.err(`AUTH FAIL  reason=${msg.reason}  step=${authState.step}${hint ? "  — " + hint : ""}`);
}

let sessionFresh = true;

function handleSignal(msg) {
  switch(msg.type) {
    case "call:invite":	handleCallInvite(msg);  break;
    case "call:claim":  handleCallClaim(msg);   break;
    case "call:cancel": handleCallCancel(msg);  break;
    case "call:end":    handleCallEnd(msg);     break;
	case "call:offer":  handleCallOffer(msg);   break;
	case "call:answer": handleCallAnswer(msg);  break;
	case "call:ice":    handleCallIce(msg);     break;
	case "data:invite":handleDataInvite(msg); break;
	case "data:claim": handleDataClaim(msg);  break;
	case "data:cancel":handleDataCancel(msg); break;
	case "data:end":   handleDataEnd(msg);    break;	
    case "data:offer": handleDataOffer(msg);  break;
    case "data:answer":handleDataAnswer(msg); break;
    case "data:ice":   handleDataIce(msg);    break;
	case "session:propose": handleX4DHPropose(msg); break;
	case "session:ack":     handleX4DHAck(msg);     break;
	
	
    case "sig:auth_challenge": handleAuthChallenge(msg); break;
    case "sig:auth_ok":        handleAuthOk(msg);        break;
    case "sig:auth_fail":      handleAuthFail(msg);      break;
    case "sig:relay_info":
      if (state.contacts[state.publicId]) {
        const me     = state.contacts[state.publicId];
        const isFresh = !me.lastRelay;   // no local truth yet — first time this identity has loaded here

        mlog.info(`RELAY_INFO version = ${msg.version || "?"} (local = ${CLIENT_VERSION})`);

        if (isFresh && msg.wss) {
          me.lastRelay = msg.wss;
          // Placeholder, not a confirmed fact — this is just whichever relay
          // happened to answer first, the lowest-confidence source there is.
          // lastRelaySeen=0 keeps it that way: any genuinely-dated record that
          // arrives later via restore/backup (even an old one) will correctly
          // outrank it through updateRelay's timestamp guard. Stamping this
          // with Date.now() would make "we just discovered this" look like
          // "we just confirmed this," letting a fresh guess beat real history.
          me.lastRelaySeen = 0;
          mlog.info(`RELAY_INFO fresh — adopted wss=${msg.wss} (placeholder, pending confirmation)`);
        } else if (msg.wss && msg.wss !== me.lastRelay) {
          // confirmation only — local storage is the source of truth once we have one.
          // A deliberate migration is the only thing allowed to change lastRelay.
          // lastRelaySeen is deliberately left untouched here too — we didn't
          // confirm anything, we ignored a contradicting announcement.
          mlog.warn(`RELAY_INFO mismatch — server says wss=${msg.wss}  local=${me.lastRelay}  keeping local`);
        }

        // shareableKey reflects OUR local truth, not whatever this connection just announced
        const baseKey = state.shareableKey.split(".").slice(0, 2).join(".");
        state.shareableKey = me.lastRelay
          ? baseKey + "." + btoa(me.lastRelay)
          : baseKey;
        me.shareableKey = state.shareableKey;

        // Close any outbound relay connection we may have opened to this host before
        // realising it's the one we're already signal-connected to — keyed on the
        // literal announced host, independent of the fresh/local-truth decision above.
        if (msg.wss) {
          const ownHost = relayHostname(msg.wss);
          if (ownHost && relayConns[ownHost]) {
            mlog.info(`RELAY_INFO closing redundant conn to signal host  host=${ownHost}`);
            relayConns[ownHost].ws?.close(1000, "same relay");
            delete relayConns[ownHost];
          }
        }
        saveContacts();
      }
      // vapidPublicKey is per-relay, not per-identity — every relay_info
      // (fresh login, ordinary reconnect, or post-migration reconnect)
      // carries whichever relay we're CURRENTLY connected to's key.
      // ensurePushSubscription() is itself the guard against redundant
      // resubscribes on an ordinary reconnect to the same relay — see its
      // pushSyncedRelayWss check.
      state.vapidPublicKey = msg.vapidPublicKey || null;
      ensurePushSubscription();
      break;

    case "sig:seen":
      mlog.debug(`SIG seen       ${pid(msg.id)}`);
      if (msg.id === state.publicId) {
        markOnline(msg.id);
        if (sessionFresh) {
          sendRestoreAckPing(state.publicId);
          mlog.info(`→ RESTORE_ACK  to self — fresh start, skipping handshake`);
        }
      } else if (state.contacts[msg.id]) {
        markOnline(msg.id);
        if (canSendRestoreRequest(msg.id)) sendRestoreRequest(msg.id);
        if (sessionFresh) {
          sendRestoreAckPing(msg.id);
          mlog.info(`→ RESTORE_ACK  to   ${pid(msg.id)} — fresh, asking for peer backup`);
        }
      } else if (sessionFresh) {
        sendRestoreAckPing(msg.id);
        mlog.info(`→ RESTORE_ACK  to   ${pid(msg.id)} — fresh, asking for peer backup`);
      }
      renderContactList();
      break;

    case "sync:restore_req":			markOnline(msg.from);		handleRestoreRequest(msg); 	break;
    case "sync:restore_ack":     		handleRestoreAck(msg);     	break;
    case "sync:restore_push":         	handleRestorePush(msg);    	break;
    case "sync:token_req":  		 	markOnline(msg.from); 		handleTokenRequest(msg);  	break;
    case "sync:token_resp": 		 	markOnline(msg.from); 		handleTokenResponse(msg); 	break;
    case "app:message":              	receiveMessage(msg);       	break;
    case "app:migrate":               	handleMigrate(msg);        	break;
	case "app:burn": 					handleBurn(msg); 			break;
    case "app:sync":         			handleMsgExchange(msg);    	break;   // markOnline now happens inside, after signature verification
    case "sync:backup_offer":         	handleBackupOffer(msg);    	break;
    case "sync:backup_accept":        	handleBackupAccept(msg);   	break;
    case "sync:backup_push":          	handleBackupPush(msg);     	break;

    default: mlog.debug(`SIG unknown type=${msg.type}`);
  }
}

function sendSignal(obj) {
  if (state.ws?.readyState === WebSocket.OPEN) state.ws.send(JSON.stringify(obj));
  // piggyback protocol traffic on open relay connections — never opens one, never resets timer
  if (obj.to && obj.type !== "app:message") sendToRelay(parseAddress(obj.to).id || obj.to, obj, false);
}

/* ══════════════════════════════════════════
   RELAY CONNECTIONS
   Keyed by relay hostname. Each entry:
     { ws, timer, queue, ready }
   Messages only open connections.
   Protocol traffic piggybacks if open, drops if not.
   Timer: 30s inactivity → graceful close (persistent entries exempt).
   Incoming: piped through handleSignal as-is.

   AUTH: every relay connection authenticates the identity — same chain
   connectSignal uses for the main signal socket (startAuth).
══════════════════════════════════════════ */
const relayConns     = {};   // hostname → { ws, timer, queue:[], ready:false, outbound:true }

function relayHostname(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

function resetRelayTimer(hostname) {
  const entry = relayConns[hostname];
  if (!entry) return;
  if (entry.persistent) return;   // persistent relay — never idle-close
  clearTimeout(entry.timer);
  entry.timer = setTimeout(() => {
    mlog.info(`RELAY      idle close  host=${hostname}`);
    entry.ws?.close(1000, "idle");
    delete relayConns[hostname];
  }, RELAY_IDLE_MS);
}

// Disposable connectivity probe for the MIGRATE panel — "is this a relay
// that speaks the protocol correctly" (full auth chain), not just
// "does a socket open." Deliberately separate from relayConns: never
// registered, never reused, always closed on its own regardless of
// outcome. Resolves { ok, reason? } rather than throwing, since a failed
// test is an expected, displayable outcome, not an error.
const RELAY_TEST_TIMEOUT_MS = 5000;

function testRelayConnection(url) {
  return new Promise((resolve) => {
    let settled = false;
    let ws;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws?.close(1000, "test complete"); } catch(e) {}
      resolve(result);
    };

    try {
      ws = new WebSocket(url);
    } catch(e) {
      resolve({ ok: false, reason: "invalid url" });
      return;
    }

    const timer = setTimeout(() => finish({ ok: false, reason: "timeout" }), RELAY_TEST_TIMEOUT_MS);

    let step = "idle";
    // no_receive is part of what the proof signs (see createRelayAuth), so
    // a relay in the middle can't flip it.
    const auth = createRelayAuth(url, { noReceive: true });

    ws.onopen = () => {
      step = "await_challenge";
      // no_receive: this probe closes itself the instant auth_ok arrives — it
      // must never be registered as a recipient server-side, or a buffer
      // flush racing the deliberate close can either warn harmlessly (the
      // common case) or, in the unlucky ordering, have the server delete a
      // buffered packet (e.g. a migrate breadcrumb) it believes was delivered
      // to a socket that was actually already gone or about to discard it.
      ws.send(JSON.stringify(auth.init()));
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        if (step === "await_challenge" && msg.type === "sig:auth_challenge") {
          // proof() throws on a malformed challenge — caught below, reported as a failed test
          ws.send(JSON.stringify(auth.proof(msg)));
          step = "await_ok";
          return;
        }

        if (step === "await_ok" && msg.type === "sig:auth_ok") {
          finish({ ok: true });
          return;
        }

        if (msg.type === "sig:auth_fail") {
          finish({ ok: false, reason: msg.reason || "auth_fail" });
          return;
        }
        // anything else during a test is ignored — this is a probe, not a real session
      } catch(e) {
        finish({ ok: false, reason: "error: " + e.message });
      }
    };

    ws.onerror = () => finish({ ok: false, reason: "connection error" });
    ws.onclose = () => finish({ ok: false, reason: "closed early" });
  });
}

function getOrOpenRelayConn(url, messageOnly) {
  const hostname = relayHostname(url);

  if (!hostname) return null;

  // same as our own home relay — never open a second connection to the
  // host we're already signal-connected to. Every caller already falls
  // back to sendSignal/state.ws when this returns null, so the home
  // relay continues to be reached, just over the existing socket instead
  // of a redundant duplicate that gets separately registered server-side.
  if (hostname === relayHostname(getSignalUrl())) {
    mlog.debug(`RELAY      skipping conn to home relay  host=${hostname}`);
    return null;
  }

  // only reuse connections WE opened — never piggyback on inbound
  if (relayConns[hostname]?.outbound) return relayConns[hostname];
  if (relayConns[hostname] && !relayConns[hostname].outbound) {
    mlog.debug(`RELAY      skipping inbound conn  host=${hostname}`);
    return null;
  }

  if (!messageOnly) return null;   // don't open for protocol traffic

  const entry = { ws: null, timer: null, queue: [], ready: false, outbound: true, authStep: "idle" };
  relayConns[hostname] = entry;

  // connection timeout — if not open within 5s, give up and fall back
  const connectTimeout = setTimeout(() => {
    if (!entry.ready) {
      mlog.warn(`RELAY      connect timeout  host=${hostname}`);
      entry.ws?.close();
    }
  }, RELAY_CONNECT_TIMEOUT_MS);

  try {
    const ws = new WebSocket(url);
    entry.ws = ws;
    const auth = createRelayAuth(url, { endpointId: state.endpointId });

    ws.onopen = () => {
      clearTimeout(connectTimeout);
      entry.authStep = "await_challenge";
      ws.send(JSON.stringify(auth.init()));
      mlog.info(`RELAY      open, authing  host=${hostname}  ${pid(state.publicId, { endpointId: state.endpointId })}`);
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        // ── challenge ──
        if (entry.authStep === "await_challenge" && msg.type === "sig:auth_challenge") {
          // A relay we dialed for a contact is exactly the kind of party that
          // might send a hostile challenge — proof() refuses anything but a
          // well-formed one, and a refusal ends the connection.
          try {
            ws.send(JSON.stringify(auth.proof(msg)));
          } catch(e) {
            mlog.warn(`RELAY      auth sign refused  host=${hostname}  err=${e.message} — closing`);
            ws.close();
            return;
          }
          entry.authStep = "await_ok";
          mlog.info(`RELAY      auth proof sent  host=${hostname}`);
          return;
        }

        // ── ok — authed, now ready to send ──
        if (entry.authStep === "await_ok" && msg.type === "sig:auth_ok") {
          entry.authStep = "done";
          entry.ready    = true;
          mlog.info(`RELAY      authed, flushing ${entry.queue.length} msg(s)  host=${hostname}`);
          entry.queue.forEach(raw => ws.send(raw));
          entry.queue = [];
          return;
        }

        // ── auth fail ──
        if (msg.type === "sig:auth_fail") {
          mlog.warn(`RELAY      auth failed  step=${entry.authStep}  host=${hostname}  reason=${msg.reason}`);
          ws.close();
          return;
        }

        // sig:auth_* belongs to THIS connection's own handshake, handled
        // above — never to handleSignal, whose auth handlers drive the MAIN
        // socket's state. Without this, a stray challenge/ok/fail arriving
        // on a contact-relay socket after its handshake was routed there.
        if (typeof msg.type === "string" && msg.type.startsWith("sig:auth_")) {
          mlog.debug(`RELAY      stray ${msg.type} ignored  host=${hostname}  step=${entry.authStep}`);
          return;
        }

        // ── anything else passes through normally ──
        handleSignal(msg);

      } catch(e) {
        mlog.warn(`RELAY      onmessage error  host=${hostname}  err=${e.message}`);
      }
    };

    ws.onerror = () => {
      mlog.warn(`RELAY      error  host=${hostname}`);
      ws.close();
    };

    ws.onclose = () => {
      clearTimeout(connectTimeout);
      mlog.info(`RELAY      closed  host=${hostname}`);
      clearTimeout(entry.timer);
      if (relayConns[hostname] === entry) delete relayConns[hostname];
      // flush any unsent queued messages through main signal server
      if (entry.queue.length) {
        mlog.info(`RELAY      flushing ${entry.queue.length} queued msg(s) via signal`);
        entry.queue.forEach(raw => {
          try { sendSignal(JSON.parse(raw)); } catch(e) {}
        });
        entry.queue = [];
      }
    };

  } catch(e) {
    mlog.warn(`RELAY      open failed  host=${hostname}  err=${e.message}`);
    delete relayConns[hostname];
    return null;
  }

  return entry;
}
const MIGRATE_DRAIN_DELAY_MS = 10_000;
const MIGRATE_DRAIN_OPEN_MS  = 3_000;
let migrationLocked = false;

function drainOldRelay(url) {
  if (!url) { migrationLocked = false; return; }
  let recovered = 0;
  const ws = new WebSocket(url);
  let step = "idle", closeTimer;
  const auth = createRelayAuth(url);   // no endpoint_id: this is a drain, not a routable session

  ws.onopen = () => {
    step = "await_challenge";
    ws.send(JSON.stringify(auth.init()));
  };

  ws.onmessage = async (evt) => {
    const msg = JSON.parse(evt.data);
    if (step === "await_challenge" && msg.type === "sig:auth_challenge") {
      try {
        ws.send(JSON.stringify(auth.proof(msg)));
      } catch(e) {
        mlog.warn(`MIGRATE    drain — auth sign refused: ${e.message} — closing`);
        ws.close();
        return;
      }
      step = "await_ok";
      return;
    }
    if (step === "await_ok" && msg.type === "sig:auth_ok") {
      step = "draining";
      mlog.info(`MIGRATE    drain — connected to old relay, waiting for flush`);
      closeTimer = setTimeout(() => ws.close(1000, "drain complete"), MIGRATE_DRAIN_OPEN_MS);
      return;
    }
    if (msg.type === "sig:auth_fail") { ws.close(); return; }
    // stray sig:auth_* after the handshake — not a recovered message, and
    // never something to hand to handleSignal (it drives the MAIN socket's auth state)
    if (typeof msg.type === "string" && msg.type.startsWith("sig:auth_")) return;
	
	// Our own breadcrumb, consumed by our own drain — buf_deliver just
    // deleted it server-side. Put it straight back so a straggler device
    // arriving after we've disconnected can still find it. Reuse the
    // blob/sig as-is — same fact, no re-encryption needed.
	if (msg.type === "app:migrate" && msg.from === state.publicId && parseAddress(msg.to).id === state.publicId) {
	  ws.send(JSON.stringify(msg));
	  mlog.info(`MIGRATE    drain — own breadcrumb consumed, replanted`);
	  return;
	}
	recovered++;
    handleSignal(msg);
  };

  ws.onclose = () => {
    clearTimeout(closeTimer);
    if (recovered > 0) {
      mlog.warn(`MIGRATE    drain recovered ${recovered} msg(s) left at old relay — a contact hadn't picked up the migrate notice in time`);
    } else {
      mlog.debug(`MIGRATE    drain — nothing left behind`);
    }
    migrationLocked = false;
  };
  ws.onerror = () => ws.close();
}

/* ══════════════════════════════════════════
   ROUTING RULE — read this before touching send logic
   
   Every outbound MESSAGE goes to the CONTACT'S relay WSS.
   Never to our own relay. Never based on online presence.
   
   state.online / seen signals = UI only (green dot).
   They have NO effect on routing decisions.

   Priority:
     1. contact.lastRelay known → sendToRelay (opens if needed)
     2. no lastRelay            → sendSignal (our main WSS, last resort)

   sendSignal = our own relay = only for contacts with no known relay.
   If their relay is unreachable, the fallback lands on our main WSS,
   which will then buffer the message in the local file queue.
══════════════════════════════════════════ */
function sendToRelay(contactId, obj, messageOnly) {
  const contact = state.contacts[contactId];
  if (!contact?.lastRelay) return false;

  const entry = getOrOpenRelayConn(contact.lastRelay, messageOnly);
  if (!entry) return false;

  const raw = JSON.stringify(obj);
  if (entry.ready && entry.ws?.readyState === WebSocket.OPEN) {
    entry.ws.send(raw);
  } else if (!entry.ready) {
    entry.queue.push(raw);   // will flush in onopen
  } else {
    // ready flag stale — connection dropped between reconnects, queue it
    entry.ready = false;
    entry.queue.push(raw);
  }

  if (messageOnly) resetRelayTimer(relayHostname(contact.lastRelay));
  return true;
}

// Same send mechanics as sendToRelay, but addressed by a literal URL
// instead of a contact's lastRelay — for the two cases where there's no
// contact relationship to route through:
//   - notifying another of OUR OWN devices still parked at the relay we
//     just left (no lastRelay lookup applies to ourselves)
//   - replanting a breadcrumb at a relay we're passively leaving behind
// Deliberately has NO sendSignal fallback. sendToRelay's fallback makes
// sense because "couldn't reach contact's relay" can still be salvaged by
// our own relay buffering it for them. Here there is no salvage path —
// this packet's entire purpose is "reach this specific relay," and our
// own relay buffering it under our own identity wouldn't deliver it to
// anyone. If the URL is unreachable, the packet is dropped; the caller
// logs and moves on rather than silently misrouting it elsewhere.
function sendViaRelayUrl(url, obj) {
  const entry = getOrOpenRelayConn(url, true);
  if (!entry) return false;

  const raw = JSON.stringify(obj);
  if (entry.ready && entry.ws?.readyState === WebSocket.OPEN) {
    entry.ws.send(raw);
  } else if (!entry.ready) {
    entry.queue.push(raw);
  } else {
    entry.ready = false;
    entry.queue.push(raw);
  }

  resetRelayTimer(relayHostname(url));
  return true;
}

/* ══════════════════════════════════════════
   AUDIO MESSAGES
   audioCache: msgId → { encBlob, mimeType }
   Raw audio is encrypted immediately and stored
   in memory only — never hits localStorage.
   Decrypt happens at render time so the element
   is ready before the user clicks play.
   Object URL is revoked after playback ends.
══════════════════════════════════════════ */
const audioCache = {};
const imageCache = {};
// msgId → { envelope, payload } — feeds the packet-info (ⓘ) inspector on
// each message bubble (meshchat-gui.js). In-memory only, same tier as
// audioCache/imageCache above: a message from before this session (page
// reload, or restored via backup/sync rather than sent/received live)
// simply has no entry, and the inspector says so rather than fabricating
// one. As of the per-device X4DH wire-key pass, `envelope` here is only
// ONE representative copy out of potentially several genuinely different
// per-device ciphertexts (see sendFannedX4DH) — good enough to inspect
// the payload/sig shape, not a claim that every device received this
// exact blob.
const packetCache = {};

let mediaRecorder = null;
let audioChunks   = [];

async function startAudioRecord() {
  if (mediaRecorder) return;
  if (!state.currentChat) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm" });
    audioChunks   = [];
    mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
    mediaRecorder.onstop = async () => {
      const blob = new Blob(audioChunks, { type: "audio/webm" });
      stream.getTracks().forEach(t => t.stop());
      mediaRecorder = null;
      document.getElementById("audioBtn").classList.remove("recording");
      mlog.info(`AUDIO      recorded  size=${blob.size}b`);
      await sendAudioMessage(blob);
    };
    mediaRecorder.start();
    document.getElementById("audioBtn").classList.add("recording");
    mlog.info("AUDIO      recording started");
  } catch(e) {
    mlog.err("AUDIO      mic error: " + e.message);
    mediaRecorder = null;
  }
}

function stopAudioRecord() {
  if (mediaRecorder?.state === "recording") mediaRecorder.stop();
}

async function sendImageMessage(file) {
  if (!state.currentChat) return;
  const contact = state.contacts[state.currentChat];
  if (!contact?.encKey) return;

  const bitmap = await createImageBitmap(file);
  const MAX = 800;
  const scale = Math.min(1, MAX / Math.max(bitmap.width, bitmap.height));
  const w = Math.round(bitmap.width  * scale);
  const h = Math.round(bitmap.height * scale);
  const canvas = Object.assign(document.createElement("canvas"), { width: w, height: h });
  canvas.getContext("2d").drawImage(bitmap, 0, 0, w, h);

  canvas.toBlob(async (blob) => {
    const reader = new FileReader();
    reader.onloadend = async () => {
      const base64   = reader.result.substring(reader.result.indexOf(",") + 1);
      const mimeType = "image/jpeg";
      const ts       = Date.now();
      const id       = crypto.randomUUID();

      let status = "failed";
      let sentN  = null;
      let ackPointer = {};
      try {
        const me       = state.contacts[state.publicId];
        const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

        sentN = nextSendCounter(state.currentChat);
        ackPointer = getAckPointer(state.currentChat) || {};
        const payload = { id, type: "image", data: base64, mimeType, ts, deviceId: state.deviceId, endpointId: state.endpointId, n: sentN, ...ackPointer, ...(relay ? { relay } : {}) };

        const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
        imageCache[id] = { encBlob, mimeType };

        const fanned = await sendFannedX4DH(state.currentChat, payload);
        packetCache[id] = { envelope: fanned.envelopes[0] || null, payload };
        status = fanned.sent ? "sent" : "failed";
        mlog.info(`→ IMAGE        to   ${pid(state.currentChat)}  ${w}×${h}  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}${!fanned.sent ? " — nowhere, no open socket" : ""}`);
      } catch(e) {
        mlog.err(`→ IMAGE        to   ${pid(state.currentChat)} — send failed: ${e.message}`);
      }

      const stored = { id, from: state.publicId, type: "image", mimeType, ts, valid: true, status, deviceId: state.deviceId, n: sentN, ...ackPointer };
      contact.messages = mergeMessages(contact.messages, [stored]);
      if (status !== "failed") sendSelfSync(contact.publicId, stored);   // stub only — see sendSelfSync
      await saveContacts();
      renderMessages();
      updateContactPreview();   // sidebar preview otherwise only ever updates on incoming traffic
    };
    reader.readAsDataURL(blob);
  }, "image/jpeg", 0.85);
}

async function sendAudioMessage(blob) {
  if (!state.currentChat) return;
  const contact = state.contacts[state.currentChat];
  if (!contact?.encKey) return;

  const reader = new FileReader();
  reader.onloadend = async () => {
    const result   = reader.result;
    const base64   = result.substring(result.indexOf(",") + 1);
    const ts       = Date.now();
    const id       = crypto.randomUUID();
    const mimeType = blob.type;

    let status = "failed";
    let sentN  = null;
    let ackPointer = {};
    try {
      const me       = state.contacts[state.publicId];
      const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

      sentN = nextSendCounter(state.currentChat);
      ackPointer = getAckPointer(state.currentChat) || {};
      const payload = { id, type: "audio", data: base64, mimeType, ts, deviceId: state.deviceId, endpointId: state.endpointId, n: sentN, ...ackPointer, ...(relay ? { relay } : {}) };

      // store encrypted in memory cache — never raw
      const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
      audioCache[id] = { encBlob, mimeType };

      const fanned = await sendFannedX4DH(state.currentChat, payload);
      packetCache[id] = { envelope: fanned.envelopes[0] || null, payload };
      status = fanned.sent ? "sent" : "failed";
      mlog.info(`→ AUDIO        to   ${pid(state.currentChat)}  size=${blob.size}b  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}${!fanned.sent ? " — nowhere, no open socket" : ""}`);
    } catch(e) {
      mlog.err(`→ AUDIO        to   ${pid(state.currentChat)} — send failed: ${e.message}`);
    }

    // stub in messages — data stays in audioCache only
    const stored = { id, from: state.publicId, type: "audio", mimeType, ts, valid: true, status, deviceId: state.deviceId, n: sentN, ...ackPointer };
    contact.messages = mergeMessages(contact.messages, [stored]);
    if (status !== "failed") sendSelfSync(contact.publicId, stored);   // stub only — see sendSelfSync
    await saveContacts();
    renderMessages();
    updateContactPreview();   // sidebar preview otherwise only ever updates on incoming traffic
  };
  reader.readAsDataURL(blob);
}

async function getAudioUrl(msgId) {
  const cached = audioCache[msgId];
  if (!cached) {
    mlog.warn(`AUDIO      no cache entry for ${msgId}`);
    return null;
  }
  try {
    const plain = await decryptObject(state.encKey, cached.encBlob);
    mlog.debug(`AUDIO      decrypted ok  mimeType=${plain.mimeType}  dataLen=${plain.data?.length}`);
    const bytes = Uint8Array.from(atob(plain.data), c => c.charCodeAt(0));
    const blob  = new Blob([bytes], { type: cached.mimeType });
    return URL.createObjectURL(blob);
  } catch(e) {
    mlog.warn(`AUDIO      decrypt failed for ${msgId}: ${e.message}`);
    return null;
  }
}

/* ══════════════════════════════════════════
   PUSH NOTIFICATIONS
   Opt-in, per-device (see server.py/protocol.md for the wire side).
   Preference is a local-only on/off flag (loadPushPref/savePushPref) —
   the actual PushSubscription object lives in the browser, obtained via
   the service worker's PushManager, keyed to whichever relay's VAPID
   public key was current at subscribe time.

   ensurePushSubscription() is the single entry point that keeps browser
   subscription + relay registration in sync with the current relay. It's
   deliberately safe to call often (relay_info fires on every connect,
   including ordinary reconnects) — pushSyncedRelayWss short-circuits the
   common case, and the key-mismatch check handles the one case that
   actually needs work: a migration having moved us to a relay whose
   VAPID key differs from whatever the browser is currently subscribed
   under. No special-cased "migration path" is needed for the subscribe
   side as a result — see commitMigration()/notifyMigration() for the
   one thing that IS migration-specific: proactively telling the OLD
   relay to drop our subscription rather than leaving it to go silently
   stale there.
══════════════════════════════════════════ */
function loadPushPref() {
  try { return localStorage.getItem(PUSH_PREF_KEY + "_" + state.publicId) === "1"; }
  catch(e) { return false; }
}
function savePushPref(enabled) {
  try { localStorage.setItem(PUSH_PREF_KEY + "_" + state.publicId, enabled ? "1" : "0"); }
  catch(e) {}
}

function pushSupported() {
  return "serviceWorker" in navigator && "PushManager" in window;
}

async function ensurePushSubscription() {
  if (!loadPushPref()) return;
  if (!state.vapidPublicKey) return;   // no relay_info received yet this connection
  if (!state.endpointId) return;       // subscriptions are keyed by endpointId on the relay — nothing to key on yet
  if (!pushSupported()) {
    mlog.warn("PUSH       not supported in this browser — leaving preference as-is");
    return;
  }
  const wss = getSignalUrl();
  if (state.pushSyncedRelayWss === wss) return;   // already synced with this relay this session

  try {
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();

    // desiredKey/currentKey comparison — a subscription created against a
    // DIFFERENT relay's VAPID key (this only ever happens right after a
    // migration) is cryptographically dead weight; the push service will
    // never accept a JWT signed by a key other than the one presented at
    // subscribe time. Detecting the mismatch here is what lets migration
    // "just work" through this same function rather than needing its own
    // resubscribe call.
    const desiredKey = base64ToRaw(state.vapidPublicKey);
    const currentKey = sub?.options?.applicationServerKey
      ? new Uint8Array(sub.options.applicationServerKey) : null;
    const keyMatches = currentKey && currentKey.length === desiredKey.length
      && currentKey.every((b, i) => b === desiredKey[i]);

    if (sub && !keyMatches) {
      await sub.unsubscribe();
      mlog.info("PUSH       dropped subscription tied to a different relay's key");
      sub = null;
    }
    if (!sub) {
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: desiredKey });
      mlog.info("PUSH       browser subscription created");
    }

    const json = sub.toJSON();
    sendSignal({
      type: "sig:push_subscribe", from: state.publicId, endpointId: state.endpointId,
      subscription: { endpoint: json.endpoint, keys: json.keys },
    });
    state.pushSyncedRelayWss = wss;
    mlog.info(`PUSH       registered with relay  ${wss}`);
  } catch(e) {
    mlog.warn("PUSH       subscribe failed: " + e.message);
  }
}

// user-facing: called from the edit-contact (self) checkbox. Turning OFF
// unsubscribes both the browser (so it stops waking this tab/SW for
// nothing) and the current relay. Does NOT touch any OTHER relay this
// identity may have subscriptions parked at from a past migration — same
// "best-effort, not a durable guarantee" tier as the rest of this feature.
async function togglePushPref(enabled) {
  if (enabled) {
    savePushPref(true);
    state.pushSyncedRelayWss = null;   // force ensurePushSubscription to actually run
    await ensurePushSubscription();
  } else {
    savePushPref(false);
    try {
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.getSubscription();
      if (sub) await sub.unsubscribe();
    } catch(e) {}
    sendSignal({ type: "sig:push_unsubscribe", from: state.publicId, endpointId: state.endpointId });
    state.pushSyncedRelayWss = null;
    mlog.info("PUSH       unsubscribed");
  }
}

/* ══════════════════════════════════════════
   MESSAGING
══════════════════════════════════════════ */

/* ── trial decryption across candidate keys (X4DH-aware) ──
   deviceId — the piece of information that would tell us WHICH key to
   use — lives INSIDE the encrypted payload by deliberate design (see
   protocol.md's Device Identity section: moved there specifically so
   the relay can never see or rewrite it). That means the recipient
   can't know which key applies before decrypting, the same chicken-
   and-egg any per-device-keyed scheme built this way runs into — there
   is no relay-visible field we can safely reuse for this without
   reopening exactly the exposure that move was meant to close.

   Resolved by trying every candidate key held for this sender until one
   succeeds. AES-GCM's auth tag makes a wrong-key attempt fail cleanly
   and immediately (a rejected crypto.subtle.decrypt, not a corrupted
   result), so this costs a handful of failed decrypt calls at worst —
   bounded by how many devices a contact runs, typically 1-3 — never a
   false positive. Order: every X4DH session held for this contact (any
   stage — rk0 is eligible, see the design discussion this pass came out
   of for why), most-recently-established first as a cheap "most likely
   still active" heuristic, then the legacy identity-level key last,
   since a device that's completed X4DH bootstrap no longer sends under
   the old key at all.

   Returns { plain, viaX4DH, theirDeviceId } — theirDeviceId is set only
   when an X4DH candidate was the one that worked. Throws if every
   candidate fails, same failure shape decryptMessage itself already
   has — callers catch this exactly as before.
── */
async function decryptIncomingMessage(fromId, blob, aad) {
  const contact  = state.contacts[fromId];
  const sessions = state.x4dhSessions[fromId] || {};
  const candidates = Object.entries(sessions)
    .sort(([, a], [, b]) => (b.establishedAt || 0) - (a.establishedAt || 0));

  for (const [theirDeviceId] of candidates) {
    // every live generation for this device, not just the send key — see
    // "wire-message keys" above. keyLabel says which one worked.
    for (const { key, label } of await getDecryptWireKeys(fromId, theirDeviceId)) {
      try {
        const plain = await decryptMessage(blob, key, aad);
        return { plain, viaX4DH: true, theirDeviceId, keyLabel: label };
      } catch(e) { /* wrong key — try the next generation / device */ }
    }
  }

  // legacy identity-level key — last resort, covers any device that
  // hasn't bootstrapped an X4DH session yet (or never will)
  const plain = await decryptMessage(blob, contact.encKey, aad);
  return { plain, viaX4DH: false, theirDeviceId: null, keyLabel: null };
}

/* ══════════════════════════════════════════
   SELF-SYNC — receive side (see sendSelfSync for the why)
   A "selfsync" payload is an ordinary app:message from OUR OWN identity
   whose plaintext carries { peerId, msg }: a copy of something another
   device of ours just sent to contact `peerId`. Merged straight into that
   contact's conversation as one of OUR messages.

   Hard rules, each one closing a specific hole:
     - msg.from MUST be us. A contact can never sync anything into our
       conversations — checked here even though the outer decrypt/verify
       path already resolves `contact` from msg.from.
     - `valid` MUST be true. receiveMessage normally displays an
       unverified message with a warning; that leniency is wrong here,
       since this merges into a DIFFERENT conversation than the sender
       field suggests. Unverified → dropped, never shown.
     - Never sends anything back: no delivery ack, no re-fan. The send
       side is only ever triggered by a local user action, so a received
       copy can't ping-pong between siblings.
     - Never bumps unread — these are our own messages.
     - ackTrusted is deliberately NOT set: provenance here is "a sibling
       told me", not "composed or received live on this device" (see the
       trust gate in mergeMessages), so the copy sits at its baseline
       (ts, id) position.
     - The embedded n is kept on the stored message but NEVER fed to
       recordKnownDevice — it's a per-(device, contact) counter for the
       peer conversation, not a sequence for the self channel.
     - Whitelisted field copy, not a spread: the inner object is
       attacker-shaped as far as this function is concerned (a
       compromised sibling is inside the trust model, but sloppy
       spreading would still let junk fields land in stored messages).
══════════════════════════════════════════ */
async function handleSelfSync(msg, plain, valid) {
  const fromDisp = pid(state.publicId, { deviceId: plain.deviceId, endpointId: plain.endpointId });
  if (msg.from !== state.publicId) {
    mlog.warn(`← SELFSYNC     from ${pid(msg.from)} — not from our own identity, dropped`);
    return;
  }
  if (!valid) {
    mlog.warn(`← SELFSYNC     from ${fromDisp} — signature invalid, dropped`);
    return;
  }
  if (plain.deviceId === state.deviceId) {
    mlog.debug(`← SELFSYNC     own echo, ignored`);
    return;
  }

  const peerId = plain.peerId;
  const inner  = plain.msg;
  const peer   = state.contacts[peerId];
  if (!peer || peer.blocked || peerId === state.publicId) {
    mlog.debug(`← SELFSYNC     from ${fromDisp} — peer=${pid(peerId)} unknown/blocked/self, ignored`);
    return;
  }
  if (!inner || typeof inner.id !== "string" || inner.id.length > 64 || !Number.isFinite(inner.ts)) {
    mlog.warn(`← SELFSYNC     from ${fromDisp} — malformed inner message, dropped`);
    return;
  }

  const m = { id: inner.id, from: state.publicId, ts: inner.ts, valid: true, status: "sent" };
  const t = inner.type || "text";
  if (t === "text") {
    if (typeof inner.text !== "string") { mlog.warn(`← SELFSYNC     from ${fromDisp} — text missing, dropped`); return; }
    m.text = inner.text;
  } else if (t === "audio" || t === "image") {
    // stub only — media is transient by design (known-limitations.md), and
    // renderMessages already shows "(not available)" for a media message
    // with no cache entry.
    m.type = t;
    m.mimeType = typeof inner.mimeType === "string" ? inner.mimeType : null;
  } else if (t === "reaction") {
    if (typeof inner.targetId !== "string") { mlog.warn(`← SELFSYNC     from ${fromDisp} — reaction target missing, dropped`); return; }
    m.type = "reaction"; m.targetId = inner.targetId; m.emoji = inner.emoji || null;
    delete m.status;
  } else {
    mlog.debug(`← SELFSYNC     from ${fromDisp} — unsupported inner type=${t}, ignored`);
    return;
  }
  if (typeof inner.deviceId === "string") m.deviceId = inner.deviceId;
  if (Number.isFinite(inner.n)) m.n = inner.n;
  if (typeof inner.ackDeviceId === "string" && Number.isFinite(inner.ackN)) { m.ackDeviceId = inner.ackDeviceId; m.ackN = inner.ackN; }

  // Immutable-content ids (text/audio/image) already on file are left
  // alone — mergeMessages' same-id rule would let this copy's status:"sent"
  // replace a local "delivered", and there's nothing to learn from a
  // duplicate anyway (a targeted copy and a broadcast fallback can both
  // arrive). Reactions are the exception: same id across states, newer ts
  // must win — mergeMessages already does that.
  if (m.type !== "reaction" && peer.messages.some(x => x.id === m.id)) {
    mlog.debug(`← SELFSYNC     from ${fromDisp} — already have ${pid(m.id)}, skipped`);
    return;
  }

  peer.messages = mergeMessages(peer.messages, [m]);
  reconcileDeliveryStatus(peer);
  mlog.info(`← SELFSYNC     from ${fromDisp}  peer=${pid(peerId)}  type=${t}  id=${pid(m.id)}`);
  await saveContacts();
  if (state.currentChat === peerId) renderMessages();
  updateContactPreview();
}

async function receiveMessage(msg) {
  if (!msg.from || !msg.blob || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  try {
    let plain, valid, viaX4DH, matchedDeviceId, keyLabel;
    // AAD is built from the envelope AS RECEIVED — a packet retyped, reflected or
    // redirected in transit no longer decrypts (see PACKET ENVELOPE above)
    ({ plain, viaX4DH, theirDeviceId: matchedDeviceId, keyLabel } = await decryptIncomingMessage(msg.from, msg.blob, envelopeAad(msg.type, msg.from, msg.to)));
    valid = verifyEnvelope(msg, contact.signPublicKey);

    // Belt-and-suspenders consistency check: a successful decrypt under
    // a specific device's X4DH session key means that ciphertext was
    // genuinely produced by whoever holds THAT session's key (AES-GCM's
    // auth tag rules out a wrong-key false positive) — so plain.deviceId,
    // the sender's own claim about which device sent this, should always
    // agree with matchedDeviceId. A mismatch shouldn't be reachable in
    // practice; treated the same as a bad signature (flagged, not
    // dropped) rather than silently trusted, since it would mean
    // something is wrong with session bookkeeping worth a human seeing.
    if (viaX4DH && valid && matchedDeviceId && plain.deviceId && matchedDeviceId !== plain.deviceId) {
      mlog.warn(`← MSG          from ${pid(msg.from)} — decrypted under ${pid(matchedDeviceId)}'s X4DH key but payload claims deviceId=${pid(plain.deviceId)} — mismatch, treating as unverified`);
      valid = false;
    }
    // A VERIFIED message under our current RK1 proves the peer holds RK1 —
    // see "wire-message keys". Only after verification: nothing here may
    // switch our send key on the strength of an unverified packet.
    if (viaX4DH && valid && keyLabel === "current") confirmX4DHPeerKey(msg.from, matchedDeviceId);

    // Duplicate-delivery guard (0.4.9) — a targeted send and the
    // identity-level broadcast fallback are NOT mutually exclusive: a
    // device resolved enough to get its own targeted copy (see
    // resolveDeviceTargets/sendFannedX4DH above) is still a live member
    // of its identity's broadcast set, so it can legitimately receive the
    // SAME message twice — once via deliver_to_endpoint, once via
    // deliver() — whenever any OTHER device of the same contact is
    // unresolved/stale and forces the broadcast fallback too.
    //
    // That overlap was always meant to be harmless — the same
    // "redundant, but merging twice is a no-op" reasoning
    // pushBackupToContacts already documents for its own self-sync
    // targeting. It WAS harmless for the stored result (mergeMessages
    // already dedups by id) but not for the SIDE EFFECTS below: each
    // physical arrival independently bumped the unread counter and
    // fired a fresh RECEIVED auto-ack — and since sendReaction is now
    // itself fanned, two duplicate receives could each spawn two acks,
    // flooding the sender with four.
    //
    // Reuses the exact dedup mechanism already used for the backup/
    // restore handshake family rather than inventing a new one — keyed
    // on (id, ts) together, not id alone, so a genuinely NEWER reaction
    // sharing its stable derived id (see deriveReactionId — the same id
    // deliberately persists across every emoji state) is never mistaken
    // for a stale duplicate of an older one.
    if (plain.id && isDuplicateInbound(`app_message:${plain.id}:${plain.ts}`)) {
      mlog.debug(`← MSG          from ${pid(msg.from)} — duplicate delivery within ${DEDUP_WINDOW_MS}ms, suppressed`);
      return;
    }

    // deviceId now travels inside the encrypted+signed payload rather than
    // the outer envelope (see notifyMigration-style payloads / protocol.md) —
    // only recorded once the signature is confirmed valid, so a message that
    // fails to decrypt, or one that decrypts but isn't validly signed, can't
    // poison the device registry. This was previously firing unconditionally
    // before decrypt/verify even ran — left over from debugging signature
    // failures early on; tightened now that it's a real trust boundary.
    if (valid && plain.deviceId) recordKnownDevice(msg.from, plain.deviceId, plain.n, plain.endpointId);
    if (plain.id) packetCache[plain.id] = { envelope: msg, payload: plain };
    // Relay hint rides inside the signed payload, so it carries the same
    // trust requirement as recordKnownDevice above: only a validly signed
    // message may steer where we send this contact's traffic. A message
    // that decrypts but fails (or lacks) the signature — a relay stripping
    // the outer sig, say — still displays, but its hint is ignored. The
    // ts is clamped to now (see clampRelayTs) so a sender-chosen future
    // timestamp can't pin lastRelaySeen and shut out later genuine notices.
    if (valid && plain.relay?.wss) {
      updateRelay(contact, plain.relay.wss, clampRelayTs(plain.ts || Date.now()));
      if (state.currentChat === msg.from) updateChatRelayInfo(msg.from);
    }
    // sub-id annotation only once signed+verified — same trust gate as
    // recordKnownDevice just above; an unverified plain.deviceId/endpointId
    // isn't safe to trust even for display, since the outer envelope's
    // deviceId doesn't exist anymore (it moved inside the signed payload).
    const fromDisp = valid ? pid(msg.from, { deviceId: plain.deviceId, endpointId: plain.endpointId }) : pid(msg.from);
    mlog.info(`← MSG          from ${fromDisp}  sig:${valid ? "✓" : "✗"}  key:${viaX4DH ? "x4dh" : "legacy"}`);

    // Self-sync copies of OUR OWN outgoing messages from a sibling device —
    // a completely different destination than an ordinary message, so it
    // branches off here, before any of the contact-conversation handling
    // below (unread, auto-ack, msgObj construction) could apply to it.
    if (plain.type === "selfsync") {
      await handleSelfSync(msg, plain, valid);
      return;
    }

    const msgObj = { id: plain.id, from: msg.from, ts: plain.ts || Date.now(), valid };
    // persist the sender's per-device send counter locally too, not just
    // in the wire payload — needed both for the gap/"missing" display
    // (recordKnownDevice above only tracks it on the registry side) and
    // as a durable record of what n's we actually have stored per contact.
    if (plain.n != null) msgObj.n = plain.n;
    // also stamp which device sent it — needed by reconcileMissingDevices
    // below to attribute a stored n to the right device's `missing` list,
    // not just "some device of this contact's."
    if (plain.deviceId) msgObj.deviceId = plain.deviceId;
    // causal-ordering pointer (getAckPointer) — carried straight through
    // from the sender's payload onto our stored copy, same "just persist
    // whatever's there" treatment as n/deviceId above. Consumed later by
    // mergeMessages to splice this message directly after whatever it's
    // acknowledging, instead of trusting ts alone.
    if (plain.ackDeviceId) msgObj.ackDeviceId = plain.ackDeviceId;
    if (plain.ackN != null) msgObj.ackN = plain.ackN;

    if (plain.type === "audio") {
      const encBlob = await encryptObject(state.encKey, { data: plain.data, mimeType: plain.mimeType });
      audioCache[plain.id] = { encBlob, mimeType: plain.mimeType };
      msgObj.type = "audio"; msgObj.mimeType = plain.mimeType;
    } else if (plain.type === "image") {
      const encBlob = await encryptObject(state.encKey, { data: plain.data, mimeType: plain.mimeType });
      imageCache[plain.id] = { encBlob, mimeType: plain.mimeType };
      msgObj.type = "image"; msgObj.mimeType = plain.mimeType;
    } else if (plain.type === "reaction") {
      msgObj.type = "reaction"; msgObj.targetId = plain.targetId; msgObj.emoji = plain.emoji || null;
      mlog.info(`← REACTION     from ${valid ? pid(msg.from, { deviceId: plain.deviceId, endpointId: plain.endpointId }) : pid(msg.from)}  target=${pid(plain.targetId)}  emoji=${plain.emoji || "nil"}`);
    } else if (plain.type === "system") {
      msgObj.type = "system"; msgObj.kind = plain.kind || null; msgObj.text = plain.text;
      mlog.info(`← SYSTEM_MSG   from ${pid(msg.from)}  kind=${plain.kind || "?"}  "${(plain.text||"").slice(0,60)}"`);
    } else {
      msgObj.text = plain.text;
      mlog.debug(`MSG content: "${(plain.text||"").slice(0,40)}${(plain.text||"").length>40?"…":""}"  id=${plain.id}`);
    }

    // ── merge + reconcile happens BEFORE any ack is sent — see below ──
    if (msgObj.type === "reaction") {
      contact.messages = mergeMessages(contact.messages, [msgObj]);
      // Any reaction — including our own auto-ack below, which is itself
      // a reaction with emoji:null — targeting a message WE sent proves
      // the other side decrypted it. A genuine "they cleared their
      // reaction" is indistinguishable on the wire and implies the exact
      // same thing, so no special-casing is needed. reconcileDeliveryStatus
      // (shared with every other merge site — see its own doc comment)
      // does this flip now instead of a one-off inline check here.
      reconcileDeliveryStatus(contact);
      reconcileMissingDevices(contact);
    } else {
      contact.messages = mergeMessages(contact.messages, [msgObj]);
      if (state.currentChat !== msg.from) {
        state.unread[msg.from] = (state.unread[msg.from] || 0) + 1;
      }
    }

    // Durability point — everything above this line is in-memory only.
    // The auto-ack below deliberately waits until AFTER this completes,
    // so RECEIVED means "I actually have this on disk," not "I decrypted
    // this and I'm about to try to save it." Previously the ack fired
    // inline above, before this await — a tab/app killed between the ack
    // leaving the socket and this write completing could show the sender
    // ✔️✔️ delivered for a message the recipient never actually persisted.
    await saveContacts();
    saveContactsBackup();

    // Auto-ack — reuses the existing reaction channel (emoji:null) rather
    // than a new packet type. Only for a message that both decrypted AND
    // verified: an ack should mean "a real device confirmed this," not
    // just "something decryptable arrived." Never fires on our own
    // self-targeted traffic (msg.from === state.publicId) — there's no
    // delivery concept to signal to ourselves. Deliberately NOT gated on
    // state.currentChat — this must go to msg.from regardless of which
    // chat happens to be open. Never fires for an incoming reaction
    // itself — no meta-acking.
    if (msgObj.type !== "reaction" && valid && msg.from !== state.publicId) {
      sendReaction(plain.id, null, msg.from, true);
    }

    if (state.currentChat === msg.from) renderMessages();
    updateContactPreview();
  } catch(e) {
    console.warn("message decrypt failed", e);
    mlog.err(`← MSG          from ${pid(msg.from)} — decrypt failed`);
  }
}

/* ══════════════════════════════════════════
   MIGRATE — receive side
   Packet: { type: "app:migrate", from, to, blob: encrypted{ newRelay, ts }, sig }
   Decryption is identical to a regular message — always state.encKey,
   regardless of sender, since this scheme is symmetric (a contact who
   has your shareableKey already holds the same key you decrypt with).
   Deliberately OUT OF SCOPE for the X4DH wire-key pass — app:migrate is
   never device-targeted by protocol design (see server.py/protocol.md),
   so there is no single device pair to derive an X4DH key against;
   this stays on the legacy identity-level key permanently, not just for
   now. Signature is verified the same way receiveMessage does it — this
   packet redirects routing, so unlike most other packet types it must
   NOT be trusted on decryption success alone. The relay is untrusted
   infrastructure; cryptographic proof is the only trust boundary.
   The two branches below only diverge in what happens AFTER decrypt:
     - from a contact  → same passive learning already used for relay
       info embedded in regular messages, just arriving as its own
       dedicated, overwrite-buffered packet instead.
     - from self        → another of our own devices migrated (or
       replanted a breadcrumb). Adopt silently — no notify packets, no
       ceremony, just follow. Also replants a breadcrumb at the relay we
       ourselves are leaving behind, so a straggler device even further
       behind than us can still find the trail.
══════════════════════════════════════════ */
async function handleMigrate(msg) {
  // never device-targeted (server.py drops a compound `to` for this type too) — bare identity only
  if (!msg.from || !msg.blob || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);

  let plain;
  try {
    plain = await decryptMessage(msg.blob, contact.encKey, envelopeAad(msg.type, msg.from, msg.to));
  } catch(e) {
    mlog.warn(`← MIGRATE      from ${pid(msg.from)} — decrypt failed`);
    return;
  }

  const sigValid = verifyEnvelope(msg, contact.signPublicKey);
  if (!sigValid) {
    mlog.warn(`← MIGRATE      from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }

  if (!plain.newRelay) {
    mlog.warn(`← MIGRATE      from ${pid(msg.from)} — missing newRelay, dropped`);
    return;
  }

  if (msg.from === state.publicId) {
    // Same timestamp-guarded adoption as every other relay update in this
    // app (updateRelay) — an out-of-order or stale-buffered copy can't
    // regress us, regardless of which device sent it or when it arrives.
    const me        = state.contacts[state.publicId];
    const beforeUrl = me.lastRelay;
    // ts clamped to now (clampRelayTs): a migrate notice is signed, but its
    // ts is still sender-chosen, and a future one would pin lastRelaySeen
    // and make every genuine later notice "not newer". The breadcrumb
    // replant below deliberately keeps the ORIGINAL plain.ts — it must not
    // manufacture freshness, and the clamp only ever lowers a ts.
    updateRelay(me, plain.newRelay, clampRelayTs(plain.ts));
    if (me.lastRelay !== beforeUrl) {
      mlog.info(`← MIGRATE      from self — following to ${plain.newRelay}`);
      me.prevRelay     = beforeUrl;
      me.prevRelaySeen = Date.now();
      await saveContacts();
      renderContactList();
      rebootSignal();
      // Replant a fresh breadcrumb at the relay we're leaving behind
      // (beforeUrl), pointing at the same fact we just adopted — same
      // newRelay, same ts. Reusing plain.ts rather than Date.now() means
      // relaying this doesn't manufacture new freshness; it's still the
      // same historical fact, just left somewhere a straggler device can
      // still find it. No contact relationship applies to ourselves, so
      // this has to go by explicit URL.
      if (beforeUrl) {
        try {
          const breadcrumbObj = await sealEnvelope("app:migrate", state.publicId, state.publicId, me.encKey, { newRelay: plain.newRelay, ts: plain.ts });
          const sent = sendViaRelayUrl(beforeUrl, breadcrumbObj);
          mlog.info(`→ MIGRATE      breadcrumb replanted @ ${beforeUrl}  sent=${sent}`);
        } catch(e) {
          mlog.warn(`→ MIGRATE      breadcrumb replant failed: ${e.message}`);
        }
      }
    } else {
      mlog.debug(`← MIGRATE      from self — ${plain.newRelay} not newer, ignored`);
    }
  } else {
    const before = contact.lastRelay;
    updateRelay(contact, plain.newRelay, clampRelayTs(plain.ts));   // clamp: see the self branch above
    if (contact.lastRelay !== before) {
      mlog.info(`← MIGRATE      from ${pid(msg.from)} — relay updated to ${plain.newRelay}`);
      await saveContacts();
      if (state.currentChat === msg.from) updateChatRelayInfo(msg.from);
    } else {
      mlog.debug(`← MIGRATE      from ${pid(msg.from)} — ${plain.newRelay} not newer, ignored`);
    }
  }
}
/* ══════════════════════════════════════════
   BURN NOTICE — receive side
   Packet: { type: "app:burn", from, to, blob: encrypted{ts}, sig }
   Decryption is identical to a regular message/migrate — always
   state.encKey, symmetric scheme. Same "OUT OF SCOPE for X4DH wire keys,
   permanently" reasoning as app:migrate above — never device-targeted
   by protocol design, so there's no per-device key to switch to.
   Signature verification is NOT optional here, same rule as app:migrate
   and the call:* group: this packet drives an irreversible action, so
   an unsigned or invalid one is dropped outright rather than flagged
   and shown.
 
   Two branches:
     - from self        → another of our own devices burned (or we
       burned from elsewhere and this is reaching a second session).
       Wipe THIS device too — no ceremony, no notify-back, just follow,
       same "adopt silently" spirit as migrate's self branch.
     - from a contact    → they burned; convert to block on our side.
       Already-blocked contact → no-op, nothing left to do.
══════════════════════════════════════════ */
async function handleBurn(msg) {
  if (!msg.from || !msg.blob) return;
 
  // never device-targeted — bare identity only (same rule as migrate)
  if (msg.to !== state.publicId) {
    mlog.warn(`← BURN         from ${pid(msg.from)} — not addressed to our bare identity, dropped`);
    return;
  }
  const isSelf  = msg.from === state.publicId;
  const contact = state.contacts[msg.from];
  if (!isSelf && !contact) return;   // unknown sender, nothing to act on
 
  let plain;
  try {
    plain = await decryptMessage(msg.blob, contact.encKey, envelopeAad(msg.type, msg.from, msg.to));
  } catch(e) {
    mlog.warn(`← BURN         from ${pid(msg.from)} — decrypt failed`);
    return;
  }
 
  const verifyKey = isSelf ? state.contacts[state.publicId]?.signPublicKey : contact.signPublicKey;
  const sigValid  = verifyEnvelope(msg, verifyKey);
  if (!sigValid) {
    mlog.warn(`← BURN         from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
 
  if (isSelf) {
    mlog.warn(`← BURN         from self — self-destruct triggered`);
    selfDestruct();
    return;
  }
 
  if (contact.blocked) {
    mlog.debug(`← BURN         from ${pid(msg.from)} — already blocked, no-op`);
    return;
  }
 
  mlog.warn(`← BURN         from ${pid(msg.from)} — converting to block`);
  burnBlockContact(msg.from);
}
 
/* Burn→block conversion. Reuses the existing manual-block wipe
   (messages, peerBackups) but additionally drops any stored peer
   token — deliberately NOT done on a manual block (see contactAction
   "block" below), since manual block is a softer, reversible-in-spirit
   action while burn is explicitly saying "treat this identity as gone
   for good." blockReason is local-only UI metadata — never a security
   boundary, just lets the edit-contact pane say WHY something is blocked
   instead of a bare yes/no. */
async function burnBlockContact(id) {
  const contact = state.contacts[id];
  if (!contact) return;
  contact.blocked         = true;
  contact.blockReason     = "burned";
  contact.lastStateChange = Date.now();
  contact.messages        = [];
  if (state.peerBackups[id]) {
    delete state.peerBackups[id];
    savePeerBackups();
  }
  if (state.peerTokens[id]) {
    delete state.peerTokens[id];
    savePeerTokens();
  }
  await saveContacts();
  mlog.info(`BURN       wiped messages/backup/token, blocked  id=${pid(id)}`);
  renderContactList();
  if (state.currentChat === id) {
    document.getElementById("blockToggleBtn").textContent = "UNBLOCK";
  }
}
 
/* ══════════════════════════════════════════
   SELF-DESTRUCT
   Not cryptographic revocation — can't be. Identity is deterministic
   from (username, passphrase); anyone who still knows the credentials
   can log back in and re-derive the exact same keys. This is purely a
   local wipe + social signal (the burn notices already sent to
   contacts convert them to block on their end). Said plainly here and
   in protocol.md rather than implying otherwise.
 
   Clears every identity-scoped storage key — contacts, peer backups,
   peer tokens, device registry, AND the device seed itself, so this
   device can't quietly re-announce its old deviceId if the same
   credentials are ever used here again. Nothing is kept anywhere
   (deliberately — see chat discussion: a "this identity was burned
   here" notice was considered and dropped, since credentials are
   credentials and we can't actually stop a re-login anyway, only
   pretend to). X4DH session state (rootKeys, retry bookkeeping) lives
   under X4DH_SESSION_KEY, wiped here same as everything else — the
   in-memory x4dhWireKeyByRoot/x4dhRetired simply becomes garbage on reload, nothing
   extra needed for it.
══════════════════════════════════════════ */
function selfDestruct() {
  const suffix = "_" + state.publicId;
  [STORAGE_KEY, PEER_BACKUP_KEY, PEER_TOKEN_KEY, DEVICE_REGISTRY_KEY, DEVICE_KEY_STORAGE, X4DH_SESSION_KEY]
    .forEach(key => localStorage.removeItem(key + suffix));
 
  mlog.warn("BURN       self-destruct — all local identity data wiped, reloading");
  try { state.ws?.close(1000, "burned"); } catch(e) {}
 
  // hard reset — reload lands back on the login screen with nothing to
  // restore from, same as a genuinely fresh browser profile.
  setTimeout(() => location.reload(), 300);
}

/* ══════════════════════════════════════════
   MIGRATE — send side
   Dispatched once, at commit time, by the MIGRATE panel's commit handler.
   Two kinds of recipients:
     - every non-self, non-blocked contact, addressed normally via
       sendToRelay (their lastRelay) with the usual sendSignal fallback —
       no different from how a regular message picks its route.
     - ourselves, at the relay we're leaving behind, in case another of
       our own devices is still parked there. No contact relationship
       applies to our own identity, so this one has to go by explicit
       URL (sendViaRelayUrl) — and deliberately has no signal fallback,
       since "couldn't reach the old relay" has no salvageable fallback
       destination the way a contact's unreachable relay does.
══════════════════════════════════════════ */
async function notifyMigration(newRelay, ts, oldRelay) {
  const payload = { newRelay, ts };

  for (const id of Object.keys(state.contacts)) {
    if (id === state.publicId) continue;
    const contact = state.contacts[id];
    if (!contact?.encKey || contact.blocked) continue;
    try {
      const migMsgObj = await sealEnvelope("app:migrate", state.publicId, id, contact.encKey, payload);
      const viaRelay  = sendToRelay(id, migMsgObj, true);
      if (!viaRelay) sendSignal(migMsgObj);
      mlog.info(`→ MIGRATE      to   ${pid(id)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
    } catch(e) {
      mlog.warn(`→ MIGRATE      to   ${pid(id)} — encrypt failed: ${e.message}`);
    }
  }

  if (oldRelay) {
    const me = state.contacts[state.publicId];
    try {
      const selfMsgObj = await sealEnvelope("app:migrate", state.publicId, state.publicId, me.encKey, payload);
      const sent = sendViaRelayUrl(oldRelay, selfMsgObj);
      mlog.info(`→ MIGRATE      to self @ old relay ${oldRelay}  sent=${sent}`);
    } catch(e) {
      mlog.warn(`→ MIGRATE      to self @ old relay — encrypt failed: ${e.message}`);
    }

    // Best-effort push cleanup at the relay being left behind. A
    // subscription registered under the OLD relay's VAPID key is already
    // cryptographically dead the moment we leave — no push sent through
    // it will ever verify — but nothing removes the file there on its
    // own, so this proactively asks. No encryption/signing needed, same
    // trust tier as sync:* — reuses the same connection queued for the
    // app:migrate breadcrumb just above (getOrOpenRelayConn dedups by
    // hostname), so this either flushes alongside it or not at all.
    if (loadPushPref()) {
      const sentUnsub = sendViaRelayUrl(oldRelay, {
        type: "sig:push_unsubscribe", from: state.publicId, endpointId: state.endpointId,
      });
      mlog.info(`→ PUSH_UNSUB   old relay ${oldRelay}  sent=${sentUnsub}`);
    }
  }
}

/* ══════════════════════════════════════════
   BURN NOTICE — send side
   Two kinds of recipients, same split as notifyMigration:
     - every non-self, non-blocked contact — normal sendToRelay/
       sendSignal routing, no different from any other message.
     - ourselves — but unlike migrate there's no "old relay" to also
       reach; this isn't a routing change, so a single sendSignal
       (same self-targeted pattern the retired pushMiniBackup used for
       packets) is sufficient. It lands on whatever relay our "me"
       contact currently points to, live-delivered to any other
       connected session of ours and durably buffered there for
       offline ones. A self-device parked at a genuinely different/
       stale relay won't see it until it next syncs there — same
       known limitation migrate already has, not solved here either.
══════════════════════════════════════════ */
async function notifyBurn(ts) {
  const payload = { ts };
 
  for (const id of Object.keys(state.contacts)) {
    if (id === state.publicId) continue;
    const contact = state.contacts[id];
    if (!contact?.encKey || contact.blocked) continue;
    try {
      const burnMsgObj = await sealEnvelope("app:burn", state.publicId, id, contact.encKey, payload);
      const viaRelay    = sendToRelay(id, burnMsgObj, true);
      if (!viaRelay) sendSignal(burnMsgObj);
      mlog.info(`→ BURN         to   ${pid(id)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
    } catch(e) {
      mlog.warn(`→ BURN         to   ${pid(id)} — encrypt failed: ${e.message}`);
    }
  }
 
  const me = state.contacts[state.publicId];
  try {
    const selfBurnObj = await sealEnvelope("app:burn", state.publicId, state.publicId, me.encKey, payload);
    sendSignal(selfBurnObj);
    mlog.info(`→ BURN         to self`);
  } catch(e) {
    mlog.warn(`→ BURN         to self — encrypt failed: ${e.message}`);
  }
}
 
/* Called from the confirm modal (see GUI section below), after the
   type-to-confirm + "ARE YOU SURE?!" gates have both been cleared.
   Notifies everyone FIRST, then wipes ourselves — same ordering
   principle as commitMigration (announce, then act locally) so
   contacts/other-devices are told before the identity that's
   telling them ceases to exist. */
async function commitBurn() {
  const ts = Date.now();
  mlog.warn(`BURN       committing — notifying contacts and self, then wiping this device`);
  await notifyBurn(ts);
  // brief pause so the outbound sends above have a chance to leave the
  // socket before selfDestruct() closes it out from under them.
  await new Promise(r => setTimeout(r, 400));
  selfDestruct();
}

/* ══════════════════════════════════════════
   SELF-SYNC — send side (replaces pushMiniBackup)
   Problem it solves: a message composed on device A never reaches our other
   devices — contacts fan THEIR messages to every device of ours, but our own
   outgoing ones only ever existed on the sending device. An offline sibling
   coming back online therefore got half the conversation.

   The old fix (pushMiniBackup) rode the backup path: a slice of the last
   messages, encrypted under the passphrase-derived backup key, unsigned,
   and — since 0.5.0 — buffered at the relay. That was the wrong channel:
   the backup path is a live handshake (offer/accept/push, wrap ephemerals
   that live 60s in memory), and buffering a wrapped push made stale copies
   surface on reconnect with no ephemeral left to unwrap them.

   This instead uses the ordinary per-device fanout (sendFannedX4DH) to our
   OWN identity: one small app:message per outgoing message/reaction,
   payload type "selfsync" wrapping the message plus the target contact id.
   What that buys over the mini backup:
     - per-sibling X4DH session keys where a self-session exists (legacy
       self key otherwise) instead of the static backup key
     - an Ed25519 signature — self-sync backup traffic carries none
     - per-endpoint offline buffers: each known sibling gets its OWN copy
       queued at the relay. An identity-level buffered packet is consumed by
       whichever device reconnects first, so two offline siblings could not
       both get it — that is exactly what per-endpoint targeting fixes.
   Known limits (accepted, the periodic full self-backup is the repair layer):
     - a sibling with no known endpointId (or stale >7d) falls back to the
       identity-level broadcast, i.e. first-reconnecting-device-wins
     - a sibling we have never heard from is not synced to at all: with
       nothing known there is no one to address. It gets discovered through
       the self-backup handshake / its own traffic, and later sends target it.
   Server side: a self-addressed app:message never triggers a push (see
   route_or_buffer in server.py) — waking a sibling to say "check the app"
   about our own message would be noise.

   Media goes as a stub (id/type/mimeType), never the payload — it would
   multiply upload size by the number of siblings, and media is transient
   anyway. Call notices are not mirrored (system record of an attempt, not
   conversation content).

   `stored` is the locally stored message object; local-only fields
   (status, valid, ackTrusted) never go on the wire — fields are copied
   explicitly, not spread. Fire-and-forget: callers don't await it and a
   failure only logs.
══════════════════════════════════════════ */
async function sendSelfSync(peerId, stored) {
  if (!state.publicId || !peerId || peerId === state.publicId || !stored?.id) return;   // self chat already fans to siblings as a plain message
  const peer = state.contacts[peerId];
  if (!peer || peer.blocked) return;

  const { knownCount } = resolveDeviceTargets(state.publicId);
  if (knownCount === 0) {
    mlog.debug(`SELFSYNC   no sibling device known yet — skipped  id=${pid(stored.id)}`);
    return;
  }

  const inner = { id: stored.id, type: stored.type || "text", ts: stored.ts };
  if (inner.type === "text")                         inner.text = stored.text;
  else if (inner.type === "audio" || inner.type === "image") inner.mimeType = stored.mimeType || null;
  else if (inner.type === "reaction")                { inner.targetId = stored.targetId; inner.emoji = stored.emoji ?? null; }
  else return;
  if (stored.deviceId) inner.deviceId = stored.deviceId;
  if (stored.n != null) inner.n = stored.n;
  if (stored.ackDeviceId && stored.ackN != null) { inner.ackDeviceId = stored.ackDeviceId; inner.ackN = stored.ackN; }

  try {
    const me    = state.contacts[state.publicId];
    const relay = me?.lastRelay ? { wss: me.lastRelay } : undefined;
    // Deterministic outer id (and the inner ts): a retry or a second
    // delivery path of the SAME copy hits receiveMessage's
    // (id, ts) duplicate guard instead of being processed twice. A
    // reaction whose state changed has a new ts, so it is never mistaken
    // for a stale duplicate of the old one.
    const payload = { id: `ss:${stored.id}`, type: "selfsync", peerId, msg: inner, ts: stored.ts,
                      deviceId: state.deviceId, endpointId: state.endpointId, ...(relay ? { relay } : {}) };
    const fanned = await sendFannedX4DH(state.publicId, payload);
    mlog.info(`→ SELFSYNC     peer=${pid(peerId)}  type=${inner.type}  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}${!fanned.sent ? " — nowhere, no open socket" : ""}`);
  } catch(e) {
    mlog.warn(`→ SELFSYNC     peer=${pid(peerId)} — send failed: ${e.message}`);
  }
}

async function sendMessage() {
  const input = document.getElementById("chatInput");
  const text  = input.value.trim();
  if (!text || !state.currentChat) return;
  const contact = state.contacts[state.currentChat];
  if (!contact?.encKey) return;
  const ts = Date.now(), id = crypto.randomUUID();
  const fromId = state.publicId;

  // status is purely client-side optimism — "did this packet genuinely
  // leave the device" (a live relay connection, or the main signal socket
  // being open), NOT a relay/recipient acknowledgement. There's no
  // round-trip to the relay for this; see the delivered/✔️✔️ path below,
  // which is the real recipient-confirmed signal (an auto-ack reaction).
  let status = "failed";
  let sentN  = null;
  let ackPointer = {};
  try {
    const me     = state.contacts[state.publicId];
    const relay  = me?.lastRelay ? { wss: me.lastRelay } : undefined;
    sentN = nextSendCounter(state.currentChat);
    ackPointer = getAckPointer(state.currentChat) || {};
    const payload = { id, text, ts, deviceId: state.deviceId, endpointId: state.endpointId, n: sentN, ...ackPointer, ...(relay ? { relay } : {}) };

    const fanned = await sendFannedX4DH(state.currentChat, payload);
    packetCache[id] = { envelope: fanned.envelopes[0] || null, payload };
    status = fanned.sent ? "sent" : "failed";
    mlog.info(`→ MSG          to   ${pid(state.currentChat)}  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}${!fanned.sent ? " — nowhere, no open socket" : ""}`);
    mlog.debug(`MSG content: "${text.slice(0,40)}${text.length>40?"…":""}"  id=${id}`);
  } catch(e) {
    mlog.err(`→ MSG          to   ${pid(state.currentChat)} — send failed: ${e.message}`);
  }

  const stored = { id, from: fromId, text, ts, valid: true, status, deviceId: state.deviceId, n: sentN, ...ackPointer };
  contact.messages = mergeMessages(contact.messages, [stored]);
  await saveContacts();
  input.value = "";
  renderMessages();
  updateContactPreview();   // sidebar preview otherwise only ever updates on incoming traffic
  if (status !== "failed") sendSelfSync(contact.publicId, stored);   // mirror to our other devices — see sendSelfSync
}

/* ══════════════════════════════════════════
   REACTIONS
   Stable ID: SHA-256("reaction:" + myId + ":" + targetMsgId)
   so mergeMessages naturally replaces, never duplicates.
   emoji: ":)" | ":(" | null  (null = cleared)
══════════════════════════════════════════ */
// isAuto — true only for the RECEIVED auto-ack fired from receiveMessage.
// A user's own emoji pick (or manual clear) is mirrored to sibling devices
// via sendSelfSync; the auto-ack is NOT — every sibling receives the
// original message from the contact itself and acks it on its own, so
// mirroring acks would just be noise.
async function sendReaction(targetMsgId, emoji, contactId = state.currentChat, isAuto = false) {
  if (!contactId) return;
  const contact = state.contacts[contactId];
  if (!contact?.encKey) return;

  const id  = await deriveReactionId(state.publicId, targetMsgId);
  const ts  = Date.now();
  const me    = state.contacts[state.publicId];
  const relay = me?.lastRelay ? { wss: me.lastRelay } : undefined;
  const payload = { id, type: "reaction", targetId: targetMsgId, emoji, ts, deviceId: state.deviceId, endpointId: state.endpointId, ...(relay ? { relay } : {}) };

  const fanned = await sendFannedX4DH(contactId, payload);
  const msgObj = { id, from: state.publicId, type: "reaction", targetId: targetMsgId, emoji, ts, valid: true, deviceId: state.deviceId };
  contact.messages = mergeMessages(contact.messages, [msgObj]);
  if (!isAuto) sendSelfSync(contactId, msgObj);
  // Fanned deliberately, same as the other send paths — a RECEIVED
  // auto-ack (emoji:null) reaching only ONE of the sender's own devices
  // would leave their OTHER devices stuck showing "sent" (✔️) forever for
  // a message that genuinely was delivered, since nothing else would
  // ever flip that status on those devices. A real emoji pick gets the
  // same treatment for consistency.
  mlog.info(`→ REACTION     to   ${pid(contactId)}  target=${pid(targetMsgId)}  emoji=${emoji || "nil"}  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}`);
  await saveContacts();
  // only the currently-open chat needs a re-render — an auto-ack fired
  // for some other contact shouldn't repaint whatever chat is on screen
  if (state.currentChat === contactId) renderMessages();
}

/* ══════════════════════════════════════════
   CALLING — wire packets
   call:invite / call:claim / call:cancel / call:end
   Not encrypted — from/to are already visible on the wire for every
   packet type, and there's no payload here worth hiding. Still signed
   mandatorily, same as app:migrate: these drive UI/state transitions
   (ringing, negotiating) rather than just being displayed with a
   warning, so an unsigned/invalid packet is dropped outright.
   callId ties every packet to one call attempt. Dedup / staleness
   rejection lives HERE, not in statemachine.js — by the time
   transition() is called, the "is this for the call in flight, or from
   one of our own devices, or stale" question has already been resolved.

   call:offer/answer/ice DO carry an encrypted blob (SDP/ICE), but this
   is deliberately OUT OF SCOPE for the X4DH wire-key pass — rtcConns is
   keyed by contactId, not deviceId (a call target isn't currently
   device-aware the way ordinary messages are), so there's no single
   device pair to derive a key against here yet. Stays on the legacy
   identity-level key; folding calls into per-device keying is its own
   follow-on scope (see the earlier design discussion).
══════════════════════════════════════════ */

function signCallPacket(obj) {
  const { type, from, to, callId, deviceId, ts, blob } = obj;
  return signBlob({ type, from, to, callId, deviceId: deviceId || null, ts, blob: blob || null });
}

function verifyCallPacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, callId, deviceId, ts, blob } = obj;
  return verifyBlob({ type, from, to, callId, deviceId: deviceId || null, ts, blob: blob || null }, obj.sig, contactSignPublicKey);
}

function signDataPacket(obj) {
  const { type, from, to, sessionId, deviceId, ts, blob } = obj;
  return signBlob({ type, from, to, sessionId, deviceId: deviceId || null, ts, blob: blob || null });
}

function verifyDataPacket(obj, contactSignPublicKey) {
  if (!obj.sig || !contactSignPublicKey) return false;
  const { type, from, to, sessionId, deviceId, ts, blob } = obj;
  return verifyBlob({ type, from, to, sessionId, deviceId: deviceId || null, ts, blob: blob || null }, obj.sig, contactSignPublicKey);
}
function sendCallPacket(toId, type, callId) {
  const obj = { type, from: state.publicId, to: toId, callId, ts: Date.now(), deviceId: state.deviceId };
  obj.sig = signCallPacket(obj);
  const viaRelay = sendToRelay(toId, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(toId)}  callId=${pid(callId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}

/* ── call notice — a real, encrypted app:message artifact left in the
   chat at the moment a call is attempted. Unlike call:invite (signed
   only, never buffered, live-only delivery), this rides the SAME channel
   as a normal text message — same X4DH-aware fanout, same auto-ack, same
   offline-buffer + push-notify path server-side. That's the whole point:
   a callee who's offline gets a push for this the same way they'd get
   one for any other message, and both sides keep a visible record of the
   attempt regardless of whether the call itself ever connects.

   type: "system" / kind: "call" rather than a plain text message — see
   the SYSTEM_ICON map + renderMessages' dedicated branch in
   meshchat-gui.js. kind exists so future system notices (a relay
   migration confirmation, a burn notice, etc.) can reuse this same
   rendering with their own icon/text rather than needing their own type.

   Text is a static placeholder for now — a later pass can make it
   state-aware (e.g. update the same id's text as the call phase
   advances) once that's actually wanted; no need to build that now.

   Deliberately only wired for voice calls, never the data session
   kind — that one has no conversational surface to leave a notice for. ── */
async function sendCallNotice(id) {
  const contact = state.contacts[id];
  if (!contact || contact.blocked || !contact.encKey) return;

  const msgId = crypto.randomUUID();
  const ts    = Date.now();
  const callerName = state.user || "Someone";
  const text  = `${callerName} is attempting a WebRTC connection`;

  let status = "failed";
  let sentN  = null;
  let ackPointer = {};
  try {
    const me    = state.contacts[state.publicId];
    const relay = me?.lastRelay ? { wss: me.lastRelay } : undefined;
    sentN = nextSendCounter(id);
    ackPointer = getAckPointer(id) || {};
    const payload = { id: msgId, type: "system", kind: "call", text, ts,
                       deviceId: state.deviceId, endpointId: state.endpointId, n: sentN, ...ackPointer, ...(relay ? { relay } : {}) };

    const fanned = await sendFannedX4DH(id, payload);
    packetCache[msgId] = { envelope: fanned.envelopes[0] || null, payload };
    status = fanned.sent ? "sent" : "failed";
    mlog.info(`→ CALL_NOTICE  to   ${pid(id)}  ${fanned.targetedCount} targeted (${fanned.x4dhCount} x4dh, ${fanned.legacyCount} legacy)${fanned.broadcastSent ? " + broadcast" : ""}${!fanned.sent ? " — nowhere, no open socket" : ""}`);
  } catch(e) {
    mlog.err(`→ CALL_NOTICE  to   ${pid(id)} — send failed: ${e.message}`);
  }

  contact.messages = mergeMessages(contact.messages, [{ id: msgId, from: state.publicId, type: "system", kind: "call", text, ts, valid: true, status, deviceId: state.deviceId, n: sentN, ...ackPointer }]);
  await saveContacts();
  if (state.currentChat === id) renderMessages();
  updateContactPreview();
}

/* ── send side — called from onStateEnter / user actions ── */

function sendCallInvite(id) {
  const contact = state.contacts[id];
  if (!contact?.call?.callId) return;
  sendCallPacket(id, "call:invite", contact.call.callId);
}

// user-facing: initiate a call
function startCall(contactId) {
  const contact = state.contacts[contactId];
  if (!contact || contact.blocked) return;
  if (contact.call && contact.call.phase !== "idle") return;
  contact.call = { callId: crypto.randomUUID(), phase: "idle", role: null };
  transition(contactId, { type: "call_started" });
}

// user-facing: answer an incoming call on THIS device
function answerCall(contactId) {
  const contact = state.contacts[contactId];
  if (!contact?.call?.callId || contact.call.phase !== "ringing") return;
  const callId = contact.call.callId;
  transition(contactId, { type: "claimed_here" });
  sendCallPacket(contactId, "call:claim", callId);          // tell the caller
  sendCallPacket(state.publicId, "call:claim", callId);     // tell our other devices to stop ringing
}

// user-facing: give up before answer / hang up
function cancelCall(contactId) {
  const contact = state.contacts[contactId];
  if (!contact?.call?.callId) return;
  sendCallPacket(contactId, "call:cancel", contact.call.callId);
  transition(contactId, { type: "call_cancelled" });
}

function endCall(contactId) {
  const contact = state.contacts[contactId];
  if (!contact?.call?.callId) return;
  sendCallPacket(contactId, "call:end", contact.call.callId);
  transition(contactId, { type: "call_ended" });
}

/* ── receive side ── */

async function handleCallInvite(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL INVITE  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  markOnline(msg.from);

  // A second invite while we're already past idle with this contact isn't
  // a new call — could be a retry or a duplicate in-flight packet. Don't
  // let it stomp a callId we (or another of our devices) may already be
  // mid-negotiation on.
  if (contact.call && contact.call.phase !== "idle") {
    mlog.debug(`← CALL INVITE  from ${pid(msg.from)} — already in call (phase=${contact.call.phase}), ignored`);
    return;
  }

  contact.call = { callId: msg.callId, phase: "idle", role: null };
  transition(msg.from, { type: "invite_received" });
}

async function handleCallClaim(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;

  if (msg.from === state.publicId) {
    // one of OUR OTHER devices answered — verify against our own signing
    // key, not a contact's, since this is self-addressed.
    const me = state.contacts[state.publicId];
    if (!verifyCallPacket(msg, me.signPublicKey)) {
      mlog.warn(`← CALL CLAIM   from self — signature invalid, dropped`);
      return;
    }
    if (msg.deviceId === state.deviceId) return; // our own echo, shouldn't happen
    const contactId = Object.keys(state.contacts)
      .find(id => state.contacts[id].call?.callId === msg.callId);
    if (!contactId) return; // stale — we're not tracking this callId (anymore)
    mlog.info(`← CALL CLAIM   from self — claimed on another device`);
    transition(contactId, { type: "claimed_elsewhere" });
    return;
  }

  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL CLAIM   from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId) {
    mlog.debug(`← CALL CLAIM   from ${pid(msg.from)} — callId mismatch/stale, ignored`);
    return;
  }
  markOnline(msg.from);
  transition(msg.from, { type: "claim_received" });
}

async function handleCallCancel(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL CANCEL  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId) return; // stale/unrelated call
  transition(msg.from, { type: "call_cancelled" });
}

async function handleCallEnd(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL END     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId) return;
  transition(msg.from, { type: "call_ended" });
}

async function handleDataInvite(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA INVITE  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  markOnline(msg.from);
  if (contact.data && contact.data.phase !== "idle") {
    mlog.debug(`← DATA INVITE  from ${pid(msg.from)} — already in session (phase=${contact.data.phase}), ignored`);
    return;
  }
  contact.data = { sessionId: msg.sessionId, phase: "idle", role: null };
  transition(msg.from, { type: "invite_received" }, "data");
}

// Called by the cancel/end handlers before they transition. If the peer stops
// a session that was mid-negotiation or mid-test and this side hadn't seen its
// half succeed, that is a result worth telling the user about; a cancel while
// still ringing (the normal "caller gave up") and the end that follows a
// successful test (finished is set) are not.
function reportDataEndedEarly(id, verb) {
  const phase = state.contacts[id]?.data?.phase;
  if ((phase === "negotiating" || phase === "connected") && !dataConns[id]?.finished) {
    reportDataResult(id, false, `${dataPeerName(id)} ${verb} the data channel test before it finished`);
  }
}

async function handleDataClaim(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;

  if (msg.from === state.publicId) {
    // one of OUR OTHER devices accepted — verify against our own signing
    // key, not a contact's, since this is self-addressed. Same multi-device
    // dedup as call:claim: every device that was ringing on this sessionId
    // stops ringing, silently.
    const me = state.contacts[state.publicId];
    if (!verifyDataPacket(msg, me.signPublicKey)) {
      mlog.warn(`← DATA CLAIM   from self — signature invalid, dropped`);
      return;
    }
    if (msg.deviceId === state.deviceId) return;   // our own echo, shouldn't happen
    const contactId = Object.keys(state.contacts)
      .find(id => state.contacts[id].data?.sessionId === msg.sessionId);
    if (!contactId) return;   // stale — we're not tracking this sessionId (anymore)
    mlog.info(`← DATA CLAIM   from self — accepted on another device`);
    transition(contactId, { type: "claimed_elsewhere" }, "data");
    return;
  }

  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA CLAIM   from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId) {
    mlog.debug(`← DATA CLAIM   from ${pid(msg.from)} — sessionId mismatch/stale, ignored`);
    return;
  }
  markOnline(msg.from);
  transition(msg.from, { type: "claim_received" }, "data");
}

async function handleDataCancel(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA CANCEL  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId) return;
  reportDataEndedEarly(msg.from, "cancelled");
  transition(msg.from, { type: "session_cancelled" }, "data");
}

async function handleDataEnd(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA END     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId) return;
  reportDataEndedEarly(msg.from, "ended");
  transition(msg.from, { type: "session_ended" }, "data");
}

// Callee side (mirrors handleCallOffer). Only valid while we've accepted
// (phase negotiating, role callee) — an offer outside that window is either
// stale or somebody poking, and answering it would open a peer connection
// the user never agreed to.
async function handleDataOffer(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA OFFER   from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId || contact.data.role !== "callee" || contact.data.phase !== "negotiating") {
    mlog.debug(`← DATA OFFER   from ${pid(msg.from)} — not expecting offer (phase=${contact.data?.phase}, role=${contact.data?.role}), ignored`);
    return;
  }
  markOnline(msg.from);
  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey); }
  catch(e) { mlog.warn(`← DATA OFFER   from ${pid(msg.from)} — decrypt failed`); return; }
  if (typeof plain?.sdp !== "string") { mlog.warn(`← DATA OFFER   from ${pid(msg.from)} — no sdp, dropped`); return; }

  try {
    const pc = createDataPeerConnection(msg.from);
    // The offerer creates the channel; we only ever receive it. Anything
    // other than the one channel this feature defines is closed unseen.
    pc.ondatachannel = (ev) => {
      if (ev.channel.label !== "data") {
        mlog.debug(`DATA RTC   unexpected channel "${ev.channel.label}" — closed  ${pid(msg.from)}`);
        ev.channel.close();
        return;
      }
      const ent = dataConns[msg.from];
      if (!ent) return;
      ent.dataCh = ev.channel;
      wireDataChannel(msg.from, ev.channel);
    };
    await pc.setRemoteDescription({ type: "offer", sdp: plain.sdp });
    await flushDataIceQueue(msg.from);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendDataSDP(msg.from, "data:answer", answer.sdp);
    mlog.info(`← DATA OFFER   from ${pid(msg.from)} — answered`);
  } catch(e) {
    mlog.err(`DATA RTC   answer failed: ${e.message}`);
    transition(msg.from, { type: "rtc_failed" }, "data");
  }
}
 
async function handleDataAnswer(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA ANSWER  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId || contact.data.role !== "caller") {
    mlog.debug(`← DATA ANSWER  from ${pid(msg.from)} — not expecting answer, ignored`);
    return;
  }
  markOnline(msg.from);
  const entry = dataConns[msg.from];
  if (!entry) { mlog.warn(`← DATA ANSWER  from ${pid(msg.from)} — no pc, dropped`); return; }
  try {
    const plain = await decryptMessage(msg.blob, contact.encKey);
    await entry.pc.setRemoteDescription({ type: "answer", sdp: plain.sdp });
    await flushDataIceQueue(msg.from);
    mlog.info(`← DATA ANSWER  from ${pid(msg.from)} — remote set`);
  } catch(e) {
    mlog.err(`← DATA ANSWER  from ${pid(msg.from)} — failed: ${e.message}`);
    transition(msg.from, { type: "rtc_failed" }, "data");
  }
}
 
async function handleDataIce(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyDataPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← DATA ICE     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.data?.sessionId !== msg.sessionId || contact.data.phase === "idle") return; // stale/unrelated session
 
  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey); }
  catch(e) { mlog.warn(`← DATA ICE     from ${pid(msg.from)} — decrypt failed`); return; }
 
  const entry = dataConns[msg.from];
  if (!entry) {
    // Callee side: the offerer's candidates can overtake its offer (its
    // trickle ICE starts the moment setLocalDescription runs, while the
    // offer still has to be encrypted and signed), and this handler can also
    // finish its decrypt before handleDataOffer has built the connection.
    // Hold them instead of dropping them; createDataPeerConnection adopts
    // the queue. Capped — this is a few candidates, not a stream.
    const q = (dataEarlyIce[msg.from] ||= []);
    if (q.length < DATA_EARLY_ICE_MAX) q.push(plain);
    return;
  }
  if (entry.pc.remoteDescription) {
    try { await entry.pc.addIceCandidate(plain); }
    catch(e) { mlog.debug(`DATA RTC   addIceCandidate failed: ${e.message}`); }
  } else {
    entry.iceQueue.push(plain);
  }
}
//  send + receive for offer/answer/ice

async function sendCallSDP(id, type, sdp) {
  const contact = state.contacts[id];
  if (!contact?.call?.callId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, { sdp });
  const obj  = { type, from: state.publicId, to: id, callId: contact.call.callId, ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signCallPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(id)}  callId=${pid(contact.call.callId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}

async function sendCallIce(id, candidate) {
  const contact = state.contacts[id];
  if (!contact?.call?.callId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, candidate.toJSON());
  const obj  = { type: "call:ice", from: state.publicId, to: id, callId: contact.call.callId, ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signCallPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.debug(`→ CALL ICE     to ${pid(id)}  callId=${pid(contact.call.callId)}`);
}

async function handleCallOffer(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL OFFER   from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId || contact.call.role !== "callee") {
    mlog.debug(`← CALL OFFER   from ${pid(msg.from)} — not expecting offer (phase=${contact.call?.phase}, role=${contact.call?.role}), ignored`);
    return;
  }
  markOnline(msg.from);
  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey); }
  catch(e) { mlog.warn(`← CALL OFFER   from ${pid(msg.from)} — decrypt failed`); return; }

  try {
    const pc = await createPeerConnection(msg.from);
    await pc.setRemoteDescription({ type: "offer", sdp: plain.sdp });
    await flushIceQueue(msg.from);
    const stream = await getLocalStream();
    stream.getTracks().forEach(t => pc.addTrack(t, stream));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendCallSDP(msg.from, "call:answer", answer.sdp);
    mlog.info(`← CALL OFFER   from ${pid(msg.from)} — answered`);
  } catch(e) {
    mlog.err(`RTC        answer failed: ${e.message}`);
    transition(msg.from, { type: "rtc_failed" });
  }
}

async function handleCallAnswer(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL ANSWER  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId || contact.call.role !== "caller") {
    mlog.debug(`← CALL ANSWER  from ${pid(msg.from)} — not expecting answer, ignored`);
    return;
  }
  markOnline(msg.from);
  const entry = rtcConns[msg.from];
  if (!entry) { mlog.warn(`← CALL ANSWER  from ${pid(msg.from)} — no pc, dropped`); return; }
  try {
    const plain = await decryptMessage(msg.blob, contact.encKey);
    await entry.pc.setRemoteDescription({ type: "answer", sdp: plain.sdp });
    await flushIceQueue(msg.from);
    mlog.info(`← CALL ANSWER  from ${pid(msg.from)} — remote set`);
  } catch(e) {
    mlog.err(`← CALL ANSWER  from ${pid(msg.from)} — failed: ${e.message}`);
    transition(msg.from, { type: "rtc_failed" });
  }
}

async function handleCallIce(msg) {
  if (!msg.from || !msg.to || !msg.callId || !isAddressedToMe(msg.to)) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL ICE     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId) return; // stale/unrelated call

  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey); }
  catch(e) { mlog.warn(`← CALL ICE     from ${pid(msg.from)} — decrypt failed`); return; }

  const entry = rtcConns[msg.from];
  if (!entry) return;
  if (entry.pc.remoteDescription) {
    try { await entry.pc.addIceCandidate(plain); }
    catch(e) { mlog.debug(`RTC        addIceCandidate failed: ${e.message}`); }
  } else {
    entry.iceQueue.push(plain);
  }
}

/* ══════════════════════════════════════════
   RTC — audio only for now (video deliberately
   deferred). One RTCPeerConnection per contact,
   keyed by contactId. iceQueue holds candidates
   that arrive before the remote description is
   set (trickle ICE races the SDP exchange).
══════════════════════════════════════════ */
const RTC_CONFIG = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:global.stun.twilio.com:3478" }
  ]
};
const rtcConns   = {};   // contactId → { pc, iceQueue: [] }

// Single shared local stream — fine under the current manual-only,
// one-call-at-a-time assumption baked into the state machine. If that
// assumption ever changes (concurrent calls to different contacts),
// this needs to become per-call.
let localStream = null;

async function getLocalStream() {
  if (localStream) return localStream;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
    });
    mlog.info("RTC        mic acquired");
  } catch(e) {
    mlog.warn(`RTC        mic unavailable (${e.message}) — using synthetic test track`);
    localStream = createSyntheticAudioStream();
  }
  return localStream;
}

// Silent (near-silent, actually — 0 gain sine) audio track for testing the
// RTC signaling path without real hardware. NOT for production use — this
// exists purely so offer/answer/ICE can be validated end-to-end on a
// machine with no mic. Remove or gate behind a debug flag once real
// hardware testing starts.
function createSyntheticAudioStream() {
  const ctx  = new AudioContext();
  const osc  = ctx.createOscillator();
  const gain = ctx.createGain();
  gain.gain.value = 0;   // silent — just needs to be a live track, not actually audible
  osc.connect(gain);
  const dest = ctx.createMediaStreamDestination();
  gain.connect(dest);
  osc.start();
  return dest.stream;
}

function releaseLocalStream() {
  if (localStream) {
    localStream.getTracks().forEach(t => t.stop());
    localStream = null;
    mlog.debug("RTC        mic released");
  }
}

async function createPeerConnection(id) {
  if (rtcConns[id]?.pc) return rtcConns[id].pc;
  const pc = new RTCPeerConnection(RTC_CONFIG);
  rtcConns[id] = { pc, iceQueue: [] };

  pc.onicecandidate = (e) => { if (e.candidate) sendCallIce(id, e.candidate); };

  pc.ontrack = (e) => {
    let audioEl = document.getElementById("remoteAudio_" + id);
    if (!audioEl) {
      audioEl = document.createElement("audio");
      audioEl.id = "remoteAudio_" + id;
      audioEl.autoplay = true;
      document.body.appendChild(audioEl);
    }
    audioEl.srcObject = e.streams[0];
    mlog.info(`RTC        remote track attached  ${pid(id)}`);
  };

  pc.onconnectionstatechange = () => {
    mlog.debug(`RTC        state=${pc.connectionState}  ${pid(id)}`);
    if (pc.connectionState === "connected") transition(id, { type: "rtc_connected" });
    else if (pc.connectionState === "failed") transition(id, { type: "rtc_failed" });
    else if (pc.connectionState === "closed") transition(id, { type: "rtc_closed" });
  };

  return pc;
}

async function flushIceQueue(id) {
  const entry = rtcConns[id];
  if (!entry) return;
  for (const cand of entry.iceQueue) {
    try { await entry.pc.addIceCandidate(cand); }
    catch(e) { mlog.debug(`RTC        queued ICE add failed: ${e.message}`); }
  }
  entry.iceQueue = [];
}

// real implementation — replaces the old stub
async function rtcOffer(id) {
  try {
    const pc     = await createPeerConnection(id);
    const stream = await getLocalStream();
    stream.getTracks().forEach(t => pc.addTrack(t, stream));
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await sendCallSDP(id, "call:offer", offer.sdp);
    mlog.info(`RTC        offer sent  ${pid(id)}`);
  } catch(e) {
    mlog.err(`RTC        offer failed: ${e.message}`);
    transition(id, { type: "rtc_failed" });
  }
}

// real implementation — replaces the old stub
function rtcClose(id) {
  const entry = rtcConns[id];
  if (entry) { entry.pc.close(); delete rtcConns[id]; }
  const audioEl = document.getElementById("remoteAudio_" + id);
  if (audioEl) { audioEl.srcObject = null; audioEl.remove(); }
  releaseLocalStream();
  mlog.debug(`RTC        closed  ${pid(id)}`);
}

/* ══════════════════════════════════════════
   DATA SESSIONS — user-facing entry points
   A data session is a connection test, nothing more: the caller opens a
   WebRTC data channel to one contact, sends a single ping, the callee
   echoes it, the caller reports "works · N ms" and ends the session. It
   exists to answer "can these two devices reach each other directly?"
   (there is no TURN — see protocol.md — so sometimes they can't), and to
   keep the full invite/accept/offer/answer/ICE/channel machinery alive and
   exercised for whatever builds on it later. Nothing from the channel is
   stored or forwarded anywhere.

   Mirrors startCall/cancelCall/endCall/answerCall exactly, data-flavored.
   The header button (meshchat-gui.js) drives start/cancel/end; the accept
   banner drives answer/cancel. sessionId plays the same role callId does
   for calls: assigned once here, never touched again by transition()
   itself.
══════════════════════════════════════════ */
function startData(id) {
  const contact = state.contacts[id];
  if (!contact || contact.blocked) return;
  if (contact.data && contact.data.phase !== "idle") return;
  contact.data = { sessionId: crypto.randomUUID(), phase: "idle", role: null };
  transition(id, { type: "session_started" }, "data");
}

function cancelData(id) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId) return;
  sendDataPacket(id, "data:cancel", contact.data.sessionId);
  transition(id, { type: "session_cancelled" }, "data");
}

function endData(id) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId) return;
  sendDataPacket(id, "data:end", contact.data.sessionId);
  transition(id, { type: "session_ended" }, "data");
}

// user-facing: accept an incoming test on THIS device. Claims twice, same as
// answerCall: once to the caller (advances their state), once to our own
// identity so our other devices stop ringing (handleDataClaim's self branch).
function answerData(id) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId || contact.data.phase !== "ringing") return;
  const sessionId = contact.data.sessionId;
  transition(id, { type: "claimed_here" }, "data");
  sendDataPacket(id, "data:claim", sessionId);
  sendDataPacket(state.publicId, "data:claim", sessionId);
}

/* ══════════════════════════════════════════
   DATA signalling + RTC — statemachine.js's onDataStateEnter calls these.
     sendDataInvite / sendDataPacket — signing (signDataPacket) + send
     dataRtcOffer / dataRtcClose — RTCPeerConnection + one data channel
       (labelled "data"); mirrors rtcOffer/rtcClose but createDataChannel
       instead of getUserMedia/addTrack. The answering half is
       handleDataOffer (callee side).
     sendDataPing / onDataReceived — the ping/echo itself
     armDataTimer / onDataTimeout / reportDataResult — what happens when it
       doesn't work, and how either outcome is surfaced
══════════════════════════════════════════ */
function sendDataPacket(id, type, sessionId) {
  const obj = { type, from: state.publicId, to: id, sessionId, ts: Date.now(), deviceId: state.deviceId };
  obj.sig = signDataPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(id)}  session=${pid(sessionId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}

function sendDataInvite(id) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId) return;
  sendDataPacket(id, "data:invite", contact.data.sessionId);
}

// Timeouts. RING covers invite→accept (the callee is a human with a banner
// to look at); NEGOTIATE covers accept→result, i.e. ICE plus the ping — long
// enough for a slow STUN round trip, short enough that "it doesn't work" is
// an answer rather than a wait.
const DATA_RING_TIMEOUT_MS      = 30_000;
const DATA_NEGOTIATE_TIMEOUT_MS = 20_000;
// The only traffic this channel is meant to carry is two tiny JSON strings,
// so anything bigger is not from this feature. Checked before JSON.parse.
const DATA_MAX_MSG_CHARS        = 128;
// A well-behaved caller sends exactly one ping; this is the slack, not the
// expectation. Bounds how much a misbehaving peer can make us echo.
const DATA_MAX_PONGS            = 3;
const DATA_EARLY_ICE_MAX        = 50;

// contactId → { pc, dataCh, iceQueue, pingNonce, pingSentAt, pongsSent, finished }
// finished: this side has seen its half of the test succeed. After that, the
// peer tearing the connection down is expected and must not be reported as a
// failure (see createDataPeerConnection's onconnectionstatechange).
const dataConns    = {};
const dataEarlyIce = {};   // contactId → candidates that arrived before the pc existed
const dataTimers   = {};   // contactId → timeout handle (at most one per session)

const dataPeerName = (id) => state.contacts[id]?.name || pid(id);
 
async function sendDataSDP(id, type, sdp) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, { sdp });
  const obj  = { type, from: state.publicId, to: id, sessionId: contact.data.sessionId,
                 ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signDataPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(id)}  session=${pid(contact.data.sessionId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}
 
async function sendDataIce(id, candidate) {
  const contact = state.contacts[id];
  if (!contact?.data?.sessionId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, candidate.toJSON());
  const obj  = { type: "data:ice", from: state.publicId, to: id, sessionId: contact.data.sessionId,
                 ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signDataPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.debug(`→ DATA ICE     to ${pid(id)}  session=${pid(contact.data.sessionId)}`);
}
 
function createDataPeerConnection(id) {
  if (dataConns[id]?.pc) return dataConns[id].pc;
  const pc = new RTCPeerConnection(RTC_CONFIG);   // reuse the same STUN-only config as calls
  const entry = { pc, dataCh: null, iceQueue: dataEarlyIce[id] || [],
                  pingNonce: null, pingSentAt: 0, pongsSent: 0, finished: false };
  delete dataEarlyIce[id];
  dataConns[id] = entry;
 
  pc.onicecandidate = (e) => { if (e.candidate) sendDataIce(id, e.candidate); };
 
  pc.onconnectionstatechange = () => {
    mlog.debug(`DATA RTC   state=${pc.connectionState}  ${pid(id)}`);
    if (pc.connectionState === "connected") transition(id, { type: "rtc_connected" }, "data");
    else if (pc.connectionState === "failed") {
      // After a successful test the caller closes its end straight away; on
      // our side that can surface as "failed" before the data:end signal
      // arrives. Not a failure — the test already worked.
      if (entry.finished) { mlog.debug(`DATA RTC   post-test teardown, ignored  ${pid(id)}`); return; }
      transition(id, { type: "rtc_failed" }, "data");
    }
    else if (pc.connectionState === "closed") transition(id, { type: "rtc_closed" }, "data");
  };
 
  return pc;
}
 
async function flushDataIceQueue(id) {
  const entry = dataConns[id];
  if (!entry) return;
  for (const cand of entry.iceQueue) {
    try { await entry.pc.addIceCandidate(cand); }
    catch(e) { mlog.debug(`DATA RTC   queued ICE add failed: ${e.message}`); }
  }
  entry.iceQueue = [];
}
 
// Offerer side only (mirrors rtcOffer for calls), but unlike calls there is
// no media to acquire — this creates the data channel up front instead.
async function dataRtcOffer(id) {
  try {
    const pc    = createDataPeerConnection(id);
    const entry = dataConns[id];
 
    entry.dataCh = pc.createDataChannel("data");
    wireDataChannel(id, entry.dataCh);
 
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await sendDataSDP(id, "data:offer", offer.sdp);
    mlog.info(`DATA RTC   offer sent  ${pid(id)}`);
  } catch(e) {
    mlog.err(`DATA RTC   offer failed: ${e.message}`);
    transition(id, { type: "rtc_failed" }, "data");
  }
}
 
function dataRtcClose(id) {
  const entry = dataConns[id];
  if (entry) {
    entry.dataCh?.close();
    entry.pc.close();
    delete dataConns[id];
  }
  delete dataEarlyIce[id];
  mlog.debug(`DATA RTC   closed  ${pid(id)}`);
}
 
// Wiring for the data channel — shared by both sides (the offerer wires the
// channel it created, the answerer wires the one handed to ondatachannel).
// The caller pings the moment its end opens; the callee just listens.
function wireDataChannel(id, ch) {
  ch.binaryType = "arraybuffer";
  ch.onopen = () => {
    mlog.info(`DATA RTC   data channel open  ${pid(id)}`);
    if (state.contacts[id]?.data?.role === "caller") sendDataPing(id);
  };
  ch.onclose = () => mlog.debug(`DATA RTC   data channel closed  ${pid(id)}`);
  ch.onmessage = (e) => onDataReceived(id, e.data);
}

function sendDataPing(id) {
  const entry = dataConns[id];
  if (!entry?.dataCh || entry.dataCh.readyState !== "open") return;
  entry.pingNonce  = Math.random().toString(36).slice(2, 10);
  entry.pingSentAt = performance.now();
  entry.dataCh.send(JSON.stringify({ t: "ping", n: entry.pingNonce }));
  mlog.debug(`DATA RTC   ping sent  ${pid(id)}`);
}

// The receive hook. Strict on purpose — this is a channel to a peer that has
// only been trusted enough to talk to, not one whose content we act on:
// strings only, short, one known shape, a nonce that must match what we sent,
// and role-gated (only a callee answers a ping, only a caller accepts a pong).
function onDataReceived(id, data) {
  const entry = dataConns[id];
  if (!entry) return;
  if (typeof data !== "string" || data.length > DATA_MAX_MSG_CHARS) {
    mlog.debug(`DATA RTC   dropped non-conforming message  ${pid(id)}`);
    return;
  }
  let msg;
  try { msg = JSON.parse(data); } catch(e) { return; }
  if (!msg || typeof msg.n !== "string" || msg.n.length > 32) return;

  const role = state.contacts[id]?.data?.role;
  if (msg.t === "ping" && role === "callee") {
    if (entry.pongsSent >= DATA_MAX_PONGS || entry.dataCh?.readyState !== "open") return;
    entry.pongsSent++;
    entry.dataCh.send(JSON.stringify({ t: "pong", n: msg.n }));
    if (!entry.finished) {
      entry.finished = true;
      reportDataResult(id, true, `data channel with ${dataPeerName(id)} works (they ran the test)`);
    }
  } else if (msg.t === "pong" && role === "caller" && entry.pingNonce !== null && msg.n === entry.pingNonce) {
    const rtt = Math.max(1, Math.round(performance.now() - entry.pingSentAt));
    entry.pingNonce = null;
    entry.finished  = true;
    reportDataResult(id, true, `data channel to ${dataPeerName(id)} works · ${rtt} ms`);
    endData(id);   // test over — signals the callee and tears our side down
  }
}

// One timer per session, replaced on every phase entry (see onDataStateEnter).
function clearDataTimer(id) {
  clearTimeout(dataTimers[id]);
  delete dataTimers[id];
}
function armDataTimer(id, ms) {
  clearDataTimer(id);
  dataTimers[id] = setTimeout(() => { delete dataTimers[id]; onDataTimeout(id); }, ms);
}

// What each phase's timeout means, and who tells the peer:
//   ringing      callee never answered — nothing to tell, the caller's own
//                timer (or its cancel) covers its side
//   calling      no answer — tell the callee to stop ringing (data:cancel)
//   negotiating/ connected but no result — tell the peer (data:end)
//   connected
// A session whose test already succeeded (finished) is only waiting on the
// peer's data:end to arrive; if that was lost, close quietly rather than
// report a failure for something that worked.
function onDataTimeout(id) {
  const d = state.contacts[id]?.data;
  if (!d || d.phase === "idle" || d.phase === "failed") return;
  const name  = dataPeerName(id);
  const phase = d.phase;

  if (dataConns[id]?.finished) {
    transition(id, { type: "idle_timeout" }, "data");
    return;
  }
  if (phase === "ringing") {
    reportDataResult(id, false, `data channel test request from ${name} expired`);
    transition(id, { type: "session_cancelled" }, "data");
    return;
  }
  reportDataResult(id, false, phase === "calling"
    ? `no answer from ${name}`
    : `couldn't connect to ${name} in time — a firewall/NAT may be blocking the direct path (there is no relay for data channels)`);
  sendDataPacket(id, phase === "calling" ? "data:cancel" : "data:end", d.sessionId);
  transition(id, { type: "idle_timeout" }, "data");
}

// Single place a result becomes visible: the in-page log and the toast.
function reportDataResult(id, ok, text) {
  if (ok) mlog.info(`DATA       ${text}`); else mlog.warn(`DATA       ${text}`);
  showDataToast(text, ok);
}

/* ══════════════════════════════════════════
   CONTACTS
══════════════════════════════════════════ */
async function addContact(name,shareableKey,save=true){
  if(!name||!shareableKey)return false;
  let x25519PublicKey,signPublicKey,relayWss=null;
  try{
    const parts=shareableKey.split(".");
    if(parts.length<2||parts.length>3)throw new Error();
    x25519PublicKey=base64ToRaw(parts[0]);
    signPublicKey=base64ToRaw(parts[1]);
    if(x25519PublicKey.length!==32||signPublicKey.length!==32)throw new Error();
    if(parts.length===3&&parts[2])relayWss=atob(parts[2]);
  }
  catch(e){return false;}
  const publicId=await deriveIdentityPublicId(x25519PublicKey,signPublicKey);
  if(publicId===state.publicId||state.contacts[publicId])return!!state.contacts[publicId];
  // encKey is derived via ECDH, not imported off the wire — this contact's
  // x25519PublicKey is public by design (it's what's in the QR code), but
  // the AES key it produces is the shared secret only WE and THEY can
  // compute, not anyone else holding this same shareable address. This
  // remains the LEGACY/fallback identity-level key even after the X4DH
  // wire-key work — see its own section further up for what supersedes
  // it per device pair once a session exists.
  const encKey=await deriveSharedAesKey(state.x25519Seed,x25519PublicKey);
  state.contacts[publicId]={name,publicId,shareableKey,encKey,x25519PublicKey,signPublicKey,messages:[],
    lastRelay:relayWss||null};
  if(save)await saveContacts();
  mlog.info(`CONTACT    added ${name}  ${pid(publicId)}${relayWss?" wss="+relayWss:""}`);
  renderContactList();
  return true;
}


/* ══════════════════════════════════════════
   EXPORT / IMPORT
══════════════════════════════════════════ */
async function exportBackup(passphrase) {
  const master    = await deriveMasterSecret(state.user, passphrase);
  const keys      = await hkdfExpand(master);
  const exportKey = await importEncKey(keys.backupKey);
  const blob      = await encryptObject(exportKey, serialiseContacts());
  const a         = Object.assign(document.createElement("a"), {
    href:     "data:application/json," + encodeURIComponent(JSON.stringify({ v: 2, user: state.user, blob })),
    download: "meshchat-backup-" + Date.now() + ".json"
  });
  a.click();
  mlog.info("BACKUP     exported to file");
}

async function importBackup(file, passphrase) {
  const parsed    = JSON.parse(await file.text());
  if (!parsed.blob) throw new Error("invalid backup file");
  const master    = await deriveMasterSecret(parsed.user || state.user, passphrase);
  const keys      = await hkdfExpand(master);
  const importKey = await importEncKey(keys.backupKey);
  const plain     = await decryptObject(importKey, parsed.blob);
  if (typeof plain !== "object") throw new Error("backup data corrupt");
  const restored  = await deserialiseContacts(plain);
  // Same latent gap as the network backup/restore paths: a self entry in
  // here could carry a newer lastRelay (e.g. importing a file exported from
  // another device after it migrated). Rare and deliberate compared to the
  // automatic background paths, but the same mergeContactMeta call below
  // means it's exposed to the same situation, so check it too.
  const prevSelfRelay = state.contacts[state.publicId]?.lastRelay;
  let added = 0;
  for (const [id, contact] of Object.entries(restored)) {
    if (!state.contacts[id]) { state.contacts[id] = contact; added++; }
    else {
      mergeContactMeta(state.contacts[id], contact);
      state.contacts[id].messages = mergeMessages(state.contacts[id].messages, contact.messages);
      reconcileDeliveryStatus(state.contacts[id]);
      reconcileMissingDevices(state.contacts[id]);
    }
  }
  await saveContacts();
  mlog.info(`BACKUP     imported — +${added} contacts`);
  renderContactList();
  if (state.contacts[state.publicId]?.lastRelay !== prevSelfRelay) {
    mlog.info(`BACKUP     self relay changed via import — rebooting signal`);
    rebootSignal();
  }
}

async function commitMigration(url) {
  const me       = state.contacts[state.publicId];
  const oldRelay = me.lastRelay;
  const ts       = Date.now();
  me.prevRelay     = oldRelay;
  me.prevRelaySeen = ts;
  me.lastRelay     = url;
  me.lastRelaySeen = ts;
  await saveContacts();
  mlog.info(`MIGRATE    committed  ${oldRelay || "(none)"} → ${url}`);
  rebootSignal();
  notifyMigration(url, ts, oldRelay);

  if (oldRelay) {
    migrationLocked = true;
    setTimeout(() => drainOldRelay(oldRelay), MIGRATE_DRAIN_DELAY_MS);
  }
  closeContactAction();
}