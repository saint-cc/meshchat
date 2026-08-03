/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat.js  (formerly script.js)
   Core client: `state`, WebSocket/relay plumbing, the protocol
   handlers (messages, migrate, burn, calls, shell escalation,
   sync/backup), and the crypto functions that reach into `state`
   directly (decryptMessage, signBlob — see lib.js for their
   stateless counterparts, decryptObject/verifyBlob etc.).

   pid(id) — trims a publicId to 8 chars for display. Lives in
   lib.js since it's pure, but used constantly below.
   NOTE: deliberately NOT named short() to avoid collision with
         the url-truncation var in lib.js's linkify().

   Load order: meshchat-lib.js → meshchat-gui.js → meshchat.js → statemachine.js
═══════════════════════════════════════════════════════════════ */
const CLIENT_VERSION = "0.4.1";

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
  vapidPublicKey: null, pushSyncedRelayWss: null
};

const SIGNAL_URL		=`wss://${window.location.hostname}/ws/`;
const STORAGE_KEY		= "meshchat_contacts";
const PEER_BACKUP_KEY	= "meshchat_peer_backups_v1";
const PEER_TOKEN_KEY	= "meshchat_peer_tokens_v1";
const DEVICE_REGISTRY_KEY = "meshchat_known_devices_v1";
const DEVICE_KEY_STORAGE = "meshchat_device_seed_v1";
const SEND_COUNTER_KEY = "meshchat_send_counters_v1";
const PUSH_PREF_KEY = "meshchat_push_pref_v1";   // per-device opt-in preference, local-only
const EXCHANGE_COUNT	= 10;

/* ══════════════════════════════════════════
   RESTORE HANDSHAKE — rate limiting
══════════════════════════════════════════ */
const lastRestoreTime  = {};

function canRestore(id) {
  const last = lastRestoreTime[id];
  return !last || (Date.now() - last) > RESTORE_COOLDOWN;
}
function markRestored(id) {
  lastRestoreTime[id] = Date.now();
  pendingRestoreRequest.delete(id);
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
async function getOrCreateDeviceId() {
  const storageKey = DEVICE_KEY_STORAGE + "_" + state.publicId;
  let seed;
  const existing = localStorage.getItem(storageKey);
  if (existing) {
    seed = base64ToRaw(existing);
  } else {
    seed = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(storageKey, rawToBase64(seed));
    mlog.info("DEVICE     new device identity generated");
  }
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
async function decryptMessage(blob, key) {
  // v missing = v0 (legacy unversioned), v:1 = AES-256-GCM explicit
  if (blob.v !== undefined && blob.v > 1) throw new Error(`unsupported message version v${blob.v}`);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(blob.iv) }, key, new Uint8Array(blob.data));
  return JSON.parse(new TextDecoder().decode(plain));
}
function signBlob(blob){
  const bytes=new TextEncoder().encode(JSON.stringify(blob));
  const sig=ed25519.sign(bytes,state.keys.signingKeySeed);
  return Array.from(sig);
}

function getLast(contactId, n = EXCHANGE_COUNT) { return (state.contacts[contactId]?.messages || []).slice(-n); }

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

function schedulePoll() {
  const jitter = (Math.random() - 0.5) * POLL_JITTER_MS;
  setTimeout(() => { pollContacts(); schedulePoll(); }, POLL_INTERVAL_MS + jitter);
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
                messages: c.messages.slice(-15).map(m => m.type === "audio" ? {...m, data:null, expired:true} : m),
                blocked: c.blocked || false,
                type:            c.type            || "human",
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
    const encKey=await deriveSharedAesKey(state.x25519Seed,x25519PublicKey);
    out[id]={...c,encKey,x25519PublicKey,signPublicKey};
  }
  return out;
}

async function saveContacts() {
  if (!state.cryptoKey) return;
  const encrypted = await encryptObject(state.cryptoKey, serialiseContacts());
  localStorage.setItem(STORAGE_KEY + "_" + state.publicId, JSON.stringify(encrypted));
  return encrypted;
}

let messagesSinceBackup = 0;

async function saveContactsBackup(force = false) {
  if (!state.cryptoKey) return;
  const encrypted = await saveContacts();
  messagesSinceBackup++;
  if (!force && messagesSinceBackup < BACKUP_THRESHOLD) return;
  messagesSinceBackup = 0;
  pushBackupToContacts(encrypted);
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

function loadDeviceRegistry() {
  try {
    state.knownDevices = JSON.parse(localStorage.getItem(DEVICE_REGISTRY_KEY + "_" + state.publicId) || "{}");
    // soft prune — 90 days, max 20 devices per identity
    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
    for (const identityId of Object.keys(state.knownDevices)) {
      const devs = state.knownDevices[identityId];
      // migrate pre-n entries: a bare lastSeen timestamp becomes
      // { lastSeen, lastN: 0 } — old data never had a counter to recover,
      // so it starts at 0 and gets corrected the next time this device
      // is actually seen sending something with an n on it.
      for (const devId of Object.keys(devs)) {
        if (typeof devs[devId] === "number") devs[devId] = { lastSeen: devs[devId], lastN: 0 };
      }
      let entries = Object.entries(devs).filter(([, v]) => v.lastSeen > cutoff);
      if (entries.length > 20) {
        entries = entries.sort(([, a], [, b]) => b.lastSeen - a.lastSeen).slice(0, 20);
      }
      state.knownDevices[identityId] = Object.fromEntries(entries);
    }
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
// see nextSendCounter() below for the mirror-image local-send side. This
// is bookkeeping only for now: a gap, dupe, or reorder is logged and
// `lastN` is updated to whatever's highest seen, but nothing is dropped or
// enforced yet. Callers that don't have an `n` (restore/backup/self-sync
// paths) simply omit it — lastSeen still updates, lastN is left alone.
function recordKnownDevice(identityId, deviceId, n) {
  if (!identityId || !deviceId) return;
  if (!state.knownDevices[identityId]) state.knownDevices[identityId] = {};
  const existing = state.knownDevices[identityId][deviceId];
  const prevLastN = (existing && typeof existing === "object") ? (existing.lastN || 0) : 0;
  let lastN = prevLastN;
  if (typeof n === "number") {
    if (n !== prevLastN + 1) {
      mlog.debug(`DEVICE     n gap/reorder  id=${pid(identityId)}  device=${pid(deviceId)}  expected=${prevLastN + 1}  got=${n}`);
    }
    lastN = Math.max(prevLastN, n);
  }
  state.knownDevices[identityId][deviceId] = { lastSeen: Date.now(), lastN };
  saveDeviceRegistry();
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

/* ══════════════════════════════════════════
   PEER BACKUP DISTRIBUTION
   Protocol (non-self peers):
     1. sender → backup_offer  { from, to, size }
     2. receiver → backup_accept { from, to } (only if willing)
     3. sender → backup_push   { from, to, blob }
   Self-sync skips the offer step (always accepted).
   Constrained peers (C64 etc.) can simply never
   send backup_accept and they will never receive blobs.
══════════════════════════════════════════ */

// tracks which peers we have a pending offer waiting for accept
const pendingBackupOffer = {};   // id → { blob, ts }

async function pushBackupToContacts(blob) {
  for (const id of Object.keys(state.contacts)) {
	const contact = state.contacts[id];
    const onOwnRelay = state.online.has(id) && 
	  (!contact.lastRelay || contact.lastRelay === state.contacts[state.publicId]?.lastRelay);
	const hasOpenRelay = contact.lastRelay && 
	  relayConns[relayHostname(contact.lastRelay)]?.outbound;
	if (!onOwnRelay && !hasOpenRelay) continue;

	if (id === state.publicId) {
		// self-sync: no negotiation needed, push directly — unless every
		// device we've heard from this session already has this exact content.
		try {
			const fingerprint = await computeBackupFingerprint();
			const knownIds    = Object.keys(state.knownDeviceFingerprints);
			const allCaughtUp = knownIds.length > 0 &&
			  knownIds.every(devId => state.knownDeviceFingerprints[devId] === fingerprint);
			if (allCaughtUp) {
				mlog.debug(`→ BACKUP_PUSH  to self — skipped, ${knownIds.length} known device(s) already current`);
				continue;
			}
			const freshBlob = await encryptObject(state.cryptoKey, serialiseContacts());
			sendSignal({ type: "sync:backup_push", from: state.publicId, to: id, blob: freshBlob,
						 deviceId: state.deviceId, fingerprint });
			mlog.info(`→ BACKUP_PUSH  to self — sent fresh data`);
		} catch(e) {
			mlog.warn(`→ BACKUP_PUSH  to self — encrypt failed`);
		}
		continue;
    }

    // estimate wire size before sending
    const size = JSON.stringify(blob).length;
    pendingBackupOffer[id] = { blob, ts: Date.now() };
    sendSignal({ type: "sync:backup_offer", from: state.publicId, to: id, size });
    mlog.info(`→ BACKUP_OFFER to   ${pid(id)}  size=${size}`);
  }
}

function handleBackupOffer(msg) {
  if (!msg.from || !msg.size) return;
  if (state.contacts[msg.from]?.blocked) return;
  markOnline(msg.from);
  // accept unconditionally — a constrained peer would simply not implement this handler
  mlog.info(`← BACKUP_OFFER from ${pid(msg.from)}  size=${msg.size} — accepting`);
  sendSignal({ type: "sync:backup_accept", from: state.publicId, to: msg.from });
}

function handleBackupAccept(msg) {
  if (!msg.from) return;

  // device-fingerprint ack (self-sync freshness tracking) — disambiguated
  // from the normal contact-offer accept by the presence of deviceId,
  // which the regular handshake never sets.
  if (msg.deviceId) {
    if (msg.deviceId === state.deviceId) return;  // own echo, shouldn't happen
    if (msg.fingerprint) {
      state.knownDeviceFingerprints[msg.deviceId] = msg.fingerprint;
	  recordKnownDevice(state.publicId, msg.deviceId);
      mlog.debug(`← BACKUP_ACK   from device ${msg.deviceId.slice(0,8)} — fingerprint recorded`);
    }
    return;
  }
  
  const pending = pendingBackupOffer[msg.from];
  if (!pending) {
    mlog.debug(`BACKUP_ACCEPT  from ${pid(msg.from)} — no pending offer, ignored`);
    return;
  }
  // honour TTL — don't send a stale blob
  if (Date.now() - pending.ts > BACKUP_OFFER_TTL) {
    delete pendingBackupOffer[msg.from];
    mlog.warn(`BACKUP_ACCEPT  from ${pid(msg.from)} — offer expired, ignored`);
    return;
  }
  delete pendingBackupOffer[msg.from];
  sendSignal({ type: "sync:backup_push", from: state.publicId, to: msg.from, blob: pending.blob });
  mlog.info(`→ BACKUP_PUSH  to   ${pid(msg.from)} — accepted`);
}

async function handleBackupPush(msg) {
  if (!msg.from || !msg.blob) return;
  if (state.contacts[msg.from]?.blocked) return;
  markOnline(msg.from);

	if (msg.from === state.publicId) {
		if (msg.deviceId && msg.deviceId === state.deviceId) return;  // own echo, shouldn't happen but be defensive
		try {
		  const plain = await decryptObject(state.cryptoKey, msg.blob);
		  if (typeof plain !== "object" || Array.isArray(plain)) return;
		  const restored      = await deserialiseContacts(plain);
		  const prevSelfRelay = state.contacts[state.publicId]?.lastRelay;
		  for (const [id, contact] of Object.entries(restored)) {
			if (!state.contacts[id]) state.contacts[id] = contact;
			else {
			  mergeContactMeta(state.contacts[id], contact);
			  state.contacts[id].messages = mergeMessages(state.contacts[id].messages, contact.messages);
			}
		  }
		  await saveContacts();
		  renderContactList();
		  if (state.currentChat) renderMessages();
		  mlog.info(`← BACKUP_PUSH  from self — merged other-me`);
		  if (state.contacts[state.publicId]?.lastRelay !== prevSelfRelay) {
			mlog.info(`BACKUP_PUSH    self relay changed via other device — rebooting signal`);
			rebootSignal();
		  }
		  // record sender's fingerprint, then ack back with our own post-merge
		  // fingerprint — reuses backup_accept's shape, disambiguated by the
		  // presence of deviceId (never set on the normal contact handshake).
		  if (msg.deviceId && msg.fingerprint) {
			state.knownDeviceFingerprints[msg.deviceId] = msg.fingerprint;
			recordKnownDevice(state.publicId, msg.deviceId);
		  }
		  if (msg.deviceId) {
			const ownFingerprint = await computeBackupFingerprint();
			sendSignal({ type: "sync:backup_accept", from: state.publicId, to: state.publicId,
						 deviceId: state.deviceId, fingerprint: ownFingerprint });
			mlog.debug(`→ BACKUP_ACK   to self — fingerprint ${ownFingerprint}`);
		  }
		} catch(e) {
		  mlog.warn(`← BACKUP_PUSH  from self — decrypt failed`);
		}
		return;
	}

  if (!state.contacts[msg.from]) {
    mlog.warn(`← BACKUP_PUSH  from ${pid(msg.from)} — unknown contact, dropped`);
    return;
  }

  state.peerBackups[msg.from] = msg.blob;
  savePeerBackups();
  mlog.info(`← BACKUP_PUSH  from ${pid(msg.from)} — stored`);

  // token exchange — one time only
  if (!state.peerTokens[msg.from]) {
    sendSignal({ type: "sync:token_req", from: state.publicId, to: msg.from });
    mlog.info(`→ TOKEN_REQ    to   ${pid(msg.from)} — no token yet`);
  }
}

async function handleTokenRequest(msg) {
  if (!msg.from) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  mlog.info(`← TOKEN_REQ    from ${pid(msg.from)} — generating token`);
  const token = await encryptObject(state.cryptoKey, {
    name:        contact.name,
    shareableKey: contact.shareableKey,
    date:        Date.now(),
  });
  const tokenRespObj = { type: "sync:token_resp", from: state.publicId, to: msg.from, token };
  const viaRelayResp = sendToRelay(msg.from, tokenRespObj, false);
  if (!viaRelayResp) sendSignal(tokenRespObj);
  mlog.info(`→ TOKEN_RESP   to   ${pid(msg.from)}  via=${viaRelayResp ? "relay" : "signal(fallback)"}`);
}

async function handleTokenResponse(msg) {
  if (!msg.from || !msg.token) return;
  if (state.peerTokens[msg.from]) {
    mlog.debug(`TOKEN_RESP     from ${pid(msg.from)} — already have token, ignored`);
    return;
  }
  state.peerTokens[msg.from] = msg.token;
  savePeerTokens();
  mlog.info(`← TOKEN_RESP   from ${pid(msg.from)} — stored`);
}
const pendingRestoreRequest = new Set();

async function sendRestoreRequest(id) {
  const contact = state.contacts[id];
  if (!contact || contact.blocked) return;
  if (pendingRestoreRequest.has(id)) {
    mlog.debug(`RESTORE_REQ already pending  to ${pid(id)}`);
    return;
  }
  if (!canRestore(id)) {
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
  const reqObj = { type: "sync:restore_req", from: state.publicId, to: id, blob, ...(token ? { token } : {}) };
  const viaRelay = sendToRelay(id, reqObj, true);
  if (!viaRelay) sendSignal(reqObj);
  mlog.info(`→ RESTORE_REQ  to   ${pid(id)}${token ? "  +token" : ""}  via=${viaRelay ? "relay" : "signal(fallback)"}`);  
 
}

async function handleRestoreRequest(msg) {
  if (!msg.from || !msg.blob) return;
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
    mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — unknown contact, can't decrypt, dropped`);
    return;
  }
  let plain;
  try {
    plain = await decryptObject(contact.encKey, msg.blob);
    if (plain.publicId_A !== msg.from) {
      mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — ID_A mismatch, dropped`);
      return;
    }
    if (plain.publicId_B !== state.publicId) {
      mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — ID_B mismatch, dropped`);
      return;
    }
  } catch(e) {
    mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — decrypt failed, dropped`);
    return;
  }

  if (contact.blocked) {
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — blocked, ignored`);
    return;
  }
  
  if (plain.deviceId) recordKnownDevice(msg.from, plain.deviceId);

  if (!canRestore(msg.from)) {
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — cooldown, no ack`);
    return;
  }

  const fresh = Object.keys(state.contacts).length <= 1;

  // if token present, validate it — only Alice can decrypt her own token
  if (msg.token) {
    try {
      const tokenPlain = await decryptObject(state.cryptoKey, msg.token);
      if (!tokenPlain.shareableKey) throw new Error("missing shareableKey");
      mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — token valid ✓`);

      // update contact with wss and signPublicKey from blob if we know them
      if (state.contacts[msg.from]) {
        if (plain.wss) updateRelay(state.contacts[msg.from], plain.wss, Date.now());
        if (plain.signPublicKey) {
          state.contacts[msg.from].signPublicKey = base64ToRaw(plain.signPublicKey);
        }
      }
    } catch(e) {
      mlog.warn(`← RESTORE_REQ  from ${pid(msg.from)} — token invalid, dropped`);
      return;
    }
	
  } else if (fresh) {
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — fresh client, no token, ignored`);
    return;
  } else {
    if (fresh) {
      mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — fresh client, requesting back`);
      sendRestoreRequest(msg.from);
    }
  }

  // send ack — cross domain if we have their wss
  const ackObj = { type: "sync:restore_ack", from: state.publicId, to: msg.from, deviceId: state.deviceId };
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
  mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — ack sent  via=${ackSent ? "relay(" + senderWss + ")" : "signal(fallback)"}`);
}

async function handleRestoreAck(msg) {
  if (!msg.from || !msg.to) return;
  if (msg.to !== state.publicId) return;
  if (msg.deviceId) recordKnownDevice(msg.from, msg.deviceId);

  if (msg.from === state.publicId) {
    const freshBlob = await encryptObject(state.cryptoKey, serialiseContacts());
    sendSignal({ type: "sync:restore_push", from: state.publicId, to: msg.from, blob: freshBlob });
    mlog.info(`← RESTORE_ACK  from self — sending fresh data`);
    return;
  }

  const backup = state.peerBackups[msg.from];
  if (!backup) {
    mlog.info(`← RESTORE_ACK  from ${pid(msg.from)} — no backup stored, nothing sent`);
    return;
  }
  mlog.info(`← RESTORE_ACK  from ${pid(msg.from)} — sending restore_push`);
  sendSignal({ type: "sync:restore_push", from: state.publicId, to: msg.from, blob: backup });
}

async function handleRestorePush(msg) {
  if (!msg.from || !msg.blob) return;
  if (!canRestore(msg.from)) {
    mlog.info(`← RESTORE_PUSH from ${pid(msg.from)} — cooldown, ignored`);
    return;
  }
  try {
    const plain = await decryptObject(state.cryptoKey, msg.blob);
    if (typeof plain !== "object" || Array.isArray(plain)) {
      mlog.warn(`← RESTORE_PUSH from ${pid(msg.from)} — bad structure, dropped`);
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
        msgsMerged += state.contacts[id].messages.length - before;
      }
    }
    markRestored(msg.from);
    sessionFresh = false;
    await saveContacts();
    renderContactList();
	if (state.currentChat) renderMessages();
    mlog.info(`← RESTORE_PUSH from ${pid(msg.from)} — +${added} contacts  +${msgsMerged} msgs`);
    setSyncStatus("restored from network ✓");
    if (state.contacts[state.publicId]?.lastRelay !== prevSelfRelay) {
      mlog.info(`RESTORE_PUSH   self relay changed via other device — rebooting signal`);
      rebootSignal();
    }
  } catch(e) {
    mlog.warn(`← RESTORE_PUSH from ${pid(msg.from)} — decrypt failed, dropped`);
  }
}

/* ══════════════════════════════════════════
   MSG EXCHANGE (manual SYNC button)
══════════════════════════════════════════ */
function initiateExchange(contactId) {
  if (!state.online.has(contactId)) {
    setSyncStatus("contact offline");
    mlog.info(`→ SYNC         to   ${pid(contactId)} — offline, aborted`);
    return;
  }
  if (state.contacts[contactId]?.blocked) return;
  sendSignal({ type: "app:sync", from: state.publicId, to: contactId, msgs: getLast(contactId), reply: false });
  mlog.info(`→ SYNC         to   ${pid(contactId)}`);
  setSyncStatus("syncing…");
}

async function handleMsgExchange(msg) {
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  if (!msg.reply) {
    mlog.info(`← SYNC_REQ     from ${pid(msg.from)} — replying`);
    const pending = msg.msgs || [];
    sendSignal({ type: "app:sync", from: state.publicId, to: msg.from, msgs: getLast(msg.from), reply: true });
    const before = contact.messages.length;
    contact.messages = mergeMessages(contact.messages, pending);
    mlog.debug(`SYNC merge +${contact.messages.length - before} msgs from ${pid(msg.from)}`);
  } else {
    const before = contact.messages.length;
    contact.messages = mergeMessages(contact.messages, msg.msgs || []);
    mlog.info(`← SYNC_REPLY   from ${pid(msg.from)} — +${contact.messages.length - before} msgs`);
    setSyncStatus("synced with " + contact.name + " ✓");
  }
  await saveContacts();
  if (state.currentChat === msg.from) renderMessages();
}

/* ══════════════════════════════════════════
   WEBSOCKET
══════════════════════════════════════════ */
/* ══════════════════════════════════════════
   AUTH STATE
   authStep: "idle" | "await_challenge" | "done"
   After "done" the usual post-connect flow runs.
══════════════════════════════════════════ */
const authState = { step: "idle" };

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
    startAuth();
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

function startAuth() {
  authState.step = "await_challenge";
  const parts = state.shareableKey.split(".");
  state.ws.send(JSON.stringify({
    type:        "sig:auth_init",
    x25519_pub:  Array.from(base64ToRaw(parts[0])),
    ed25519_pub: Array.from(base64ToRaw(parts[1])),
  }));
  mlog.info("AUTH       init");
}

// Possession proof is now "sign the nonce with your Ed25519 private key,"
// not "decrypt the nonce with the same AES key you just handed the server
// in auth_init" (which proved nothing — the server already had that key
// in plaintext from the message immediately before). The nonce itself
// travels in the clear now too; there's nothing about it worth hiding,
// only something worth proving you can sign.
function handleAuthChallenge(msg) {
  try {
    const nonce = new Uint8Array(msg.nonce);
    const sig   = Array.from(ed25519.sign(nonce, state.keys.signingKeySeed));
    state.ws.send(JSON.stringify({ type: "sig:auth_proof", sig }));
    mlog.info("AUTH       proof sent");
  } catch(e) {
    mlog.err(`AUTH       sign failed: ${e.message}`);
  }
}

function handleAuthOk(msg) {
  mlog.info(`AUTH OK    id=${pid(msg.public_id)}`);

  // fully authenticated, run post-connect flow
  authState.step = "done";
  setConnected(true);
  state.ws.send(JSON.stringify({ type: "sig:relay_req" }));
  pollContacts();
  schedulePoll();
}

function handleAuthFail(msg) {
  if (authState.step === "done") {
    mlog.debug(`RELAY      remote rejected unauthenticated traffic  reason=${msg.reason}`);
    return;
  }
  mlog.err(`AUTH FAIL  reason=${msg.reason}  step=${authState.step}`);
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
	case "shell:invite":handleShellInvite(msg); break;
	case "shell:claim": handleShellClaim(msg);  break;
	case "shell:cancel":handleShellCancel(msg); break;
	case "shell:end":   handleShellEnd(msg);    break;	
    case "shell:offer": handleShellOffer(msg);  break;
    case "shell:answer":handleShellAnswer(msg); break;
    case "shell:ice":   handleShellIce(msg);    break;
	
	
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
          sendSignal({ type: "sync:restore_ack", from: state.publicId, to: state.publicId });
          mlog.info(`→ RESTORE_ACK  to self — fresh start, skipping handshake`);
        }
      } else if (state.contacts[msg.id]) {
        markOnline(msg.id);
        if (canRestore(msg.id)) sendRestoreRequest(msg.id);
        if (sessionFresh) {
          sendSignal({ type: "sync:restore_ack", from: state.publicId, to: msg.id });
          mlog.info(`→ RESTORE_ACK  to   ${pid(msg.id)} — fresh, asking for peer backup`);
        }
      } else if (sessionFresh) {
        sendSignal({ type: "sync:restore_ack", from: state.publicId, to: msg.id });
        mlog.info(`→ RESTORE_ACK  to   ${pid(msg.id)} — fresh, asking for peer backup`);
      }
      renderContactList();
      break;

    case "sync:restore_req":			markOnline(msg.from);		handleRestoreRequest(msg); 	break;
    case "sync:restore_ack":     		markOnline(msg.from);		handleRestoreAck(msg);     	break;
    case "sync:restore_push":         	markOnline(msg.from);		handleRestorePush(msg);    	break;
    case "sync:token_req":  		 	markOnline(msg.from); 		handleTokenRequest(msg);  	break;
    case "sync:token_resp": 		 	markOnline(msg.from); 		handleTokenResponse(msg); 	break;
    case "app:message":              	receiveMessage(msg);       	break;
    case "app:migrate":               	handleMigrate(msg);        	break;
	case "app:burn": 					handleBurn(msg); 			break;
    case "app:sync":         			markOnline(msg.from);		handleMsgExchange(msg);    	break;
    case "sync:backup_offer":         	markOnline(msg.from);		handleBackupOffer(msg);    	break;
    case "sync:backup_accept":        	markOnline(msg.from);		handleBackupAccept(msg);   	break;
    case "sync:backup_push":          	markOnline(msg.from);		handleBackupPush(msg);     	break;

    default: mlog.debug(`SIG unknown type=${msg.type}`);
  }
}

function sendSignal(obj) {
  if (state.ws?.readyState === WebSocket.OPEN) state.ws.send(JSON.stringify(obj));
  // piggyback protocol traffic on open relay connections — never opens one, never resets timer
  if (obj.to && obj.type !== "app:message") sendToRelay(obj.to, obj, false);
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

    ws.onopen = () => {
      step = "await_challenge";
      const parts = state.shareableKey.split(".");
      // no_receive: this probe closes itself the instant auth_ok arrives — it
      // must never be registered as a recipient server-side, or a buffer
      // flush racing the deliberate close can either warn harmlessly (the
      // common case) or, in the unlucky ordering, have the server delete a
      // buffered packet (e.g. a migrate breadcrumb) it believes was delivered
      // to a socket that was actually already gone or about to discard it.
      ws.send(JSON.stringify({
        type: "sig:auth_init",
        x25519_pub:  Array.from(base64ToRaw(parts[0])),
        ed25519_pub: Array.from(base64ToRaw(parts[1])),
        no_receive: true,
      }));
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        if (step === "await_challenge" && msg.type === "sig:auth_challenge") {
          const nonce = new Uint8Array(msg.nonce);
          const sig   = Array.from(ed25519.sign(nonce, state.keys.signingKeySeed));
          ws.send(JSON.stringify({ type: "sig:auth_proof", sig }));
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

    ws.onopen = () => {
      clearTimeout(connectTimeout);
      entry.authStep = "await_challenge";
      const parts = state.shareableKey.split(".");
      ws.send(JSON.stringify({
        type: "sig:auth_init",
        x25519_pub:  Array.from(base64ToRaw(parts[0])),
        ed25519_pub: Array.from(base64ToRaw(parts[1])),
      }));
      mlog.info(`RELAY      open, authing  host=${hostname}`);
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        // ── challenge ──
        if (entry.authStep === "await_challenge" && msg.type === "sig:auth_challenge") {
          const nonce = new Uint8Array(msg.nonce);
          const sig   = Array.from(ed25519.sign(nonce, state.keys.signingKeySeed));
          ws.send(JSON.stringify({ type: "sig:auth_proof", sig }));
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

  ws.onopen = () => {
    step = "await_challenge";
    const parts = state.shareableKey.split(".");
    ws.send(JSON.stringify({
      type: "sig:auth_init",
      x25519_pub:  Array.from(base64ToRaw(parts[0])),
      ed25519_pub: Array.from(base64ToRaw(parts[1])),
    }));
  };

  ws.onmessage = async (evt) => {
    const msg = JSON.parse(evt.data);
    if (step === "await_challenge" && msg.type === "sig:auth_challenge") {
      const nonce = new Uint8Array(msg.nonce);
      const sig   = Array.from(ed25519.sign(nonce, state.keys.signingKeySeed));
      ws.send(JSON.stringify({ type: "sig:auth_proof", sig }));
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
	
	// Our own breadcrumb, consumed by our own drain — buf_deliver just
    // deleted it server-side. Put it straight back so a straggler device
    // arriving after we've disconnected can still find it. Reuse the
    // blob/sig as-is — same fact, no re-encryption needed.
	if (msg.type === "app:migrate" && msg.from === state.publicId && msg.to === state.publicId) {
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
// one.
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
      try {
        const me       = state.contacts[state.publicId];
        const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

        const payload   = { id, type: "image", data: base64, mimeType, ts, deviceId: state.deviceId, n: nextSendCounter(state.currentChat), ...(relay ? { relay } : {}) };
        const encrypted = await encryptMessage(contact.encKey, payload);
        const sig       = await signBlob(encrypted);

        const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
        imageCache[id] = { encBlob, mimeType };

        const imgMsgObj  = { type: "app:message", from: state.publicId,
                   to: state.currentChat, blob: encrypted, sig };
        packetCache[id] = { envelope: imgMsgObj, payload };
        const viaRelayImg = sendToRelay(state.currentChat, imgMsgObj, true);
        const wsOpen      = state.ws?.readyState === WebSocket.OPEN;
        if (!viaRelayImg) sendSignal(imgMsgObj);
        status = (viaRelayImg || wsOpen) ? "sent" : "failed";
        mlog.info(`→ IMAGE        to   ${pid(state.currentChat)}  ${w}×${h}  via=${viaRelayImg ? "relay" : (wsOpen ? "signal(fallback)" : "nowhere — no open socket")}`);
      } catch(e) {
        mlog.err(`→ IMAGE        to   ${pid(state.currentChat)} — send failed: ${e.message}`);
      }

      contact.messages = mergeMessages(contact.messages, [{ id, from: state.publicId, type: "image", mimeType, ts, valid: true, status }]);
      await saveContacts();
      renderMessages();
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
    try {
      const me       = state.contacts[state.publicId];
      const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

      // encrypt for transit
      const payload   = { id, type: "audio", data: base64, mimeType, ts, deviceId: state.deviceId, n: nextSendCounter(state.currentChat), ...(relay ? { relay } : {}) };
      const encrypted = await encryptMessage(contact.encKey, payload);
      const sig       = await signBlob(encrypted);

      // store encrypted in memory cache — never raw
      const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
      audioCache[id] = { encBlob, mimeType };

      const audioMsgObj = { type: "app:message", from: state.publicId,
               to: state.currentChat, blob: encrypted, sig };
      packetCache[id] = { envelope: audioMsgObj, payload };
      const viaRelayAud = sendToRelay(state.currentChat, audioMsgObj, true);
      const wsOpen      = state.ws?.readyState === WebSocket.OPEN;
      if (!viaRelayAud) sendSignal(audioMsgObj);
      status = (viaRelayAud || wsOpen) ? "sent" : "failed";
      mlog.info(`→ AUDIO        to   ${pid(state.currentChat)}  size=${blob.size}b  via=${viaRelayAud ? "relay" : (wsOpen ? "signal(fallback)" : "nowhere — no open socket")}`);
    } catch(e) {
      mlog.err(`→ AUDIO        to   ${pid(state.currentChat)} — send failed: ${e.message}`);
    }

    // stub in messages — data stays in audioCache only
    contact.messages = mergeMessages(contact.messages, [{ id, from: state.publicId, type: "audio", mimeType, ts, valid: true, status }]);
    await saveContacts();
    renderMessages();
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
      type: "sig:push_subscribe", from: state.publicId, deviceId: state.deviceId,
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
    sendSignal({ type: "sig:push_unsubscribe", from: state.publicId, deviceId: state.deviceId });
    state.pushSyncedRelayWss = null;
    mlog.info("PUSH       unsubscribed");
  }
}

/* ══════════════════════════════════════════
   MESSAGING
══════════════════════════════════════════ */
async function receiveMessage(msg) {
  if (!msg.from || !msg.blob) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  try {
    let plain, valid;
    plain = await decryptMessage(msg.blob, contact.encKey);
    valid = msg.sig && contact.signPublicKey
      ? verifyBlob(msg.blob, msg.sig, contact.signPublicKey)
      : false;
    // deviceId now travels inside the encrypted+signed payload rather than
    // the outer envelope (see notifyMigration-style payloads / protocol.md) —
    // only recorded once the signature is confirmed valid, so a message that
    // fails to decrypt, or one that decrypts but isn't validly signed, can't
    // poison the device registry. This was previously firing unconditionally
    // before decrypt/verify even ran — left over from debugging signature
    // failures early on; tightened now that it's a real trust boundary.
    if (valid && plain.deviceId) recordKnownDevice(msg.from, plain.deviceId, plain.n);
    if (plain.id) packetCache[plain.id] = { envelope: msg, payload: plain };
    if (plain.relay?.wss) {
      updateRelay(contact, plain.relay.wss, plain.ts || Date.now());
      if (state.currentChat === msg.from) updateChatRelayInfo(msg.from);
    }
    mlog.info(`← MSG          from ${pid(msg.from)}  sig:${valid ? "✓" : "✗"}`);

    const msgObj = { id: plain.id, from: msg.from, ts: plain.ts || Date.now(), valid };

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
      mlog.info(`← REACTION     from ${pid(msg.from)}  target=${pid(plain.targetId)}  emoji=${plain.emoji || "nil"}`);
    } else {
      msgObj.text = plain.text;
      mlog.debug(`MSG content: "${(plain.text||"").slice(0,40)}${(plain.text||"").length>40?"…":""}"  id=${plain.id}`);
    }

    if (msgObj.type === "reaction") {
      contact.messages = mergeMessages(contact.messages, [msgObj]);
      // Any reaction — including our own auto-ack below, which is itself
      // a reaction with emoji:null — targeting a message WE sent proves
      // the other side decrypted it. A genuine "they cleared their
      // reaction" is indistinguishable on the wire and implies the exact
      // same thing, so no special-casing is needed: just flip status
      // once, on whichever reaction gets there first.
      const target = contact.messages.find(m => m.id === msgObj.targetId);
      if (target && target.from === state.publicId && target.status !== "delivered") {
        target.status = "delivered";
      }
    } else {
      contact.messages = mergeMessages(contact.messages, [msgObj]);
      if (state.currentChat !== msg.from) {
        state.unread[msg.from] = (state.unread[msg.from] || 0) + 1;
      }
      // Auto-ack — reuses the existing reaction channel (emoji:null)
      // rather than a new packet type. Only for a message that both
      // decrypted AND verified: an ack should mean "a real device
      // confirmed this," not just "something decryptable arrived."
      // Never fires on our own self-targeted traffic (msg.from ===
      // state.publicId) — there's no delivery concept to signal to
      // ourselves. Deliberately NOT gated on state.currentChat — this
      // must go to msg.from regardless of which chat happens to be open.
      if (valid && msg.from !== state.publicId) {
        sendReaction(plain.id, null, msg.from);
      }
    }
    await saveContacts();
    saveContactsBackup();
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
   Signature is verified the same way receiveMessage does it — this packet
   redirects routing, so unlike most other packet types it must NOT be
   trusted on decryption success alone. The relay is untrusted
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
  if (!msg.from || !msg.blob) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);

  let plain;
  try {
    plain = await decryptMessage(msg.blob, contact.encKey);
  } catch(e) {
    mlog.warn(`← MIGRATE      from ${pid(msg.from)} — decrypt failed`);
    return;
  }

  const sigValid = msg.sig && contact.signPublicKey
    ? verifyBlob(msg.blob, msg.sig, contact.signPublicKey)
    : false;
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
    updateRelay(me, plain.newRelay, plain.ts);
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
          const blob = await encryptMessage(me.encKey, { newRelay: plain.newRelay, ts: plain.ts });
          const sig  = await signBlob(blob);
          const breadcrumbObj = { type: "app:migrate", from: state.publicId, to: state.publicId, blob, sig };
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
    updateRelay(contact, plain.newRelay, plain.ts);
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
   state.encKey, symmetric scheme. Signature verification is NOT
   optional here, same rule as app:migrate and the call:* group:
   this packet drives an irreversible action, so an unsigned or
   invalid one is dropped outright rather than flagged and shown.
 
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
 
  const isSelf  = msg.from === state.publicId;
  const contact = state.contacts[msg.from];
  if (!isSelf && !contact) return;   // unknown sender, nothing to act on
 
  let plain;
  try {
    plain = await decryptMessage(msg.blob, contact.encKey);
  } catch(e) {
    mlog.warn(`← BURN         from ${pid(msg.from)} — decrypt failed`);
    return;
  }
 
  const verifyKey = isSelf ? state.contacts[state.publicId]?.signPublicKey : contact.signPublicKey;
  const sigValid  = msg.sig && verifyKey ? verifyBlob(msg.blob, msg.sig, verifyKey) : false;
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
   for good." blockReason is local-only UI metadata, same trust tier as
   contact.type — never a security boundary, just lets the edit-contact
   pane say WHY something is blocked instead of a bare yes/no. */
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
   pretend to).
══════════════════════════════════════════ */
function selfDestruct() {
  const suffix = "_" + state.publicId;
  [STORAGE_KEY, PEER_BACKUP_KEY, PEER_TOKEN_KEY, DEVICE_REGISTRY_KEY, DEVICE_KEY_STORAGE]
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
      const blob = await encryptMessage(contact.encKey, payload);
      const sig  = await signBlob(blob);
      const migMsgObj = { type: "app:migrate", from: state.publicId, to: id, blob, sig };
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
      const blob = await encryptMessage(me.encKey, payload);
      const sig  = await signBlob(blob);
      const selfMsgObj = { type: "app:migrate", from: state.publicId, to: state.publicId, blob, sig };
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
        type: "sig:push_unsubscribe", from: state.publicId, deviceId: state.deviceId,
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
       (same pattern pushMiniBackup already uses for self-targeted
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
      const blob = await encryptMessage(contact.encKey, payload);
      const sig  = await signBlob(blob);
      const burnMsgObj = { type: "app:burn", from: state.publicId, to: id, blob, sig };
      const viaRelay    = sendToRelay(id, burnMsgObj, true);
      if (!viaRelay) sendSignal(burnMsgObj);
      mlog.info(`→ BURN         to   ${pid(id)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
    } catch(e) {
      mlog.warn(`→ BURN         to   ${pid(id)} — encrypt failed: ${e.message}`);
    }
  }
 
  const me = state.contacts[state.publicId];
  try {
    const blob = await encryptMessage(me.encKey, payload);
    const sig  = await signBlob(blob);
    const selfBurnObj = { type: "app:burn", from: state.publicId, to: state.publicId, blob, sig };
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

async function pushMiniBackup(contactId) {
  const contact = state.contacts[contactId];
  if (!contact) return;
  const slim = { [contactId]: { ...serialiseContacts()[contactId] } };
  const blob = await encryptObject(state.cryptoKey, slim);
  sendSignal({ type: "sync:backup_push", from: state.publicId, to: state.publicId, blob });
  mlog.info(`→ MINI_BACKUP  to self  contact=${pid(contactId)}`);
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
  try {
    const me     = state.contacts[state.publicId];
    const relay  = me?.lastRelay ? { wss: me.lastRelay } : undefined;
    const payload = { id, text, ts, deviceId: state.deviceId, n: nextSendCounter(state.currentChat), ...(relay ? { relay } : {}) };
    const blob   = await encryptMessage(contact.encKey, payload);
    const sig    = await signBlob(blob);

    const msgObj = { type: "app:message", from: fromId, to: contact.publicId, blob, ...(sig ? { sig } : {}) };
    packetCache[id] = { envelope: msgObj, payload };
    const viaRelay = sendToRelay(state.currentChat, msgObj, true);
    const wsOpen   = state.ws?.readyState === WebSocket.OPEN;
    if (!viaRelay) sendSignal(msgObj);
    status = (viaRelay || wsOpen) ? "sent" : "failed";
    mlog.info(`→ MSG          to   ${pid(state.currentChat)}  via=${viaRelay ? "relay" : (wsOpen ? "signal(fallback)" : "nowhere — no open socket")}`);
    mlog.debug(`MSG content: "${text.slice(0,40)}${text.length>40?"…":""}"  id=${id}`);
  } catch(e) {
    mlog.err(`→ MSG          to   ${pid(state.currentChat)} — send failed: ${e.message}`);
  }

  contact.messages = mergeMessages(contact.messages, [{ id, from: fromId, text, ts, valid: true, status }]);
  await saveContacts();
  input.value = "";
  renderMessages();
  pushMiniBackup(contact.publicId);
}

/* ══════════════════════════════════════════
   REACTIONS
   Stable ID: SHA-256("reaction:" + myId + ":" + targetMsgId)
   so mergeMessages naturally replaces, never duplicates.
   emoji: ":)" | ":(" | null  (null = cleared)
══════════════════════════════════════════ */
async function sendReaction(targetMsgId, emoji, contactId = state.currentChat) {
  if (!contactId) return;
  const contact = state.contacts[contactId];
  if (!contact?.encKey) return;

  const id  = await deriveReactionId(state.publicId, targetMsgId);
  const ts  = Date.now();
  const me    = state.contacts[state.publicId];
  const relay = me?.lastRelay ? { wss: me.lastRelay } : undefined;
  const payload  = { id, type: "reaction", targetId: targetMsgId, emoji, ts, deviceId: state.deviceId, ...(relay ? { relay } : {}) };
  const blob     = await encryptMessage(contact.encKey, payload);
  const sig      = await signBlob(blob);

  const reactMsgObj = { type: "app:message", from: state.publicId, to: contactId, blob, sig };
  const viaRelayReact = sendToRelay(contactId, reactMsgObj, true);
  if (!viaRelayReact) sendSignal(reactMsgObj);
  const msgObj = { id, from: state.publicId, type: "reaction", targetId: targetMsgId, emoji, ts, valid: true };
  contact.messages = mergeMessages(contact.messages, [msgObj]);
  mlog.info(`→ REACTION     to   ${pid(contactId)}  target=${pid(targetMsgId)}  emoji=${emoji || "nil"}  via=${viaRelayReact ? "relay" : "signal(fallback)"}`);
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

function signShellPacket(obj) {
  const { type, from, to, sessionId, deviceId, ts, blob } = obj;
  return signBlob({ type, from, to, sessionId, deviceId: deviceId || null, ts, blob: blob || null });
}

function verifyShellPacket(obj, contactSignPublicKey) {
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;

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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyCallPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← CALL END     from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.call?.callId !== msg.callId) return;
  transition(msg.from, { type: "call_ended" });
}

async function handleShellInvite(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL INVITE from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  markOnline(msg.from);
  if (contact.shell && contact.shell.phase !== "idle") {
    mlog.debug(`← SHELL INVITE from ${pid(msg.from)} — already in session (phase=${contact.shell.phase}), ignored`);
    return;
  }
  contact.shell = { sessionId: msg.sessionId, phase: "idle", role: null };
  transition(msg.from, { type: "invite_received" }, "shell");
}

async function handleShellClaim(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL CLAIM  from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.shell?.sessionId !== msg.sessionId) {
    mlog.debug(`← SHELL CLAIM  from ${pid(msg.from)} — sessionId mismatch/stale, ignored`);
    return;
  }
  markOnline(msg.from);
  transition(msg.from, { type: "claim_received" }, "shell");
}

async function handleShellCancel(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL CANCEL from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.shell?.sessionId !== msg.sessionId) return;
  transition(msg.from, { type: "call_cancelled" }, "shell");
}

async function handleShellEnd(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL END    from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.shell?.sessionId !== msg.sessionId) return;
  transition(msg.from, { type: "call_ended" }, "shell");
}

async function handleShellOffer(msg) {
  // Client-side is not expected to receive shell:offer today — the human
  // is always the offerer per the agreed asymmetry, and agent.py never
  // initiates. Guarded and logged rather than silently ignored, in case
  // that assumption changes later (human-to-human shell sharing).
  mlog.debug(`← SHELL OFFER  from ${pid(msg.from)} — unexpected, human client is always offerer, ignored`);
}
 
async function handleShellAnswer(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL ANSWER from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.shell?.sessionId !== msg.sessionId || contact.shell.role !== "caller") {
    mlog.debug(`← SHELL ANSWER from ${pid(msg.from)} — not expecting answer, ignored`);
    return;
  }
  markOnline(msg.from);
  const entry = shellConns[msg.from];
  if (!entry) { mlog.warn(`← SHELL ANSWER from ${pid(msg.from)} — no pc, dropped`); return; }
  try {
    const plain = await decryptMessage(msg.blob, contact.encKey);
    await entry.pc.setRemoteDescription({ type: "answer", sdp: plain.sdp });
    await flushShellIceQueue(msg.from);
    mlog.info(`← SHELL ANSWER from ${pid(msg.from)} — remote set`);
  } catch(e) {
    mlog.err(`← SHELL ANSWER from ${pid(msg.from)} — failed: ${e.message}`);
    transition(msg.from, { type: "rtc_failed" }, "shell");
  }
}
 
async function handleShellIce(msg) {
  if (!msg.from || !msg.to || !msg.sessionId || msg.to !== state.publicId) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  if (!verifyShellPacket(msg, contact.signPublicKey)) {
    mlog.warn(`← SHELL ICE    from ${pid(msg.from)} — signature invalid, dropped`);
    return;
  }
  if (contact.shell?.sessionId !== msg.sessionId) return; // stale/unrelated session
 
  let plain;
  try { plain = await decryptMessage(msg.blob, contact.encKey); }
  catch(e) { mlog.warn(`← SHELL ICE    from ${pid(msg.from)} — decrypt failed`); return; }
 
  const entry = shellConns[msg.from];
  if (!entry) return;
  if (entry.pc.remoteDescription) {
    try { await entry.pc.addIceCandidate(plain); }
    catch(e) { mlog.debug(`SHELL RTC  addIceCandidate failed: ${e.message}`); }
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
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
  if (!msg.from || !msg.to || !msg.callId || msg.to !== state.publicId) return;
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
   SHELL ESCALATION — user-facing entry points
   Mirrors startCall/cancelCall/endCall exactly, shell-flavored. Real
   signing/sending (sendShellInvite etc.) is still a stub — see the
   "SHELL UI/RTC stubs" section below — so these correctly advance local
   FSM state and update the header button, but nothing reaches the wire
   yet. sessionId plays the same role callId does for calls: assigned
   once here, never touched again by transition() itself.
══════════════════════════════════════════ */
function startShell(id) {
  const contact = state.contacts[id];
  if (!contact || contact.blocked) return;
  if (contact.type !== "agent") return;   // shell only makes sense for agent contacts — mirrors the header button's own gate
  if (contact.shell && contact.shell.phase !== "idle") return;
  contact.shell = { sessionId: crypto.randomUUID(), phase: "idle", role: null };
  transition(id, { type: "session_started" }, "shell");
}

function cancelShell(id) {
  const contact = state.contacts[id];
  if (!contact?.shell?.sessionId) return;
  sendShellPacket(id, "shell:cancel", contact.shell.sessionId);
  transition(id, { type: "session_cancelled" }, "shell");
}

function endShell(id) {
  const contact = state.contacts[id];
  if (!contact?.shell?.sessionId) return;
  sendShellPacket(id, "shell:end", contact.shell.sessionId);
  transition(id, { type: "session_ended" }, "shell");
}

/* ══════════════════════════════════════════
   SHELL UI/RTC stubs — statemachine.js's onShellStateEnter already calls
   these unconditionally, same pattern the original "RTC/UI stubs" used
   for calls: visible no-ops so entering negotiating/connected/failed
   doesn't throw before that work happens. Each one names the piece of
   work it's standing in for:
     sendShellInvite / sendShellPacket — real signing (signShellPacket,
       mirroring agent.py's already-tested version) + wire send
     showIncomingShellUI / hideIncomingShellUI — unreachable against
       agent.py today (it auto-claims), kept for human-to-human parity
     shellRtcOffer / shellRtcClose — RTCPeerConnection + the two data
       channels (shell-data, shell-ctrl), mirrors rtcOffer/rtcClose but
       createDataChannel instead of getUserMedia/addTrack
     openShellTerminal — the xterm.js panel, the actual visible payoff
══════════════════════════════════════════ */
function sendShellPacket(id, type, sessionId) {
  const obj = { type, from: state.publicId, to: id, sessionId, ts: Date.now(), deviceId: state.deviceId };
  obj.sig = signShellPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(id)}  session=${pid(sessionId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}

function sendShellInvite(id) {
  const contact = state.contacts[id];
  if (!contact?.shell?.sessionId) return;
  sendShellPacket(id, "shell:invite", contact.shell.sessionId);
}

const shellConns = {};   // contactId → { pc, dataCh, ctrlCh, iceQueue: [] }
 
async function sendShellSDP(id, type, sdp) {
  const contact = state.contacts[id];
  if (!contact?.shell?.sessionId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, { sdp });
  const obj  = { type, from: state.publicId, to: id, sessionId: contact.shell.sessionId,
                 ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signShellPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.info(`→ ${type.toUpperCase()}  to ${pid(id)}  session=${pid(contact.shell.sessionId)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
}
 
async function sendShellIce(id, candidate) {
  const contact = state.contacts[id];
  if (!contact?.shell?.sessionId || !contact.encKey) return;
  const blob = await encryptMessage(contact.encKey, candidate.toJSON());
  const obj  = { type: "shell:ice", from: state.publicId, to: id, sessionId: contact.shell.sessionId,
                 ts: Date.now(), deviceId: state.deviceId, blob };
  obj.sig = signShellPacket(obj);
  const viaRelay = sendToRelay(id, obj, false);
  if (!viaRelay) sendSignal(obj);
  mlog.debug(`→ SHELL ICE    to ${pid(id)}  session=${pid(contact.shell.sessionId)}`);
}
 
function createShellPeerConnection(id) {
  if (shellConns[id]?.pc) return shellConns[id].pc;
  const pc = new RTCPeerConnection(RTC_CONFIG);   // reuse the same STUN-only config as calls
  const entry = { pc, dataCh: null, ctrlCh: null, iceQueue: [] };
  shellConns[id] = entry;
 
  pc.onicecandidate = (e) => { if (e.candidate) sendShellIce(id, e.candidate); };
 
  pc.onconnectionstatechange = () => {
    mlog.debug(`SHELL RTC  state=${pc.connectionState}  ${pid(id)}`);
    if (pc.connectionState === "connected") transition(id, { type: "rtc_connected" }, "shell");
    else if (pc.connectionState === "failed") transition(id, { type: "rtc_failed" }, "shell");
    else if (pc.connectionState === "closed") transition(id, { type: "rtc_closed" }, "shell");
  };
 
  return pc;
}
 
async function flushShellIceQueue(id) {
  const entry = shellConns[id];
  if (!entry) return;
  for (const cand of entry.iceQueue) {
    try { await entry.pc.addIceCandidate(cand); }
    catch(e) { mlog.debug(`SHELL RTC  queued ICE add failed: ${e.message}`); }
  }
  entry.iceQueue = [];
}
 
// real implementation — replaces the old stub. Human is always the
// offerer (mirrors rtcOffer for calls), but unlike calls there is media
// to acquire — this creates the two data channels up front instead.
async function shellRtcOffer(id) {
  try {
    const pc    = createShellPeerConnection(id);
    const entry = shellConns[id];
 
    entry.dataCh = pc.createDataChannel("shell-data");
    entry.ctrlCh = pc.createDataChannel("shell-ctrl");
    wireShellDataChannel(id, entry.dataCh);
    wireShellCtrlChannel(id, entry.ctrlCh);
 
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await sendShellSDP(id, "shell:offer", offer.sdp);
    mlog.info(`SHELL RTC  offer sent  ${pid(id)}`);
  } catch(e) {
    mlog.err(`SHELL RTC  offer failed: ${e.message}`);
    transition(id, { type: "rtc_failed" }, "shell");
  }
}
 
// real implementation — replaces the old stub
function shellRtcClose(id) {
  const entry = shellConns[id];
  if (entry) {
    entry.dataCh?.close();
    entry.ctrlCh?.close();
    entry.pc.close();
    delete shellConns[id];
  }
  const termEntry = shellTerminals[id];
  if (termEntry) { termEntry.term.dispose(); delete shellTerminals[id]; }
  closeShellTerminalUI(id);
  mlog.debug(`SHELL RTC  closed  ${pid(id)}`);
}
 
// Wiring for the two data channels — shared by the offerer (channels
// created locally in shellRtcOffer) so both sides end up with identical
// message handling once open. The callee-side equivalent doesn't exist
// yet client-side because the human is always the offerer; this is here
// purely for the human's own local channels.
function wireShellDataChannel(id, ch) {
  ch.binaryType = "arraybuffer";
  ch.onopen = () => mlog.info(`SHELL RTC  data channel open  ${pid(id)}`);
  ch.onclose = () => mlog.debug(`SHELL RTC  data channel closed  ${pid(id)}`);
  ch.onmessage = (e) => {
    console.log("SHELL DATA raw", typeof e.data, e.data instanceof ArrayBuffer, e.data?.byteLength ?? e.data?.size);   // ← temporary debug line
    const bytes = e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data;
    if (typeof onShellDataReceived === "function") onShellDataReceived(id, bytes);
  };
}
 
function wireShellCtrlChannel(id, ch) {
  ch.onopen = () => mlog.debug(`SHELL RTC  ctrl channel open  ${pid(id)}`);
  ch.onclose = () => mlog.debug(`SHELL RTC  ctrl channel closed  ${pid(id)}`);
  ch.onmessage = () => {}; // agent doesn't send ctrl messages back today — nothing to handle yet
}
 
// Send resize over the ctrl channel — step 4 (terminal UI) will call this
// on window/panel resize. Exposed now so that wiring is a one-line call
// once xterm.js is in place, not another RTC-layer change.
function sendShellResize(id, cols, rows) {
  const ch = shellConns[id]?.ctrlCh;
  if (!ch || ch.readyState !== "open") return;
  ch.send(JSON.stringify({ type: "resize", cols, rows }));
}

/* ══════════════════════════════════════════
   CONTACTS
══════════════════════════════════════════ */
async function addContact(name,shareableKey,save=true,type="human"){
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
  // type is local-only UI metadata — never on the wire, never trusted as a
  // security boundary. It just decides which button (call vs shell) shows
  // in the header. Real enforcement of shell access lives entirely in the
  // agent's own SHELL_CONTACTS allowlist. Anything but "agent" is "human".
  // encKey is derived via ECDH, not imported off the wire — this contact's
  // x25519PublicKey is public by design (it's what's in the QR code), but
  // the AES key it produces is the shared secret only WE and THEY can
  // compute, not anyone else holding this same shareable address.
  const encKey=await deriveSharedAesKey(state.x25519Seed,x25519PublicKey);
  state.contacts[publicId]={name,publicId,shareableKey,encKey,x25519PublicKey,signPublicKey,messages:[],
    lastRelay:relayWss||null, type: type==="agent"?"agent":"human"};
  if(save)await saveContacts();
  mlog.info(`CONTACT    added ${name}  ${pid(publicId)}${relayWss?" wss="+relayWss:""}${type==="agent"?"  [agent]":""}`);
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