/* ═════════════════════════════════════════════════════════════
   LOGGING
   mlog.info()  → console + in-page
   mlog.debug() → console only
   mlog.warn()  → console.warn + in-page
   mlog.err()   → console.error + in-page
   In-page: circular buffer, max LOG_MAX_LINES.
   Console: hard-cleared every LOG_CLEAR_INTERVAL ms.
   pid(id) — trims a publicId to 8 chars for display.
   NOTE: deliberately NOT named short() to avoid
         collision with the url-truncation var in linkify().
═══════════════════════════════════════════════════════════════ */
// Protocol version — informational only for now, surfaced via sig:relay_info
// so client/server drift shows up in both logs. Not enforced yet; room to
// add real backwards-compat handling once that's actually needed.
const CLIENT_VERSION = "0.3.2";

const LOG_MAX_LINES      = 20;
const LOG_CLEAR_INTERVAL = 5 * 60 * 1000;

const POLL_INTERVAL_MS        	= 30_000;			// base interval between presence polls
const POLL_JITTER_MS          	= 10_000;			// ± random jitter added to poll interval
const PRUNE_INTERVAL_MS       	= 30_000;			// how often to sweep expired online entries
const BACKUP_INTERVAL_MS      	= 10 * 60 * 1000;	// periodic backup + restore-request sweep
const WS_RECONNECT_MS         	= 3_000;			// delay before reconnecting signal websocket
const RELAY_CONNECT_TIMEOUT_MS 	= 5_000;			// max wait for relay websocket to open
const RELAY_RECONNECT_MS      	= 5_000;			// delay before reconnecting a persistent relay
const MODAL_CLOSE_DELAY_MS    	= 1_200;			// brief pause before closing export/import modal
const RESTORE_COOLDOWN 			= 5 * 60 * 1000;

const MAX_DOT_AGE   			= 300_000; 			// = PRUNE_INTERVAL_MS
const BACKUP_THRESHOLD  		= 2;
const BACKUP_OFFER_TTL   		= 60_000;
const RELAY_IDLE_MS  			= 30_000;

function pid(id) { return id ? String(id).slice(0, 8) : "?"; }

const mlog = (() => {
  const ts    = () => new Date().toLocaleTimeString([], { hour:"2-digit", minute:"2-digit", second:"2-digit" });
  const lines = [];
  let visible = false;

  function render() {
    const body = document.getElementById("meshLogBody");
    if (!body) return;
    body.innerHTML = lines.map(l =>
      `<div class="mlog-line ${l.level}">${l.text}</div>`
    ).join("");
    body.scrollTop = body.scrollHeight;
  }

  function push(level, text) {
    lines.push({ level, text: `${ts()} ${text}` });
    if (lines.length > LOG_MAX_LINES) lines.shift();
    render();
  }

  return {
    debug : (...a) => console.debug("[MC]", ...a),
    info  : (text, ...a) => { console.log  ("[MC]", text, ...a); push("info",  text); },
    warn  : (text, ...a) => { console.warn ("[MC]", text, ...a); push("warn",  text); },
    err   : (text, ...a) => { console.error("[MC]", text, ...a); push("err",   text); },
    clear : ()           => { lines.length = 0; render(); },
    show  : ()           => { visible = true;  document.getElementById("meshLog").classList.add("open"); },
    hide  : ()           => { visible = false; document.getElementById("meshLog").classList.remove("open"); },
    toggle: ()           => visible ? mlog.hide() : mlog.show(),
  };
})();

setInterval(() => {
  console.clear();
  console.log("[MC] console cleared", new Date().toLocaleTimeString());
}, LOG_CLEAR_INTERVAL);

/* ══════════════════════════════════════════
   STATE
══════════════════════════════════════════ */
const state = {
  user: null, publicId: null, shareableKey: null,
  keys: null, cryptoKey: null, encKey: null,
  contacts: {}, peerBackups: {}, peerTokens: {},
  currentChat: null, ws: null, online: new Set(),
  unread: {}
};

const isSecure        = window.location.protocol === "https:";
const SIGNAL_URL =isSecure
  ? `wss://${window.location.hostname}/ws/`
  : `ws://${window.location.hostname}:8888`;
const STORAGE_KEY     = "meshchat_contacts";
const PEER_BACKUP_KEY = "meshchat_peer_backups_v1";
const PEER_TOKEN_KEY  = "meshchat_peer_tokens_v1";
const DEVICE_KEY_STORAGE = "meshchat_device_seed_v1";
const EXCHANGE_COUNT  = 10;

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
  dotTimestamps[id] = Date.now();
  if (!wasOnline) mlog.info(`● ONLINE       ${pid(id)}`);
}

function pruneOnline() {
  const now = Date.now();
  for (const id of state.online) {
    if (!onlineTimestamps[id] || (now - onlineTimestamps[id]) > ONLINE_EXPIRY) {
      state.online.delete(id);
      dotTimestamps[id] = null;
      mlog.info(`○ GONE(prune)  ${pid(id)}`);
    }
  }
  renderContactList();
}
setInterval(pruneOnline, PRUNE_INTERVAL_MS);

/* ══════════════════════════════════════════
   LOGIN NOTICES
══════════════════════════════════════════ */
function setRandomLoginNotice() {
const notices = [
  "<strong>note —</strong> your name and passphrase are your identity.<br>there are no accounts to recover.",
  "<strong>hint —</strong> your passphrase is the only way to your identity.<br>choose it carefully.",
  "<strong>hint —</strong> contacts are stored on your device.<br>your network grows one friend at a time.",
  "<strong>hint —</strong> relay servers forward encrypted messages.<br>they cannot read what they carry.",
  "<strong>hint —</strong> your current relay is shared automatically with contacts.<br>moving later is supported.",
  "<strong>hint —</strong> conversations may update over time.<br>late messages are placed where they belong.",
  "<strong>hint —</strong> different devices may briefly disagree.<br>they converge as information spreads.",
  "<strong>hint —</strong> the last activity shown is the last one observed.<br>absence is not proof of absence.",
  "<strong>hint —</strong> relay servers are temporary meeting places.<br>your identity is independent of any relay.",
  "<strong>hint —</strong> encrypted peer backups help devices catch up.<br>no central history exists.",
  "<strong>hint —</strong> resilience comes before immediacy.<br>the network prefers eventual delivery over failure.",
  "<strong>hint —</strong> your contacts maintain their own view of the network.<br>there is no global directory.",
  "<strong>hint —</strong> trust people, not servers.<br>servers transport data, they do not define identity.",
  "<strong>hint —</strong> every message can carry updated relay information.<br>the network repairs itself through conversation.",
  "<strong>hint —</strong> if something seems missing, don't panic.<br>distributed systems occasionally take the scenic route."
];
  const el = document.getElementById("loginNotice");
  if (el) el.innerHTML = notices[Math.floor(Math.random() * notices.length)];
}

/* ══════════════════════════════════════════
   FADING GREEN DOT
══════════════════════════════════════════ */
const dotTimestamps = {};
const DOT_ON_COLOR  = [17, 255, 17];
const DOT_OFF_COLOR = [17,  17, 17];

function lerp(a, b, t) { return a + (b - a) * t; }

function dotColor(id) {
  const ts = dotTimestamps[id];
  if (!ts) return `rgb(${DOT_OFF_COLOR.join(",")})`;
  const t = Math.min(1, (Date.now() - ts) / MAX_DOT_AGE);
  return `rgb(${Math.round(lerp(DOT_ON_COLOR[0],DOT_OFF_COLOR[0],t))},${Math.round(lerp(DOT_ON_COLOR[1],DOT_OFF_COLOR[1],t))},${Math.round(lerp(DOT_ON_COLOR[2],DOT_OFF_COLOR[2],t))})`;
}

function tickDots() {
  document.querySelectorAll(".contactStatus[data-dot-id]").forEach(el => {
    el.style.background = dotColor(el.dataset.dotId);
  });
  requestAnimationFrame(tickDots);
}
requestAnimationFrame(tickDots);

/* ══════════════════════════════════════════
   CRYPTO
══════════════════════════════════════════ */
async function deriveMasterSecret(name, passphrase) {
  if (!crypto?.subtle) throw new Error("crypto.subtle unavailable — needs HTTPS or localhost");
  const enc      = new TextEncoder();
  const saltData = await crypto.subtle.digest("SHA-256", enc.encode("meshchat-v1:" + name.toLowerCase().trim()));
  const baseKey  = await crypto.subtle.importKey("raw", enc.encode(passphrase), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits     = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltData, iterations: 100000, hash: "SHA-256" }, baseKey, 256);
  return new Uint8Array(bits);
}

async function hkdfExpand(master){
  const key=await crypto.subtle.importKey("raw",master,{name:"HKDF"},false,["deriveBits"]);
  const derive=async(label)=>new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(32),info:new TextEncoder().encode("meshchat-v1:"+label)},key,256));
  const encryptionKey=await derive("encryption");
  const backupKey=await derive("backup");
  const signingKeySeed=await derive("signing");  // raw bytes now, not imported as HMAC
  return{signingKeySeed,encryptionKey,backupKey};
}

async function derivePublicId(rawKey) {
  const hash = await crypto.subtle.digest("SHA-256", rawKey);
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

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

// Stable reaction message ID: same sender + same target always → same ID.
// This makes mergeMessages naturally replace rather than duplicate reactions.
async function deriveReactionId(myPublicId, targetMsgId) {
  const enc  = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode("reaction:" + myPublicId + ":" + targetMsgId));
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function rawToBase64(raw) { return btoa(String.fromCharCode(...raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function base64ToRaw(b64) { return Uint8Array.from(atob(b64.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }

async function importEncKey(raw)  { return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt","decrypt"]); }
async function importSignKey(raw) { return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign","verify"]); }

async function compress(str) {
  const stream = new CompressionStream("gzip");
  const writer = stream.writable.getWriter();
  writer.write(new TextEncoder().encode(str));
  writer.close();
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}
async function decompress(bytes) {
  const stream = new DecompressionStream("gzip");
  const writer = stream.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return new TextDecoder().decode(await new Response(stream.readable).arrayBuffer());
}
async function encryptObject(key, obj) {
  const iv     = crypto.getRandomValues(new Uint8Array(12));
  const plain  = await compress(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
  return { v: 2, iv: Array.from(iv), data: Array.from(new Uint8Array(cipher)) };
}
async function decryptObject(key, payload) {
  // v missing = v0 (legacy unversioned), v1 = AES-GCM plain JSON, v2 = AES-GCM + gzip
  if (payload.v !== undefined && payload.v > 2) throw new Error(`unsupported object version v${payload.v}`);
  const raw  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(payload.iv) }, key, new Uint8Array(payload.data));
  const text = payload.v === 2
    ? await decompress(new Uint8Array(raw))
    : new TextDecoder().decode(raw);
  return JSON.parse(text);
}

async function encryptMessage(recipientEncKey, payload) {
  const iv     = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, recipientEncKey, new TextEncoder().encode(JSON.stringify(payload)));
  return { v: 1, iv: Array.from(iv), data: Array.from(new Uint8Array(cipher)) };
}
async function decryptMessage(blob) {
  // v missing = v0 (legacy unversioned), v:1 = AES-256-GCM explicit
  if (blob.v !== undefined && blob.v > 1) throw new Error(`unsupported message version v${blob.v}`);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(blob.iv) }, state.encKey, new Uint8Array(blob.data));
  return JSON.parse(new TextDecoder().decode(plain));
}
function signBlob(blob){
  const bytes=new TextEncoder().encode(JSON.stringify(blob));
  const sig=ed25519.sign(bytes,state.keys.signingKeySeed);
  return Array.from(sig);
}

function verifyBlob(blob,sig,contactSignPublicKey){
  try{
    const bytes=new TextEncoder().encode(JSON.stringify(blob));
    return ed25519.verify(new Uint8Array(sig),bytes,contactSignPublicKey);
  }catch(e){
    return false;
  }
}

/* ══════════════════════════════════════════
   HELPERS
══════════════════════════════════════════ */
function updateRelay(contact, wss, ts) {
  if (wss && (ts || 0) > (contact.lastRelaySeen || 0)) {
    contact.lastRelay     = wss;
    contact.lastRelaySeen = ts || Date.now();
  }
}

function mergeMessages(a, b) {
  const byId = {};
  for (const m of [...(a||[]),...(b||[])]) if (m.id) byId[m.id] = m;
  // ts alone isn't a reliable order for near-simultaneous messages — two
  // events with equal/very-close ts would otherwise tiebreak on whichever
  // side of the merge happened to list them first, which flips depending
  // on merge direction (send-side push vs. receive-side merge vs. restore
  // merge) and is exactly what causes a message to visibly jump position
  // between renders. id is stable and arbitrary but always the same for
  // the same message, so adding it as the tiebreak makes the result of
  // this sort identical no matter which order a/b were merged in.
  return Object.values(byId).sort((x,y) => (x.ts - y.ts) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
}

function mergeContactMeta(local, remote) {
  if ((remote.lastStateChange || 0) > (local.lastStateChange || 0)) {
    local.name            = remote.name;
    local.blocked         = remote.blocked;
    local.lastStateChange = remote.lastStateChange;
  }
  // Backups/restores carry lastRelay too — same timestamp-guarded adoption
  // as updateRelay() already does for relay info embedded in messages.
  // This is what lets a second device pick up a relay change made on a
  // first device, purely through normal backup/restore traffic — no
  // migrate packet involved, since nothing here is a deliberate migration.
  if (remote.lastRelay) updateRelay(local, remote.lastRelay, remote.lastRelaySeen);
}

function getLast(contactId, n = EXCHANGE_COUNT) { return (state.contacts[contactId]?.messages || []).slice(-n); }
function esc(str) { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function setSyncStatus(msg) { document.getElementById("syncStatus").textContent = msg; }

function linkify(text) {
  return text.replace(/(https?:\/\/[^\s]+)/g, (url) => {
    try {
      new URL(url);
      const short_url = url.length > 50 ? url.slice(0, 47) + "..." : url;
      return `<a href="${url}" target="_blank" rel="noopener noreferrer">${short_url}</a>`;
    } catch { return url; }
  });
}

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
                lastStateChange: c.lastStateChange || 0,
                lastRelay:       c.lastRelay       || null,
                lastRelaySeen:   c.lastRelaySeen    || 0 };
  return out;
}

async function deserialiseContacts(raw){
  const out={};
  for(const[id,c]of Object.entries(raw)){
    const parts=c.shareableKey.split(".");
    const encKeyBytes=base64ToRaw(parts[0]);
    const signPublicKey=parts.length>=2?base64ToRaw(parts[1]):null;
    // parts[2] is base64-encoded relay WSS — preserved as-is in shareableKey
    out[id]={...c,encKey:await importEncKey(encKeyBytes),signPublicKey};
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
      // self-sync: no negotiation needed, push directly
      try {
        const freshBlob = await encryptObject(state.cryptoKey, serialiseContacts());
        sendSignal({ type: "sync:backup_push", from: state.publicId, to: id, blob: freshBlob });
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
  });
  const token = state.peerTokens[id] || null;
  const reqObj = { type: "sync:restore_req", from: state.publicId, to: id, blob, ...(token ? { token } : {}) };
  const viaRelay = sendToRelay(id, reqObj, true);
  if (!viaRelay) sendSignal(reqObj);
  mlog.info(`→ RESTORE_REQ  to   ${pid(id)}${token ? "  +token" : ""}  via=${viaRelay ? "relay" : "signal(fallback)"}`);  
 
}

async function handleRestoreRequest(msg) {
  if (!msg.from || !msg.blob) return;
  let plain;
  try {
    plain = await decryptObject(state.encKey, msg.blob);
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

  if (state.contacts[msg.from]?.blocked) {
    mlog.info(`← RESTORE_REQ  from ${pid(msg.from)} — blocked, ignored`);
    return;
  }

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
  const ackObj = { type: "sync:restore_ack", from: state.publicId, to: msg.from };
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
  state.ws.send(JSON.stringify({
    type:    "sig:auth_init",
    enc_key: Array.from(base64ToRaw(state.shareableKey.split(".")[0])),
  }));
  mlog.info("AUTH       init");
}

async function handleAuthChallenge(msg) {
  try {
    const iv         = new Uint8Array(msg.iv);
    const data       = new Uint8Array(msg.data);
    const plainBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.encKey, data);
    const nonce      = Array.from(new Uint8Array(plainBytes));
    state.ws.send(JSON.stringify({ type: "sig:auth_proof", nonce }));
    mlog.info("AUTH       proof sent");
  } catch(e) {
    mlog.err(`AUTH       decrypt failed: ${e.message}`);
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

    case "sync:restore_req": markOnline(msg.from);		handleRestoreRequest(msg); break;
    case "sync:restore_ack":     markOnline(msg.from);		handleRestoreAck(msg);     break;
    case "sync:restore_push":         markOnline(msg.from);		handleRestorePush(msg);    break;
    case "sync:token_req":  		 markOnline(msg.from); 		handleTokenRequest(msg);  break;
    case "sync:token_resp": 		 markOnline(msg.from); 		handleTokenResponse(msg); break;
    case "app:message":              receiveMessage(msg);       break;
    case "app:migrate":               handleMigrate(msg);        break;
    case "app:sync":         markOnline(msg.from);		handleMsgExchange(msg);    break;
    case "sync:backup_offer":         markOnline(msg.from);		handleBackupOffer(msg);    break;
    case "sync:backup_accept":        markOnline(msg.from);		handleBackupAccept(msg);   break;
    case "sync:backup_push":          markOnline(msg.from);		handleBackupPush(msg);     break;

    default: mlog.debug(`SIG unknown type=${msg.type}`);
  }
}

function sendSignal(obj) {
  // Route once — try an already-open relay connection first (protocol
  // traffic never opens one, per sendToRelay's messageOnly=false), falling
  // back to the main signal socket only if that didn't happen. Previously
  // this sent down BOTH channels whenever both were viable, which
  // double-delivered any non-app:message packet to the recipient (e.g.
  // sync:restore_push hitting the cooldown race) — same packet, twice,
  // each one a fully valid delivery from the server's point of view.
  const viaRelay = (obj.to && obj.type !== "app:message")
    ? sendToRelay(obj.to, obj, false)
    : false;
  if (!viaRelay && state.ws?.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify(obj));
  }
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
      const encKey = Array.from(base64ToRaw(state.shareableKey.split(".")[0]));
      ws.send(JSON.stringify({ type: "sig:auth_init", enc_key: encKey }));
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        if (step === "await_challenge" && msg.type === "sig:auth_challenge") {
          const iv         = new Uint8Array(msg.iv);
          const data       = new Uint8Array(msg.data);
          const plainBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.encKey, data);
          ws.send(JSON.stringify({ type: "sig:auth_proof", nonce: Array.from(new Uint8Array(plainBytes)) }));
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

  // Never open a second, independently-authed connection to a host we're
  // already connected to as ourselves via the main signal socket. Without
  // this, e.g. sending a restore_req to a contact who happens to share our
  // own relay host opens a redundant outbound connection auth'd as us on
  // that same host — the server then has two live sockets registered under
  // our public_id there and (correctly, per its own fan-out logic) delivers
  // every reply to BOTH, double-firing whatever handler receives it (this
  // is what caused the double restore_push observed in testing). The
  // existing sig:relay_info cleanup closes this kind of redundant
  // connection reactively, after the fact; this stops it from ever being
  // opened in the first place. Falls through to the caller's existing
  // sendSignal fallback, same as "no relay connection available" already
  // does — our own signal socket reaches this host already.
  const ownHost = relayHostname(getSignalUrl());
  if (ownHost && hostname === ownHost) {
    mlog.debug(`RELAY      skipping conn to own signal host  host=${hostname}`);
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
      const encKey = Array.from(base64ToRaw(state.shareableKey.split(".")[0]));
      ws.send(JSON.stringify({ type: "sig:auth_init", enc_key: encKey }));
      mlog.info(`RELAY      open, authing  host=${hostname}`);
    };

    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);

        // ── challenge ──
        if (entry.authStep === "await_challenge" && msg.type === "sig:auth_challenge") {
          const iv         = new Uint8Array(msg.iv);
          const data       = new Uint8Array(msg.data);
          const plainBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.encKey, data);
          const nonce      = Array.from(new Uint8Array(plainBytes));
          ws.send(JSON.stringify({ type: "sig:auth_proof", nonce }));
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
      const me       = state.contacts[state.publicId];
      const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

      const payload   = { id, type: "image", data: base64, mimeType, ts, ...(relay ? { relay } : {}) };
      const encrypted = await encryptMessage(contact.encKey, payload);
      const sig       = await signBlob(encrypted);

      const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
      imageCache[id] = { encBlob, mimeType };

      const imgMsgObj  = { type: "app:message", from: state.publicId,
                   to: state.currentChat, blob: encrypted, sig };
      const viaRelayImg = sendToRelay(state.currentChat, imgMsgObj, true);
      if (!viaRelayImg) sendSignal(imgMsgObj);

      contact.messages = mergeMessages(contact.messages, [{ id, from: state.publicId, type: "image", mimeType, ts, valid: true }]);
      await saveContacts();
      renderMessages();
      mlog.info(`→ IMAGE        to   ${pid(state.currentChat)}  ${w}×${h}  via=${viaRelayImg ? "relay" : "signal(fallback)"}`);
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
    const me       = state.contacts[state.publicId];
    const relay    = me?.lastRelay ? { wss: me.lastRelay } : undefined;

    // encrypt for transit
    const payload   = { id, type: "audio", data: base64, mimeType, ts, ...(relay ? { relay } : {}) };
    const encrypted = await encryptMessage(contact.encKey, payload);
    const sig       = await signBlob(encrypted);

    // store encrypted in memory cache — never raw
    const encBlob = await encryptObject(state.encKey, { data: base64, mimeType });
    audioCache[id] = { encBlob, mimeType };

    const audioMsgObj = { type: "app:message", from: state.publicId,
                 to: state.currentChat, blob: encrypted, sig };
    const viaRelayAud  = sendToRelay(state.currentChat, audioMsgObj, true);
    if (!viaRelayAud) sendSignal(audioMsgObj);

    // stub in messages — data stays in audioCache only
    contact.messages = mergeMessages(contact.messages, [{ id, from: state.publicId, type: "audio", mimeType, ts, valid: true }]);
    await saveContacts();
    renderMessages();
    mlog.info(`→ AUDIO        to   ${pid(state.currentChat)}  size=${blob.size}b  via=${viaRelayAud ? "relay" : "signal(fallback)"}`);
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
   MESSAGING
══════════════════════════════════════════ */
async function receiveMessage(msg) {
  if (!msg.from || !msg.blob) return;
  const contact = state.contacts[msg.from];
  if (!contact || contact.blocked) return;
  markOnline(msg.from);
  try {
    let plain, valid;
    plain = await decryptMessage(msg.blob);
    valid = msg.sig && contact.signPublicKey
      ? verifyBlob(msg.blob, msg.sig, contact.signPublicKey)
      : false;
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
    } else {
      contact.messages = mergeMessages(contact.messages, [msgObj]);
      if (state.currentChat !== msg.from) {
        state.unread[msg.from] = (state.unread[msg.from] || 0) + 1;
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
    plain = await decryptMessage(msg.blob);
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
  }
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
  const me     = state.contacts[state.publicId];
  const relay  = me?.lastRelay ? { wss: me.lastRelay } : undefined;
  const blob   = await encryptMessage(contact.encKey, { id, text, ts, ...(relay ? { relay } : {}) });
  const sig    = await signBlob(blob);

  const msgObj = { type: "app:message", from: fromId, to: contact.publicId, blob, ...(sig ? { sig } : {}) };
  const viaRelay = sendToRelay(state.currentChat, msgObj, true);
  if (!viaRelay) sendSignal(msgObj);
  contact.messages = mergeMessages(contact.messages, [{ id, from: fromId, text, ts, valid: true }]);
  mlog.info(`→ MSG          to   ${pid(state.currentChat)}  via=${viaRelay ? "relay" : "signal(fallback)"}`);
  mlog.debug(`MSG content: "${text.slice(0,40)}${text.length>40?"…":""}"  id=${id}`);
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
async function sendReaction(targetMsgId, emoji) {
  if (!state.currentChat) return;
  const contact = state.contacts[state.currentChat];
  if (!contact?.encKey) return;

  const id  = await deriveReactionId(state.publicId, targetMsgId);
  const ts  = Date.now();
  const me    = state.contacts[state.publicId];
  const relay = me?.lastRelay ? { wss: me.lastRelay } : undefined;
  const payload  = { id, type: "reaction", targetId: targetMsgId, emoji, ts, ...(relay ? { relay } : {}) };
  const blob     = await encryptMessage(contact.encKey, payload);
  const sig      = await signBlob(blob);

  const reactMsgObj = { type: "app:message", from: state.publicId, to: state.currentChat, blob, sig };
  const viaRelayReact = sendToRelay(state.currentChat, reactMsgObj, true);
  if (!viaRelayReact) sendSignal(reactMsgObj);
  const msgObj = { id, from: state.publicId, type: "reaction", targetId: targetMsgId, emoji, ts, valid: true };
  contact.messages = mergeMessages(contact.messages, [msgObj]);
  mlog.info(`→ REACTION     to   ${pid(state.currentChat)}  target=${pid(targetMsgId)}  emoji=${emoji || "nil"}  via=${viaRelayReact ? "relay" : "signal(fallback)"}`);
  await saveContacts();
  renderMessages();
}

// Build the reaction row rendered below a message bubble.
// Shows both sides' emojis + ↩ trigger if no own reaction yet.
function buildReactionRow(msgId, allMsgs, mine) {
  const reactions     = allMsgs.filter(m => m.type === "reaction" && m.targetId === msgId);
  const myReaction    = reactions.find(r => r.from === state.publicId);
  const theirReaction = reactions.find(r => r.from !== state.publicId);

  const row = document.createElement("div");
  row.className  = "reaction-row";
  // absolutely pinned to bottom-right inside the bubble
  row.style.cssText = "position:absolute;bottom:4px;right:6px;display:flex;align-items:center;gap:3px;";

  // Their emoji (read-only label)
  if (theirReaction?.emoji) {
    const span = document.createElement("span");
    span.className   = "reaction-emoji theirs-emoji";
    span.title       = "their reaction";
    span.textContent = theirReaction.emoji === ":)" ? "😊" : "😞";
    row.appendChild(span);
  }

  // My emoji (clickable to change/clear) or ↩ trigger — suppressed on own bubbles
  if (myReaction?.emoji) {
    const btn = document.createElement("button");
    btn.className   = "reaction-emoji mine-emoji";
    btn.title       = "click to change or clear";
    btn.textContent = myReaction.emoji === ":)" ? "😊" : "😞";
    btn.onclick = (e) => { e.stopPropagation(); showReactionPicker(btn, msgId, myReaction.emoji); };
    row.appendChild(btn);
  } else if (!mine) {
    const trigger = document.createElement("button");
    trigger.className   = "reaction-trigger-btn";
    trigger.title       = "react";
    trigger.textContent = "↩";
    trigger.onclick = (e) => { e.stopPropagation(); showReactionPicker(trigger, msgId, null); };
    row.appendChild(trigger);
  }

  return row;
}

// Small inline picker that opens next to the anchor element.
let _openPicker = null;

function showReactionPicker(anchor, msgId, current) {
  if (_openPicker) { _openPicker.remove(); _openPicker = null; }

  const picker = document.createElement("div");
  picker.className = "reaction-picker-popup";
  _openPicker = picker;

  const opts = [
    { label: "😊", value: ":)"  },
    { label: "😞", value: ":("  },
    { label: "✕",  value: null  },
  ];

  opts.forEach(({ label, value }) => {
    if (value === current) return;  // skip already-active choice
    const btn = document.createElement("button");
    btn.textContent = label;
    btn.title       = value === null ? "clear reaction" : value;
    btn.onclick = async (e) => {
      e.stopPropagation();
      picker.remove(); _openPicker = null;
      await sendReaction(msgId, value);
    };
    picker.appendChild(btn);
  });

  anchor.parentNode.insertBefore(picker, anchor.nextSibling);

  // close picker on any outside click
  setTimeout(() => {
    document.addEventListener("click", function _close() {
      if (_openPicker) { _openPicker.remove(); _openPicker = null; }
      document.removeEventListener("click", _close);
    }, { once: true });
  }, 0);
}

/* ══════════════════════════════════════════
   CONTACTS
══════════════════════════════════════════ */
async function addContact(name,shareableKey,save=true){
  if(!name||!shareableKey)return false;
  let encKeyBytes,signPublicKey,relayWss=null;
  try{
    const parts=shareableKey.split(".");
    if(parts.length<2||parts.length>3)throw new Error();
    encKeyBytes=base64ToRaw(parts[0]);
    signPublicKey=base64ToRaw(parts[1]);
    if(encKeyBytes.length!==32||signPublicKey.length!==32)throw new Error();
    if(parts.length===3&&parts[2])relayWss=atob(parts[2]);
  }
  catch(e){return false;}
  const publicId=await derivePublicId(encKeyBytes);
  if(publicId===state.publicId||state.contacts[publicId])return!!state.contacts[publicId];
  state.contacts[publicId]={name,publicId,shareableKey,encKey:await importEncKey(encKeyBytes),signPublicKey,messages:[],
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

/* ══════════════════════════════════════════
   QR
══════════════════════════════════════════ */
let scanner = null, scannerRunning = false;

function buildMyQR(key) {
  const el = document.getElementById("myQrCode");
  el.innerHTML = "";
  if (!key) return;
  try { new QRCode(el, { text: key, width: 192, height: 192, colorDark: "#000", colorLight: "#fff" }); }
  catch(e) { el.textContent = "QR unavailable"; }
}

function switchTab(tab) {
  if (tab !== "scan" && scannerRunning) stopScanner();
  ["show","scan","paste"].forEach(t => {
    const T = t.charAt(0).toUpperCase() + t.slice(1);
    document.getElementById("tab"   + T)?.classList.toggle("active", t === tab);
    document.getElementById("panel" + T)?.classList.toggle("active", t === tab);
  });
}

async function toggleScanner() { scannerRunning ? stopScanner() : await startScanner(); }

async function startScanner() {
  const btn = document.getElementById("scanToggleBtn");
  btn.textContent = "STOP CAMERA";
  btn.classList.add("active");
  document.getElementById("scanResult").textContent = "";
  scanner = new Html5Qrcode("qrReader");
  try {
    await scanner.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: 200 },
      (decoded) => {
        document.getElementById("scanResult").textContent = "✓ key captured";
        document.getElementById("modalContactKey").value  = decoded.trim();
        stopScanner();
        switchTab("paste");
        document.getElementById("modalContactName").focus();
      },
      () => {}
    );
    scannerRunning = true;
  } catch(e) {
    btn.textContent = "START CAMERA";
    btn.classList.remove("active");
    document.getElementById("scanResult").textContent = "camera error: " + e.message;
    scannerRunning = false;
  }
}

function stopScanner() {
  if (!scanner || !scannerRunning) return;
  scanner.stop().then(() => {
    document.getElementById("qrReader").innerHTML = "";
    scannerRunning = false;
    const btn = document.getElementById("scanToggleBtn");
    btn.textContent = "START CAMERA";
    btn.classList.remove("active");
  }).catch(() => {});
}

/* ══════════════════════════════════════════
   UI
══════════════════════════════════════════ */
function setConnected(on) {
  document.getElementById("connDot").className       = on ? "connected" : "";
  document.getElementById("connLabel").textContent   = on ? "connected · " + state.publicId.slice(0,8) + "…" : "disconnected";
  document.getElementById("sidebarMeta").textContent = on ? state.user + " · " + state.publicId.slice(0,8) + "…" : "not connected";
}


let showBlocked = false;

function toggleShowBlocked() {
  showBlocked = !showBlocked;
  renderContactList();
}

function renderContactList() {
  const list  = document.getElementById("contactList");
  list.innerHTML = "";
  const all   = Object.values(state.contacts);
  const blockedCount = all.filter(c => c.blocked).length;

  const toggleWrap = document.getElementById("showBlockedToggle");
  const toggleBtn  = document.getElementById("showBlockedBtn");
  if (blockedCount > 0) {
    toggleWrap.style.display = "block";
    toggleBtn.textContent = showBlocked
      ? `HIDE BLOCKED (${blockedCount})`
      : `SHOW BLOCKED (${blockedCount})`;
  } else {
    toggleWrap.style.display = "none";
    showBlocked = false;
  }

  all.sort((a,b) => (a.blocked ? 1 : 0) - (b.blocked ? 1 : 0)).forEach(c => {
    if (c.blocked && !showBlocked) return;

    const isMe  = c.publicId === state.publicId;
    const li    = document.createElement("li");
    li.className = "contactItem"
      + (state.currentChat === c.publicId ? " active" : "")
      + (c.blocked ? " blocked" : "");
    li.dataset.id = c.publicId;
    li.onclick    = () => openChat(c.publicId);
    const unread  = state.unread[c.publicId] || 0;
    const msgs    = c.messages || [];
    const last    = msgs[msgs.length - 1];
    const preview = last
      ? last.type === "audio"
        ? "🎤 audio message"
        : last.type === "image"
        ? "🖼 image"
        : (last.text || "").slice(0, 28) + (last.text?.length > 28 ? "…" : "")
      : "";
    const hasBackup = !!state.peerBackups[c.publicId];
    li.innerHTML =
      '<div class="contactAvatar">' + esc(c.name[0].toUpperCase()) + '</div>' +
      '<div class="contactInfo">' +
        '<div class="contactName">' + esc(c.name) +
          (isMe ? ' <span style="font-size:9px;color:var(--muted);letter-spacing:0.08em">YOU</span>' : '') +
          (hasBackup ? ' <span title="backup stored" style="font-size:9px;color:var(--muted);letter-spacing:0.04em">🗄</span>' : '') +
        '</div>' +
        '<div class="contactId">' + c.publicId.slice(0,16) + '…</div>' +
        (preview ? '<div class="contactPreview">' + esc(preview) + '</div>' : '') +
      '</div>' +
      (unread > 0 ? '<div class="unreadBadge">' + unread + '</div>' : '') +
      '<div class="contactStatus" data-dot-id="' + c.publicId + '"></div>';
    list.appendChild(li);
  });
}

function updateContactPreview() { renderContactList(); }

function updateChatRelayInfo(id) {
  const el = document.getElementById("chatHeaderRelay");
  if (!el) return;
  const c = state.contacts[id];
  const parts = [c?.lastRelay].filter(Boolean);
  if (parts.length) {
    el.textContent   = parts.join(" · ");
    el.style.display = "block";
  } else {
    el.style.display = "none";
  }
}

function openChat(id) {
  state.currentChat = id;
  state.unread[id]  = 0;
  document.getElementById("appContainer").classList.add("chatOpen");
  const c      = state.contacts[id];
  const nameEl = document.getElementById("chatHeaderName");
  const idEl   = document.getElementById("chatHeaderId");
  document.getElementById("emptyChat").style.display = "none";
  nameEl.style.display = idEl.style.display = "block";
  nameEl.textContent = c.name;
  idEl.textContent   = c.publicId.slice(0,16) + "…";
  updateChatRelayInfo(id);
  const menuBtn = document.getElementById("contactMenuBtn");
  const isMe    = c.publicId === state.publicId;
  menuBtn.classList.add("visible");
  document.getElementById("syncBtn").style.display          = isMe ? "none" : "";
  document.getElementById("blockToggleBtn").style.display   = isMe ? "none" : "";
  document.querySelector("#contactDropdown .danger").style.display = isMe ? "none" : "";
  if (!isMe) document.getElementById("blockToggleBtn").textContent = c.blocked ? "UNBLOCK" : "BLOCK";
  // MIGRATE is self-only — inverse of sync/block/delete above. Injected
  // dynamically rather than added to the static markup, since it didn't
  // exist when the dropdown was originally built.
  let migrateBtn = document.getElementById("migrateBtn");
  if (isMe) {
    if (!migrateBtn) {
      migrateBtn = document.createElement("button");
      migrateBtn.id = "migrateBtn";
      migrateBtn.textContent = "MIGRATE";
      migrateBtn.onclick = () => contactAction("migrate");
      document.getElementById("contactDropdown").appendChild(migrateBtn);
    }
    migrateBtn.style.display = "";
  } else if (migrateBtn) {
    migrateBtn.style.display = "none";
  }
  document.getElementById("contactDropdown").classList.remove("open");
  renderContactList();
  renderMessages();
  document.getElementById("chatInput").focus();
}

function renderMessages() {
  const container = document.getElementById("chatMessages");
  container.innerHTML = "";
  if (!state.currentChat) return;
  // Defensive — storage should already be sorted (every mutation path goes
  // through mergeMessages), but render shouldn't be the thing that silently
  // breaks if some future code path appends without merging. Same ts/id
  // tiebreak as mergeMessages, so this is a no-op when storage is already
  // correct and never produces an order that conflicts with it.
  const msgs = [...(state.contacts[state.currentChat]?.messages || [])]
    .sort((x,y) => (x.ts - y.ts) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));

  // filter out reaction messages — they render as overlays on their target bubbles
  const visible = msgs.filter(m => m.type !== "reaction");

  if (!visible.length) {
    container.innerHTML = '<div style="color:var(--muted);font-size:12px;text-align:center;margin-top:40px;letter-spacing:0.1em">no messages yet</div>';
    return;
  }

  visible.forEach(m => {
    const mine = m.from === state.publicId;
    const wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:" + (mine ? "flex-end" : "flex-start");
    const bubble = document.createElement("div");
    bubble.className = "message " + (mine ? "mine" : "theirs") + (m.valid === false ? " invalid" : "");

    if (m.type === "audio") {
      if (m.expired || !audioCache[m.id]) {
        bubble.innerHTML = `<span style="color:var(--muted);font-size:12px">🎤 audio message (not available)</span>`;
      } else {
        // decrypt at render time — URL ready before user clicks play
        const audio = document.createElement("audio");
        audio.controls = true;
        audio.style.maxWidth = "200px";
        getAudioUrl(m.id).then(url => {
          if (url) {
            audio.src = url;
            audio.addEventListener("ended", () => {
              URL.revokeObjectURL(url);
              audio.removeAttribute("src");
            }, { once: true });
          } else {
            bubble.innerHTML = `<span style="color:var(--muted);font-size:12px">🎤 audio message (unavailable)</span>`;
          }
        });
        bubble.appendChild(audio);
      }
    } else if (m.type === "image") {
      if (!imageCache[m.id]) {
        bubble.innerHTML = `<span style="color:var(--muted);font-size:12px">🖼 image (not available)</span>`;
      } else {
        const img = document.createElement("img");
        img.style.cssText = "max-width:200px;display:block;border-radius:2px";
        img.alt = "image";
        (async () => {
          try {
            const plain = await decryptObject(state.encKey, imageCache[m.id].encBlob);
            const bytes = Uint8Array.from(atob(plain.data), c => c.charCodeAt(0));
            const blob  = new Blob([bytes], { type: plain.mimeType });
            img.src = URL.createObjectURL(blob);
          } catch(e) {
            bubble.innerHTML = `<span style="color:var(--muted);font-size:12px">🖼 image (unavailable)</span>`;
          }
        })();
        bubble.appendChild(img);
      }
    } else {
      bubble.innerHTML = linkify(m.text || "");
    }

    const meta   = document.createElement("div");
    meta.className   = "msgMeta";
    const d      = new Date(m.ts);
    meta.textContent = d.toLocaleDateString([], { month:"short", day:"numeric" }) + " "
                     + d.toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" })
                     + (m.valid === false ? " · ⚠ unverified" : "");

    bubble.appendChild(buildReactionRow(m.id, msgs, mine));
    wrap.appendChild(bubble);
    wrap.appendChild(meta);
    container.appendChild(wrap);
  });
  container.scrollTop = container.scrollHeight;
}

function openModal() {
  document.getElementById("myKeyDisplay").textContent = state.shareableKey;
  document.getElementById("modalContactName").value   = "";
  document.getElementById("modalContactKey").value    = "";
  document.getElementById("scanResult").textContent   = "";
  buildMyQR(state.shareableKey);
  switchTab("show");
  document.getElementById("modalOverlay").classList.add("open");
}
function closeModal() { if (scannerRunning) stopScanner(); document.getElementById("modalOverlay").classList.remove("open"); }

function openExportModal() {
  document.getElementById("exportPassphrase").value   = "";
  document.getElementById("exportStatus").textContent = "";
  document.getElementById("exportOverlay").classList.add("open");
  document.getElementById("exportPassphrase").focus();
}
function closeExportModal() { document.getElementById("exportOverlay").classList.remove("open"); }

/* ══════════════════════════════════════════
   CONTACT ACTIONS (edit / block / delete)
══════════════════════════════════════════ */
function contactAction(action) {
  document.getElementById("contactDropdown").classList.remove("open");
  const c = state.contacts[state.currentChat];
  if (!c) return;
  const title = document.getElementById("contactActionTitle");
  const body  = document.getElementById("contactActionBody");
  const btns  = document.getElementById("contactActionBtns");
  body.innerHTML = btns.innerHTML = "";

  if(action==="edit"){
    title.textContent="EDIT CONTACT";
    const isMe = c.publicId === state.publicId;

    // info display
    const info = document.createElement("div");
    info.style.cssText = "font-size:10px;color:var(--muted);line-height:1.9;word-break:break-all;border:1px solid var(--border);padding:10px 12px;background:var(--bg)";
    info.innerHTML =
      `<strong style="color:var(--dim)">id</strong> ${esc(c.publicId)}<br>` +
      `<strong style="color:var(--dim)">key</strong> ${esc(c.shareableKey)}<br>` +
      `<strong style="color:var(--dim)">relay</strong> ${esc(c.lastRelay || "—")}<br>` +
      `<strong style="color:var(--dim)">msgs</strong> ${c.messages?.length || 0}<br>` +
      `<strong style="color:var(--dim)">blocked</strong> ${c.blocked ? "yes" : "no"}`;
    body.appendChild(info);

    // Wrapping in a <form> helps Firefox honour autocomplete="off" outright.
    // Chrome largely ignores autocomplete="off" on login-heuristic fields by
    // design (since ~2014), so this alone won't stop it there — the readonly
    // trick below is what actually does the work for Chrome.
    const editForm = document.createElement("form");
    editForm.autocomplete = "off";
    editForm.style.cssText = "display:flex;flex-direction:column;gap:12px";
    editForm.onsubmit = (e) => e.preventDefault();
    body.appendChild(editForm);

    const nameInput = document.createElement("input");
    nameInput.value        = c.name;
    nameInput.placeholder  = "contact name";
    nameInput.name         = "mc-edit-name";
    nameInput.autocomplete = "off";
    editForm.appendChild(nameInput);

    // key field — not applicable to self. Changing your OWN key isn't a
    // contact edit, it's effectively a different identity (new encKey,
    // new derived publicId) — that's a re-login, not something this modal
    // should offer. Same reasoning as why sync/block/delete are hidden
    // for self elsewhere in this menu.
    let keyInput = null;
    if (!isMe) {
      keyInput = document.createElement("input");
      keyInput.placeholder  = "paste new key to update (optional)";
      keyInput.name         = "mc-edit-key";
      keyInput.autocomplete = "off";
      keyInput.spellcheck   = false;
      editForm.appendChild(keyInput);
    }

    // relay override — useful for contacts without wss in their key.
    // Chrome's credential-suggestion dropdown ignores autocomplete="off" on
    // fields it heuristically flags as login-related, but it never targets
    // readonly fields. Start readonly, drop it the instant the field is
    // focused (before any keystroke) — invisible to the user, but Chrome
    // never gets a chance to attach its autofill UI in the first place.
    // The randomized name suffix also means Chrome has never seen this
    // exact field before, so it has nothing to correlate against anyway.
    const relayInput = document.createElement("input");
    relayInput.type          = "url";
    relayInput.placeholder   = "relay wss override (optional)";
    relayInput.value         = "wss://";
    relayInput.name          = "mc-edit-relay-wss-" + Math.random().toString(36).slice(2, 8);
    relayInput.autocomplete  = "off";
    relayInput.spellcheck    = false;
    relayInput.autocapitalize = "off";
    relayInput.setAttribute("data-lpignore", "true");     // LastPass
    relayInput.setAttribute("data-1p-ignore", "true");    // 1Password
    relayInput.setAttribute("list", "relayDatalist");
    relayInput.readOnly = true;
    relayInput.addEventListener("focus", () => { relayInput.readOnly = false; }, { once: true });
    editForm.appendChild(relayInput);

    // datalist — unique WSS values collected from all contacts
    const datalist = document.createElement("datalist");
    datalist.id = "relayDatalist";
    const knownRelays = new Set();
    for (const contact of Object.values(state.contacts)) {
      if (contact.lastRelay && !knownRelays.has(contact.lastRelay)) {
        knownRelays.add(contact.lastRelay);
        const opt = document.createElement("option");
        opt.value = contact.lastRelay;
        datalist.appendChild(opt);
      }
    }
    body.appendChild(datalist);

    btns.innerHTML = '<button class="btn-cancel" onclick="closeContactAction()">CANCEL</button>' +
                     '<button class="btn-confirm" id="contactActionConfirm">SAVE</button>';
    document.getElementById("contactActionOverlay").classList.add("open");
    nameInput.focus();

    document.getElementById("contactActionConfirm").onclick = async () => {
      const val = nameInput.value.trim();
      if (!val) return;
      c.name = val;
      c.lastStateChange = Date.now();

      // relay override
      const relayVal  = relayInput.value.trim();
      const prevRelay = c.lastRelay;
      if (relayVal && relayVal !== c.lastRelay) {
        c.lastRelay = relayVal;
        mlog.info(`CONTACT    relay updated  ${pid(c.publicId)}  wss=${relayVal}`);
      } else if (!relayVal) {
        c.lastRelay = null;
      }
      const ownRelayChanged = c.publicId === state.publicId && c.lastRelay !== prevRelay;

      const newKey = keyInput ? keyInput.value.trim() : "";
      if (newKey) {
        try {
          const parts = newKey.split(".");
          if (parts.length < 2 || parts.length > 3) throw new Error("invalid key format");
          const encKeyBytes   = base64ToRaw(parts[0]);
          const signPublicKey = base64ToRaw(parts[1]);
          if (encKeyBytes.length !== 32 || signPublicKey.length !== 32) throw new Error("invalid key length");
          c.shareableKey  = newKey;
          c.encKey        = await importEncKey(encKeyBytes);
          c.signPublicKey = signPublicKey;
          if (parts.length === 3 && parts[2] && !relayVal) c.lastRelay = atob(parts[2]);
          mlog.info(`CONTACT    key updated  ${pid(c.publicId)}`);
        } catch(e) {
          mlog.warn("CONTACT    key update failed: " + e.message);
          return;
        }
      }

      await saveContacts();
      document.getElementById("chatHeaderName").textContent = val;
      updateChatRelayInfo(state.currentChat);
      renderContactList();
      closeContactAction();
      if (ownRelayChanged) rebootSignal();
    };
    nameInput.onkeydown = (e) => { if (e.key === "Enter") document.getElementById("contactActionConfirm").click(); };

  } else if (action === "block") {
    const blocking = !c.blocked;
    title.textContent = blocking ? "BLOCK CONTACT" : "UNBLOCK CONTACT";
    const hint = document.createElement("div");
    hint.className   = "hint";
    hint.textContent = blocking
      ? "You will stop receiving messages from this contact. You can unblock them at any time."
      : "You will start receiving messages from this contact again.";
    body.appendChild(hint);
    btns.innerHTML =
      '<button class="btn-cancel" onclick="closeContactAction()">CANCEL</button>' +
      '<button class="btn-confirm" id="contactActionConfirm">' + (blocking ? "BLOCK" : "UNBLOCK") + '</button>';
    document.getElementById("contactActionOverlay").classList.add("open");
    document.getElementById("contactActionConfirm").onclick = async () => {
      c.blocked = blocking; c.lastStateChange = Date.now();
      if (blocking) {
        // wipe local message history and any stored backup for this contact
        c.messages = [];
        if (state.peerBackups[c.publicId]) {
          delete state.peerBackups[c.publicId];
          savePeerBackups();
          mlog.info(`BLOCK      wiped backup  id=${pid(c.publicId)}`);
        }
        mlog.info(`BLOCK      wiped messages  id=${pid(c.publicId)}`);
      }
      await saveContacts();
      document.getElementById("blockToggleBtn").textContent = c.blocked ? "UNBLOCK" : "BLOCK";
      renderContactList(); closeContactAction();
    };

  } else if (action === "delete") {
    title.textContent = "DELETE CONTACT";
    const hint = document.createElement("div");
    hint.className = "hint";
    hint.innerHTML =
      "<strong style='color:var(--danger)'>Only delete if their key is permanently lost.</strong><br><br>" +
      "If they might still be reachable, use <em>Block</em> instead — " +
      "deleted contacts cannot be recovered without their key.";
    body.appendChild(hint);
    btns.innerHTML =
      '<button class="btn-cancel" onclick="closeContactAction()">CANCEL — KEEP</button>' +
      '<button class="btn-confirm" style="background:var(--danger);border-color:var(--danger)" id="contactActionConfirm">DELETE</button>';
    document.getElementById("contactActionOverlay").classList.add("open");
    document.getElementById("contactActionConfirm").onclick = async () => {
      delete state.contacts[state.currentChat];
      state.currentChat = null;
      document.getElementById("emptyChat").style.display      = "block";
      document.getElementById("chatHeaderName").style.display = "none";
      document.getElementById("chatHeaderId").style.display   = "none";
      document.getElementById("contactMenuBtn").classList.remove("visible");
      document.getElementById("chatMessages").innerHTML = "";
      await saveContacts(); renderContactList(); closeContactAction();
    };

  } else if (action === "migrate") {
    title.textContent = "MIGRATE RELAY";

    const hint = document.createElement("div");
    hint.className = "hint";
    hint.innerHTML =
      "Test a relay before migrating — only the <strong style='color:var(--text)'>most recently passed</strong> " +
      "test can be migrated to. On commit, all contacts and any other device of yours still at the old " +
      "relay are notified automatically.";
    body.appendChild(hint);

    const listWrap = document.createElement("div");
    listWrap.style.cssText = "display:flex;flex-direction:column;gap:8px;margin-top:4px";
    body.appendChild(listWrap);

    // Local to this modal's lifecycle — reset every time it opens. A pass
    // from a previous visit shouldn't silently authorize a migrate now;
    // the relay could be down by the time you come back.
    let lastTestedUrl = null;
    let testInFlight  = false;
    const rows = [];   // { getUrl, migrateBtn }

    function refreshMigrateButtons() {
      for (const row of rows) {
        const url = row.getUrl();
        row.migrateBtn.disabled = !(url && url === lastTestedUrl);
      }
    }

    function buildRow(fixedUrl, isManual) {
      const rowEl = document.createElement("div");
      rowEl.style.cssText = "display:flex;gap:6px;align-items:center";

      let getUrl;
      if (isManual) {
        const inputEl = document.createElement("input");
        inputEl.type            = "url";
        inputEl.value           = "wss://";
        inputEl.placeholder     = "manual relay wss://…";
        inputEl.name            = "mc-migrate-manual-" + Math.random().toString(36).slice(2, 8);
        inputEl.autocomplete    = "off";
        inputEl.spellcheck      = false;
        inputEl.autocapitalize  = "off";
        inputEl.setAttribute("data-lpignore", "true");
        inputEl.setAttribute("data-1p-ignore", "true");
        inputEl.readOnly = true;
        inputEl.addEventListener("focus", () => { inputEl.readOnly = false; }, { once: true });
        inputEl.style.flex = "1";
        inputEl.addEventListener("input", refreshMigrateButtons);
        rowEl.appendChild(inputEl);
        getUrl = () => inputEl.value.trim();
      } else {
        const labelEl = document.createElement("div");
        labelEl.textContent = fixedUrl;
        labelEl.style.cssText = "flex:1;font-size:11px;color:var(--dim);word-break:break-all";
        rowEl.appendChild(labelEl);
        getUrl = () => fixedUrl;
      }

      const statusEl = document.createElement("span");
      statusEl.textContent = "untested";
      statusEl.style.cssText = "font-size:9px;min-width:62px;text-align:center;color:var(--muted)";

      const testBtn = document.createElement("button");
      testBtn.className = "btn-alt";
      testBtn.textContent = "TEST";
      testBtn.style.cssText = "flex:0 0 auto;padding:6px 10px;font-size:10px";

      const migrateBtn = document.createElement("button");
      migrateBtn.className = "btn-confirm";
      migrateBtn.textContent = "MIGRATE";
      migrateBtn.style.cssText = "flex:0 0 auto;padding:6px 10px;font-size:10px";
      migrateBtn.disabled = true;

      testBtn.onclick = async () => {
        const url = getUrl();
        if (!url || url === "wss://") {
          statusEl.textContent = "enter a url";
          statusEl.style.color = "var(--danger)";
          return;
        }
        if (testInFlight) return;
        testInFlight = true;
        testBtn.disabled = true;
        // Starting ANY new test attempt immediately revokes whatever
        // passed before — trust is only "the one JUST tested," not "the
        // one that happened to pass at some earlier point." Without this,
        // retesting the same url and getting a failure this time wouldn't
        // actually disable its migrate button, since success was the only
        // thing ever writing to lastTestedUrl.
        lastTestedUrl = null;
        refreshMigrateButtons();
        statusEl.textContent = "testing…";
        statusEl.style.color = "var(--accent)";
        mlog.info(`MIGRATE    testing ${url}`);
        const result = await testRelayConnection(url);
        testInFlight = false;
        testBtn.disabled = false;
        if (result.ok) {
          lastTestedUrl = url;
          statusEl.textContent = "✓ passed";
          statusEl.style.color = "var(--online)";
          mlog.info(`MIGRATE    test passed  ${url}`);
        } else {
          statusEl.textContent = "✗ " + (result.reason || "failed");
          statusEl.style.color = "var(--danger)";
          mlog.warn(`MIGRATE    test failed  ${url}  reason=${result.reason}`);
        }
        refreshMigrateButtons();
      };

      migrateBtn.onclick = async () => {
        const url = getUrl();
        if (url !== lastTestedUrl) return;   // shouldn't be reachable — button would be disabled
        const me      = state.contacts[state.publicId];
        const oldRelay = me.lastRelay;
        const ts       = Date.now();
        me.prevRelay     = oldRelay;
        me.prevRelaySeen = ts;
        me.lastRelay     = url;
        // Deliberate migration is the most authoritative thing that can
        // happen to this field — give it a real timestamp now, the same
        // one going out on the wire to contacts/self. Leaving this
        // untouched would risk a stale lastRelaySeen (e.g. 0 from an
        // earlier fresh-bootstrap adoption) letting an old restore/backup
        // override something we just set on purpose.
        me.lastRelaySeen = ts;
        await saveContacts();
        mlog.info(`MIGRATE    committed  ${oldRelay || "(none)"} → ${url}`);
        rebootSignal();
        notifyMigration(url, ts, oldRelay);
        closeContactAction();
      };

      rowEl.appendChild(statusEl);
      rowEl.appendChild(testBtn);
      rowEl.appendChild(migrateBtn);
      rows.push({ getUrl, migrateBtn });
      return rowEl;
    }

    // Excludes our own current relay — migrating "to" where we already are
    // isn't a migration. Includes prevRelay (wherever we last migrated
    // FROM) even if no contact currently references it — once we've moved
    // away, nothing keeps that address in any contact's lastRelay, so
    // without this it could silently fall out of the known set entirely,
    // leaving no easy way back if the new relay turns out to be bad.
    const me           = state.contacts[state.publicId];
    const currentRelay = me?.lastRelay;
    const knownRelays  = new Set();
    for (const contact of Object.values(state.contacts)) {
      if (contact.lastRelay && contact.lastRelay !== currentRelay) knownRelays.add(contact.lastRelay);
    }
    if (me?.prevRelay && me.prevRelay !== currentRelay) knownRelays.add(me.prevRelay);
    for (const url of knownRelays) {
      listWrap.appendChild(buildRow(url, false));
    }
    listWrap.appendChild(buildRow(null, true));

    btns.innerHTML = '<button class="btn-cancel" onclick="closeContactAction()">CLOSE</button>';
    document.getElementById("contactActionOverlay").classList.add("open");
  }
}

function closeContactAction() {
  document.getElementById("contactActionOverlay").classList.remove("open");
}

/* ══════════════════════════════════════════
   LOGIN
══════════════════════════════════════════ */
document.getElementById("loginButton").onclick = async (e) => {
  e.preventDefault();
  const name   = document.getElementById("inputName").value.trim();
  const pass   = document.getElementById("inputPassphrase").value;
  const status = document.getElementById("loginStatus");
  if (!name || !pass) { status.textContent = "name and passphrase required"; return; }
  const btn = document.getElementById("loginButton");
  btn.disabled = true;
  status.textContent = "deriving keys…";
  try {
    const master = await deriveMasterSecret(name, pass);
    const keys   = await hkdfExpand(master);
	state.user=name;
	state.keys=keys;
	state.publicId=await derivePublicId(keys.encryptionKey);
	const signPublicKey=ed25519.getPublicKey(keys.signingKeySeed);
	state.shareableKey=rawToBase64(keys.encryptionKey)+"."+rawToBase64(signPublicKey);
	state.cryptoKey=await importEncKey(keys.backupKey);
	state.encKey=await importEncKey(keys.encryptionKey);
	// device identity — local-only, never backed up, never synced. Get-or-create
	// every boot: same device + same identity always yields the same id.
	state.deviceId = await getOrCreateDeviceId();
	mlog.info(`DEVICE     ${pid(state.deviceId)}`);
    await loadContacts();
	if(!state.contacts[state.publicId]){
	  const parts=state.shareableKey.split(".");
	  const encKeyBytes=base64ToRaw(parts[0]);
	  state.contacts[state.publicId]={name:state.user+" (me)",publicId:state.publicId,shareableKey:state.shareableKey,encKey:await importEncKey(encKeyBytes),signPublicKey,messages:[]};
	}else{
	  // patch existing me contact with fresh 2-part key (wss segment appended later via relay_info)
	  state.contacts[state.publicId].shareableKey=state.shareableKey;
	  state.contacts[state.publicId].signPublicKey=signPublicKey;
	}
    loadPeerBackups();
    loadPeerTokens();
    document.getElementById("loginScreen").style.display  = "none";
    document.getElementById("appContainer").style.display = "flex";
    mlog.info(`LOGIN      ${name}  ${pid(state.publicId)}`);
    renderContactList();
    connectSignal();
  } catch(e) { status.textContent = e.message || "error during login"; btn.disabled = false; }
};

/* ══════════════════════════════════════════
   EVENTS
══════════════════════════════════════════ */
document.getElementById("addContactBtn").onclick  = openModal;
document.getElementById("showBlockedBtn").onclick = toggleShowBlocked;
document.getElementById("modalCancel").onclick    = closeModal;
document.getElementById("exportBtn").onclick      = openExportModal;
document.getElementById("exportCancel").onclick   = closeExportModal;
document.getElementById("syncBtn").onclick        = () => { if (state.currentChat) initiateExchange(state.currentChat); };
document.getElementById("myKeyBox").onclick       = () => navigator.clipboard.writeText(state.shareableKey).catch(()=>{});
document.getElementById("contactMenuBtn").onclick = (e) => {
  e.stopPropagation();
  document.getElementById("contactDropdown").classList.toggle("open");
};
document.addEventListener("click", () => {
  document.getElementById("contactDropdown").classList.remove("open");
});
document.getElementById("modalOverlay").onclick  = (e) => { if (e.target === document.getElementById("modalOverlay"))  closeModal(); };
document.getElementById("exportOverlay").onclick = (e) => { if (e.target === document.getElementById("exportOverlay")) closeExportModal(); };

document.getElementById("modalConfirm").onclick = async () => {
  const name    = document.getElementById("modalContactName").value.trim();
  const key     = document.getElementById("modalContactKey").value.trim();
  if (!name || !key) return;
  const ok = await addContact(name, key);
  if (ok) closeModal();
};

document.getElementById("exportConfirm").onclick = async () => {
  const pass   = document.getElementById("exportPassphrase").value;
  const status = document.getElementById("exportStatus");
  if (!pass) { status.textContent = "passphrase required"; return; }
  try { status.textContent = "encrypting…"; await exportBackup(pass); status.textContent = "exported!"; setTimeout(closeExportModal, MODAL_CLOSE_DELAY_MS); }
  catch(e) { status.textContent = "export failed: " + e.message; }
};

document.getElementById("importConfirm").onclick = () => {
  const input = Object.assign(document.createElement("input"), { type: "file", accept: ".json" });
  input.onchange = async () => {
    const file   = input.files[0];
    const pass   = document.getElementById("exportPassphrase").value;
    const status = document.getElementById("exportStatus");
    if (!file) return;
    if (!pass) { status.textContent = "enter passphrase first"; return; }
    try { status.textContent = "decrypting…"; await importBackup(file, pass); status.textContent = "restored!"; setTimeout(closeExportModal, MODAL_CLOSE_DELAY_MS); }
    catch(e) { status.textContent = "restore failed — wrong passphrase or file?"; }
  };
  input.click();
};

document.getElementById("sendButton").onclick  = sendMessage;
document.getElementById("chatInput").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } };

// audio button — push to talk
const audioBtn = document.getElementById("audioBtn");
if (audioBtn) {
  audioBtn.addEventListener("mousedown",  startAudioRecord);
  audioBtn.addEventListener("mouseup",    stopAudioRecord);
  audioBtn.addEventListener("touchstart", e => { e.preventDefault(); startAudioRecord(); });
  audioBtn.addEventListener("touchend",   e => { e.preventDefault(); stopAudioRecord(); });
}

// image button
const imageBtn   = document.getElementById("imageBtn");
const imageInput = document.getElementById("imageInput");
if (imageBtn && imageInput) {
  imageBtn.addEventListener("click", () => { if (state.currentChat) imageInput.click(); });
  imageInput.addEventListener("change", () => {
    const file = imageInput.files[0];
    if (file) { sendImageMessage(file); imageInput.value = ""; }
  });
}

setRandomLoginNotice();