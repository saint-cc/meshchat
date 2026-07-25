/* ═════════════════════════════════════════════════════════════
   MESHCHAT — lib.js
   Pure helper functions only: no DOM access, no `state` access,
   no network. Everything here takes its inputs as parameters and
   returns a value (or mutates an object passed in, e.g.
   updateRelay/mergeContactMeta). Loads first — gui.js and
   meshchat.js both depend on it existing.

   Load order: lib.js → gui.js → meshchat.js → statemachine.js
═══════════════════════════════════════════════════════════════ */

/* ── passphrase entropy model (login screen strength meter) ── */
function calcEntropy(pass) {
  let charset = 0;

  if (/[a-z]/.test(pass)) charset += 26;
  if (/[A-Z]/.test(pass)) charset += 26;
  if (/[0-9]/.test(pass)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) charset += 32;

  if (charset === 0) return 0;

  return pass.length * Math.log2(charset);
}

function usernameEntropy(user) {
  if (!user) return 0;

  const common = [
    "admin","test","user","root","guest",
    "bob","alice","administrator"
  ];

  if (common.includes(user.toLowerCase())) {
    return 4; // extremely weak effective entropy
  }

  return Math.log2(5000); // rough generic namespace estimate
}

function estimateCrackTimeBits(bits, rate = 1e11) {
  const totalGuesses = Math.pow(2, bits);
  const seconds = totalGuesses / rate;

  const minute = 60;
  const hour = 3600;
  const day = 86400;
  const year = 31557600;

  let value, unit;

  if (seconds < minute) {
    value = seconds;
    unit = "seconds";
  } else if (seconds < hour) {
    value = seconds / minute;
    unit = "minutes";
  } else if (seconds < day) {
    value = seconds / hour;
    unit = "hours";
  } else if (seconds < year) {
    value = seconds / day;
    unit = "days";
  } else {
    value = seconds / year;
    unit = "years";
  }

  return { value, unit, seconds };
}

function linguisticPenalty(str) {
  if (!str) return 0;

  const s = str.toLowerCase();

  // common word / phrase indicators
  const commonPhrases = [
    "hello",
    "i am",
    "admin",
    "god",
    "this is",
    "very",
    "mellon",
    "password",
    "let me",
    "test",
    "qwerty",
    "please"
  ];

  let penalty = 0;

  for (const p of commonPhrases) {
    if (s.includes(p)) penalty += 8;
  }

  // repeated structure penalty
  const words = s.split(/\s+/);
  const unique = new Set(words);

  if (words.length > 0) {
    const repetitionRatio = 1 - (unique.size / words.length);
    penalty += repetitionRatio * 20;
  }

  return penalty;
}

/* ── ids / text / misc ── */

function pid(id) { return id ? String(id).slice(0, 8) : "?"; }

function lerp(a, b, t) { return a + (b - a) * t; }

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
    // type deliberately does NOT follow name/blocked's unconditional
    // overwrite. An older peer that never serialized this field would
    // send remote.type === undefined, and blindly adopting that on any
    // newer lastStateChange (e.g. triggered by an unrelated name change)
    // would silently downgrade a contact you deliberately marked "agent"
    // back to "human" — quietly hiding the shell button, not a cosmetic
    // regression the way a stale name would be. Only adopt an explicit
    // value; otherwise keep whatever's already local.
    if (remote.type) local.type = remote.type;
  }
  // Backups/restores carry lastRelay too — same timestamp-guarded adoption
  // as updateRelay() already does for relay info embedded in messages.
  // This is what lets a second device pick up a relay change made on a
  // first device, purely through normal backup/restore traffic — no
  // migrate packet involved, since nothing here is a deliberate migration.
  if (remote.lastRelay) updateRelay(local, remote.lastRelay, remote.lastRelaySeen);
}
function esc(str) { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function linkify(text) {
  return text.replace(/(https?:\/\/[^\s]+)/g, (url) => {
    try {
      new URL(url);
      const short_url = url.length > 50 ? url.slice(0, 47) + "..." : url;
      return `<a href="${url}" target="_blank" rel="noopener noreferrer">${short_url}</a>`;
    } catch { return url; }
  });
}

function relativeDate(ts) {
  const days = Math.floor((Date.now() - ts) / (24 * 60 * 60 * 1000));
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7)  return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return `${Math.floor(days / 30)}mo ago`;
}