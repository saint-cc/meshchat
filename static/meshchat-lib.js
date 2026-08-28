/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat-lib.js
   Pure helper functions only: no DOM access, no `state` access,
   no network. Everything here takes its inputs as parameters and
   returns a value (or mutates an object passed in, e.g.
   updateRelay/mergeContactMeta). Loads first — gui.js and
   meshchat.js both depend on it existing.

   Load order: meshchat-lib.js → meshchat-gui.js → meshchat.js → statemachine.js
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

// pid(id) — unchanged: 8-char display truncation of a publicId/contactId,
// used everywhere as before.
//
// pid(id, { deviceId, endpointId }) — same base, optionally annotated with
// whichever of the two sub-ids is in scope at the call site. Deliberately
// TWO different separators, not one, because deviceId and endpointId are
// intentionally unlinkable (see deriveDeviceEndpointId) and a log line
// should never make them look like the same kind of thing:
//   "::EPID"  — endpointId, 4 chars. Reuses ADDR_SEP ("::"), the same
//               separator the wire's compound "id::endpointId" address
//               already uses (see buildAddress/parseAddress) and the one
//               server.py's short_addr() already renders in relay logs —
//               so a client log line reads the same way the server-side
//               log for the same packet would.
//   " DVID"   — deviceId, 4 chars, space-separated. deviceId never rides
//               on `to`/routing the way endpointId does, so it gets no
//               wire-format-flavored separator — this is purely a local
//               display convenience, not something that means anything
//               to the relay.
// Both are truncated to 4 chars — display-only disambiguation ("which of
// my 2-3 sessions is this"), not a full id; never compare/match on this
// output, only pid()/the untruncated id itself for that.
function pid(id, opts) {
  let s = id ? String(id).slice(0, 8) : "?";
  if (opts?.endpointId) s += ADDR_SEP + String(opts.endpointId).slice(0, 4);
  if (opts?.deviceId)   s += " "      + String(opts.deviceId).slice(0, 4);
  return s;
}

/* ── COMPOUND ADDRESSING — "id::endpointId" ──
   Mirrors server.py's parse_address()/build_address() exactly. `to` may
   carry an optional device-routing suffix, the same way a house number
   carries an optional unit letter: "1534" routes to the building,
   "1534b" to one specific unit inside it. Replaces the old separate
   toEndpoint field entirely — one field to send/read instead of two, and
   a human glancing at a packet or log line sees the whole routing story
   in one string.

   `from` deliberately never uses this — it's not a routing instruction,
   it's "who sent this", and the relay derives the true sender from the
   authed socket regardless of what's written there. Only `to` ever
   carries a unit.

   ADDR_SEP is "::" — base64url (every id in this app's charset) never
   contains ':', so the split is unambiguous with no escaping needed. */
const ADDR_SEP = "::";

function buildAddress(id, endpointId) {
  return endpointId ? `${id}${ADDR_SEP}${endpointId}` : id;
}

// "id" or "id::endpointId" -> { id, endpoint }, endpoint: null when
// there's no unit. Deliberately permissive on malformed input (returns
// { id: null, endpoint: null } rather than throwing) — callers that
// compare .id against state.publicId simply get a non-match, the same
// safe failure mode as any other malformed field on an incoming packet.
function parseAddress(addr) {
  if (typeof addr !== "string" || !addr) return { id: null, endpoint: null };
  if (addr.includes(ADDR_SEP)) {
    const parts = addr.split(ADDR_SEP);
    if (parts.length !== 2 || !parts[0] || !parts[1]) return { id: null, endpoint: null };
    return { id: parts[0], endpoint: parts[1] };
  }
  return { id: addr, endpoint: null };
}

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
  // x25519Seed replaces the old raw AES "encryptionKey" — this is now a DH
  // private scalar, never handed to anyone. What goes in the shareable
  // address is x25519.getPublicKey(x25519Seed), a genuine public key, not
  // a secret. See deriveSharedAesKey() below for what actually produces
  // the AES key now (ECDH output, per-contact, not this seed directly).
  const x25519Seed=await derive("x25519");
  const backupKey=await derive("backup");
  const signingKeySeed=await derive("signing");  // raw bytes now, not imported as HMAC
  return{signingKeySeed,x25519Seed,backupKey};
}

// Single-key hash — used for DEVICE identity only (getOrCreateDeviceId），
// which derives a device id from a lone Ed25519 device pubkey with no
// paired X25519 key involved. NOT used for identity publicId anymore —
// see deriveIdentityPublicId() below, which binds two keys together and
// is what auth/contacts actually use.
async function derivePublicId(rawKey) {
  const hash = await crypto.subtle.digest("SHA-256", rawKey);
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

// Identity publicId — binds BOTH the X25519 and Ed25519 public keys into
// one hash. This is deliberate, not cosmetic: if publicId were derived
// from the X25519 key alone, someone could present a victim's real
// (public, no secret needed) x25519_pub alongside their OWN ed25519_pub,
// sign the server's auth challenge with their own Ed25519 private key,
// and the server would register their socket under the victim's
// publicId — they'd never be able to decrypt anything, but they could
// silently swallow everything routed to that identity. Hashing both
// keys together means the server can only derive one specific publicId
// from one specific (x25519, ed25519) pair, so there's no way to mix a
// stolen public key from one identity with a private key from another
// and land on someone else's publicId.
async function deriveIdentityPublicId(x25519PublicKey, ed25519PublicKey) {
  const combined = new Uint8Array(x25519PublicKey.length + ed25519PublicKey.length);
  combined.set(x25519PublicKey, 0);
  combined.set(ed25519PublicKey, x25519PublicKey.length);
  const hash = await crypto.subtle.digest("SHA-256", combined);
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

// Device routing ID — a SEPARATE derivation off the same device seed that
// produces deviceId, deliberately unlinkable from it. deviceId hashes a
// public Ed25519 key (something contacts see and use to build their device
// popover); endpointId is a raw HKDF output presented only to the relay,
// under its own info label. HKDF-SHA256 is a PRF, so knowing one output
// gives no leverage on the other without the seed itself — a relay
// operator who sees every endpointId that ever connects can't link any of
// them to a deviceId a contact might know, and a contact who only ever
// sees deviceId can't derive endpointId. That separation is what makes
// per-device relay routing ("bob::laptop") possible without handing the
// relay a durable identifier that doubles as a device fingerprint contacts
// would also recognise. Same seed as getOrCreateDeviceId — get-or-created
// together at login (see getOrCreateDeviceSeed in meshchat.js) since both
// need it at the same moment.
async function deriveDeviceEndpointId(deviceSeed) {
  const key  = await crypto.subtle.importKey("raw", deviceSeed, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("meshchat-v1:device-endpoint") },
    key, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

// Stable reaction message ID: same sender + same target always → same ID.
// This makes mergeMessages naturally replace rather than duplicate reactions.
//
// IMPORTANT: this ID is stable across DIFFERENT reaction states — the
// same (myPublicId, targetMsgId) pair produces the same id whether the
// stored payload is a real emoji, a cleared reaction (emoji: null typed
// by the user), or the RECEIVED auto-ack (emoji: null, sent automatically
// on decrypt+verify — see protocol.md's Delivery Acknowledgement section
// and agent.py's send_ack). That's deliberate — it's what lets an emoji
// change/clear naturally replace the old value on merge instead of
// duplicating it. But it also means a "collision" on this id is a normal,
// expected event representing one of several genuinely different
// contents over time, NOT an error condition or a sign of an actual
// duplicate — see mergeMessages()'s dedup comment for why that matters
// for how collisions must be resolved.
async function deriveReactionId(myPublicId, targetMsgId) {
  const enc  = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode("reaction:" + myPublicId + ":" + targetMsgId));
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 12))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function rawToBase64(raw) { return btoa(String.fromCharCode(...raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function base64ToRaw(b64) { return Uint8Array.from(atob(b64.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }

// Plain byte-array -> hex string. Display-only helper (currently used by
// the packet inspector to render `sig` as a compact string instead of one
// JSON.stringify(..., null, 2) line per byte); doesn't touch any stored
// data, purely a rendering convenience.
function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

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

// THE fix — replaces "AES key handed out in the QR code" with a real
// X25519 static-static ECDH: two identities each combine their OWN
// private scalar with the OTHER's public key and land on the same
// shared secret, which nobody who only has one side's public key can
// compute. HKDF over the raw ECDH output (never used directly as key
// material) yields the actual AES-256-GCM key.
//
// Self-case (talking to your own identity, e.g. multi-device sync) is
// not special-cased: X25519(myPriv, myPub) is a well-defined DH
// operation and every device holding the same identity seed derives the
// identical result, so state.encKey is produced by this same function.
//
// Static-static means this same key is reused for every message between
// this pair, forever (barring a passphrase change) — this fixes the
// pairwise-separation bug (every contact no longer shares one AES key),
// it does NOT add forward secrecy. That's a separate, later piece of
// work (Double Ratchet), not something this function claims to solve.
async function deriveSharedAesKey(myX25519Seed, theirX25519PublicKey) {
  const shared = x25519.getSharedSecret(myX25519Seed, theirX25519PublicKey);
  const hkdfKey = await crypto.subtle.importKey("raw", shared, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("meshchat-v1:pairwise") },
    hkdfKey, 256
  );
  return importEncKey(new Uint8Array(bits));
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

// selectRetainedMessages(messages, n) — chooses which messages survive
// local persistence (serialiseContacts' retention cap / getLast's sync
// window), keyed on actual recency (ts, id) rather than array position.
//
// Before causal splicing existed, contact.messages was always kept in
// strict (ts, id) order, so "last n array elements" and "n most recent
// messages" were the same statement — a plain slice(-n) was correct.
// mergeMessages' ack-pointer splice (see its own comment) can now move a
// message far from its timestamp-sorted position — a message can sit
// well before messages that are chronologically newer than it, if it's
// someone's causal parent. A positional slice(-n) after that splice can
// therefore silently keep old messages and drop newer ones, or split a
// message from the parent its ackDeviceId/ackN points at — which then
// silently reverts to timestamp ordering on the next merge (see
// mergeMessages: an ack pointer that resolves to nothing in the merged
// set just gets no edge), with no way to ever recover the missing parent
// since there's no wire-level backfill (see Roadmap.md).
//
// Fix: select the n most recent messages by (ts, id) — never by position
// — then do one pass rescuing each kept message's direct ack-target if it
// exists elsewhere in the full set, so a still-known parent doesn't get
// severed purely for falling just outside the recency window. NOT a full
// transitive closure — a rescued parent's own parent is not chased. Ack
// chains here are shallow in practice (each message points at whichever
// single device/n was freshest when it was composed, not a long
// lineage), and anything unresolvable after one hop already degrades
// gracefully via mergeMessages' existing fallback.
//
// Finally, filter the ORIGINAL array down to the surviving ids — this
// preserves whatever causal order mergeMessages already established
// among the kept messages, rather than re-deriving it here.
function selectRetainedMessages(messages, n) {
  if (!Array.isArray(messages) || messages.length <= n) return messages || [];

  const byId = new Map(messages.map(m => [m.id, m]));
  const byDeviceN = new Map();
  for (const m of messages) {
    if (m.deviceId && m.n != null) byDeviceN.set(`${m.deviceId}:${m.n}`, m.id);
  }

  const byRecency = [...messages].sort((a, b) =>
    (b.ts - a.ts) || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
  const keep = new Set(byRecency.slice(0, n).map(m => m.id));

  for (const id of Array.from(keep)) {
    const m = byId.get(id);
    if (!m?.ackDeviceId || m.ackN == null) continue;
    const parentId = byDeviceN.get(`${m.ackDeviceId}:${m.ackN}`);
    if (parentId && !keep.has(parentId)) keep.add(parentId);
  }

  return messages.filter(m => keep.has(m.id));
}

// mergeMessages(a, b) — last-write-wins merge by id, THEN a causal splice
// pass on top of the plain (ts, id) baseline order.
//
// ── byId dedup: recency-based, NOT positional ──
// A message id is not always immutable content. Ordinary text/audio/
// image/system messages ARE immutable once sent — a given id's content
// never changes, so which copy "wins" a same-id collision never matters
// for them. Reactions are the deliberate exception: deriveReactionId()
// produces the SAME id for every state a given (sender, target) pair
// ever takes — a real emoji, a manual clear, and the emoji:null
// RECEIVED auto-ack (see protocol.md's Delivery Acknowledgement section)
// all collide on one id by design, so that an emoji change/clear
// naturally replaces rather than duplicates on merge.
//
// The bug this fixes: byId used to be populated by plain array-order
// last-write-wins —
//   for (const m of [...a, ...b]) if (m.id) byId[m.id] = m;
// — "last" meaning last in iteration order, not last in real time. For
// immutable-content ids that's a distinction without a difference. For a
// reaction id it isn't: the auto-ack fires the instant a message
// decrypts+verifies, independent of whatever reaction the user has or
// hasn't picked yet, and can reach a given contact.messages array via a
// different path and a different merge call than the user's actual emoji
// pick (a delayed live delivery, a peer/self backup push, a manual sync
// exchange). If a stale emoji:null object ever ends up LATER in the
// concatenated [...a, ...b] than a genuinely newer emoji pick — entirely
// possible once backups/restores/multi-device are in the mix — the old
// positional rule let it silently overwrite the real reaction with
// nothing. No error, no log line: the reaction just disappears on the
// next render.
//
// Fix: resolve same-id collisions by ts, not position — whichever copy
// actually happened more recently in real time wins, regardless of which
// side of the merge it arrived from or what order the arrays happen to
// be concatenated in. Every reaction (auto-ack or real) stamps a fresh
// Date.now() at send time, so this correctly resolves ack-then-react to
// the emoji, react-then-clear to null, and a stale buffered/backed-up ack
// can no longer regress a fresher local reaction. For immutable-content
// ids this is a no-op (same id always carries the same ts), so it's safe
// to apply unconditionally in this one shared dedup path rather than
// special-casing reactions out. Tiebreak on an exact ts match: the
// incoming (later-iterated) copy wins, same as the old behavior — two
// genuinely different actions landing on the identical millisecond is
// vanishingly unlikely in practice, and the two other unresolved
// dimensions here (mergeMessages has no cross-device vector clock, only
// per-contact ts) mean a perfect tiebreak isn't achievable anyway.
//
// Baseline sort is otherwise unchanged: ts alone isn't a reliable order
// for near-simultaneous messages, so id is added as a stable secondary
// sort key. That baseline is now ALSO the fallback for anything the
// causal pass below can't resolve, and the sibling order used among
// multiple messages that ack the same target — reordering is the
// exception here, not the norm (see Roadmap.md).
//
// Causal pass: a message stamped with ackDeviceId/ackN (see
// getAckPointer, meshchat.js) is understood as "sent after seeing that
// specific (device, n) message" — if that target is present in this
// merged set, splice the message in directly after it, recursively, so
// a reply-to-a-reply nests correctly. Deliberately NOT a full causal/
// vector-clock reorder: multiple messages acking the SAME target keep
// their existing relative (ts, id) order rather than being further
// disambiguated against each other.
function mergeMessages(a, b) {
  const byId = {};
  for (const m of [...(a||[]),...(b||[])]) {
    if (!m.id) continue;
    const existing = byId[m.id];
    // recency wins, not position — see the function-level comment above
    // for why this matters specifically for reaction ids (deriveReactionId
    // deliberately collides across emoji states, including the RECEIVED
    // auto-ack). >= means the incoming copy wins an exact ts tie, matching
    // the old positional behavior for the (effectively never-occurring)
    // case of two genuinely different actions on the identical millisecond.
    if (!existing || (m.ts || 0) >= (existing.ts || 0)) byId[m.id] = m;
  }

  const baseline = Object.values(byId)
    .sort((x,y) => (x.ts - y.ts) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));

  // Index every (deviceId, n)-bearing message for O(1) ack-pointer
  // resolution instead of scanning the merged set per message. Anything
  // missing either field (reactions, pre-this-feature messages) simply
  // can't be pointed at — it can still be a CHILD via its own ack fields,
  // it just never becomes anyone's parent.
  const byDeviceN = new Map();
  for (const m of baseline) {
    if (m.deviceId && m.n != null) byDeviceN.set(`${m.deviceId}:${m.n}`, m.id);
  }

  // Resolve ack pointers into parent edges. A pointer that resolves to
  // nothing in THIS merged set (target not (yet) present — could still
  // arrive on a later merge) or to the message itself gets no edge and
  // simply stays at its baseline position.
  const parentOf = new Map();   // childId -> targetId
  for (const m of baseline) {
    if (!m.ackDeviceId || m.ackN == null) continue;
    const targetId = byDeviceN.get(`${m.ackDeviceId}:${m.ackN}`);
    if (targetId && targetId !== m.id) parentOf.set(m.id, targetId);
  }

  // Cycle guard. A real ack graph is always a forest — you can only ack a
  // message that already existed when yours was sent, so nothing should
  // ever point back at its own descendant. This is a pure function over
  // whatever's handed to it, though, and a malformed or replayed set
  // could otherwise send the depth-first emit below into infinite
  // recursion. Walk each parent chain looking for a revisit; break the
  // offending edge (demoting that one message back to its baseline slot)
  // rather than failing the whole merge.
  for (const childId of Array.from(parentOf.keys())) {
    const seen = new Set([childId]);
    let cur = parentOf.get(childId);
    while (cur != null) {
      if (seen.has(cur)) { parentOf.delete(childId); break; }
      seen.add(cur);
      cur = parentOf.get(cur);
    }
  }

  // Group children by target, walked in baseline order — this is what
  // keeps multiple replies to the SAME message in their existing
  // relative (ts, id) order among each other; only a child's position
  // relative to non-siblings changes, never sibling-vs-sibling order.
  const childrenOf = new Map();   // targetId -> [childId, ...] in baseline order
  for (const m of baseline) {
    const targetId = parentOf.get(m.id);
    if (targetId == null) continue;
    if (!childrenOf.has(targetId)) childrenOf.set(targetId, []);
    childrenOf.get(targetId).push(m.id);
  }

  // Emit depth-first: walk baseline order, and for every message that
  // ISN'T itself someone's child (a root), place it, then recursively
  // place its children in their own baseline order, then theirs, etc. A
  // message that IS someone's child is skipped at the top level — it
  // already went out when its parent was placed.
  const out    = [];
  const placed = new Set();
  function place(id) {
    if (placed.has(id)) return;
    placed.add(id);
    out.push(byId[id]);
    for (const childId of childrenOf.get(id) || []) place(childId);
  }
  for (const m of baseline) if (!parentOf.has(m.id)) place(m.id);
  // Belt-and-suspenders: every parent id is guaranteed present in
  // baseline and the graph is guaranteed acyclic after the guard above,
  // so this should be a no-op — but emitting anything somehow still
  // unplaced (in baseline order, at the end) beats silently dropping a
  // message if that invariant is ever wrong.
  for (const m of baseline) place(m.id);

  return out;
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
      // Percent-encode any literal double-quote before it goes into the
      // href attribute — the URL text is untrusted (comes straight from a
      // decrypted message), and a raw " here would close the attribute
      // early and let the rest of the string inject new attributes/markup.
      // %22 round-trips correctly for any genuine URL that happened to
      // contain one, same as any other reserved character.
      const safeHref  = url.replace(/"/g, "%22");
      const short_url = url.length > 50 ? url.slice(0, 47) + "..." : url;
      return `<a href="${safeHref}" target="_blank" rel="noopener noreferrer">${short_url}</a>`;
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