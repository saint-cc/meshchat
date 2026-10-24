/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat-identity.js
   One identity, one tab (per browser profile) — plus the session edges:
   auto login and logout (sections further down).

   Two tabs of the same browser profile share localStorage, so they share
   the device seed, and therefore the same deviceId and endpointId — to
   contacts and the relay they ARE one device. But each tab keeps its own
   in-memory state (ephemerals for the backup/restore wrap, pending X4DH
   proposals, held outbox, ...) and both write to the same stored
   contacts / sessions / send counters, last writer wins. That is what
   produced "unwrap failed against 1 candidate(s)": a reply for tab A's
   ephemeral landing in tab B.

   Guard: a Web Lock named after the publicId, held for the life of the tab.
   - Scope is origin + storage partition, i.e. exactly the boundary that
     makes two tabs "the same device". Another browser, another profile or
     incognito has its own storage and device seed, so it correctly counts
     as a different device and is not blocked.
   - Released by the browser when the tab closes or crashes: no heartbeat,
     no stale state to time out.
   - Takeover: request({ steal: true }) makes the previous holder's request
     promise reject with AbortError, so the displaced tab finds out without
     any messaging, and stops at once (onIdentityStolen).

   Fails open: with no navigator.locks the check is skipped, login is never
   blocked on an unsupported browser.

   Load order: after meshchat.js (uses `state`/`mlog` only when called).
   Hooked into login in meshchat-gui.js: claimIdentityOrAsk(), right after
   state.publicId is derived and before anything touches storage.

   AUTO LOGIN / LOGOUT (sections further down) need two ids from index.html
   (#autoLoginChk, #logoutBtn) and two one-line hooks elsewhere:
     meshchat-gui.js, login handler:
       deriveMasterSecret(name, pass)  ->  deriveMasterSecretOrRemembered(name, pass)
     meshchat.js, first line of selfDestruct():
       forgetRemembered();
   Both are checked at boot (see rememberHooksPresent) — a missing one turns
   auto login OFF with a note instead of letting it misbehave.
═══════════════════════════════════════════════════════════════ */
const IDENTITY_LOCK_PREFIX    = "meshchat-identity-";
const IDENTITY_DISPLACED_FLAG = "meshchat_identity_displaced";   // sessionStorage: survives the reload, gone with the tab

const identityLock = { name: null, release: null };   // the lock THIS tab holds, if any

// Set for exactly one login attempt: the one auto login fired. Read (and
// consumed) by claimIdentityOrAsk — an auto login must never pop the
// "take over?" confirm(), see AUTO LOGIN below.
let identityLoginIsAuto = false;

// Resolves true if this tab now holds the identity lock (or locks are
// unsupported), false if another tab of this browser profile holds it.
function claimIdentity({ steal = false } = {}) {
  if (!navigator.locks?.request) return Promise.resolve(true);
  const name = IDENTITY_LOCK_PREFIX + state.publicId;
  if (identityLock.name === name) return Promise.resolve(true);   // already ours — a retried login after a failed attempt
  if (identityLock.name) releaseIdentity();                       // this tab moved on to a different identity
  return new Promise(resolve => {
    navigator.locks.request(name, steal ? { steal: true } : { ifAvailable: true }, lock => {
      if (!lock) { resolve(false); return; }   // ifAvailable and someone else has it
      // Hold until the tab dies or releaseIdentity() resolves this promise.
      return new Promise(release => {
        identityLock.name    = name;
        identityLock.release = release;
        resolve(true);
      });
    }).catch(e => {
      if (e?.name === "AbortError") onIdentityStolen();   // another tab stole it from us
      else { mlog.warn(`IDENTITY   lock request failed (${e?.message || e}) — continuing without the guard`); resolve(true); }
    });
  });
}

function releaseIdentity() {
  const release = identityLock.release;
  identityLock.name = identityLock.release = null;
  if (release) release();
}

// Login entry point: claim, or ask whether to take over from the other tab.
//
// An AUTO login (identityLoginIsAuto) never asks. Nobody is looking at the
// screen at that moment, and a take-over that happens without a human
// choosing it would turn two auto-login tabs into a steal ping-pong. It
// retries the lock once — a page reload can race the old page's lock
// release by a moment — and otherwise gives up; the caller shows
// "identity already open in another tab" and a manual ENTER asks as usual.
async function claimIdentityOrAsk() {
  const auto = identityLoginIsAuto;
  identityLoginIsAuto = false;

  let ok = await claimIdentity();
  if (!ok && auto) {
    await new Promise(r => setTimeout(r, 1000));
    ok = await claimIdentity();
  }
  if (ok) {
    // a login a human chose lifts the "no auto login for this tab" mark
    // (set by logout / displacement) — see AUTO LOGIN below
    if (!auto) clearAutoLoginSuppression();
    await persistRememberCandidate();   // "Auto login" ticked: remember this login — only now that the identity is ours
    return true;
  }
  if (auto) { rememberCandidate = null; return false; }

  const takeOver = confirm(
    "This identity is already open in another tab or window of this browser.\n\n" +
    "Take over here? The other one will stop."
  );
  if (!takeOver) { rememberCandidate = null; return false; }
  const stole = await claimIdentity({ steal: true });
  if (stole) { clearAutoLoginSuppression(); await persistRememberCandidate(); }
  else rememberCandidate = null;
  return stole;
}

// We were displaced. Stop at once and reload to the login screen: a stale
// tab left running would keep its timers (backup sweep, held outbox, ...)
// and could overwrite the new owner's stored contacts. No alert() first —
// it blocks, and a background tab defers it, leaving the stale tab alive
// in the meantime. The reason is shown on the login screen after the reload.
function onIdentityStolen() {
  identityLock.name = identityLock.release = null;
  try { sessionStorage.setItem(IDENTITY_DISPLACED_FLAG, "1"); } catch(e) {}
  suppressAutoLogin("displaced");   // else this tab would auto-login straight back and take the identity from the tab that just took it
  try { if (state.ws) { state.ws.onclose = null; state.ws.close(1000, "superseded"); } } catch(e) {}   // onclose would schedule a reconnect
  mlog.warn("IDENTITY   taken over by another tab — reloading");
  location.reload();
}

// After a displacement reload: tell the user why they are back at login.
try {
  if (sessionStorage.getItem(IDENTITY_DISPLACED_FLAG)) {
    sessionStorage.removeItem(IDENTITY_DISPLACED_FLAG);
    const el = document.getElementById("loginStatus");
    if (el) el.textContent = "this identity was opened in another tab — this tab was reset";
  }
} catch(e) {}

/* ═════════════════════════════════════════════════════════════
   AUTO LOGIN  ("remember me on this device")
   Zero taps: with the box ticked, a page load logs straight in. It does NOT
   use the browser's password autofill — that cannot work: Chrome keeps an
   autofilled password hidden from scripts until a user gesture, phones want
   a tap on the suggestion, and Safari has no silent credential API at all.

   WHAT IS STORED. Not the passphrase: the 32-byte PBKDF2 master secret
   (deriveMasterSecret's output) and the username, in IndexedDB
   ("meshchat-remember"), AES-GCM-encrypted under a NON-EXTRACTABLE WebCrypto
   key that sits beside it as a CryptoKey. Consequences, stated plainly:
     - the master secret IS the identity: whoever holds it can log in as you,
       forever (identities cannot be revoked — see known-limitations.md);
     - it is not your passphrase, so a leak does not expose a passphrase you
       reuse elsewhere, and login skips the 1,000,000-iteration derivation;
     - the non-extractable key stops a script (XSS) or a storage dump from
       copying the key bytes. It does NOT stop a script from asking the page
       to decrypt, and it is no protection against someone with real access
       to the browser profile — both key and ciphertext live in it.
   Normal login protects contacts/sessions at rest with a key derived from the
   passphrase; a remembered login drops that layer on this device.

   FLOW
     login, box ticked   claimIdentityOrAsk wins the lock -> persistRememberCandidate
     page load, record   startAutoLogin: name field + REMEMBERED_PASS, press ENTER
     logout, BURN,       forgetRemembered() deletes the record (logout() below;
     box unticked        selfDestruct() in meshchat.js; the checkbox handler)
   A stale record is not deleted on a failed login: one page load makes one
   attempt, so nothing can loop, and a transient storage error should not
   cost the user their remembered login.

   HOW THE LOGIN HANDLER GETS THE SECRET. meshchat-gui.js calls
   deriveMasterSecretOrRemembered(name, pass). With pass === REMEMBERED_PASS
   (contains a NUL — nobody can type it) it returns the stored master secret;
   otherwise it derives as always and keeps the result as rememberCandidate,
   persisted by claimIdentityOrAsk once the identity lock is won.

   TAB RULES, unchanged from before. Two events must stop the very next page
   load from logging straight back in, so they set a mark in sessionStorage
   (NO_AUTOLOGIN_FLAG — per tab, survives the reload, gone with the tab):
     - displacement (onIdentityStolen): otherwise two tabs with auto login
       would take the identity from each other forever;
     - logout: belt and braces — the record is gone too, but another tab's
       login could write a new one before this tab reloads.
   A manual login lifts the mark. An auto login never shows the take-over
   confirm() (see claimIdentityOrAsk).

   The localStorage flag AUTOLOGIN_KEY is the checkbox state (the user's
   intent); the IndexedDB record is the secret. Unticking deletes the record.

   Reasoned from the APIs, not yet observed on devices: storing a CryptoKey
   in IndexedDB on iOS Safari, and Safari clearing site storage after ~7 days
   without a visit unless the app is on the Home Screen (the remembered login
   then simply disappears and the login screen shows).
═════════════════════════════════════════════════════════════ */
const AUTOLOGIN_KEY     = "meshchat_autologin";       // localStorage: "1" = checkbox ticked
const NO_AUTOLOGIN_FLAG = "meshchat_no_autologin";    // sessionStorage: this tab must not auto-login ("logout" | "displaced")
const REMEMBER_DB       = "meshchat-remember";
const REMEMBER_STORE    = "kv";
const REMEMBER_KEY      = "remembered";
const REMEMBER_AAD      = "meshchat-remember-v1";
const REMEMBERED_PASS   = "\u0000remembered\u0000";

let pendingRemembered = null;   // { name, master } loaded for the login startAutoLogin is about to fire
let rememberCandidate = null;   // { name, master } from a typed login, persisted once the lock is won
let autoFireFlag      = false;  // set just before startAutoLogin clicks ENTER; consumed by the click listener below

function autoLoginEnabled() {
  try { return localStorage.getItem(AUTOLOGIN_KEY) === "1"; } catch(e) { return false; }
}
function setAutoLoginEnabled(on) {
  try { if (on) localStorage.setItem(AUTOLOGIN_KEY, "1"); else localStorage.removeItem(AUTOLOGIN_KEY); } catch(e) {}
}
function suppressAutoLogin(why) {
  try { sessionStorage.setItem(NO_AUTOLOGIN_FLAG, why || "1"); } catch(e) {}
}
function clearAutoLoginSuppression() {
  try { sessionStorage.removeItem(NO_AUTOLOGIN_FLAG); } catch(e) {}
}
function autoLoginSuppressed() {
  try { return !!sessionStorage.getItem(NO_AUTOLOGIN_FLAG); } catch(e) { return false; }
}

/* ── IndexedDB plumbing: one tiny store, one record ── */
function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(REMEMBER_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(REMEMBER_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error || new Error("indexedDB open failed"));
    req.onblocked = () => reject(new Error("indexedDB open blocked"));
  });
}
async function idbDo(mode, fn) {
  const db = await idbOpen();
  try {
    return await new Promise((resolve, reject) => {
      const tx  = db.transaction(REMEMBER_STORE, mode);
      const req = fn(tx.objectStore(REMEMBER_STORE));
      tx.oncomplete = () => resolve(req ? req.result : undefined);
      tx.onerror = tx.onabort = () => reject(tx.error || new Error("indexedDB transaction failed"));
    });
  } finally { try { db.close(); } catch(e) {} }
}

// The name rides as AES-GCM additional data, so a record whose name was
// swapped for another one fails to decrypt instead of logging in under it.
const rememberAad = (name) => new TextEncoder().encode(REMEMBER_AAD + "\0" + name);

async function rememberStore(name, master) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);   // extractable: false — the point
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: rememberAad(name) }, key, master));
  await idbDo("readwrite", s => s.put({ v: 1, name, iv, ct, key, createdAt: Date.now() }, REMEMBER_KEY));
}

// -> { name, master: Uint8Array(32) } or null. Never throws: anything wrong with the record is "no record".
async function rememberLoad() {
  try {
    const rec = await idbDo("readonly", s => s.get(REMEMBER_KEY));
    if (!rec || rec.v !== 1 || typeof rec.name !== "string" || !rec.name || !rec.key) return null;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv, additionalData: rememberAad(rec.name) }, rec.key, rec.ct);
    if (pt.byteLength !== 32) return null;
    return { name: rec.name, master: new Uint8Array(pt) };
  } catch(e) { return null; }
}

// Called by logout(), selfDestruct() (meshchat.js — fire-and-forget there; it
// reloads after 300 ms, the delete takes a few) and the checkbox. Never throws.
async function forgetRemembered() {
  try { await idbDo("readwrite", s => s.delete(REMEMBER_KEY)); } catch(e) {}
}

async function persistRememberCandidate() {
  const c = rememberCandidate;
  rememberCandidate = null;
  if (!c || !autoLoginEnabled()) return;
  try { await rememberStore(c.name, c.master); mlog.info("REMEMBER  login remembered on this device"); }
  catch(e) { mlog.warn(`REMEMBER  couldn't store the login: ${e.message}`); }   // login itself carries on
}

// The one function meshchat-gui.js's login handler calls instead of deriveMasterSecret.
async function deriveMasterSecretOrRemembered(name, pass) {
  if (pass === REMEMBERED_PASS) {
    const rec = pendingRemembered;
    pendingRemembered = null;
    rememberCandidate = null;   // nothing new to store — it is already there
    if (!rec || rec.name !== name) throw new Error("remembered login unavailable — log in with your passphrase");
    return rec.master;
  }
  const master = await deriveMasterSecret(name, pass);
  rememberCandidate = { name, master };
  return master;
}

// Both one-line hooks must be in place, or a remembered login would feed
// REMEMBERED_PASS to the real KDF — a perfectly valid login to a DIFFERENT,
// empty identity, with no error. Checked by looking at the handler's source.
function rememberHooksPresent() {
  try {
    const guiOk = String(document.getElementById("loginButton")?.onclick || "").includes("deriveMasterSecretOrRemembered");
    const burnOk = typeof selfDestruct !== "function" || String(selfDestruct).includes("forgetRemembered");
    if (!burnOk) mlog.warn("REMEMBER  selfDestruct() does not call forgetRemembered() — BURN would leave the remembered login behind");
    return guiOk && burnOk;
  } catch(e) { return false; }
}

/* ── the click that logs in ── */
(function wireLoginButtonForAuto() {
  const btn = document.getElementById("loginButton");
  if (!btn) return;
  // Registered after meshchat-gui.js's onclick, so it runs after that
  // handler's synchronous part — which ends at its first await, long before
  // claimIdentityOrAsk reads identityLoginIsAuto. Enter-key logins also reach
  // the button through .click(), so this flag — not event.isTrusted — is what
  // tells an auto login from a manual one.
  btn.addEventListener("click", () => {
    identityLoginIsAuto = autoFireFlag;
    autoFireFlag = false;
  });
})();

async function startAutoLogin() {
  const nameEl = document.getElementById("inputName");
  const passEl = document.getElementById("inputPassphrase");
  const btn    = document.getElementById("loginButton");
  const status = document.getElementById("loginStatus");
  if (!nameEl || !passEl || !btn) return;

  if (!autoLoginEnabled()) { await forgetRemembered(); return; }   // unticked elsewhere (another tab): drop any leftover secret
  if (autoLoginSuppressed()) return;

  const rec = await rememberLoad();
  if (!rec) return;
  // The user may have started typing while the record loaded — never overwrite that.
  if (nameEl.value.trim() || passEl.value) { mlog.debug("REMEMBER  fields already in use — not auto-logging in"); return; }
  if (btn.disabled) return;

  pendingRemembered = rec;
  nameEl.value = rec.name;
  passEl.value = REMEMBERED_PASS;
  if (status) status.textContent = "logging in…";
  autoFireFlag = true;
  btn.click();
}

// checkbox: reflects and writes the intent; unticking forgets the secret at once
async function wireAutoLoginCheckbox(usable, whyNot) {
  const chk  = document.getElementById("autoLoginChk");
  const hint = document.getElementById("autoLoginHint");
  if (!chk) return;
  if (!usable) {
    chk.checked = false;
    chk.disabled = true;
    if (hint) hint.textContent = "not available: " + whyNot;
    return;
  }
  chk.checked = autoLoginEnabled();
  chk.addEventListener("change", () => {
    setAutoLoginEnabled(chk.checked);
    if (!chk.checked) forgetRemembered();
  });
}

async function initAutoLogin() {
  let whyNot = null;
  if (typeof indexedDB === "undefined" || !crypto?.subtle) whyNot = "this browser has no IndexedDB / WebCrypto";
  else if (!rememberHooksPresent()) { whyNot = "update meshchat-gui.js / meshchat.js (see meshchat-identity.js)"; mlog.warn("REMEMBER  hook missing — auto login disabled"); }
  else {
    try { await idbDo("readonly", s => s.get(REMEMBER_KEY)); }   // private modes can have IndexedDB present but unusable
    catch(e) { whyNot = "this browser won't let MeshChat store it (private mode?)"; }
  }
  await wireAutoLoginCheckbox(!whyNot, whyNot);
  if (!whyNot) await startAutoLogin();
}

// after a logout reload: say so, unless something more specific already did
try {
  const why = sessionStorage.getItem(NO_AUTOLOGIN_FLAG);
  const el  = document.getElementById("loginStatus");
  if (why === "logout" && el && !el.textContent) el.textContent = "logged out";
} catch(e) {}

// Not at script-eval time: this file loads before statemachine.js, and the
// deferred <script type="module"> that provides window.ed25519 / x25519
// (needed by the login handler) only runs once parsing is done. The login
// handler would most likely cope, but "most likely" is not a load-order
// guarantee. DOMContentLoaded is.
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initAutoLogin, { once: true });
else initAutoLogin();

/* ═════════════════════════════════════════════════════════════
   LOGOUT
   A full page reload, the same way selfDestruct and onIdentityStolen end
   a session: this client keeps far too much in module-level state to reset
   in place (pending X4DH ephemerals, retired roots, the wire-key cache,
   media caches, a dozen timers), and a reload drops all of it at once.

   Unlike BURN this wipes nothing. Contacts, the device seed, X4DH sessions
   and held messages all stay in localStorage, encrypted as before — logging
   back in picks up exactly where this left off (held messages go out then).
   That is also why it needs no confirmation.

   Order:
     1. end or decline anything in flight — otherwise the peer rings until
        its own timeout;
     2. flush storage. saveContacts is already serialised; saveX4DHSessions
        is not awaited by every caller, so wait for it here;
     3. a short pause so what step 1 queued can leave the socket (same
        reasoning as commitBurn's);
     4. drop the socket WITHOUT onclose — it would schedule a reconnect;
     5. forget the remembered login (AUTO LOGIN), release the identity lock,
        mark this tab "no auto login", then reload.
═════════════════════════════════════════════════════════════ */
const LOGOUT_FLUSH_MS = 300;
let loggingOut = false;

// Same phase → action mapping as the header buttons in meshchat-gui.js
// (callBtn / dataBtn onclick) and the DECLINE buttons. "idle" has nothing to
// end; "failed" has nothing live either — the peer already gave up on it.
const LIVE_PHASES_CANCEL = new Set(["calling", "ringing", "negotiating"]);
function endActiveSessions() {
  for (const [id, c] of Object.entries(state.contacts || {})) {
    if (id === state.publicId) continue;
    try {
      const cp = c.call?.phase, dp = c.data?.phase;
      if (cp === "connected")                 endCall(id);
      else if (LIVE_PHASES_CANCEL.has(cp))    cancelCall(id);
      if (dp === "connected")                 endData(id);
      else if (LIVE_PHASES_CANCEL.has(dp))    cancelData(id);
    } catch(e) { mlog.warn(`LOGOUT     couldn't end session with ${pid(id)}: ${e.message}`); }
  }
}

async function logout() {
  if (loggingOut || !state.publicId) return;
  loggingOut = true;
  mlog.info("LOGOUT     ending sessions, flushing storage");
  const btn = document.getElementById("logoutBtn");
  if (btn) btn.disabled = true;

  try { endActiveSessions(); } catch(e) {}
  try { await saveContacts(); }        catch(e) { mlog.warn(`LOGOUT     saveContacts failed: ${e.message}`); }
  try { await saveX4DHSessions(); }    catch(e) { mlog.warn(`LOGOUT     saveX4DHSessions failed: ${e.message}`); }
  await new Promise(r => setTimeout(r, LOGOUT_FLUSH_MS));

  try { if (state.ws) { state.ws.onclose = null; state.ws.close(1000, "logout"); } } catch(e) {}
  await forgetRemembered();   // logout also means "forget this device" — see AUTO LOGIN
  releaseIdentity();
  suppressAutoLogin("logout");
  location.reload();
}

(function wireLogoutButton() {
  const btn = document.getElementById("logoutBtn");
  if (btn) btn.addEventListener("click", logout);
})();