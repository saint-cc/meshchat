/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat-identity.js
   One identity, one tab (per browser profile).

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
═══════════════════════════════════════════════════════════════ */
const IDENTITY_LOCK_PREFIX    = "meshchat-identity-";
const IDENTITY_DISPLACED_FLAG = "meshchat_identity_displaced";   // sessionStorage: survives the reload, gone with the tab

const identityLock = { name: null, release: null };   // the lock THIS tab holds, if any

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
async function claimIdentityOrAsk() {
  if (await claimIdentity()) return true;
  const takeOver = confirm(
    "This identity is already open in another tab or window of this browser.\n\n" +
    "Take over here? The other one will stop."
  );
  return takeOver ? claimIdentity({ steal: true }) : false;
}

// We were displaced. Stop at once and reload to the login screen: a stale
// tab left running would keep its timers (backup sweep, held outbox, ...)
// and could overwrite the new owner's stored contacts. No alert() first —
// it blocks, and a background tab defers it, leaving the stale tab alive
// in the meantime. The reason is shown on the login screen after the reload.
function onIdentityStolen() {
  identityLock.name = identityLock.release = null;
  try { sessionStorage.setItem(IDENTITY_DISPLACED_FLAG, "1"); } catch(e) {}
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