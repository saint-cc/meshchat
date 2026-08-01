/* ═════════════════════════════════════════════════════════════
   MESHCHAT — meshchat-gui.js
   All DOM rendering, modals, event wiring, and the in-page log
   console. Depends on lib.js (pure helpers) but not on
   meshchat.js at *load* time — cross-file calls into meshchat.js
   (sendSignal, saveContacts, rebootSignal, transition, etc.) only
   happen inside event-handler closures, which run after every
   script on the page has finished loading, so the forward
   reference is safe.

   Load order: meshchat-lib.js → meshchat-gui.js → meshchat.js → statemachine.js
═══════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════
   LOGGING
   mlog.info()  → console + in-page
   mlog.debug() → console only
   mlog.warn()  → console.warn + in-page
   mlog.err()   → console.error + in-page
   In-page: circular buffer, max LOG_MAX_LINES.
   Console: hard-cleared every LOG_CLEAR_INTERVAL ms.
═══════════════════════════════════════════════════════════════ */

const LOG_MAX_LINES      = 20;
const LOG_CLEAR_INTERVAL = 5 * 60 * 1000;
const MODAL_CLOSE_DELAY_MS    	= 1_200;			// brief pause before closing export/import modal

const MAX_DOT_AGE   			= 300_000; 			// = PRUNE_INTERVAL_MS

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

// Called from meshchat.js's markOnline()/pruneOnline() — presence tracking
// lives in meshchat.js, but the fading-dot render state is gui.js's own.
function touchDot(id) { dotTimestamps[id] = Date.now(); }
function clearDot(id) { dotTimestamps[id] = null; }

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
function setSyncStatus(msg) { document.getElementById("syncStatus").textContent = msg; }

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

/* ── RTC/UI stubs — statemachine.js's onStateEnter already calls these
   unconditionally; real implementations are the NEXT step, not this one.
   Kept as visible no-ops so entering ringing/negotiating/failed doesn't
   throw before that work happens. ── */
let incomingCallContactId = null;

function showIncomingCallUI(id) {
  incomingCallContactId = id;
  const contact = state.contacts[id];
  document.getElementById("incomingCallName").textContent = (contact?.name || pid(id)) + " is calling…";
  document.getElementById("incomingCallBanner").classList.add("open");
  updateCallHeaderBtn(id);
}

function hideIncomingCallUI(id) {
  if (incomingCallContactId === id) {
    incomingCallContactId = null;
    document.getElementById("incomingCallBanner").classList.remove("open");
  }
  updateCallHeaderBtn(id);
}

// Reflects call.phase on the header button — only touches the DOM if the
// contact in question is the one currently open, same guard pattern as
// updateChatRelayInfo.
function updateCallHeaderBtn(id) {
  if (id !== state.currentChat) return;
  const btn = document.getElementById("callBtn");
  if (!btn) return;
  const isMe    = id === state.publicId;
  const isAgent = state.contacts[id]?.type === "agent";   // agent.py never implements call:* — nothing to show
  const phase  = state.contacts[id]?.call?.phase || "idle";
  const GLYPH  = { idle: "☎", calling: "☎…", ringing: "☎…", negotiating: "☎…", connected: "⏹", failed: "☎" };
  const TITLE  = { idle: "Call", calling: "Calling… (click to cancel)", ringing: "Incoming — use the popup",
                   negotiating: "Connecting… (click to cancel)", connected: "Hang up", failed: "Call failed (click to reset)" };
  btn.className   = "state-" + phase;
  btn.classList.toggle("visible", !isMe && !isAgent);
  btn.textContent = GLYPH[phase]  || "☎";
  btn.title       = TITLE[phase]  || "Call";
  btn.disabled    = phase === "ringing";   // answer/decline only via the popup, to avoid two conflicting controls
}

// Mirrors updateCallHeaderBtn now that the shell FSM exists (see
// statemachine.js) — visibility gate is unchanged from 0.3.5, but phase
// now drives the glyph/title/state-class the same way it does for calls.
function updateShellHeaderBtn(id) {
  if (id !== state.currentChat) return;
  const btn = document.getElementById("shellBtn");
  if (!btn) return;
  const isMe    = id === state.publicId;
  const isAgent = state.contacts[id]?.type === "agent";
  const phase   = state.contacts[id]?.shell?.phase || "idle";
  const GLYPH = { idle: "⌁", calling: "⌁…", ringing: "⌁…", negotiating: "⌁…", connected: "⏹", failed: "⌁" };
  const TITLE = { idle: "Shell", calling: "Requesting… (click to cancel)", ringing: "Incoming — use the popup",
                  negotiating: "Connecting… (click to cancel)", connected: "End session", failed: "Session failed (click to reset)" };
  btn.className   = "state-" + phase;
  btn.classList.toggle("visible", isAgent && !isMe);
  btn.textContent = GLYPH[phase] || "⌁";
  btn.title       = TITLE[phase] || "Shell";
  btn.disabled    = phase === "ringing";   // parity with callBtn — unreachable against agent.py today, see statemachine.js
}

document.getElementById("callBtn").onclick = () => {
  const id = state.currentChat;
  if (!id || id === state.publicId) return;
  const phase = state.contacts[id]?.call?.phase || "idle";
  if (phase === "idle")                              startCall(id);
  else if (phase === "calling" || phase === "negotiating") cancelCall(id);
  else if (phase === "connected")                    endCall(id);
  else if (phase === "failed")                       transition(id, { type: "reset" });
};

document.getElementById("answerCallBtn").onclick  = () => { if (incomingCallContactId) answerCall(incomingCallContactId); };
document.getElementById("declineCallBtn").onclick = () => { if (incomingCallContactId) cancelCall(incomingCallContactId); };

// Prep only — no shell:invite, no session FSM, no data channels yet.
// Visible now that agent contacts exist, so it needs to say SOMETHING
// rather than silently do nothing on click.
document.getElementById("shellBtn").onclick = () => {
  const id = state.currentChat;
  if (!id || id === state.publicId) return;
  const phase = state.contacts[id]?.shell?.phase || "idle";
  if (phase === "idle")                                     startShell(id);
  else if (phase === "calling" || phase === "negotiating")  cancelShell(id);
  else if (phase === "connected")                           endShell(id);
  else if (phase === "failed")                               transition(id, { type: "reset" }, "shell");
};

function showIncomingShellUI(id) {
  mlog.debug(`SHELL      showIncomingShellUI(${pid(id)}) — stub, unreachable against agent.py today`);
}

function hideIncomingShellUI(id) {
  mlog.debug(`SHELL      hideIncomingShellUI(${pid(id)}) — stub`);
}

/* ══════════════════════════════════════════
   SHELL TERMINAL — one xterm.js instance per contact, keyed the same
   way shellConns is. Kept separate from shellConns because a terminal
   can legitimately outlive a brief data-channel hiccup (not currently
   exploited, but no reason to couple their lifecycles tighter than
   necessary).
 
   Bytes can start arriving the instant the agent's data channel opens
   and its pty spawns — which the connected-phase log showed happening
   right after (not before) openShellTerminal() is invoked, but nothing
   guarantees that ordering. term.write() called before term.open() is
   safe — xterm.js buffers writes internally until a renderer exists —
   so no separate pending-bytes queue is needed here.
══════════════════════════════════════════ */
const shellTerminals = {};   // contactId → { term, fitAddon }
let currentShellContactId = null;
 
function ensureShellTerminal(id) {
  if (shellTerminals[id]) return shellTerminals[id];
  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: "monospace",
    theme: { background: "#0a0a0a", foreground: "#c8c8c8" },
  });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
 
  // keystrokes → data channel. Guarded on readyState so typing into a
  // stale/closed session (e.g. right as it's tearing down) doesn't throw.
  term.onData((data) => {
    const conn = shellConns[id];
    if (conn?.dataCh?.readyState === "open") conn.dataCh.send(data);
  });
 
  const entry = { term, fitAddon };
  shellTerminals[id] = entry;
  return entry;
}
 
function fitAndSendResize(id) {
  const entry = shellTerminals[id];
  if (!entry) return;
  entry.fitAddon.fit();
  sendShellResize(id, entry.term.cols, entry.term.rows);
}
 
// real implementation — replaces the old stub. Called by
// onShellStateEnter() on entering "connected" (statemachine.js, unchanged).
function openShellTerminal(id) {
  const { term } = ensureShellTerminal(id);
  const contact = state.contacts[id];
  document.getElementById("shellTerminalName").textContent = (contact?.name || pid(id)) + " — shell";
  document.getElementById("shellTerminalPanel").classList.add("open");
 
  const container = document.getElementById("shellTerminalContainer");
  if (!term.element) term.open(container);   // only attach once per Terminal instance
 
  currentShellContactId = id;
  // layout isn't settled until the panel's actually visible/painted —
  // same reason chat scroll positioning elsewhere waits a frame.
  requestAnimationFrame(() => { fitAndSendResize(id); term.focus(); });
}
 
function closeShellTerminalUI(id) {
  if (currentShellContactId !== id) return;
  document.getElementById("shellTerminalPanel").classList.remove("open");
  currentShellContactId = null;
}
 
// receive-side hook, called from wireShellDataChannel's onmessage
// (shell-rtc-step3.js, Drop-in C above) with a Uint8Array of raw pty
// output. Writing straight to term is safe pre-open — see comment above.
function onShellDataReceived(id, data) {
  const { term } = ensureShellTerminal(id);
  term.write(data);
}
 
// window resize — only meaningful while a shell panel is actually open;
// the guard avoids fitting/resizing a terminal nobody's looking at.
window.addEventListener("resize", () => {
  if (currentShellContactId) fitAndSendResize(currentShellContactId);
});
 
document.getElementById("shellTerminalEndBtn").onclick = () => {
  if (currentShellContactId) endShell(currentShellContactId);
};

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

function toggleDevicePopover(id, li) {
  const pop = li.querySelector('.devicePopover[data-pop="' + id + '"]');
  if (!pop) return;
  const isOpen = pop.classList.contains("open");
  document.querySelectorAll(".devicePopover.open").forEach(p => p.classList.remove("open"));
  if (isOpen) return;
  const devices = Object.entries(state.knownDevices[id] || {})
    .sort(([, a], [, b]) => b.lastSeen - a.lastSeen);   // most recent first
  pop.innerHTML = devices.length
    ? devices.map(([devId, info]) =>
        `<div class="devicePopoverRow">` +
          `<span>${esc(pid(devId))}</span>` +
          `<span class="devicePopoverDate">${relativeDate(info.lastSeen)}${info.lastN ? " · n:" + info.lastN : ""}</span>` +
        `</div>`
      ).join("")
    : '<div class="devicePopoverRow unknown">unknown</div>';
  pop.classList.add("open");
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
    const isAgent = c.type === "agent";
    const li    = document.createElement("li");
    li.className = "contactItem"
      + (state.currentChat === c.publicId ? " active" : "")
      + (c.blocked ? " blocked" : "")
      + (isAgent ? " agent-contact" : "");
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
          (isAgent ? ' <span class="agentBadge" title="agent contact — shell-capable">⌁ agent</span>' : '') +
          (hasBackup ? ' <span title="backup stored" style="font-size:9px;color:var(--muted);letter-spacing:0.04em">🗄</span>' : '') +
        '</div>' +
        '<div class="contactId">' + c.publicId.slice(0,16) + '…</div>' +
        (preview ? '<div class="contactPreview">' + esc(preview) + '</div>' : '') +
      '</div>' +
      (unread > 0 ? '<div class="unreadBadge">' + unread + '</div>' : '') +
      '<div class="contactStatus" data-dot-id="' + c.publicId + '"></div>' +
      '<button class="deviceInfoBtn" title="known devices" data-id="' + c.publicId + '">+</button>' +
      '<div class="devicePopover" data-pop="' + c.publicId + '"></div>';
    list.appendChild(li);
	li.querySelector(".deviceInfoBtn").onclick = (e) => { e.stopPropagation(); toggleDevicePopover(c.publicId, li); };
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
  updateCallHeaderBtn(id);
  updateShellHeaderBtn(id);
  const menuBtn = document.getElementById("contactMenuBtn");
  const isMe    = c.publicId === state.publicId;
  menuBtn.classList.add("visible");
  document.getElementById("syncBtn").style.display          = isMe ? "none" : "";
  document.getElementById("blockToggleBtn").style.display   = isMe ? "none" : "";
  document.querySelector("#contactDropdown .danger").style.display = isMe ? "none" : "";
  document.addEventListener("click", () => {
    document.querySelectorAll(".devicePopover.open").forEach(p => p.classList.remove("open"));
  });
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
  
  let burnBtn = document.getElementById("burnBtn");
  if (isMe) {
    if (!burnBtn) {
      burnBtn = document.createElement("button");
      burnBtn.id = "burnBtn";
      burnBtn.textContent = "BURN";
      burnBtn.style.color = "var(--danger)";
      burnBtn.onclick = () => contactAction("burn");
      document.getElementById("contactDropdown").appendChild(burnBtn);
    }
    burnBtn.style.display = "";
  } else if (burnBtn) {
    burnBtn.style.display = "none";
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

  // Agent contacts read more like a terminal session than a conversation —
  // command and response both flow left, top to bottom, instead of the
  // normal mine-right/theirs-left bubble split. Colour (mine/theirs class)
  // still distinguishes what you typed from what came back; only the
  // positioning changes. Reactions don't mean anything on command output,
  // so they're skipped entirely for these chats rather than left dangling.
  const isAgentChat = state.contacts[state.currentChat]?.type === "agent";

  visible.forEach(m => {
    const mine = m.from === state.publicId;
    const wrap = document.createElement("div");
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:" + (isAgentChat ? "flex-start" : (mine ? "flex-end" : "flex-start"));
    const bubble = document.createElement("div");
    bubble.className = "message " + (mine ? "mine" : "theirs") + (m.valid === false ? " invalid" : "") + (isAgentChat ? " no-reaction-pad" : "");

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
      // esc() first — m.text is untrusted (a decrypted message body from a
      // contact), and was previously handed straight to linkify() and then
      // innerHTML with no escaping at all. Any contact could send literal
      // markup (e.g. an <img onerror=...>) and have it execute in this
      // page — the same context holding state.contacts, sendMessage(),
      // addContact(), exportBackup(), etc. esc() neutralises &/</>, and
      // linkify's own URL regex still matches fine afterwards since a URL
      // never legitimately contains a literal < or > to begin with.
      bubble.innerHTML = linkify(esc(m.text || ""));
    }

    const meta   = document.createElement("div");
    meta.className   = "msgMeta";

    const infoBtn = document.createElement("button");
    infoBtn.className   = "packetInfoBtn";
    infoBtn.title       = "show raw packet";
    infoBtn.textContent = "ⓘ";
    infoBtn.onclick = (e) => { e.stopPropagation(); togglePacketInfo(m.id, wrap); };
    meta.appendChild(infoBtn);

    const metaText = document.createElement("span");
    const d      = new Date(m.ts);
    metaText.textContent = d.toLocaleDateString([], { month:"short", day:"numeric" }) + " "
                     + d.toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" })
                     + (m.valid === false ? " · ⚠ unverified" : "");
    meta.appendChild(metaText);

    const infoPre = document.createElement("pre");
    infoPre.className = "packetInfoPre";
    infoPre.style.display = "none";

    if (!isAgentChat) bubble.appendChild(buildReactionRow(m.id, msgs, mine));
    wrap.appendChild(bubble);
    wrap.appendChild(meta);
    wrap.appendChild(infoPre);
    container.appendChild(wrap);
  });
  container.scrollTop = container.scrollHeight;
}

// Packet inspector (ⓘ) — shows the wire envelope with the decrypted
// payload spliced in where the ciphertext blob was, i.e. "everything
// except the blob". Pulls from packetCache (meshchat.js), populated at
// the same point each send/receive function already has both pieces in
// hand. A message from before this session (reload, or arrived via
// restore/backup/sync rather than a live send/receive) has no cache
// entry — shown as unavailable rather than guessed at.
function formatPacketInfo(msgId) {
  const cached = packetCache[msgId];
  if (!cached) return "packet info unavailable — not cached this session";
  const { envelope, payload } = cached;
  const display = { ...envelope };
  delete display.blob;
  if (Array.isArray(display.sig)) {
    display.sig = bytesToHex(display.sig);
  }
  const payloadDisplay = { ...payload };
  if (payloadDisplay.data) {
    payloadDisplay.data = `<${payloadDisplay.data.length} chars omitted>`;
  }
  display.payload = payloadDisplay;
  return JSON.stringify(display, null, 2);
}

function togglePacketInfo(msgId, wrap) {
  const pre = wrap.querySelector(".packetInfoPre");
  if (!pre) return;
  const opening = pre.style.display === "none";
  if (opening) pre.textContent = formatPacketInfo(msgId);
  pre.style.display = opening ? "block" : "none";
}

function openModal() {
  document.getElementById("myKeyDisplay").textContent = state.shareableKey;
  document.getElementById("modalContactName").value   = "";
  document.getElementById("modalContactKey").value    = "";
  document.getElementById("scanResult").textContent   = "";
  document.getElementById("modalContactIsAgent").checked = false;
  document.getElementById("agentToggleRow").style.display = "flex";
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

  if(action === "edit"){
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
      `<strong style="color:var(--dim)">blocked</strong> ${c.blocked ? "yes" + (c.blockReason ? ` (${esc(c.blockReason)})` : "") : "no"}`;
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

    // Agent toggle — mirrors the add-contact modal's agentToggleRow.
    // Not applicable to self, same reasoning as the key field above:
    // contact.type only ever decides which header button (call vs shell)
    // shows for THIS contact, and self gets neither.
    let agentCheckbox = null;
    if (!isMe) {
      const agentRow = document.createElement("div");
      agentRow.style.cssText = "display:flex;align-items:center;gap:8px;font-size:11px;color:var(--muted)";
      agentCheckbox = document.createElement("input");
      agentCheckbox.type = "checkbox";
      agentCheckbox.id = "editContactIsAgent";
      agentCheckbox.checked = c.type === "agent";
      const agentLabel = document.createElement("label");
      agentLabel.htmlFor = "editContactIsAgent";
      agentLabel.textContent = "this is an agent (enables shell access, not just chat)";
      agentRow.appendChild(agentCheckbox);
      agentRow.appendChild(agentLabel);
      editForm.appendChild(agentRow);
    }

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
      if (agentCheckbox) c.type = agentCheckbox.checked ? "agent" : "human";
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
          const x25519PublicKey = base64ToRaw(parts[0]);
          const signPublicKey   = base64ToRaw(parts[1]);
          if (x25519PublicKey.length !== 32 || signPublicKey.length !== 32) throw new Error("invalid key length");
          c.shareableKey    = newKey;
          c.encKey          = await deriveSharedAesKey(state.x25519Seed, x25519PublicKey);
          c.x25519PublicKey = x25519PublicKey;
          c.signPublicKey   = signPublicKey;
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
      // type may have just changed via agentCheckbox — call/shell button
      // visibility depends on it, same gate startShell()/the header render
      // already use elsewhere.
      updateCallHeaderBtn(state.currentChat);
      updateShellHeaderBtn(state.currentChat);
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
	  
	  if (migrationLocked) {
	    title.textContent = "MIGRATE RELAY";
	    const hint = document.createElement("div");
	    hint.className = "hint";
	    hint.textContent = "A migration was just committed and the old relay is still being checked for stragglers. Try again in a few seconds.";
	    body.appendChild(hint);
	    btns.innerHTML = '<button class="btn-cancel" onclick="closeContactAction()">CLOSE</button>';
	    document.getElementById("contactActionOverlay").classList.add("open");
	    return;
	  }
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

	  migrateBtn.onclick = () => {
	    const url = getUrl();
	    if (url !== lastTestedUrl) return;   // shouldn't be reachable — button would be disabled
	    showMigrateWarning(url);
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
  } else if (action === "burn") {
    buildBurnPanel();
  }
}

function closeContactAction() {
  document.getElementById("contactActionOverlay").classList.remove("open");
}

function showMigrateWarning(url) {
  const title = document.getElementById("contactActionTitle");
  const body  = document.getElementById("contactActionBody");
  const btns  = document.getElementById("contactActionBtns");
  body.innerHTML = btns.innerHTML = "";

  title.textContent = "CONFIRM MIGRATION";

  const warn = document.createElement("div");
  warn.className = "hint";
  warn.style.cssText = "color:var(--danger);line-height:1.6";
  warn.textContent =
    "This takes effect immediately and cannot be undone — every contact and " +
    "any other device of yours will be notified and will start routing to the " +
    "new relay right away. If it turns out to be unreachable or misbehaving, " +
    "messages sent to you in the meantime may not reach you until you migrate again.";
  body.appendChild(warn);

  const cancelBtn = document.createElement("button");
  cancelBtn.className   = "btn-cancel";
  cancelBtn.textContent = "WAIT, NO!";
  cancelBtn.onclick     = () => contactAction("migrate");   // rebuilds the panel fresh

  const confirmBtn = document.createElement("button");
  confirmBtn.className   = "btn-confirm";
  confirmBtn.style.cssText = "background:var(--danger);border-color:var(--danger)";
  confirmBtn.textContent = "I KNOW WHAT I AM DOING";
  confirmBtn.onclick     = () => commitMigration(url);

  btns.appendChild(cancelBtn);
  btns.appendChild(confirmBtn);
}

function buildBurnPanel() {
  const title = document.getElementById("contactActionTitle");
  const body  = document.getElementById("contactActionBody");
  const btns  = document.getElementById("contactActionBtns");
  body.innerHTML = btns.innerHTML = "";
 
  title.textContent = "BURN IDENTITY";
 
  const hint = document.createElement("div");
  hint.className = "hint";
  hint.style.cssText = "line-height:1.6";
  hint.innerHTML =
    "This notifies every contact and any other device of yours, then wipes " +
    "<strong style='color:var(--text)'>all local data on this device</strong> — contacts, messages, backups, device identity — " +
    "and returns you to the login screen.<br><br>" +
    "<strong style='color:var(--danger)'>This is not real revocation.</strong> " +
    "Your identity is derived from your username and passphrase — anyone who still knows them " +
    "(including you) can log back in and it will work exactly as before. Burn only wipes what's local here " +
    "and asks contacts to stop trusting it; it cannot force that anywhere else.";
  body.appendChild(hint);
 
  const confirmInput = document.createElement("input");
  confirmInput.placeholder  = 'type BURN to continue';
  confirmInput.name         = "mc-burn-confirm";
  confirmInput.autocomplete = "off";
  confirmInput.spellcheck   = false;
  body.appendChild(confirmInput);
 
  const proceedBtn = document.createElement("button");
  proceedBtn.className   = "btn-confirm";
  proceedBtn.style.cssText = "background:var(--danger);border-color:var(--danger)";
  proceedBtn.textContent = "CONTINUE";
  proceedBtn.disabled    = true;
 
  confirmInput.addEventListener("input", () => {
    proceedBtn.disabled = confirmInput.value.trim() !== "BURN";
  });
 
  const cancelBtn = document.createElement("button");
  cancelBtn.className   = "btn-cancel";
  cancelBtn.textContent = "CANCEL";
  cancelBtn.onclick     = closeContactAction;
 
  proceedBtn.onclick = () => showBurnWarning();
 
  btns.appendChild(cancelBtn);
  btns.appendChild(proceedBtn);
  document.getElementById("contactActionOverlay").classList.add("open");
  confirmInput.focus();
}
 
function showBurnWarning() {
  const title = document.getElementById("contactActionTitle");
  const body  = document.getElementById("contactActionBody");
  const btns  = document.getElementById("contactActionBtns");
  body.innerHTML = btns.innerHTML = "";
 
  title.textContent = "ARE YOU SURE?!";
 
  const warn = document.createElement("div");
  warn.className = "hint";
  warn.style.cssText = "color:var(--danger);line-height:1.6";
  warn.textContent =
    "Last chance to back out. Once you continue, contacts are notified immediately, " +
    "this device is wiped, and you are logged out. There is no undo.";
  body.appendChild(warn);
 
  const cancelBtn = document.createElement("button");
  cancelBtn.className   = "btn-cancel";
  cancelBtn.textContent = "WAIT, NO!";
  cancelBtn.onclick     = buildBurnPanel;   // back to the type-to-confirm step, fresh
 
  const confirmBtn = document.createElement("button");
  confirmBtn.className   = "btn-confirm";
  confirmBtn.style.cssText = "background:var(--danger);border-color:var(--danger)";
  confirmBtn.textContent = "BURN IT DOWN";
  confirmBtn.onclick     = () => { closeContactAction(); commitBurn(); };
 
  btns.appendChild(cancelBtn);
  btns.appendChild(confirmBtn);
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
	// X25519 identity keypair — keys.x25519Seed is the private scalar,
	// NEVER shared. Only x25519PublicKey goes in the shareable address.
	// This is the actual fix: the address used to carry a raw AES key
	// (a secret every contact shared identically); now it carries a
	// genuine public key, and each pairwise AES key is derived fresh via
	// ECDH (deriveSharedAesKey, lib.js) — see addContact/deserialiseContacts.
	state.x25519Seed=keys.x25519Seed;
	const x25519PublicKey=x25519.getPublicKey(keys.x25519Seed);
	const signPublicKey=ed25519.getPublicKey(keys.signingKeySeed);
	// publicId binds BOTH keys (deriveIdentityPublicId, lib.js) — see the
	// comment there for why hashing only the X25519 key would be exploitable.
	state.publicId=await deriveIdentityPublicId(x25519PublicKey,signPublicKey);
	state.shareableKey=rawToBase64(x25519PublicKey)+"."+rawToBase64(signPublicKey);
	state.cryptoKey=await importEncKey(keys.backupKey);
	// "our own" AES key, for self-targeted traffic (multi-device sync,
	// mini-backups, etc.) — ECDH against our own public key. Deterministic,
	// same result on every device that logs into this identity.
	state.encKey=await deriveSharedAesKey(keys.x25519Seed,x25519PublicKey);
	// device identity — local-only, never backed up, never synced. Get-or-create
	// every boot: same device + same identity always yields the same id.
	state.deviceId = await getOrCreateDeviceId();
	mlog.info(`DEVICE     ${pid(state.deviceId)}`);
	
    await loadContacts();
	if(!state.contacts[state.publicId]){
	  state.contacts[state.publicId]={name:state.user+" (me)",publicId:state.publicId,shareableKey:state.shareableKey,encKey:state.encKey,x25519PublicKey,signPublicKey,messages:[]};
	}else{
	  // patch existing me contact with fresh 2-part key (wss segment appended later via relay_info)
	  state.contacts[state.publicId].shareableKey=state.shareableKey;
	  state.contacts[state.publicId].signPublicKey=signPublicKey;
	  state.contacts[state.publicId].x25519PublicKey=x25519PublicKey;
	  state.contacts[state.publicId].encKey=state.encKey;
	}
    loadPeerBackups();
    loadPeerTokens();
	loadDeviceRegistry();
	loadSendCounters();
	recordKnownDevice(state.publicId, state.deviceId);
	
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
  const isAgent = document.getElementById("modalContactIsAgent").checked;
  if (!name || !key) return;
  const ok = await addContact(name, key, true, isAgent ? "agent" : "human");
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

document.getElementById("sendButton").onclick  = () => sendMessage();
document.getElementById("chatInput").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } };

// audio button — push to talk
const audioBtn = document.getElementById("audioBtn");
if (audioBtn) {
  audioBtn.addEventListener("mousedown",  () => startAudioRecord());
  audioBtn.addEventListener("mouseup",    () => stopAudioRecord());
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
document.getElementById("chatInput").addEventListener("paste", (e) => {
  if (!state.currentChat) return;
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {
    if (item.type.startsWith("image/")) {
      e.preventDefault();
      const file = item.getAsFile();
      if (file) sendImageMessage(file);
      return;
    }
  }
  // no image item found — fall through to normal text paste
});
setRandomLoginNotice();

/* ══════════════════════════════════════════
   LOGIN — passphrase entropy meter
   Moved out of index.html's inline <script> blocks. The pure
   calculation functions (calcEntropy, usernameEntropy,
   estimateCrackTimeBits, linguisticPenalty) live in lib.js;
   this is just the DOM wiring on top of them.
══════════════════════════════════════════ */
function togglePw(el) {
  document.getElementById("inputPassphrase").type =
    el.checked ? "text" : "password";
}

function updateEntr() {
  const user = document.getElementById('inputName').value;
  const pass = document.getElementById('inputPassphrase').value;

  let entropyPass = calcEntropy(pass);
  let entropyUser = usernameEntropy(user);

  let entropy = entropyPass + entropyUser;
  entropy -= linguisticPenalty(pass);
  entropy = Math.max(entropy, 0);

  // penalty if username appears inside password
  if (user && pass.toLowerCase().includes(user.toLowerCase())) {
    entropy *= 0.7;
  }

  const crack = estimateCrackTimeBits(entropy);

  let bar = document.getElementById('barEntr');
  let label = document.getElementById('labelEntr');

  let percent = Math.min(entropy / 120 * 100, 100);

  let color = "black";
  if (entropy < 20) color = "black";
  else if (entropy < 40) color = "red";
  else if (entropy < 60) color = "orange";
  else if (entropy < 80) color = "yellow";
  else color = "green";

  bar.style.width = percent + "%";
  bar.style.background = color;

  let crackText;

  if (crack.seconds > 1e17) {
    crackText = ">> heat death of universe";
  } else {
    crackText = `${crack.value.toExponential(2)} ${crack.unit}`;
  }

  label.textContent =
`entropy: ${entropy.toFixed(1)} bits
brute force: ${crackText}`;
}

document.getElementById('inputName').addEventListener('input', updateEntr);
document.getElementById('inputPassphrase').addEventListener('input', updateEntr);