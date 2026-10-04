/* ══════════════════════════════════════════
   SESSION STATE MACHINE — shared by voice calls and data sessions
   transition(id, event, kind) — pure logic, no side effects
   kind: "call" (default) | "data" — selects contact.call vs contact.data
   Valid phases: idle | calling | ringing | negotiating | connected | failed
   Valid roles:  caller | callee (set on entering calling/ringing, cleared on idle)

   Manual only — no passive/background check. A session only exists once
   the user has either initiated it (caller) or an invite has arrived
   (callee, possibly on several of the contact's devices at once).

   Multi-device dedup does NOT live in this file — it happens one level
   up, wherever incoming invite/claim packets are handled. By the time
   transition() sees "claimed", the dedup question ("was it us or one of
   our other devices that answered") has already been resolved by
   whoever calls transition() — this machine only tracks the state of
   the session THIS device is party to.

   ONE table, TWO kinds. The phase/role logic below is identical for a
   voice call and a data session — same "did the other side
   claim/accept," same "cancel before connect," same "fail after
   connect" shape — so it's written once. What differs between the two
   is entirely on the OTHER side of the fork: onStateEnter (call) vs.
   onDataStateEnter (data) below have no shared code, because their
   side effects are genuinely different (getUserMedia/addTrack vs.
   createDataChannel; an audio element vs. no media element at all).
   Sharing the table but forking the consequences means a fix
   to the tricky bits (stale-callId rejection, the multi-device races)
   only has to happen once.

   "ringing" for the data kind: an incoming data:invite puts the contact
   into "ringing" (handleDataInvite) and showIncomingDataUI raises an
   accept/decline banner. Nothing auto-claims: answering lets the caller
   learn this device's network address through ICE, so it takes an
   explicit user action — same as a voice call.
══════════════════════════════════════════ */

// Lets kind-appropriate event names normalize to the single internal
// vocabulary the switch below actually matches on, without touching any
// existing call call-site — they already pass the right-hand names below,
// so the alias lookup is simply a no-op for them. Data-session call-sites
// can use either form; "session_*" just reads less oddly than "call_*"
// when the session isn't a phone call.
const EVENT_ALIASES = {
  session_started:   "call_started",
  session_cancelled: "call_cancelled",
  session_ended:     "call_ended",
};

function transition(id, event, kind = "call") {
	const contact = state.contacts[id];
	if (!contact) return;
	const key  = kind === "data" ? "data" : "call";
	const conn = contact[key] ??= { phase: "idle", role: null };

	const oldPhase = conn.phase;
	const type     = EVENT_ALIASES[event.type] || event.type;

	switch (conn.phase) {

	  case "idle":
		if (type === "call_started")     // user initiated
		  { conn.phase = "calling"; conn.role = "caller"; }

		if (type === "invite_received")  // contact is initiating with us
		  { conn.phase = "ringing"; conn.role = "callee"; }
		break;

	  case "calling":
		if (type === "claim_received")   // one of their devices answered
		  conn.phase = "negotiating";

		if (type === "call_cancelled" || type === "no_answer" || type === "idle_timeout")
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "ringing":
		if (type === "claimed_here")     // user answered on THIS device
		  conn.phase = "negotiating";

		if (type === "claimed_elsewhere" || type === "call_cancelled")
		  // another of our devices answered, or the initiator gave up —
		  // either way, stop ringing here, silently
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "negotiating":
		if (type === "rtc_connected")
		  conn.phase = "connected";

		if (type === "rtc_failed" || type === "call_ended" || type === "call_cancelled" || type === "idle_timeout")
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "connected":
		if (type === "call_ended" || type === "rtc_closed" || type === "idle_timeout")
		  { conn.phase = "idle"; conn.role = null; }

		if (type === "rtc_failed")
		  conn.phase = "failed";
		break;

	  case "failed":
		if (type === "reset")
		  { conn.phase = "idle"; conn.role = null; }
		break;
	}

	if (conn.phase !== oldPhase) {
		mlog.info(`${kind.toUpperCase()}  ${pid(id)}  ${oldPhase} → ${conn.phase}${conn.role ? " ("+conn.role+")" : ""}`);
		if (kind === "data") onDataStateEnter(id, oldPhase, conn.phase, conn.role);
		else                  onStateEnter(id, oldPhase, conn.phase, conn.role);
	}
	return { from: oldPhase, to: conn.phase };
}


/* ══════════════════════════════════════════
   ON STATE ENTER — voice calls
   Side effects on phase entry. Called by transition(), never directly.
   role disambiguates "negotiating" — caller makes the offer once claimed,
   callee waits for it and answers.
══════════════════════════════════════════ */
function onStateEnter(id, oldPhase, newPhase, role) {
  switch (newPhase) {

    case "calling":
      sendCallInvite(id);
      sendCallNotice(id);
      break;

    case "ringing":
      showIncomingCallUI(id);
      break;

    case "negotiating":
      if (oldPhase === "ringing") hideIncomingCallUI(id);
      if (role === "caller") rtcOffer(id);
      // callee waits for the offer to arrive, then calls rtcAnswer(id)
      // itself from the signal handler — nothing to do on entry here
      break;

    case "connected":
      mlog.info(`CALL UP  ${pid(id)}`);
      hideIncomingCallUI(id);
      break;

    case "failed":
      mlog.warn(`CALL FAILED  ${pid(id)}`);
      rtcClose(id);
      break;

    case "idle":
      if (oldPhase === "ringing" || oldPhase === "calling")
        hideIncomingCallUI(id);
	  rtcClose(id);   // ← added — safe no-op if no pc exists for this contact
      break;
  }
  updateCallHeaderBtn(id);
}

/* ══════════════════════════════════════════
   ON STATE ENTER — data sessions
   Mirrors onStateEnter's structure exactly (same switch, same "here's
   what happens on entry into each phase" shape) but the hooks it calls
   are data-specific: a data channel instead of media tracks, no <audio>
   element. The hooks live in meshchat.js (sendDataInvite, dataRtcOffer,
   dataRtcClose, armDataTimer/clearDataTimer, reportDataResult) and
   meshchat-gui.js (showIncomingDataUI/hideIncomingDataUI,
   updateDataHeaderBtn).

   Timers live here, on phase entry, so every way into a phase arms the
   right one and every way out of it (idle/failed) clears it: "calling"
   and "ringing" get the ring timeout, "negotiating" gets the (shorter)
   connect-and-ping timeout, which deliberately keeps running through
   "connected" — the test isn't over until the pong is back. What a
   timeout actually does is onDataTimeout's job (meshchat.js).
══════════════════════════════════════════ */
function onDataStateEnter(id, oldPhase, newPhase, role) {
  switch (newPhase) {

    case "calling":
      sendDataInvite(id);
      armDataTimer(id, DATA_RING_TIMEOUT_MS);
      break;

    case "ringing":
      // needs an explicit user action — see the "ringing" paragraph at the top
      showIncomingDataUI(id);
      armDataTimer(id, DATA_RING_TIMEOUT_MS);
      break;

    case "negotiating":
      if (oldPhase === "ringing") hideIncomingDataUI(id);
      if (role === "caller") dataRtcOffer(id);
      // callee waits for the offer to arrive (handleDataOffer answers it)
      // — nothing to do on entry here, same as the call-side comment above
      armDataTimer(id, DATA_NEGOTIATE_TIMEOUT_MS);
      break;

    case "connected":
      mlog.info(`DATA UP  ${pid(id)}`);
      hideIncomingDataUI(id);
      break;

    case "failed":
      mlog.warn(`DATA FAILED  ${pid(id)}`);
      clearDataTimer(id);
      reportDataResult(id, false, `data channel with ${dataPeerName(id)} failed — the connection could not be established (firewall/NAT? there is no relay for data channels)`);
      dataRtcClose(id);
      break;

    case "idle":
      clearDataTimer(id);
      if (oldPhase === "ringing" || oldPhase === "calling")
        hideIncomingDataUI(id);
      dataRtcClose(id);   // safe no-op if no pc exists for this contact
      break;
  }
  updateDataHeaderBtn(id);
}