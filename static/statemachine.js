/* ══════════════════════════════════════════
   CALL STATE MACHINE
   transition(id, event) — pure logic, no side effects
   Valid phases: idle | calling | ringing | negotiating | connected | failed
   Valid roles:  caller | callee (set on entering calling/ringing, cleared on idle)

   Manual only — no passive/background check. A call only exists once
   the user has either clicked "call" (caller) or an invite has arrived
   (callee, possibly on several of the contact's devices at once).

   Multi-device dedup does NOT live in this file — it happens one level
   up, wherever incoming call_invite/call_claim packets are handled.
   By the time transition() sees "claimed", the dedup question ("was it
   us or one of our other devices that answered") has already been
   resolved by whoever calls transition() — this machine only tracks
   the state of the call THIS device is party to.
══════════════════════════════════════════ */
function transition(id, event) {
	const contact = state.contacts[id];
	if (!contact) return;
	const conn = contact.call ??= { phase: "idle", role: null };

	const oldPhase = conn.phase;

	switch (conn.phase) {

	  case "idle":
		if (event.type === "call_started")     // user clicked call
		  { conn.phase = "calling"; conn.role = "caller"; }

		if (event.type === "invite_received")  // contact is calling us
		  { conn.phase = "ringing"; conn.role = "callee"; }
		break;

	  case "calling":
		if (event.type === "claim_received")   // one of their devices answered
		  conn.phase = "negotiating";

		if (event.type === "call_cancelled" || event.type === "no_answer")
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "ringing":
		if (event.type === "claimed_here")     // user answered on THIS device
		  conn.phase = "negotiating";

		if (event.type === "claimed_elsewhere" || event.type === "call_cancelled")
		  // another of our devices answered, or caller gave up —
		  // either way, stop ringing here, silently
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "negotiating":
		if (event.type === "rtc_connected")
		  conn.phase = "connected";

		if (event.type === "rtc_failed" || event.type === "call_ended" || event.type === "call_cancelled")
		  { conn.phase = "idle"; conn.role = null; }
		break;

	  case "connected":
		if (event.type === "call_ended" || event.type === "rtc_closed")
		  { conn.phase = "idle"; conn.role = null; }

		if (event.type === "rtc_failed")
		  conn.phase = "failed";
		break;

	  case "failed":
		if (event.type === "reset")
		  { conn.phase = "idle"; conn.role = null; }
		break;
	}

	if (conn.phase !== oldPhase) {
		mlog.info(`CALL  ${pid(id)}  ${oldPhase} → ${conn.phase}${conn.role ? " ("+conn.role+")" : ""}`);
		onStateEnter(id, oldPhase, conn.phase, conn.role);
	}
	return { from: oldPhase, to: conn.phase };
}

/* ══════════════════════════════════════════
   ON STATE ENTER
   Side effects on phase entry. Called by transition(), never directly.
   role disambiguates "negotiating" — caller makes the offer once claimed,
   callee waits for it and answers.
══════════════════════════════════════════ */
function onStateEnter(id, oldPhase, newPhase, role) {
  switch (newPhase) {

    case "calling":
      sendCallInvite(id);
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