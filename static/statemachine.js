/* ══════════════════════════════════════════
   STATE MACHINE
   transition(id, event) — pure logic, no side effects
   Valid phases: idle | offering | answering | negotiating | connected | failed
   Valid tiers:  signal | relay | rtc
══════════════════════════════════════════ */
function transition(id, event) {
	const contact = state.contacts[id];
	if (!contact) return;
	const conn = contact.conn ??= { phase: "idle", tier: "signal", legacy: false };

	const oldPhase = conn.phase;
	switch (conn.phase) {

	  case "idle":
		if (event.type === "rtc_available")
		  conn.phase = "offering";
		break;

	  case "offering":
		if (event.type === "offer_sent")
		  conn.phase = "negotiating";

		if (event.type === "rtc_failed")
		  conn.phase = "failed";
		break;

	  case "negotiating":
		if (event.type === "rtc_connected")
		  conn.phase = "connected";

		if (event.type === "rtc_failed")
		  conn.phase = "failed";
		break;

	  case "connected":
		if (event.type === "rtc_closed")
		  conn.phase = "idle";
		break;

	  case "failed":
		if (event.type === "reset")
		  conn.phase = "idle";
		break;
	}

	if (conn.phase !== oldPhase) {
		mlog.info(`SM  ${pid(id)}  ${oldPhase} → ${conn.phase}`);
		onStateEnter(id, oldPhase, conn.phase);
	}
	return { from: oldPhase, to: conn.phase }
}

/* ══════════════════════════════════════════
   ROUTER
   route(id, obj) — consult state, pick transport
   Messages open new connections, protocol traffic only piggybacks
══════════════════════════════════════════ */
function route(id, obj) {
	const tier = state.contacts[id]?.conn?.tier;
	const isMessage = obj.type === "message";

	switch(tier){
		case "rtc":			
			rtcSend(id, obj); break;
		case "relay":
			if (!sendToRelay(id, obj, isMessage)) sendSignal(obj);
			break;
		default:
			sendSignal(obj); break;
	}

}
/* ══════════════════════════════════════════
   ON STATE ENTER
   transport(id, phase) — side effects on phase entry
   Called by setPhase, never directly
══════════════════════════════════════════ */
function onStateEnter(id, oldState, newState) {
  switch (newState.phase) {

    case "offering":
      rtcOffer(id);
      break;

    case "connected":
      mlog.info(`RTC UP ${pid(id)}`);
      break;

    case "failed":
      rtcClose(id);
      break;
  }
}