/* ══════════════════════════════════════════
   BOOT — the little that used to be inline in index.html
   index.html's Content-Security-Policy allows scripts from this origin only
   (script-src 'self'): no inline <script> blocks, no onclick="" attributes.
   So the two things that lived inline are here instead:

     1. service-worker registration
     2. wiring for the STATIC buttons in index.html. Each one used to carry an
        inline handler; now it has an id and gets a listener here. The handlers
        are looked up when the click happens (the arrow functions below), not
        when this file loads, so load order against meshchat-gui.js doesn't
        matter. The dynamically built dialog buttons are handled in
        meshchat-gui.js (data-close-action, next to closeContactAction).

   Loaded LAST in index.html. If an id is missing the log says which one,
   instead of the button silently doing nothing.
══════════════════════════════════════════ */
(function () {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(e => console.warn("service worker registration failed:", e));
  }

  function on(id, event, fn) {
    const el = document.getElementById(id);
    if (!el) { console.warn("meshchat-boot: no element #" + id); return; }
    el.addEventListener(event, fn);
  }

  // login
  on("showPwChk", "change", (e) => togglePw(e.target));

  // chat header
  on("backBtn",         "click", () => document.getElementById("appContainer").classList.remove("chatOpen"));
  on("contactEditBtn",  "click", () => contactAction("edit"));
  on("blockToggleBtn",  "click", () => contactAction("block"));

  // in-page log
  on("meshLogClear", "click", () => mlog.clear());
  on("meshLogHide",  "click", () => mlog.hide());

  // add-contact modal
  on("tabShow",         "click", () => switchTab("show"));
  on("tabScan",         "click", () => switchTab("scan"));
  on("tabPaste",        "click", () => switchTab("paste"));
  on("qrModeOffline",   "click", () => setQrMode("offline"));
  on("qrModeLive",      "click", () => setQrMode("live"));
  on("qrLiveRefresh",   "click", () => refreshQrLive());
  on("scanToggleBtn",   "click", () => toggleScanner());
})();
