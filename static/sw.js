self.addEventListener("install", () => {
  console.log("SW installed");
});

self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});

self.addEventListener("fetch", event => {
  event.respondWith(
    fetch(event.request).catch(() => {
      // aborted (tab closed mid-request), offline, or a CDN hiccup —
      // swallow rather than let it surface as an unhandled SW error.
      // Real offline support (cache-first for the app shell) is a
      // separate, bigger piece of work, not implied by this.
      return new Response("", { status: 504, statusText: "offline or network error" });
    })
  );
});

/* ══════════════════════════════════════════
   PUSH NOTIFICATIONS
   Every push MeshChat sends is deliberately bodyless — no message
   content, sender identity, or any other metadata, ever (see
   protocol.md's Push Notifications section). event.data is expected to
   be null; this is a wake-up ping, not a payload delivery, so there is
   nothing to decrypt or parse here. userVisibleOnly:true (required by
   the browser at subscribe time — see ensurePushSubscription in
   meshchat.js) obligates showing a notification for every push received,
   which is exactly what this does.
══════════════════════════════════════════ */
self.addEventListener("push", (event) => {
  event.waitUntil(
    self.registration.showNotification("MeshChat", {
      body: "tap to check",
      tag: "meshchat-push",   // collapses multiple pending pushes into one visible notification
      renotify: true,        // …but still re-alert (banner/sound) each time, even if the prior one is unread
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ("focus" in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow("./");
    })
  );
});