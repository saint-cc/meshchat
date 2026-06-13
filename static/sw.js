self.addEventListener("install", () => {
  console.log("SW installed");
});

self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});

self.addEventListener("fetch", event => {
  event.respondWith(fetch(event.request));
});