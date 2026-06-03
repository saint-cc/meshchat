self.addEventListener("install", () => {
  console.log("SW installed");
});

self.addEventListener("fetch", event => {
  event.respondWith(fetch(event.request));
});