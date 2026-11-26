// Kenuxa Heimdall dashboard service worker.
// It shows notifications for an open dashboard page, shows pushed notifications, and focuses the
// dashboard when one is clicked. It does NOT use Web Push, so it cannot wake a closed browser: use the native companion for that.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/alerts";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) if ("focus" in c) { c.navigate(url).catch(() => undefined); return c.focus(); }
      return self.clients.openWindow(url);
    }),
  );
});

// Web Push (added devices, docs/DEVICES.md): approvals and incidents arrive even when no Heimdall tab is open.
self.addEventListener("push", (event) => {
  let m = {};
  try { m = event.data ? event.data.json() : {}; } catch { m = { title: "Kenuxa Heimdall", body: event.data ? event.data.text() : "" }; }
  const url = typeof m.url === "string" && m.url.startsWith("/") ? m.url : "/alerts";
  event.waitUntil(self.registration.showNotification(m.title || "Kenuxa Heimdall", {
    body: m.body || "", tag: m.tag || undefined, data: { url }, requireInteraction: url === "/approvals",
  }));
});
self.addEventListener("pushsubscriptionchange", (event) => {
  // The browser renewed the subscription; the dashboard re-sends it on next open (usePushRefresh).
  event.waitUntil(Promise.resolve());
});
