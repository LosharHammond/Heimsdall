import { useEffect, useState } from "react";
import { api } from "./api";

const KEY = "heimdall_browser_notifications";
const read = () => {
  try {
    return localStorage.getItem(KEY) === "on";
  } catch {
    return false;
  }
};

export type BrowserNotifState = { supported: boolean; permission: NotificationPermission | "unsupported"; enabled: boolean };

export function browserNotifState(): BrowserNotifState {
  const supported = typeof Notification !== "undefined" && "serviceWorker" in navigator;
  return { supported, permission: supported ? Notification.permission : "unsupported", enabled: read() && supported && Notification.permission === "granted" };
}

/** Asks the browser for permission (must be called from a click), registers the service worker, remembers the choice locally. */
export async function enableBrowserNotifications(): Promise<BrowserNotifState> {
  if (!browserNotifState().supported) return browserNotifState();
  const p = await Notification.requestPermission();
  if (p === "granted") {
    await navigator.serviceWorker.register("/sw.js");
    try {
      localStorage.setItem(KEY, "on");
    } catch {
      /* storage unavailable: the choice just won't persist */
    }
  }
  return browserNotifState();
}

export function disableBrowserNotifications() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

/**
 * While the dashboard is loaded (open, minimized or in a background tab), poll for NEW incident-class alerts and show them via the
 * service worker's showNotification. Each alert uses its id as the notification tag so it can never stack twice.
 * This is not Web Push: when the tab or browser is closed nothing is delivered; the native companion covers that.
 */
export function useIncidentNotifier(orgId: string) {
  const [state, setState] = useState(browserNotifState());
  useEffect(() => {
    if (!state.enabled) return;
    let stop = false;
    const sk = `heimdall_incident_cursor_${orgId}`;
    const getSince = () => {
      try {
        return sessionStorage.getItem(sk) ?? new Date().toISOString();
      } catch {
        return new Date().toISOString();
      }
    };
    let since = getSince();
    const tick = async () => {
      try {
        const r = await api<{ items: Array<{ id: string; title: string; severity: string; created_at: string }>; server_time: string }>("GET", `/api/orgs/${orgId}/incidents?since=${encodeURIComponent(since)}`);
        const reg = await navigator.serviceWorker.ready;
        for (const it of r.items.slice(0, 3)) {
          await reg.showNotification(it.severity === "high" ? "Heimdall: high-risk incident" : "Heimdall: incident", { body: it.title, tag: `alert-${it.id}`, data: { url: "/alerts" }, requireInteraction: it.severity === "high" });
        }
        if (r.items.length > 3) await reg.showNotification("Heimdall: more incidents", { body: `${r.items.length - 3} more incidents. Open the dashboard to review.`, tag: "incident-backlog", data: { url: "/alerts" } });
        since = r.items.length ? r.items[r.items.length - 1].created_at : since;
        try {
          sessionStorage.setItem(sk, since);
        } catch {
          /* ignore */
        }
      } catch {
        /* network/auth hiccup: try again next tick */
      }
    };
    const t = setInterval(() => !stop && void tick(), 15_000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [orgId, state.enabled]);
  return { state, refresh: () => setState(browserNotifState()) };
}
