/* Heimdall browser guard: background worker. Holds this browser's Heimdall link and asks Heimdall for decisions. */
const VERSION = chrome.runtime.getManifest().version;
const DEFAULT_URL = "https://kenuxa-heimdall.vercel.app";
const get = () => chrome.storage.local.get(["apiUrl", "apiKey", "agentName", "stats", "lastOk"]);
const today = () => new Date().toISOString().slice(0, 10);

async function bump(field) {
  const { stats } = await get();
  const s = stats && stats.day === today() ? stats : { day: today(), checked: 0, blocked: 0, approvals: 0 };
  s[field] = (s[field] || 0) + 1;
  await chrome.storage.local.set({ stats: s });
  if (field === "blocked") chrome.action.setBadgeText({ text: String(s.blocked) }), chrome.action.setBadgeBackgroundColor({ color: "#C8473A" });
}

async function call(method, path, body) {
  const { apiUrl, apiKey } = await get();
  if (!apiUrl || !apiKey) return { offline: true, error: "this browser is not linked to Heimdall yet" };
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 8000);
    const r = await fetch(apiUrl + path, { method, signal: ctl.signal, headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    clearTimeout(t);
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 || r.status === 403) return { offline: true, error: "the link to Heimdall was removed; connect this browser again", status: r.status };
    if (!r.ok && !j.decision) return { offline: true, error: j?.error?.message || `Heimdall answered ${r.status}` };
    await chrome.storage.local.set({ lastOk: Date.now() });
    return j;
  } catch (e) { return { offline: true, error: "Heimdall could not be reached" }; }
}

async function authorize(m) {
  const request_id = `bg_${Date.now().toString(36)}_${crypto.getRandomValues(new Uint32Array(2)).join("")}`.slice(0, 120);
  const level = ["public", "internal", "confidential", "restricted"].includes(m.level) ? m.level : "internal";
  const r = await call("POST", "/v1/authorize", {
    request_id, tool: "browser", operation: "external_transfer",
    resource: `browser/${m.host}/${m.kind}`.replace(/[^A-Za-z0-9/_.-]/g, "-"), destination: `https://${m.host}`,
    data_classification: level,
    args: { found: (m.findings || []).slice(0, 20).map((f) => `${f.label}${f.count > 1 ? ` x${f.count}` : ""}`) },
    adapter: { name: "heimdall-browser-guard", version: VERSION },
  });
  if (r.offline) { if (level === "restricted") bump("blocked"); return r; }
  if (r.decision === "deny") {
    bump("blocked");
    call("POST", `/v1/actions/${request_id}/outcome`, { status: "refused", error_code: "BLOCKED_IN_BROWSER" });
  } else if (r.decision === "allow" && r.action_digest) {
    call("POST", `/v1/actions/${request_id}/claim`, { action_digest: r.action_digest })
      .then((c) => c && c.permitted && call("POST", `/v1/actions/${request_id}/outcome`, { status: "succeeded" }));
  } else if (r.decision === "require_approval") bump("approvals");
  return { ...r, request_id };
}

async function heartbeat() {
  const r = await call("GET", "/v1/whoami");
  return !r.offline;
}

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  (async () => {
    if (m.type === "hello") { const { apiKey } = await get(); return { connected: !!apiKey }; }
    if (m.type === "count") { await bump(m.what); return { ok: true }; }
    if (m.type === "authorize") return authorize(m);
    if (m.type === "poll") {
      const r = await call("GET", `/v1/actions/${encodeURIComponent(m.request_id)}`);
      if (r?.approval?.status === "approved" && r.action_digest) {
        const c = await call("POST", `/v1/actions/${encodeURIComponent(m.request_id)}/claim`, { action_digest: r.action_digest });
        if (!c.permitted) return { approval: { status: "rejected" } };
        call("POST", `/v1/actions/${encodeURIComponent(m.request_id)}/outcome`, { status: "succeeded" });
      }
      return r;
    }
    if (m.type === "connect") {
      // Only from the Heimdall dashboard (connect.js runs on the Heimdall site alone), and only an https URL or this computer.
      const url = String(m.apiUrl || "").replace(/\/$/, "");
      if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(url)) return { ok: false, error: "bad address" };
      if (!/^asg_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{43}$/.test(String(m.apiKey || ""))) return { ok: false, error: "bad key" };
      if (new URL(sender.url || "http://x").origin !== url) return { ok: false, error: "this page is not the Heimdall site it names" };
      await chrome.storage.local.set({ apiUrl: url, apiKey: m.apiKey, agentName: m.agentName || "" });
      const ok = await heartbeat();
      chrome.action.setBadgeText({ text: "" });
      return { ok, agentName: m.agentName };
    }
    if (m.type === "status") { const s = await get(); return { connected: !!s.apiKey, apiUrl: s.apiUrl || DEFAULT_URL, agentName: s.agentName, stats: s.stats, lastOk: s.lastOk, version: VERSION }; }
    if (m.type === "disconnect") { await chrome.storage.local.remove(["apiKey", "agentName"]); return { ok: true }; }
    return { error: "unknown" };
  })().then(reply);
  return true;
});

chrome.alarms.onAlarm.addListener((a) => { if (a.name === "heartbeat") heartbeat(); });
chrome.runtime.onInstalled.addListener(async (d) => {
  chrome.alarms.create("heartbeat", { periodInMinutes: 5 });
  if (d.reason === "install") {
    const { apiKey } = await get();
    if (!apiKey) chrome.tabs.create({ url: DEFAULT_URL + "/protection?guard=installed" });
  }
});
chrome.runtime.onStartup.addListener(() => { chrome.alarms.create("heartbeat", { periodInMinutes: 5 }); heartbeat(); });
