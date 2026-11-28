/* Runs on the Heimdall dashboard only. Tells the page the extension is installed and passes the one-time link on to the extension. */
(() => {
  document.documentElement.setAttribute("data-heimdall-guard", chrome.runtime.getManifest().version);
  chrome.runtime.sendMessage({ type: "status" }, (s) => {
    if (chrome.runtime.lastError || !s) return;
    window.postMessage({ type: "heimdall-guard-status", connected: s.connected, agentName: s.agentName || "", apiUrl: s.apiUrl }, location.origin);
  });
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || !e.data || e.data.type !== "heimdall-guard-connect") return;
    chrome.runtime.sendMessage({ type: "connect", apiUrl: e.data.apiUrl, apiKey: e.data.apiKey, agentName: e.data.agentName }, (r) => {
      window.postMessage({ type: "heimdall-guard-connected", ok: !!(r && r.ok), error: r && r.error, agentName: r && r.agentName }, location.origin);
    });
  });
})();
