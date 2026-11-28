/* Heimdall browser guard, on AI chat websites. Checks what you paste, send or upload; asks Heimdall before secrets or
 * personal data reach the AI. The text itself never leaves your browser: Heimdall only learns what kind of thing was found. */
(() => {
  "use strict";
  if (window.__heimdallGuard) return;
  window.__heimdallGuard = true;
  const D = globalThis.HeimdallDetect;
  const HOST = location.hostname;
  let bypassOnce = false;            // set while Heimdall itself re-inserts approved text
  let busy = false;

  // ---------------------------------------------------------------- small UI, in a shadow root so the site's CSS can't touch it
  const host = document.createElement("heimdall-guard");
  const shadow = host.attachShadow({ mode: "closed" });
  shadow.innerHTML = `<style>
    :host{all:initial}
    .pill{position:fixed;right:16px;bottom:16px;z-index:2147483647;display:flex;align-items:center;gap:8px;padding:8px 12px 8px 10px;border-radius:999px;
      background:#1F2547;color:#fff;font:600 12.5px/1 Inter,Segoe UI,system-ui,sans-serif;box-shadow:0 8px 28px rgba(10,12,30,.28);cursor:default;
      transition:opacity .3s,transform .3s;opacity:.96}
    .pill.min span{display:none}.pill.min{padding:8px}
    .pill svg{flex:none}
    .ov{position:fixed;inset:0;z-index:2147483647;background:rgba(15,18,40,.45);display:none;align-items:center;justify-content:center;font:15px/1.5 Inter,Segoe UI,system-ui,sans-serif}
    .ov.on{display:flex}
    .box{width:min(520px,calc(100vw - 32px));background:#fff;color:#1C2033;border-radius:16px;box-shadow:0 24px 64px rgba(10,12,30,.35);overflow:hidden}
    .bar{display:flex;gap:12px;align-items:center;padding:18px 20px;background:#1F2547;color:#fff}
    .bar b{font-size:16px}.bar small{display:block;color:#C9CDE6;font-size:12.5px;font-weight:500}
    .body{padding:18px 20px}
    .body p{margin:0 0 10px}
    ul{margin:0 0 12px;padding-left:18px}li{margin:3px 0}
    .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}
    .deny{background:#F6E1DE;color:#A2362B}.ask{background:#F8EDCC;color:#7A5B0D}.ok{background:#E1EEE7;color:#2F6A4F}
    .acts{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;padding:14px 20px;background:#F5F6FA;border-top:1px solid #E3E5EE}
    button{font:600 14px Inter,Segoe UI,system-ui,sans-serif;height:40px;padding:0 16px;border-radius:10px;border:1px solid #D4D7E3;background:#fff;color:#1C2033;cursor:pointer}
    button.primary{background:#E0B23D;border-color:#E0B23D;color:#1F2547}button:hover{filter:brightness(.97)}
    button:focus-visible{outline:3px solid #E0B23D;outline-offset:2px}
    .spin{width:16px;height:16px;border:2px solid #E0B23D;border-right-color:transparent;border-radius:50%;display:inline-block;vertical-align:-3px;animation:s 1s linear infinite;margin-right:6px}
    @keyframes s{to{transform:rotate(360deg)}}
    .fine{color:#5D6480;font-size:12.5px}
  </style>
  <div class="pill" id="pill" title="Heimdall is checking what you paste, send and upload here"><svg width="16" height="16" viewBox="0 0 24 24" fill="#E0B23D"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 14.2-3.5-3.5 1.4-1.4 2.1 2.1 4.9-4.9 1.4 1.4-6.3 6.3Z"/></svg><span id="pill-t">Heimdall is guarding this chat</span></div>
  <div class="ov" id="ov" role="dialog" aria-modal="true" aria-labelledby="t"><div class="box">
    <div class="bar"><svg width="28" height="28" viewBox="0 0 24 24" fill="#E0B23D"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/></svg><div><b id="t">Heimdall stopped this</b><small id="st"></small></div></div>
    <div class="body" id="msg"></div><div class="acts" id="acts"></div></div></div>`;
  const $ = (id) => shadow.getElementById(id);
  const mount = () => { if (!host.isConnected) (document.body || document.documentElement).appendChild(host); };
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", mount) : mount();
  setTimeout(() => $("pill").classList.add("min"), 5000);
  $("pill").addEventListener("mouseenter", () => $("pill").classList.remove("min"));
  $("pill").addEventListener("mouseleave", () => $("pill").classList.add("min"));

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  function dialog(title, sub, html, actions) {
    $("t").textContent = title; $("st").textContent = sub || "";
    $("msg").innerHTML = html;
    const acts = $("acts"); acts.replaceChildren();
    for (const a of actions) {
      const b = document.createElement("button");
      b.textContent = a.label; if (a.primary) b.className = "primary";
      b.onclick = () => { close(); a.run && a.run(); };
      acts.appendChild(b);
    }
    $("ov").classList.add("on");
    setTimeout(() => (acts.querySelector(".primary") || acts.lastChild)?.focus(), 30);
  }
  const close = () => $("ov").classList.remove("on");
  shadow.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });

  const list = (findings) => "<ul>" + findings.map((f) => `<li>${esc(f.label)}${f.count > 1 && !/^list of/.test(f.label) ? ` ×${f.count}` : ""} <span class="tag ${f.level === "restricted" ? "deny" : "ask"}">${f.level === "restricted" ? "never shared" : "needs approval"}</span></li>`).join("") + "</ul>";

  // ---------------------------------------------------------------- talk to Heimdall (through the extension's background worker)
  const ask = (msg) => new Promise((res) => {
    try { chrome.runtime.sendMessage(msg, (r) => res(chrome.runtime.lastError ? { offline: true } : r || { offline: true })); }
    catch { res({ offline: true }); }
  });

  /** One decision for this content. Returns {decision: allow|deny|require_approval, ...} */
  async function decide(kind, scan) {
    return ask({ type: "authorize", host: HOST, kind, level: scan.level, findings: scan.findings.map((f) => ({ label: f.label, level: f.level, count: f.count })) });
  }

  // ---------------------------------------------------------------- putting text into the chat box
  function insertText(target, text) {
    bypassOnce = true;
    try {
      target.focus();
      if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
        const { selectionStart: s, selectionEnd: e } = target;
        target.setRangeText(text, s ?? target.value.length, e ?? target.value.length, "end");
        target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
      } else {
        document.execCommand("insertText", false, text);
      }
    } finally { setTimeout(() => (bypassOnce = false), 0); }
  }
  function replaceAll(target, text) {
    bypassOnce = true;
    try {
      target.focus();
      if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
        target.value = text; target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
      } else {
        const sel = getSelection(); const r = document.createRange(); r.selectNodeContents(target); sel.removeAllRanges(); sel.addRange(r);
        document.execCommand("insertText", false, text);
      }
    } finally { setTimeout(() => (bypassOnce = false), 0); }
  }
  const editorOf = (el) => el && (el.closest?.("textarea, input[type=text], [contenteditable=''], [contenteditable=true], [role=textbox]") || null);
  const composer = () => editorOf(document.activeElement) || document.querySelector("#prompt-textarea, div[contenteditable=true].ProseMirror, rich-textarea [contenteditable=true], textarea");
  const textOf = (el) => !el ? "" : (el.value !== undefined && el.tagName !== "DIV" ? el.value : el.innerText || "");

  // ---------------------------------------------------------------- what happens when something sensitive is found
  async function handle(kind, scan, onAllow, onRedact) {
    if (busy) return;
    busy = true;
    dialog("Checking with Heimdall…", HOST, `<p><span class="spin"></span>This ${kind === "upload" ? "file" : "text"} contains:</p>${list(scan.findings)}`, []);
    const r = await decide(kind, scan);
    busy = false;
    const offline = r.offline || r.error;
    const decision = offline ? (scan.level === "restricted" ? "deny" : "ask_user") : r.decision;
    const why = offline ? `<p class="fine">Heimdall could not be reached${r.error ? ` (${esc(r.error)})` : ""}, so the browser decided on its own: secrets are never sent.</p>`
      : `<p class="fine">${esc(r.explanation || "")}</p>`;
    if (decision === "allow") { close(); onAllow(); return; }
    if (decision === "deny") {
      dialog("Heimdall stopped this", `Not sent to ${HOST}`, `<p>It contains:</p>${list(scan.findings)}${why}`,
        [{ label: "Cancel" }, ...(onRedact ? [{ label: "Use it with these removed", primary: true, run: onRedact }] : [])]);
      return;
    }
    if (decision === "ask_user") {
      dialog("Check before you send", HOST, `<p>It contains:</p>${list(scan.findings)}${why}`,
        [{ label: "Cancel", primary: true }, { label: "Send anyway", run: onAllow }]);
      return;
    }
    // require_approval: wait for an administrator in the Heimdall dashboard
    dialog("Waiting for approval", HOST, `<p><span class="spin"></span>An administrator has been asked to approve sharing:</p>${list(scan.findings)}<p class="fine">You can keep this open. It continues by itself once they decide (up to 15 minutes).</p>`,
      [{ label: "Cancel" }]);
    const end = Date.now() + 15 * 60_000;
    while (Date.now() < end && $("ov").classList.contains("on")) {
      await new Promise((s) => setTimeout(s, 4000));
      const p = await ask({ type: "poll", request_id: r.request_id });
      const st = p?.approval?.status;
      if (st === "approved") { close(); onAllow(); return; }
      if (st === "rejected" || st === "expired") {
        dialog("Not approved", HOST, `<p>An administrator did not approve sharing this.</p>${list(scan.findings)}`,
          [{ label: "Close" }, ...(onRedact ? [{ label: "Use it with these removed", primary: true, run: onRedact }] : [])]);
        return;
      }
    }
  }

  // paste
  document.addEventListener("paste", (e) => {
    if (bypassOnce) return;
    const target = editorOf(e.target);
    const text = e.clipboardData?.getData("text/plain") || "";
    const files = [...(e.clipboardData?.files || [])];
    const fileHit = files.map((f) => D.scanFileName(f.name)).filter(Boolean);
    const scan = D.scan(text);
    if (fileHit.length) { scan.findings.push(...fileHit); scan.level = "restricted"; }
    ask({ type: "count", what: "checked" });
    if (!scan.findings.length || !target) return;
    e.preventDefault(); e.stopImmediatePropagation();
    handle("paste", scan, () => insertText(target, text), scan.spans.some((s) => s.level === "restricted") ? () => insertText(target, D.redact(text, scan.spans)) : null);
  }, true);

  // sending typed text: Enter in the chat box, or the send button
  const sendCheck = (e, trigger) => {
    if (bypassOnce) return;
    const box = composer();
    const text = textOf(box);
    if (!text || text.length < 6) return;
    const scan = D.scan(text);
    if (!scan.findings.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    handle("message", scan, () => { bypassOnce = true; trigger(); setTimeout(() => (bypassOnce = false), 50); },
      scan.spans.some((s) => s.level === "restricted") ? () => replaceAll(box, D.redact(text, scan.spans)) : null);
  };
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing || !editorOf(e.target)) return;
    const target = e.target;
    sendCheck(e, () => target.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true })));
  }, true);
  document.addEventListener("click", (e) => {
    const btn = e.target.closest?.("button[data-testid='send-button'], button[aria-label*='Send' i], button[aria-label*='Submit' i], button[type=submit]");
    if (!btn) return;
    sendCheck(e, () => btn.click());
  }, true);

  // uploads: file pickers and drag-and-drop
  const fileCheck = (e, files) => {
    if (bypassOnce) return;
    const hits = [...files].map((f) => D.scanFileName(f.name)).filter(Boolean);
    if (!hits.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    if (e.target instanceof HTMLInputElement) e.target.value = "";
    handle("upload", { level: "restricted", findings: hits, spans: [] }, () => {}, null);
  };
  document.addEventListener("change", (e) => { if (e.target instanceof HTMLInputElement && e.target.type === "file" && e.target.files?.length) fileCheck(e, e.target.files); }, true);
  document.addEventListener("drop", (e) => { if (e.dataTransfer?.files?.length) fileCheck(e, e.dataTransfer.files); }, true);

  ask({ type: "hello", host: HOST }).then((r) => {
    $("pill-t").textContent = r && r.connected ? "Heimdall is guarding this chat" : "Heimdall is guarding this chat (not linked to your account yet)";
  });
})();
