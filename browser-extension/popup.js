chrome.runtime.sendMessage({ type: "status" }, (s) => {
  document.getElementById("ver").textContent = "Version " + s.version;
  document.getElementById("state").textContent = s.connected ? "On — protecting this browser" : "On — not linked to your account";
  document.getElementById("dot").className = "dot" + (s.connected ? "" : " off");
  document.getElementById("who").textContent = s.connected ? `Linked as “${s.agentName}”.` : "Secrets are still blocked. Link it to see activity and approvals in your dashboard.";
  const st = s.stats && s.stats.day === new Date().toISOString().slice(0, 10) ? s.stats : {};
  document.getElementById("n1").textContent = st.checked || 0; document.getElementById("n2").textContent = st.blocked || 0; document.getElementById("n3").textContent = st.approvals || 0;
  const open = document.getElementById("open");
  open.href = s.apiUrl + (s.connected ? "/live" : "/protection?guard=installed");
  open.textContent = s.connected ? "Open Heimdall" : "Link to my Heimdall account";
  const off = document.getElementById("off"); off.hidden = !s.connected;
  off.onclick = () => chrome.runtime.sendMessage({ type: "disconnect" }, () => location.reload());
});
