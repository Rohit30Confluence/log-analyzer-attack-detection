const $ = (sel) => document.querySelector(sel);

const connDot = $("#conn-dot");
const connText = $("#conn-text");
const feed = $("#feed");
const feedPulse = $("#feed-pulse");
const alertRows = $("#alert-rows");
const statTotal = $("#stat-total");
const typeBars = $("#type-bars");
const topIps = $("#top-ips");

function sevClass(sev) {
  return `sev-${(sev || "medium").toLowerCase()}`;
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  return d.toLocaleTimeString();
}

function addFeedLine(alert) {
  const el = document.createElement("div");
  el.className = `feed-line ${sevClass(alert.severity)}`;
  el.innerHTML = `<span class="ts">${fmtTime(alert.created_at)}</span><b>${alert.type}</b> — ${alert.ip || "?"} — ${alert.detail || ""}`;
  feed.appendChild(el);
  while (feed.children.length > 60) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

function prependRow(alert) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${fmtTime(alert.created_at)}</td>
    <td>${alert.type}</td>
    <td>${alert.ip || "-"}</td>
    <td><span class="sev-tag ${sevClass(alert.severity)}">${alert.severity || "medium"}</span></td>
    <td>${alert.detail || ""}</td>`;
  alertRows.prepend(tr);
  while (alertRows.children.length > 50) alertRows.removeChild(alertRows.lastChild);
}

async function refreshStats() {
  const res = await fetch("/api/stats");
  const stats = await res.json();
  statTotal.textContent = stats.total_alerts ?? 0;

  typeBars.innerHTML = "";
  const byType = stats.by_type || {};
  const max = Math.max(1, ...Object.values(byType));
  for (const [type, count] of Object.entries(byType)) {
    const row = document.createElement("div");
    row.className = "type-bar-row";
    row.innerHTML = `
      <span>${type}</span>
      <span class="type-bar-track"><span class="type-bar-fill" style="width:${(count / max) * 100}%"></span></span>
      <span>${count}</span>`;
    typeBars.appendChild(row);
  }

  topIps.innerHTML = "";
  for (const item of stats.top_ips || []) {
    const li = document.createElement("li");
    li.innerHTML = `<b>${item.ip}</b> — ${item.count} alert(s)`;
    topIps.appendChild(li);
  }
}

async function refreshAlerts() {
  const res = await fetch("/api/alerts?limit=50");
  const rows = await res.json();
  alertRows.innerHTML = "";
  for (const a of rows) prependRow(a);
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);

  ws.onopen = () => {
    connDot.className = "dot dot-on";
    connText.textContent = "live";
  };
  ws.onclose = () => {
    connDot.className = "dot dot-off";
    connText.textContent = "disconnected — retrying…";
    setTimeout(connectWS, 2000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "alerts") {
      for (const a of msg.data) {
        addFeedLine(a);
        prependRow(a);
      }
      refreshStats();
    } else if (msg.type === "traffic") {
      feedPulse.classList.add("active");
      setTimeout(() => feedPulse.classList.remove("active"), 800);
    }
  };
}

// --- Controls ---
$("#sim-start").addEventListener("click", async () => {
  await fetch("/api/simulate/start", { method: "POST" });
  $("#sim-start").disabled = true;
  $("#sim-stop").disabled = false;
});

$("#sim-stop").addEventListener("click", async () => {
  await fetch("/api/simulate/stop", { method: "POST" });
  $("#sim-start").disabled = false;
  $("#sim-stop").disabled = true;
});

$("#analyze-btn").addEventListener("click", async () => {
  const input = $("#file-input");
  const resultBox = $("#analyze-result");
  if (!input.files.length) {
    resultBox.textContent = "Choose a log file first.";
    return;
  }
  const form = new FormData();
  form.append("file", input.files[0]);
  resultBox.textContent = "Analyzing…";
  const res = await fetch("/api/analyze", { method: "POST", body: form });
  const data = await res.json();
  resultBox.textContent = `Parsed ${data.parsed_entries} entries, ${data.alerts.length} alert(s) generated.`;
  refreshStats();
  refreshAlerts();
});

// --- Init ---
(async function init() {
  const status = await (await fetch("/api/simulate/status")).json();
  $("#sim-start").disabled = status.running;
  $("#sim-stop").disabled = !status.running;
  await refreshStats();
  await refreshAlerts();
  connectWS();
})();
