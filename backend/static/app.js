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

function createTextCell(text, className = "") {
  const el = document.createElement("td");
  if (className) el.className = className;
  el.textContent = text ?? "";
  return el;
}

function addFeedLine(alert) {
  const el = document.createElement("div");
  el.className = `feed-line ${sevClass(alert.severity)}`;

  const ts = document.createElement("span");
  ts.className = "ts";
  ts.textContent = fmtTime(alert.created_at);

  const type = document.createElement("b");
  type.textContent = alert.type || "";

  el.appendChild(ts);
  el.appendChild(type);
  el.appendChild(
    document.createTextNode(
      ` — ${alert.ip || "?"} — ${alert.detail || ""}`
    )
  );

  feed.appendChild(el);

  while (feed.children.length > 60) {
    feed.removeChild(feed.firstChild);
  }

  feed.scrollTop = feed.scrollHeight;
}

function prependRow(alert) {
  const tr = document.createElement("tr");

  tr.appendChild(createTextCell(fmtTime(alert.created_at)));
  tr.appendChild(createTextCell(alert.type));
  tr.appendChild(createTextCell(alert.ip || "-"));

  const severityCell = document.createElement("td");
  const severityTag = document.createElement("span");
  severityTag.className = `sev-tag ${sevClass(alert.severity)}`;
  severityTag.textContent = alert.severity || "medium";
  severityCell.appendChild(severityTag);
  tr.appendChild(severityCell);

  tr.appendChild(createTextCell(alert.detail || ""));

  alertRows.prepend(tr);

  while (alertRows.children.length > 50) {
    alertRows.removeChild(alertRows.lastChild);
  }
}

async function refreshStats() {
  const res = await fetch("/api/stats");
  const stats = await res.json();

  statTotal.textContent = stats.total_alerts ?? 0;

  typeBars.replaceChildren();

  const byType = stats.by_type || {};
  const max = Math.max(1, ...Object.values(byType));

  for (const [type, count] of Object.entries(byType)) {
    const row = document.createElement("div");
    row.className = "type-bar-row";

    const label = document.createElement("span");
    label.textContent = type;

    const track = document.createElement("span");
    track.className = "type-bar-track";

    const fill = document.createElement("span");
    fill.className = "type-bar-fill";
    fill.style.width = `${(count / max) * 100}%`;

    const countEl = document.createElement("span");
    countEl.textContent = count;

    track.appendChild(fill);
    row.appendChild(label);
    row.appendChild(track);
    row.appendChild(countEl);
    typeBars.appendChild(row);
  }

  topIps.replaceChildren();

  for (const item of stats.top_ips || []) {
    const li = document.createElement("li");

    const ip = document.createElement("b");
    ip.textContent = item.ip;

    li.appendChild(ip);
    li.appendChild(
      document.createTextNode(` — ${item.count} alert(s)`)
    );

    topIps.appendChild(li);
  }
}

async function refreshAlerts() {
  const res = await fetch("/api/alerts?limit=50");
  const rows = await res.json();

  alertRows.replaceChildren();

  // Reverse because prependRow() intentionally inserts newest first.
  for (const a of [...rows].reverse()) {
    prependRow(a);
  }
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

  const res = await fetch("/api/analyze", {
    method: "POST",
    body: form,
  });

  const data = await res.json();

  resultBox.textContent =
    `Parsed ${data.parsed_entries} entries, ` +
    `${data.alerts.length} alert(s) generated.`;

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
