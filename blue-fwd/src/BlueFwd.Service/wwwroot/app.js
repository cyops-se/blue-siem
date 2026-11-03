"use strict";

const FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
  "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3",
  "local4", "local5", "local6", "local7"];

const PRESETS = {
  sysmon: { name: "Sysmon", channel: "Microsoft-Windows-Sysmon/Operational", query: "*" },
  security: {
    name: "Security logons", channel: "Security",
    query: "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4732)]]",
  },
  powershell: {
    name: "PowerShell", channel: "Microsoft-Windows-PowerShell/Operational",
    query: "*[System[(EventID=4103 or EventID=4104)]]",
  },
  empty: { name: "", channel: "", query: "*" },
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

let config = null;
let lastSample = null;
let channelsLoaded = false;

// ---------- API ----------

function storedKey() {
  try { return localStorage.getItem("bluefwd.apiKey") || ""; } catch { return ""; }
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const key = storedKey();
  if (key) headers["X-Api-Key"] = key;

  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    const entered = prompt("API key required:");
    if (entered) {
      try { localStorage.setItem("bluefwd.apiKey", entered); } catch { /* storage unavailable */ }
      return api(path, options);
    }
    throw new Error("Unauthorized");
  }
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) {
    const err = new Error(body?.errors?.join("\n") || body?.detail || res.statusText);
    err.body = body;
    throw err;
  }
  return body;
}

// ---------- formatting ----------

const nf = new Intl.NumberFormat();
const fmtNum = n => nf.format(n ?? 0);

function fmtBytes(b) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function fmtAgo(iso) {
  if (!iso) return "–";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(iso).toLocaleString();
}

function fmtDuration(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${sec % 60}s`;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function setMsg(el, text, kind) {
  el.textContent = text || "";
  el.className = `${el.className.replace(/\b(ok|warn|bad)\b/g, "").trim()} ${kind || ""}`.trim();
}

// ---------- overview ----------

async function refreshStatus() {
  let s;
  try {
    s = await api("/api/status");
  } catch (e) {
    $("#connPill").className = "conn bad";
    $("#connText").textContent = "Service unreachable";
    return;
  }

  $("#hostInfo").textContent = `${s.machine} · v${s.version} · data: ${s.dataDirectory}`;
  $("#uptime").textContent = `Uptime ${fmtDuration(s.uptimeSeconds)}`;

  const snd = s.sender;
  $("#connPill").className = `conn ${snd.connected ? "ok" : "bad"}`;
  $("#connText").textContent = snd.connected ? `Connected to ${snd.endpoint}` : `Not connected (${s.target})`;

  $("#targetValue").textContent = s.target;
  $("#targetMeta").textContent = snd.connected
    ? `Connected ${fmtAgo(snd.connectedSinceUtc)} · ${fmtNum(snd.connects)} connects`
    : (snd.lastError ? `Last error: ${snd.lastError}` : "Waiting for first event");

  const now = performance.now();
  if (lastSample) {
    const dt = (now - lastSample.t) / 1000;
    const rate = Math.max(0, (snd.sent - lastSample.sent) / dt);
    $("#rateValue").textContent = rate < 10 ? rate.toFixed(1) : fmtNum(Math.round(rate));
  }
  lastSample = { t: now, sent: snd.sent };
  $("#sentMeta").textContent = `${fmtNum(snd.sent)} sent · ${fmtBytes(snd.bytesSent)} · last ${fmtAgo(snd.lastSendUtc)}`;

  $("#queueValue").textContent = fmtNum(s.queue.length);
  $("#queueCap").textContent = `/ ${fmtNum(s.queue.capacity)}`;
  $("#queueBar").style.width = `${Math.min(100, s.queue.length / s.queue.capacity * 100)}%`;

  $("#errorsValue").textContent = fmtNum(snd.errors);
  $("#errorsMeta").textContent = snd.lastError ? `${fmtAgo(snd.lastErrorUtc)}: ${snd.lastError}` : "No errors";

  const rows = s.subscriptions.map(x => `
    <tr>
      <td><strong>${esc(x.name)}</strong></td>
      <td>${esc(x.channel)}</td>
      <td><span class="badge ${esc(x.state)}">${esc(x.state)}</span></td>
      <td class="num">${fmtNum(x.received)}</td>
      <td class="num">${fmtNum(x.forwarded)}</td>
      <td class="num">${fmtNum(x.dropped)}</td>
      <td class="num">${fmtNum(x.errors)}</td>
      <td>${fmtAgo(x.lastEventUtc)}</td>
      <td class="num">${x.storedPosition ?? "–"}</td>
    </tr>
    ${x.lastError ? `<tr><td></td><td colspan="8" class="err">${esc(fmtAgo(x.lastErrorUtc))}: ${esc(x.lastError)}</td></tr>` : ""}`);
  $("#subsBody").innerHTML = rows.join("") || `<tr><td colspan="9" class="muted">No subscriptions configured.</td></tr>`;
}

// ---------- live events ----------

async function refreshEvents() {
  const list = await api("/api/recent");
  const open = new Set($$("#eventsList details[open]").map(d => d.dataset.key));
  $("#eventsList").innerHTML = list.length
    ? list.map(e => {
        const key = `${e.receivedUtc}|${e.eventId}`;
        return `<details data-key="${esc(key)}" ${open.has(key) ? "open" : ""}>
          <summary><span class="t">${new Date(e.receivedUtc).toLocaleTimeString()}</span>
            <span class="s">${esc(e.subscription)} · ${esc(e.eventId)}</span>
            <span class="p">${esc(e.preview)}</span></summary>
          <pre>${esc(prettyPayload(e.preview))}</pre>
        </details>`;
      }).join("")
    : `<div class="muted">No events yet.</div>`;
}

function prettyPayload(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

// ---------- configuration ----------

function fillFacilities() {
  $("[name=facility]").innerHTML = FACILITIES.map((f, i) => `<option value="${i}">${i} – ${f}</option>`).join("");
}

async function loadConfig() {
  config = await api("/api/config");
  const form = $("#syslogForm");
  for (const el of $$("[name]", form)) {
    const v = config.syslog[el.name];
    if (el.type === "checkbox") el.checked = !!v;
    else el.value = v ?? "";
  }
  renderSubscriptions();
  setMsg($("#saveMsg"), "");
}

function readSyslogForm() {
  const out = { ...config.syslog };
  for (const el of $$("#syslogForm [name]")) {
    if (el.type === "checkbox") out[el.name] = el.checked;
    else if (el.type === "number" || el.name === "facility") out[el.name] = Number(el.value);
    else out[el.name] = el.value;
  }
  return out;
}

function renderSubscriptions() {
  const host = $("#subsEditor");
  host.innerHTML = "";
  config.subscriptions.forEach((sub, idx) => host.appendChild(buildSubCard(sub, idx)));
  if (!config.subscriptions.length)
    host.innerHTML = `<div class="muted">No subscriptions. Add one with the buttons above.</div>`;
}

function buildSubCard(sub, idx) {
  const node = $("#subTemplate").content.firstElementChild.cloneNode(true);
  node.dataset.idx = idx;
  for (const el of $$("[data-f]", node)) {
    const v = sub[el.dataset.f];
    if (el.type === "checkbox") el.checked = !!v;
    else el.value = v ?? "";
    el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", () => {
      sub[el.dataset.f] = el.type === "checkbox" ? el.checked : el.value;
      node.classList.toggle("disabled", !sub.enabled);
    });
  }
  node.classList.toggle("disabled", !sub.enabled);
  $("[data-f=channel]", node).addEventListener("focus", loadChannels, { once: true });

  $("[data-act=remove]", node).addEventListener("click", () => {
    if (!confirm(`Remove subscription "${sub.name || sub.channel}"?`)) return;
    config.subscriptions.splice(idx, 1);
    renderSubscriptions();
  });

  $("[data-act=probe]", node).addEventListener("click", async () => {
    const msg = $(".probe-msg", node);
    setMsg(msg, "Testing…");
    try {
      const r = await api("/api/subscriptions/probe", { method: "POST", body: JSON.stringify(sub) });
      setMsg(msg, r.message, r.ok ? "ok" : "warn");
    } catch (e) {
      setMsg(msg, e.message, "bad");
    }
  });
  return node;
}

function addSubscription(preset) {
  const p = PRESETS[preset];
  config.subscriptions.push({
    id: crypto.randomUUID().replaceAll("-", ""),
    enabled: true,
    payloadFormat: "Json",
    includeRenderedMessage: false,
    resumeFromLastPosition: true,
    readExistingOnFirstStart: false,
    ...p,
  });
  renderSubscriptions();
  $("#subsEditor").lastElementChild?.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function loadChannels() {
  if (channelsLoaded) return;
  channelsLoaded = true;
  try {
    const names = await api("/api/channels");
    $("#channelList").innerHTML = names.map(n => `<option value="${esc(n)}">`).join("");
  } catch {
    channelsLoaded = false;
  }
}

async function saveConfig() {
  const btn = $("#saveBtn");
  const msg = $("#saveMsg");
  btn.disabled = true;
  setMsg(msg, "Saving…");
  try {
    const body = { syslog: readSyslogForm(), subscriptions: config.subscriptions };
    const r = await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
    await loadConfig();
    if (r.warnings?.length) setMsg(msg, `Saved and applied, with warnings:\n${r.warnings.join("\n")}`, "warn");
    else setMsg(msg, "Saved and applied.", "ok");
  } catch (e) {
    setMsg(msg, `Not saved:\n${e.message}`, "bad");
  } finally {
    btn.disabled = false;
  }
}

async function sendTest() {
  const msg = $("#saveMsg");
  try {
    await api("/api/test", { method: "POST", body: "{}" });
    setMsg(msg, "Test message queued – check the Overview tab and your syslog server.", "ok");
  } catch (e) {
    setMsg(msg, `Test failed: ${e.message}`, "bad");
  }
}

// ---------- wiring ----------

function showTab(name) {
  $$(".tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach(t => t.classList.toggle("active", t.id === `tab-${name}`));
  if (name === "events") refreshEvents().catch(() => {});
  try { sessionStorage.setItem("bluefwd.tab", name); } catch { /* storage unavailable */ }
}

$$(".tabs button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));
$$("[data-preset]").forEach(b => b.addEventListener("click", () => addSubscription(b.dataset.preset)));
$("#saveBtn").addEventListener("click", saveConfig);
$("#reloadBtn").addEventListener("click", () => loadConfig().catch(e => setMsg($("#saveMsg"), e.message, "bad")));
$("#testBtn").addEventListener("click", sendTest);

fillFacilities();
loadConfig().catch(e => setMsg($("#saveMsg"), `Could not load configuration: ${e.message}`, "bad"));
refreshStatus();
setInterval(refreshStatus, 2000);
setInterval(() => {
  if ($("#tab-events").classList.contains("active") && $("#autoRefresh").checked)
    refreshEvents().catch(() => {});
}, 2000);

try { showTab(sessionStorage.getItem("bluefwd.tab") || "overview"); } catch { showTab("overview"); }
