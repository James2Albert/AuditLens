"use strict";

const state = {
  view: "overview",
  scanId: null,
  scan: null,
  poll: null,
  filters: { severity: "all", detector: "all", exploitability: "all", verification: "all", q: "" },
  selectedFinding: null,
  selectedPath: null,
  sourceFile: null,
  highlight: null,
  pathTab: "graph",
  verifyTab: "trace",
  status: null,
  evidence: {},
  ledger: {},
  busy: {},
  flash: null,
  patchEditor: null,
};

const SEV_CLASS = { High: "high", Medium: "medium", Low: "low", Informational: "info", Optimization: "info" };
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    const detail = Array.isArray(body.detail) ? body.detail.map((d) => d.msg).join("; ") : body.detail;
    throw new Error(detail || r.statusText);
  }
  return r.json();
};
const postJSON = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
const findingUrl = (f, suffix) => `/api/scans/${state.scan.id}/findings/${f.id}/${suffix}`;

/* Runs a long backend action with a busy flag, then refreshes scan + evidence. */
async function runAction(key, findingId, fn, okMessage) {
  state.busy[key] = true; state.flash = null; render();
  try {
    await fn();
    if (okMessage) state.flash = { kind: "ok", msg: okMessage };
  } catch (e) {
    state.flash = { kind: "error", msg: e.message };
  } finally {
    delete state.busy[key];
    delete state.evidence[findingId];
    delete state.ledger[state.scanId];
    try { state.scan = await api(`/api/scans/${state.scanId}`); } catch (e) { state.flash = { kind: "error", msg: "Could not refresh scan: " + e.message }; }
    render();
  }
}
function flashBanner() {
  if (!state.flash) return null;
  const b = el("div", "flash " + state.flash.kind, esc(state.flash.msg));
  const x = el("button", "btn ghost", "Dismiss"); x.onclick = () => { state.flash = null; render(); };
  b.append(x);
  return b;
}
function spinnerInline(label) { return el("span", "busy-inline", `<span class="spin-sm"></span>${esc(label)}`); }

/* ---------- appearance: Light / Dark / System ---------- */
const THEME_KEY = "auditlens.theme";
const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");
const themePref = () => document.documentElement.dataset.themePref || "system";
function applyTheme(pref) {
  const root = document.documentElement;
  root.dataset.themePref = pref;
  root.dataset.theme = pref === "system" ? (darkQuery.matches ? "dark" : "light") : pref;
}
function announce(text) {
  const a = document.getElementById("announcer");
  if (!a) return;
  a.textContent = "";
  setTimeout(() => { a.textContent = text; }, 30);
}
function setTheme(pref) {
  try { localStorage.setItem(THEME_KEY, pref); } catch (e) { /* storage blocked: applies for this session only */ }
  applyTheme(pref);
  renderThemeSwitch();
  announce(`Appearance set to ${pref}${pref === "system" ? `, currently ${document.documentElement.dataset.theme}` : ""}`);
}
/* Only re-resolves the theme attribute; views are never re-rendered, so state is kept. */
darkQuery.addEventListener("change", () => {
  if (themePref() === "system") { applyTheme("system"); renderThemeSwitch(); }
});
const THEME_ICONS = {
  light: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  dark: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
  system: '<rect x="3" y="4" width="18" height="12" rx="1"/><path d="M8 20h8M12 16v4"/>',
};
function renderThemeSwitch() {
  const box = document.getElementById("theme-switch");
  if (!box) return;
  box.innerHTML = "";
  const resolved = document.documentElement.dataset.theme;
  [["light", "Light"], ["dark", "Dark"], ["system", "System"]].forEach(([value, label]) => {
    const checked = themePref() === value;
    const b = el("button", null, `<svg viewBox="0 0 24 24" aria-hidden="true">${THEME_ICONS[value]}</svg><span class="ts-label">${label}</span>`);
    b.type = "button";
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(checked));
    b.setAttribute("aria-label", value === "system" ? `System appearance (follows your OS, currently ${resolved})` : `${label} appearance`);
    b.title = value === "system" ? `Follow the operating system (currently ${resolved})` : `${label} appearance`;
    b.onclick = () => setTheme(value);
    box.append(b);
  });
}

/* ---------- routing ---------- */
function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  syncHash();
  render();
}
function syncHash() {
  const parts = [`view=${state.view}`];
  if (state.scanId) parts.push(`scan=${state.scanId}`);
  if (state.scanId && state.selectedFinding) parts.push(`finding=${state.selectedFinding}`);
  history.replaceState(null, "", "#" + parts.join("&"));
}
function readHash() {
  const h = new URLSearchParams(location.hash.slice(1));
  return { view: h.get("view"), scan: h.get("scan"), finding: h.get("finding") };
}
document.getElementById("nav").addEventListener("click", (e) => {
  const btn = e.target.closest(".nav-item");
  if (btn) setView(btn.dataset.view);
});

/* ---------- scan lifecycle ---------- */
async function startScan(body, isDemo) {
  stopPoll();
  const opts = JSON.stringify(collectOptions());
  let res;
  if (isDemo) {
    res = await api(`/api/scans/demo?options=${encodeURIComponent(opts)}`, { method: "POST" });
  } else {
    body.append("options", opts);
    res = await api(`/api/scans?options=${encodeURIComponent(opts)}`, { method: "POST", body });
  }
  state.scanId = res.id;
  setView("scan");
  pollScan();
}

function collectOptions() {
  const g = (id) => { const e = document.getElementById(id); return e ? e.checked : true; };
  return {
    static_analysis: true,
    ai_triage: g("opt-ai"),
    attack_paths: g("opt-paths"),
    dynamic_verification: g("opt-verify"),
  };
}

function pollScan() {
  stopPoll();
  const tick = async () => {
    try {
      const scan = await api(`/api/scans/${state.scanId}`);
      state.scan = scan;
      updateTopbar();
      if (["overview", "scan", "findings", "paths", "verify", "remediate", "report", "source"].includes(state.view)) render();
      if (scan.status === "done" || scan.status === "failed") { stopPoll(); }
    } catch (e) { stopPoll(); }
  };
  tick();
  state.poll = setInterval(tick, 1000);
}
function stopPoll() { if (state.poll) { clearInterval(state.poll); state.poll = null; } }

function updateTopbar() {
  const s = state.scan;
  const proj = document.getElementById("project-name");
  const file = document.getElementById("project-file");
  proj.firstChild.textContent = s ? s.name + " " : "No contract loaded ";
  file.textContent = s && s.compiler ? s.compiler : "";
  const st = document.getElementById("scan-status");
  const running = s && s.status === "running";
  st.className = "pill " + (running ? "busy" : s && s.status === "done" ? "live" : "");
  st.querySelector("span:last-child").textContent = s ? cap(s.status) : "Idle";
  document.getElementById("nav-findings").textContent = s ? s.findings.length : 0;
  document.getElementById("nav-paths").textContent = s ? s.attack_paths.length : 0;
}
const cap = (s) => s ? s[0].toUpperCase() + s.slice(1) : s;

/* ---------- top-level render ---------- */
function render() {
  const main = document.getElementById("main");
  main.innerHTML = "";
  const s = state.scan;
  const flash = flashBanner();
  if (flash) main.append(flash);
  if (state.view === "scan") return main.append(renderScanProgress());
  if (state.view === "scans") return renderScansList(main);
  if (!s && state.view !== "overview") return main.append(emptyState("No scan yet", "Start a scan to populate this view.", "New Scan", () => setView("scan")));
  ({
    overview: () => renderOverview(main),
    findings: () => renderFindings(main),
    paths: () => renderPaths(main),
    verify: () => renderVerification(main),
    remediate: () => renderRemediation(main),
    source: () => renderSource(main),
    report: () => renderReport(main),
  }[state.view] || (() => renderOverview(main)))();
}

function emptyState(title, msg, btnLabel, onClick) {
  const e = el("div", "empty");
  e.append(el("div", "empty-ico", "◍"), el("h3", null, esc(title)), el("p", null, esc(msg)));
  if (btnLabel) { const b = el("button", "btn primary", esc(btnLabel)); b.onclick = onClick; e.append(b); }
  return e;
}

/* ---------- overview ---------- */
function renderOverview(main) {
  main.append(el("div", "page-title", "Security Overview"));
  main.append(el("div", "page-sub", "Detect → Understand → Trace → Verify → Fix → Prove"));
  if (!state.scan) { main.append(startCard()); return; }
  const sum = state.scan.summary;
  const score = state.scan.summary.security_score;
  const ring = el("div", "card score-card");
  ring.append(scoreRing(score), (() => {
    const d = el("div");
    d.append(el("div", "stat", `<div class="label">Security Score</div>`));
    d.append(el("div", null, `<div class="sub" style="font-size:13px;color:var(--text-dim)">${score >= 80 ? "Low risk surface" : score >= 50 ? "Needs attention" : "High risk — review required"}</div>`));
    return d;
  })());
  const cards = el("div", "grid cards");
  cards.append(
    ring,
    statCard("Exploits Demonstrated", sum.verified_exploits, "exploit", "harmful outcome reproduced in the sandbox"),
    statCard("High", sum.high, "high", "critical severity"),
    statCard("Medium", sum.medium, "medium"),
    statCard("Low", sum.low, ""),
    statCard("AI-Flagged Exploitable", sum.ai_confirmed, "accent", "hypotheses, not proof"),
    statCard("Potential False Positives", sum.potential_false_positives, ""),
    statCard("Attack Paths", sum.attack_paths, "accent"),
    statCard("Patches Validated", sum.patches_validated || 0, "verified", "fix re-tested against the exploit"),
  );
  main.append(cards);
  if (sum.score_breakdown) main.append(scoreBreakdownCard(sum));
  if (sum.ai_scorecard) main.append(scorecardCard(sum.ai_scorecard));
  main.append(sevBreakdown(sum));
}

function scoreBreakdownCard(sum) {
  const c = el("div", "card"); c.style.marginBottom = "14px";
  c.append(el("div", "block-label", `How the score is computed — 100 − ${sum.score_breakdown.reduce((a, d) => a + d.points, 0)} = ${sum.security_score}`));
  if (!sum.score_breakdown.length) { c.append(el("div", "finding-meta", "No High, Medium or Low root causes.")); return c; }
  const t = el("table", "check-table");
  t.append(el("tr", null, "<th>Points</th><th>Root cause</th><th>Severity</th><th>Evidence</th><th>Findings</th>"));
  sum.score_breakdown.forEach((d) => {
    const tr = el("tr", "clickable");
    tr.append(el("td", "mono", `−${d.points}`), el("td", "mono", esc(d.root_cause)), el("td", null, `<span class="sev-badge ${esc(d.impact)}">${esc(d.impact)}</span>`),
      el("td", null, d.verified ? '<span class="tag exploit">! exploit demonstrated</span>' : '<span class="tag">static</span>'),
      el("td", null, esc(d.titles.join(" · "))));
    tr.onclick = () => { state.selectedFinding = d.finding_ids[0]; setView("findings"); };
    t.append(tr);
  });
  c.append(t);
  c.append(el("div", "disclaimer", "One deduction per root cause (vulnerability class × function), weighted by its worst finding: High 20 / Medium 8 / Low 3, or 30 / 15 / 6 when an exploit was verified. Validated patches change the score only when the fixed code is scanned."));
  return c;
}

function scorecardCard(card) {
  const c = el("div", "card"); c.style.marginBottom = "14px";
  c.append(el("div", "block-label", "AI hypothesis scorecard — predictions graded against execution"));
  const row = el("div", "score-row");
  [["confirmed", "Confirmed", "predicted exploitable, exploit demonstrated"], ["refuted", "Refuted", "predicted exploitable, exploit not reproduced"],
   ["missed", "Missed", "predicted safe, exploit demonstrated"], ["correctly_dismissed", "Correctly dismissed", "predicted safe, not reproduced"],
   ["untested", "Untested", "no decisive execution"]].forEach(([k, label, sub]) => {
    const cell = el("div", "score-cell"); cell.append(el("div", "value", String(card[k] || 0)), el("div", "label", esc(label)), el("div", "sub", esc(sub)));
    row.append(cell);
  });
  c.append(row);
  c.append(el("div", "disclaimer", "Counts on this scan only — not a precision or recall figure. Inconclusive runs count as untested."));
  return c;
}

function statCard(label, value, cls, sub) {
  const c = el("div", "card stat " + (cls || ""));
  c.append(el("div", "label", esc(label)));
  c.append(el("div", "value", esc(value)));
  if (sub) c.append(el("div", "sub", esc(sub)));
  return c;
}

function scoreRing(score) {
  const r = 40, circ = 2 * Math.PI * r, off = circ * (1 - score / 100);
  const color = score >= 80 ? "var(--ok)" : score >= 50 ? "var(--medium)" : "var(--high)";
  const wrap = el("div", "ring");
  wrap.innerHTML = `<svg width="92" height="92"><circle cx="46" cy="46" r="${r}" stroke="var(--bg-elev2)" stroke-width="8" fill="none"/><circle cx="46" cy="46" r="${r}" stroke="${color}" stroke-width="8" fill="none" stroke-dasharray="${circ}" stroke-dashoffset="${off}" stroke-linecap="round"/></svg><div class="num">${score}</div>`;
  return wrap;
}

function sevBreakdown(sum) {
  const wrap = el("div", "card");
  wrap.append(el("div", "block-label", "Finding distribution"));
  const total = sum.high + sum.medium + sum.low + sum.informational || 1;
  const bar = el("div", null, `<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;margin:8px 0 14px">
    <div style="width:${sum.high/total*100}%;background:var(--high)"></div>
    <div style="width:${sum.medium/total*100}%;background:var(--medium)"></div>
    <div style="width:${sum.low/total*100}%;background:var(--low)"></div>
    <div style="width:${sum.informational/total*100}%;background:var(--info)"></div></div>`);
  wrap.append(bar);
  const legend = el("div", null, `<div style="display:flex;gap:18px;font-size:12px;color:var(--text-dim)">
    <span><span class="sev-tick high" style="display:inline-block;margin-right:5px"></span>High ${sum.high}</span>
    <span><span class="sev-tick medium" style="display:inline-block;margin-right:5px"></span>Medium ${sum.medium}</span>
    <span><span class="sev-tick low" style="display:inline-block;margin-right:5px"></span>Low ${sum.low}</span>
    <span><span class="sev-tick info" style="display:inline-block;margin-right:5px"></span>Info ${sum.informational}</span></div>`);
  wrap.append(legend);
  return wrap;
}

function startCard() {
  const c = el("div", "card");
  c.append(el("h3", null, "Get started"), el("p", "page-sub", "Analyze a contract to see its security posture."));
  const row = el("div", "btn-row");
  const demo = el("button", "btn primary", "▶ Run demo scan");
  demo.onclick = () => startScan(null, true);
  const up = el("button", "btn", "Upload contract");
  up.onclick = () => setView("scan");
  row.append(demo, up);
  c.append(row);
  return c;
}

window.addEventListener("DOMContentLoaded", async () => {
  renderThemeSwitch();
  try {
    const st = await api("/api/status");
    state.status = st;
    document.querySelector("#ai-status span:last-child").textContent = "AI: " + st.ai_provider;
    const sc = document.getElementById("scan-status");
    if (st.foundry) sc.title = "Sandboxed dynamic verification ready";
  } catch (e) {}
  const h = readHash();
  if (h.scan) { state.scanId = h.scan; state.selectedFinding = h.finding; if (h.view) state.view = h.view; document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === state.view)); pollScan(); }
  else render();
});

/* ---------- new scan / upload ---------- */
function renderScanProgress() {
  const wrap = el("div");
  if (!state.scan || (state.view === "scan" && !state.scanId)) return renderUpload(wrap);
  const s = state.scan;
  if (!s) return renderUpload(wrap);
  wrap.append(el("div", "page-title", "Analysis pipeline"));
  wrap.append(el("div", "page-sub", `${esc(s.name)} · ${esc(s.compiler || "detecting compiler…")}`));
  if (s.error) { const b = el("div", "result-banner verification_error", "⚠ " + esc(s.error)); wrap.append(b); }
  const pipe = el("div", "pipeline");
  s.stages.forEach((st) => {
    const row = el("div", "stage " + st.status);
    const icon = { done: "✓", running: "", failed: "✕", skipped: "–", pending: "" }[st.status] ?? "";
    row.append(el("div", "stage-ico", icon));
    const body = el("div", "stage-body");
    body.append(el("div", "stage-label", esc(st.label)));
    body.append(el("div", "stage-detail" + (st.status === "running" ? " live" : ""), esc(st.detail || statusWord(st.status))));
    row.append(body);
    pipe.append(row);
  });
  wrap.append(pipe);
  if (s.status === "done") {
    const row = el("div", "btn-row"); row.style.marginTop = "18px";
    const b = el("button", "btn primary", "View findings →"); b.onclick = () => setView("findings");
    const o = el("button", "btn", "Overview"); o.onclick = () => setView("overview");
    row.append(b, o, newScanButton()); wrap.append(row);
  } else if (s.status === "failed") {
    const row = el("div", "btn-row"); row.style.marginTop = "18px";
    row.append(newScanButton()); wrap.append(row);
  }
  return wrap;
}
function newScanButton() {
  const n = el("button", "btn", "＋ New scan");
  n.onclick = () => { stopPoll(); state.scanId = null; state.scan = null; state.evidence = {}; updateTopbar(); setView("scan"); };
  return n;
}
const statusWord = (s) => ({ pending: "Waiting…", running: "Running…", skipped: "Skipped", done: "Done" }[s] || "");

function renderUpload(wrap) {
  wrap.append(el("div", "page-title", "Analyze Smart Contract"));
  wrap.append(el("div", "page-sub", "Upload Solidity/Vyper sources. Slither runs first; AI and dynamic checks build on its evidence."));
  const dz = el("div", "dropzone");
  dz.innerHTML = `<h2>Drag &amp; drop .sol / .vy files</h2><p>or select files below</p>`;
  const input = el("input"); input.type = "file"; input.multiple = true; input.accept = ".sol,.vy"; input.className = "hidden";
  const pick = el("button", "btn", "Choose files"); pick.onclick = () => input.click();
  dz.append(pick, el("div", "dz-or", "— OR —"));
  const demo = el("button", "btn primary", "▶ Use bundled vulnerable demo"); demo.onclick = () => startScan(null, true);
  dz.append(demo);
  dz.append(optionsBlock());
  dz.append(input);
  const chosen = el("div", "page-sub"); chosen.style.marginTop = "12px";
  const submit = el("button", "btn primary", "Start analysis"); submit.disabled = true;
  submit.style.marginTop = "10px";
  let files = [];
  const setFiles = (f) => { files = [...f]; chosen.textContent = files.length ? files.map((x) => x.name).join(", ") : ""; submit.disabled = !files.length; };
  input.onchange = () => setFiles(input.files);
  ["dragover", "dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => setFiles(e.dataTransfer.files));
  submit.onclick = () => { const fd = new FormData(); files.forEach((f) => fd.append("files", f)); startScan(fd, false); };
  wrap.append(dz, chosen, submit);
  return wrap;
}

function optionsBlock() {
  const box = el("div", "opt-list");
  const opts = [
    ["opt-ai", "AI Triage", "Reason over Slither's evidence to assess exploitability"],
    ["opt-paths", "Attack Path Analysis", "Build a security graph and trace attacker routes"],
    ["opt-verify", "Dynamic Verification", "Run controlled exploit tests in a sandbox"],
  ];
  opts.forEach(([id, t, d]) => {
    const o = el("label", "opt");
    o.innerHTML = `<input type="checkbox" id="${id}" checked><div><div class="opt-t">${t}</div><div class="opt-d">${d}</div></div>`;
    box.append(o);
  });
  return box;
}

/* ---------- findings ---------- */
function renderFindings(main) {
  const s = state.scan;
  main.append(el("div", "page-title", "Findings"));
  main.append(el("div", "page-sub", `${s.findings.length} static findings · sorted by severity`));
  main.append(findingsToolbar());
  const list = el("div");
  const filtered = s.findings.filter(passesFilter);
  if (!filtered.length) { list.append(emptyState("No matching findings", "Adjust the filters above.")); }
  filtered.forEach((f) => list.append(findingCard(f)));
  main.append(list);
}

function findingsToolbar() {
  const bar = el("div", "toolbar");
  const sev = selectEl("severity", ["all", "High", "Medium", "Low", "Informational"], state.filters.severity);
  const detectors = ["all", ...new Set(state.scan.findings.map((f) => f.detector))];
  const det = selectEl("detector", detectors, state.filters.detector);
  const expl = selectEl("exploitability", ["all", "likely_exploitable", "possibly_exploitable", "likely_false_positive", "unknown"], state.filters.exploitability);
  const ver = selectEl("verification", ["all", "verified_exploit", "not_verified", "inconclusive", "verification_error", "not_run"], state.filters.verification);
  const q = el("input", "search"); q.placeholder = "Search findings…"; q.value = state.filters.q;
  q.oninput = () => { state.filters.q = q.value; refreshFindings(); };
  bar.append(sev, det, expl, ver, q);
  return bar;
}
function selectEl(key, values, current) {
  const s = el("select", "select");
  values.forEach((v) => { const o = el("option", null, v === "all" ? cap(key) + ": all" : v.replace(/_/g, " ")); o.value = v; if (v === current) o.selected = true; s.append(o); });
  s.onchange = () => { state.filters[key] = s.value; refreshFindings(); };
  return s;
}
function refreshFindings() { const main = document.getElementById("main"); main.innerHTML = ""; renderFindings(main); }
function passesFilter(f) {
  const fl = state.filters;
  if (fl.severity !== "all" && f.impact !== fl.severity) return false;
  if (fl.detector !== "all" && f.detector !== fl.detector) return false;
  if (fl.exploitability !== "all" && (!f.assessment || f.assessment.classification !== fl.exploitability)) return false;
  if (fl.verification !== "all" && f.verification.status !== fl.verification) return false;
  if (fl.q && !(`${f.title} ${f.detector} ${f.function || ""}`.toLowerCase().includes(fl.q.toLowerCase()))) return false;
  return true;
}

function findingCard(f) {
  const card = el("div", "finding" + (state.selectedFinding === f.id ? " open" : ""));
  const head = el("div", "finding-head");
  head.append(el("span", "sev-badge " + f.impact, f.impact));
  const mid = el("div");
  mid.append(el("div", "finding-title", esc(f.title)));
  const loc = f.location ? `${f.location.file}:${(f.location.lines || [])[0] || "?"}` : f.detector;
  mid.append(el("div", "finding-meta", esc((f.function || f.detector) + "  ·  " + loc)));
  head.append(mid);
  const tags = el("div", "finding-tags");
  if (f.origin === "auditlens-graph") tags.append(el("span", "tag", "graph rule"));
  if (f.assessment) tags.append(el("span", "tag ai", assessLabel(f.assessment)));
  const vs = f.verification.status;
  if (vs === "verified_exploit") tags.append(el("span", "tag exploit", "! Exploit demonstrated"));
  else if (vs === "inconclusive") tags.append(el("span", "tag inconclusive", "Inconclusive"));
  else if (vs === "not_verified") tags.append(el("span", "tag", "Not reproduced"));
  else if (vs === "verification_error") tags.append(el("span", "tag error", "Verification error"));
  if (f.remediation) tags.append(el("span", "tag patch-" + f.remediation.status, "Patch " + f.remediation.status));
  head.append(tags);
  head.onclick = () => { state.selectedFinding = state.selectedFinding === f.id ? null : f.id; syncHash(); refreshFindings(); };
  card.append(head);
  if (state.selectedFinding === f.id) card.append(findingBody(f));
  return card;
}
function assessLabel(a) {
  const src = (a.provider === "heuristic" || !a.provider) ? "Heuristic" : "AI";
  return `${src}: ${a.classification.replace(/_/g, " ")} ${a.confidence}%`;
}

function findingBody(f) {
  const body = el("div", "finding-body");
  const stat = block("static", f.origin === "auditlens-graph" ? "Static inference — AuditLens graph rule over Slither data (deterministic)" : "Static fact — Slither (deterministic)");
  stat.append(el("div", "pre", esc(f.description)));
  if (f.evidence) {
    const ev = f.evidence;
    const kv = el("dl", "kv");
    const rows = [["Contract", ev.contract], ["Function", ev.signature], ["Visibility", ev.visibility],
      ["Protected", ev.is_protected], ["Sends ETH", ev.sends_eth],
      ["State written", ev.state_written.join(", ") || "—"], ["External calls", (ev.low_level_calls.concat(ev.external_calls)).join(", ") || "—"]];
    rows.forEach(([k, v]) => { kv.append(el("dt", null, k), el("dd", null, esc(String(v)))); });
    stat.append(kv);
  }
  if (f.evidence && f.evidence.code) { stat.append(el("div", "block-label", "Code evidence")); stat.append(el("div", "pre code-evidence", esc(f.evidence.code))); }
  body.append(stat);

  if (f.assessment) body.append(aiBlock(f.assessment));

  const dyn = block("dynamic", "Execution evidence — sandboxed Foundry test");
  dyn.append(verificationSummary(f));
  body.append(dyn);

  body.append(evidenceBlock(f));
  body.append(findingNav(f, "findings"));
  return body;
}

/* Buttons that move between the views of one finding without losing scan context. */
function findingNav(f, here) {
  const actions = el("div", "btn-row"); actions.style.marginTop = "16px";
  const add = (label, view, fn) => { if (view === here) return; const b = el("button", "btn", label); b.onclick = fn; actions.append(b); };
  add("Finding", "findings", () => { state.selectedFinding = f.id; setView("findings"); });
  add("Source", "source", () => openSource(f));
  const path = state.scan.attack_paths.find((p) => p.finding_ids.includes(f.id) && p.category === f.category) || state.scan.attack_paths.find((p) => p.finding_ids.includes(f.id));
  if (path) add("Attack path", "paths", () => openPath(path.id));
  if (hasVerification(f)) add("Verification", "verify", () => { state.selectedFinding = f.id; setView("verify"); });
  add("Remediation", "remediate", () => { state.selectedFinding = f.id; setView("remediate"); });
  return actions;
}
const AUTO_PATCH = ["reentrancy-eth", "auditlens-privilege-escalation"];
const hasVerification = (f) => f.verification.status !== "not_run" || f.category === "reentrancy" || f.category === "access-control";

async function loadEvidence(fid) {
  state.evidence[fid] = { loading: true };
  try { state.evidence[fid] = await api(`/api/scans/${state.scan.id}/findings/${fid}/evidence`); }
  catch (e) { state.evidence[fid] = { error: e.message }; }
  if (["findings", "verify", "remediate"].includes(state.view)) render();
}

function evidenceBlock(f) {
  const b = block("evidence", "Security evidence ledger");
  const rec = state.evidence[f.id];
  if (!rec) { loadEvidence(f.id); b.append(spinnerInline("Loading ledger…")); return b; }
  if (rec.loading) { b.append(spinnerInline("Loading ledger…")); return b; }
  if (rec.error) { b.append(el("div", "flash error", "Could not load evidence: " + esc(rec.error))); return b; }
  const last = (xs) => xs && xs.length ? xs[xs.length - 1] : null;
  const ex = last(rec.executions), rem = last(rec.remediations);
  const rows = [
    ["Static fact", "static", rec.static_fact, rec.static_fact ? `${f.detector} · ${f.impact}` : "missing"],
    ["AI hypothesis", "ai", rec.ai_hypothesis, rec.ai_hypothesis ? `${rec.ai_hypothesis.payload.classification.replace(/_/g, " ")} · ${rec.ai_hypothesis.payload.confidence}% · needs validation` : "none (AI stage skipped or not applicable)"],
    ["Execution evidence", "dynamic", ex, ex ? `${vStatusLabel(ex.payload.status)}${ex.payload.run ? " · run " + ex.payload.run.run_id : " · not executed"}` : "no test run"],
    ["Remediation evidence", "remediation", rem, rem ? (rem.payload.stage === "validated" ? `patch ${rem.payload.patch_id} · ${rem.payload.status}` : `patch ${rem.payload.id} proposed · not validated`) : "no patch yet"],
  ];
  const t = el("table", "ledger-table");
  t.append(el("tr", null, "<th>Category</th><th>Latest record</th><th>Entries</th><th>Entry hash</th>"));
  const counts = { static: rec.static_fact ? 1 : 0, ai: rec.ai_hypothesis ? 1 : 0, dynamic: rec.executions.length, remediation: rec.remediations.length };
  rows.forEach(([label, cls, entry, text]) => {
    const tr = el("tr");
    tr.append(el("td", null, `<span class="cat-dot ${cls}"></span>${esc(label)}`), el("td", null, esc(text)),
      el("td", null, String(counts[cls])), el("td", "mono", entry ? esc(entry.entry_hash.slice(0, 16)) + "…" : "—"));
    t.append(tr);
  });
  b.append(t);
  const chain = rec.chain;
  b.append(el("div", "disclaimer", chain.valid
    ? `Ledger chain intact: ${chain.entries} entries, head ${esc(chain.head.slice(0, 16))}…. ${esc(chain.guarantee)}`
    : `⚠ Ledger chain broken at entry #${chain.broken_at}.`));
  if (!rec.current_run_recorded) b.append(el("div", "flash error", "The displayed run is not in the ledger."));
  if (rec.attack_paths.length) b.append(el("div", "finding-meta", "Linked attack paths: " + esc([...new Set(rec.attack_paths.map((e) => `${e.payload.path_id} (${e.payload.evidence_status})`))].join(", "))));
  return b;
}

function block(kind, label) { const b = el("div", "block " + kind); b.append(el("div", "block-label", esc(label))); return b; }

function aiBlock(a) {
  const src = (a.provider === "heuristic" || !a.provider) ? "Heuristic assessment" : `AI assessment · ${esc(a.model || a.provider)}`;
  const b = block("ai", src + " — hypothesis");
  if (a.raw_error) { b.append(el("div", "pre", esc(a.raw_error))); return b; }
  const cls = el("div", "classification", `${esc(a.classification.replace(/_/g, " "))}`);
  b.append(cls);
  b.append(el("div", "confidence-bar", `<span style="width:${a.confidence}%"></span>`));
  b.append(el("div", "disclaimer", `Confidence ${a.confidence}% — assessment, not proof. Verify dynamically before acting.`));
  if (a.why_it_matters) { b.append(el("div", "block-label", "Why it matters")); b.append(el("div", null, esc(a.why_it_matters))); }
  if (a.preconditions && a.preconditions.length) { b.append(el("div", "block-label", "Exploit conditions")); b.append(checklist(a.preconditions)); }
  if (a.evidence && a.evidence.length) { b.append(el("div", "block-label", "Evidence")); b.append(checklist(a.evidence)); }
  if (a.attack_steps && a.attack_steps.length) { b.append(el("div", "block-label", "Candidate attack")); b.append(orderedSteps(a.attack_steps)); }
  if (a.remediation) { b.append(el("div", "block-label", "Remediation")); b.append(el("div", null, esc(a.remediation))); }
  return b;
}
function checklist(items) { const ul = el("ul", "checklist"); items.forEach((i) => ul.append(el("li", null, esc(i)))); return ul; }
function orderedSteps(items) { const ol = el("ul", "steps-list"); items.forEach((i) => ol.append(el("li", null, esc(i)))); return ol; }

function verificationSummary(f) {
  const v = f.verification;
  const d = el("div");
  d.append(el("div", "result-banner " + v.status, verificationIcon(v.status) + " " + esc(vStatusLabel(v.status))));
  d.append(el("div", "status-explain", esc(STATUS_EXPLAIN[v.status] || "")));
  if (v.summary) d.append(el("div", "disclaimer", esc(v.summary)));
  if (v.status === "not_verified" || v.status === "inconclusive" || v.status === "verification_error")
    d.append(el("div", "disclaimer", "The static warning above still stands; this only describes what the test could show."));
  if (v.run) d.append(el("div", "finding-meta", esc(`run ${v.run.run_id} · ${v.run.test_contract}::${v.run.test_function} · ${v.run.sandboxed ? "sandboxed" : "NOT sandboxed"}`)));
  if (v.impact && v.impact.length) d.append(impactTable(v));
  return d;
}

function impactTable(v) {
  const wrap = el("div");
  wrap.append(el("div", "block-label", "Measured impact — local test fixture, not a production estimate"));
  const t = el("table", "impact-table");
  t.append(el("tr", null, "<th>Measurement</th><th>Before</th><th>After</th><th>Change</th>"));
  v.impact.forEach((m) => {
    const tr = el("tr", m.violated ? "violated" : "");
    const flag = m.violated === true ? ' <span class="tag error">violated</span>' : m.violated === false ? ' <span class="tag verified">holds</span>' : "";
    tr.append(el("td", null, esc(m.label) + flag), el("td", "mono", esc(m.before || "")), el("td", "mono", esc(m.after || "")), el("td", "mono", esc(m.delta || "")));
    t.append(tr);
  });
  wrap.append(t);
  return wrap;
}
const vStatusLabel = (s) => ({ verified_exploit: "EXPLOIT DEMONSTRATED", not_verified: "NOT VERIFIED", inconclusive: "INCONCLUSIVE", verification_error: "VERIFICATION ERROR", not_run: "Not run for this finding" }[s] || s);
const verificationIcon = (s) => ({ verified_exploit: "!", not_verified: "✕", inconclusive: "?", verification_error: "⚠", not_run: "○" }[s] || "○");

const STATUS_EXPLAIN = {
  verified_exploit: "The exploit test's assertion succeeded: the harmful outcome was reproduced in the sandbox. This is a confirmed problem, not a passing check.",
  not_verified: "The attack ran and its security assertion failed: no violation was observed in this fixture. The static warning still stands.",
  inconclusive: "The run could not decide (unrelated revert, attack path not exercised, no template, or no sandbox).",
  verification_error: "Compilation, setUp(), timeout or tooling failure. Not evidence either way.",
  not_run: "No exploit test has been executed for this finding.",
};

/* ---------- source viewer ---------- */
function openSource(f) {
  state.sourceFile = f.location ? f.location.file : Object.keys(state.scan.sources)[0];
  state.highlight = { finding: f.id, lines: (f.location && f.location.lines) || [], related: (f.related || []).flatMap((r) => r.lines || []) };
  setView("source");
}
function renderSource(main) {
  const s = state.scan;
  const files = Object.keys(s.sources);
  if (!files.length) return main.append(emptyState("No source", "Sources were not captured."));
  if (!state.sourceFile) state.sourceFile = files[0];
  main.append(el("div", "page-title", "Source"));
  const picker = selectEl2(files, state.sourceFile, (v) => { state.sourceFile = v; refresh(); });
  const sub = el("div", "toolbar"); sub.append(picker); main.append(sub);
  const layout = el("div", "source-wrap");
  layout.append(codePanel(state.sourceFile, s.sources[state.sourceFile]));
  layout.append(sourceExplain());
  main.append(layout);
}
function selectEl2(values, current, onChange) {
  const s = el("select", "select");
  values.forEach((v) => { const o = el("option", null, v); o.value = v; if (v === current) o.selected = true; s.append(o); });
  s.onchange = () => onChange(s.value);
  return s;
}
function codePanel(file, code) {
  const panel = el("div", "code-panel");
  panel.append(el("div", "code-head", esc(file)));
  const scroll = el("div", "code-scroll");
  const table = el("table", "code");
  const hl = state.highlight || { lines: [], related: [] };
  const hlSet = new Set(hl.lines), relSet = new Set(hl.related);
  (code || "").split("\n").forEach((line, i) => {
    const n = i + 1;
    const tr = el("tr", hlSet.has(n) ? "hl" : relSet.has(n) ? "rel" : "");
    tr.append(el("td", "ln", String(n)), el("td", null, esc(line) || " "));
    table.append(tr);
  });
  scroll.append(table); panel.append(scroll);
  setTimeout(() => { const first = panel.querySelector("tr.hl"); if (first) first.scrollIntoView({ block: "center" }); }, 30);
  return panel;
}
function sourceExplain() {
  const p = el("div", "explain-panel");
  const f = state.scan.findings.find((x) => state.highlight && x.id === state.highlight.finding);
  if (!f) { p.append(el("div", "empty", "Select a finding to see its explanation here.")); return p; }
  p.append(el("span", "sev-badge " + f.impact, f.impact));
  p.append(el("h3", null, esc(f.title))); p.style.paddingTop = "16px";
  p.append(el("div", "finding-meta", esc(f.function || "")));
  if (f.assessment && !f.assessment.raw_error) {
    p.append(el("div", "block-label", "Why it matters"));
    p.append(el("div", null, esc(f.assessment.why_it_matters || f.assessment.summary)));
  }
  if (f.location) {
    p.append(el("div", "block-label", "Highlighted"));
    p.append(el("div", "finding-meta", esc("Lines " + (f.location.lines || []).join(", "))));
  }
  const b = el("button", "btn", "Back to findings"); b.style.marginTop = "14px"; b.onclick = () => setView("findings");
  p.append(b);
  return p;
}

/* ---------- attack paths ---------- */
function openPath(id) { state.selectedPath = id; setView("paths"); }
function renderPaths(main) {
  const paths = state.scan.attack_paths;
  main.append(el("div", "page-title", "Attack Paths"));
  main.append(el("div", "page-sub", `${paths.length} candidate paths derived from Slither's call graph. Solid evidence badges mean a test executed the path; everything else is a static hypothesis.`));
  if (!paths.length) return main.append(emptyState("No attack paths", "None were derived for this contract."));
  if (!state.selectedPath || !paths.find((p) => p.id === state.selectedPath)) {
    const f = state.scan.findings.find((x) => x.id === state.selectedFinding);
    const linked = f && (paths.find((p) => p.finding_ids.includes(f.id) && p.category === f.category) || paths.find((p) => p.finding_ids.includes(f.id)));
    state.selectedPath = (linked || paths[0]).id;
  }
  const picker = el("div", "toolbar");
  picker.append(selectEl2(paths.map((p) => p.id), state.selectedPath, (v) => { state.selectedPath = v; refresh(); }));
  const path = paths.find((p) => p.id === state.selectedPath);
  const catTag = el("span", "tag", path.category); picker.append(catTag);
  picker.append(el("span", "path-status small " + path.evidence_status, esc(PATH_STATUS[path.evidence_status] || path.evidence_status)));
  main.append(picker);
  const tabs = el("div", "tabs");
  ["graph", "steps"].forEach((t) => { const b = el("button", "tab" + (state.pathTab === t ? " active" : ""), cap(t) + " view"); b.onclick = () => { state.pathTab = t; refresh(); }; tabs.append(b); });
  main.append(tabs);
  const layout = el("div", "graph-layout");
  const left = el("div", "graph-card");
  if (state.pathTab === "graph") left.append(renderGraph(path)); else left.append(renderSteps(path));
  layout.append(left, pathDetail(path));
  main.append(layout);
}

function renderSteps(path) {
  const wrap = el("div"); wrap.style.padding = "12px";
  wrap.append(el("h3", null, esc(path.title)));
  const ol = el("ul", "steps-list"); ol.style.marginTop = "14px";
  path.narrative.forEach((n) => ol.append(el("li", null, esc(n))));
  wrap.append(ol);
  return wrap;
}

const PATH_STATUS = {
  "static-hypothesis": "Static hypothesis — graph connectivity, not proof",
  "dynamically-demonstrated": "Dynamically demonstrated by an executed test",
  "not-reproduced": "Attempted dynamically — not reproduced",
  inconclusive: "Dynamic attempt inconclusive",
};
const NODE_COLORS = {
  attacker: "var(--node-attacker)", "entry-point": "var(--node-entry)", "vulnerable-function": "var(--node-vulnerable)",
  "external-call": "var(--node-external)", "state-mutation": "var(--node-state)", "attacker-controlled": "var(--node-controlled)", state: "var(--node-state)",
};
function renderGraph(path) {
  const NS = "http://www.w3.org/2000/svg";
  const nodes = path.nodes, n = nodes.length;
  const W = 640, rowH = 82, boxW = 220, boxH = 46, cx = W / 2;
  const H = n * rowH + 40;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("width", "100%");
  const pos = {}; nodes.forEach((nd, i) => { pos[nd.id] = { x: cx, y: 30 + i * rowH }; });
  const defs = document.createElementNS(NS, "defs");
  defs.innerHTML = `<marker id="arw" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6" style="fill: var(--graph-edge)"/></marker>`;
  svg.append(defs);
  path.edges.forEach(([a, b, rel]) => {
    if (!pos[a] || !pos[b]) return;
    const p1 = pos[a], p2 = pos[b];
    const line = document.createElementNS(NS, "path");
    const backward = p2.y <= p1.y;
    if (backward) {
      const offX = cx + boxW / 2 + 40;
      line.setAttribute("d", `M${p1.x + boxW/2},${p1.y} C${offX},${p1.y} ${offX},${p2.y} ${p2.x + boxW/2},${p2.y}`);
    } else {
      line.setAttribute("d", `M${p1.x},${p1.y + boxH/2} L${p2.x},${p2.y - boxH/2}`);
    }
    line.setAttribute("fill", "none"); line.style.stroke = "var(--graph-edge)"; line.setAttribute("stroke-width", "1.5");
    line.setAttribute("marker-end", "url(#arw)"); if (backward) line.setAttribute("stroke-dasharray", "4 3");
    svg.append(line);
    if (rel) {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", backward ? cx + boxW/2 + 46 : cx + 8); t.setAttribute("y", (p1.y + p2.y) / 2);
      t.style.fill = "var(--graph-edge)"; t.setAttribute("font-size", "10"); t.textContent = rel;
      svg.append(t);
    }
  });
  nodes.forEach((nd) => {
    const p = pos[nd.id];
    const g = document.createElementNS(NS, "g");
    g.setAttribute("transform", `translate(${p.x - boxW/2},${p.y - boxH/2})`);
    g.setAttribute("class", "node-rect");
    const color = NODE_COLORS[nd.kind] || "var(--node-entry)";
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", boxW); rect.setAttribute("height", boxH); rect.setAttribute("rx", "8");
    rect.style.fill = "var(--graph-node-bg)"; rect.style.stroke = color; rect.setAttribute("stroke-width", "1.6");
    g.append(rect);
    const bar = document.createElementNS(NS, "rect");
    bar.setAttribute("width", "4"); bar.setAttribute("height", boxH); bar.setAttribute("rx", "2"); bar.style.fill = color;
    g.append(bar);
    const label = document.createElementNS(NS, "text");
    label.setAttribute("x", "14"); label.setAttribute("y", "20"); label.style.fill = "var(--graph-text)"; label.setAttribute("font-size", "12.5");
    label.setAttribute("font-family", "monospace");
    label.textContent = truncate(nd.label, 26); g.append(label);
    const kind = document.createElementNS(NS, "text");
    kind.setAttribute("x", "14"); kind.setAttribute("y", "36"); kind.setAttribute("font-size", "10"); kind.style.fill = color;
    kind.textContent = nd.kind.replace(/-/g, " "); g.append(kind);
    g.setAttribute("tabindex", "0");
    g.setAttribute("role", "button");
    g.setAttribute("aria-label", `${nd.label}, ${nd.kind.replace(/-/g, " ")}. Show detail`);
    g.onclick = () => showNodeDetail(nd);
    g.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showNodeDetail(nd); } };
    svg.append(g);
  });
  return svg;
}
const truncate = (s, n) => s.length > n ? s.slice(0, n - 1) + "…" : s;

function pathDetail(path) {
  const d = el("div", "graph-detail"); d.id = "path-detail";
  d.append(el("h3", null, esc(path.title)));
  d.append(el("div", "disclaimer", "Derived from: " + esc(path.derived_from)));
  d.append(el("div", "path-status " + path.evidence_status, esc(PATH_STATUS[path.evidence_status] || path.evidence_status)));
  d.append(el("div", "finding-meta", esc(path.evidence_note)));
  if (path.patch_status) d.append(el("div", "finding-meta", "Linked patch validation: " + esc(path.patch_status)));
  if (path.run_ids.length) {
    const f = state.scan.findings.find((x) => x.verification.run && path.run_ids.includes(x.verification.run.run_id));
    if (f) { const b = el("button", "btn", "Open run " + esc(path.run_ids[0])); b.style.marginTop = "8px"; b.onclick = () => { state.selectedFinding = f.id; setView("verify"); }; d.append(b); }
  }
  if (path.finding_ids.length) {
    d.append(el("div", "block-label", "Related findings"));
    path.finding_ids.forEach((fid) => {
      const f = state.scan.findings.find((x) => x.id === fid); if (!f) return;
      const b = el("button", "btn ghost", esc(f.title)); b.style.padding = "4px 0"; b.onclick = () => { state.selectedFinding = fid; setView("findings"); };
      d.append(b);
    });
  }
  d.append(el("div", "block-label", "Click a node for detail"));
  d.append(el("div", "finding-meta", "Select any node in the graph."));
  return d;
}
function showNodeDetail(nd) {
  const d = document.getElementById("path-detail"); if (!d) return;
  d.innerHTML = "";
  d.append(el("h3", null, esc(nd.label)));
  d.append(el("span", "tag", nd.kind.replace(/-/g, " ")));
  if (nd.reason) { d.append(el("div", "block-label", "Why it matters")); d.append(el("div", null, esc(nd.reason))); }
  if (nd.source) {
    d.append(el("div", "block-label", "Source"));
    d.append(el("div", "finding-meta", esc(nd.source.file + ":" + (nd.source.lines || []).join(","))));
    if (nd.function) { const b = el("button", "btn", "Open source"); b.style.marginTop = "10px"; b.onclick = () => { state.sourceFile = nd.source.file; state.highlight = { lines: nd.source.lines || [], related: [] }; setView("source"); }; d.append(b); }
  }
}


/* ---------- drain timeline chart (values come only from the executed test's logs) ---------- */
const SERIES_COLORS = ["var(--series-1)", "var(--series-2)"]; // categorical slots 1-2, validated per theme
const toEth = (wei) => Number(BigInt(wei) * 1000n / 10n ** 18n) / 1000;
function timelineOf(obs) { return obs && obs.contract_balance_timeline ? obs.contract_balance_timeline.split(",").map(toEth) : null; }
function stepLabel(i, n) { return i === 0 ? "before attack" : i === n - 1 ? "after attack" : `payout callback ${i}`; }

function drainChart(series, owedEth, title) {
  const NS = "http://www.w3.org/2000/svg";
  const wrap = el("div", "chart-card");
  wrap.append(el("div", "block-label", esc(title)));
  if (series.length > 1) {
    const legend = el("div", "chart-legend");
    series.forEach((s, i) => legend.append(el("span", null, `<span class="key" style="background:${SERIES_COLORS[i]}"></span>${esc(s.name)}`)));
    wrap.append(legend);
  }
  const W = 680, H = 260, m = { l: 52, r: 150, t: 14, b: 34 };
  const maxN = Math.max(...series.map((s) => s.values.length));
  const top = Math.max(owedEth || 0, ...series.flatMap((s) => s.values)) || 1;
  const maxY = top * 1.2;
  const x = (i) => m.l + (maxN > 1 ? i * (W - m.l - m.r) / (maxN - 1) : 0);
  const y = (v) => m.t + (1 - v / maxY) * (H - m.t - m.b);
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("width", "100%"); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", title);
  const STYLE_ATTRS = new Set(["fill", "stroke"]);
  const add = (tag, attrs, text) => {
    const n = document.createElementNS(NS, tag);
    Object.entries(attrs).forEach(([k, v]) => { if (STYLE_ATTRS.has(k)) n.style[k] = v; else n.setAttribute(k, v); });
    if (text != null) n.textContent = text;
    svg.append(n);
    return n;
  };
  [0, top / 2, top].forEach((v) => {
    add("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: "var(--chart-grid)", "stroke-width": 1 });
    add("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end", fill: "var(--chart-axis)", "font-size": 11 }, `${+v.toFixed(2)} ETH`);
  });
  add("text", { x: m.l, y: H - 8, fill: "var(--chart-axis)", "font-size": 11 }, "before attack");
  add("text", { x: W - m.r, y: H - 8, fill: "var(--chart-axis)", "font-size": 11, "text-anchor": "end" }, "after attack");
  if (owedEth) {
    add("line", { x1: m.l, x2: W - m.r, y1: y(owedEth), y2: y(owedEth), stroke: "var(--chart-axis)", "stroke-width": 1 });
    add("text", { x: m.l + 6, y: y(owedEth) - 8, fill: "var(--chart-axis)", "font-size": 11 }, `owed to honest depositor: ${owedEth} ETH`);
  }
  const tip = el("div", "chart-tip hidden");
  series.forEach((s, si) => {
    const color = SERIES_COLORS[si];
    const last = s.values.length - 1;
    const pts = s.values.map((v, i) => [x(i === last ? maxN - 1 : i), y(v)]);
    add("polyline", { points: pts.map((p) => p.join(",")).join(" "), fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" });
    pts.forEach(([px, py], i) => {
      add("circle", { cx: px, cy: py, r: 4, fill: color, stroke: "var(--chart-surface)", "stroke-width": 2 });
      const hit = add("circle", { cx: px, cy: py, r: 11, fill: "transparent" }); hit.style.cursor = "crosshair";
      hit.addEventListener("mouseenter", () => {
        tip.innerHTML = `<strong>${esc(s.name)}</strong><br>${esc(stepLabel(i, s.values.length))}: ${s.values[i]} ETH`;
        tip.style.left = `${(px / W) * 100}%`; tip.style.top = `${(py / H) * 100}%`; tip.classList.remove("hidden");
      });
      hit.addEventListener("mouseleave", () => tip.classList.add("hidden"));
    });
    const [lx, ly] = pts[pts.length - 1];
    const others = series.filter((o, oi) => oi !== si && Math.abs(o.values[o.values.length - 1] - s.values[last]) < top * 0.08);
    add("text", { x: lx + 10, y: ly + 4 + (others.length ? (si ? 14 : -10) : 0), fill: "var(--chart-text)", "font-size": 12 }, `${s.name}: ${s.values[last]} ETH`);
  });
  const plot = el("div", "chart-plot"); plot.append(svg, tip); wrap.append(plot);
  const table = el("details", "chart-table");
  table.append(el("summary", null, "Table view"));
  const t = el("table", "impact-table");
  t.append(el("tr", null, "<th>Series</th><th>Step</th><th>Contract balance</th>"));
  series.forEach((s) => s.values.forEach((v, i) => t.append(el("tr", null, `<td>${esc(s.name)}</td><td>${esc(stepLabel(i, s.values.length))}</td><td class="mono">${v} ETH</td>`))));
  table.append(t); wrap.append(table);
  wrap.append(el("div", "disclaimer", "Recorded inside the executed test (balance at each attacker callback). Local fixture values."));
  return wrap;
}

/* ---------- verification page ---------- */
function sandboxBanner() {
  const st = state.status;
  if (!st) return null;
  if (!st.foundry) return el("div", "result-banner inconclusive", "⚠ Foundry not available — tests are generated but not executed. " + esc(st.foundry_detail || ""));
  if (!st.sandbox) return el("div", "result-banner inconclusive", "⚠ Foundry ready, but bubblewrap is missing: tests run with a cleared environment but without network/filesystem isolation.");
  return el("div", "result-banner ok", "✓ Foundry sandbox ready — tests run under bubblewrap with no network and a cleared environment.");
}

function findingPicker(candidates, onPick) {
  const picker = el("div", "toolbar");
  picker.append(selectEl2(candidates.map((f) => `${f.id} · ${f.impact} · ${f.title}${f.function ? " — " + f.function : ""}`), null, (v) => onPick(v.split(" · ")[0])));
  const sel = picker.querySelector("select");
  [...sel.options].forEach((o) => { o.selected = o.value.startsWith(state.selectedFinding + " "); });
  return picker;
}

function renderVerification(main) {
  const s = state.scan;
  main.append(el("div", "page-title", "Dynamic Verification"));
  main.append(el("div", "page-sub", "Controlled exploit tests from fixed templates. \u201cExploit demonstrated\u201d means the harmful outcome was reproduced in an executed sandbox run \u2014 it is not a passing check."));
  const banner = sandboxBanner(); if (banner) main.append(banner);
  const targets = s.findings.filter(hasVerification);
  if (!targets.length) return main.append(emptyState("No verifiable findings", "Templates exist for reentrancy-eth, privilege escalation and unprotected privileged functions. Other findings remain static warnings."));
  if (!state.selectedFinding || !targets.find((f) => f.id === state.selectedFinding)) state.selectedFinding = targets[0].id;
  main.append(findingPicker(targets, (id) => { state.selectedFinding = id; syncHash(); render(); }));
  const f = targets.find((x) => x.id === state.selectedFinding);
  const v = f.verification;
  main.append(el("div", "section-title", esc(f.title + " — " + (f.function || ""))));

  const busy = state.busy["verify:" + f.id];
  const row = el("div", "btn-row");
  const rerun = el("button", "btn primary", v.status === "not_run" ? "Run verification" : "Re-run verification");
  rerun.disabled = !!busy || s.status !== "done" || !(state.status && state.status.foundry);
  if (state.status && !state.status.foundry) rerun.title = "Foundry is not available on the server";
  rerun.onclick = () => runAction("verify:" + f.id, f.id, () => postJSON(findingUrl(f, "verify")), "Verification run recorded in the ledger.");
  row.append(rerun);
  if (busy) row.append(spinnerInline("Compiling and executing in the sandbox…"));
  main.append(row);

  const steps = v.steps && v.steps.length ? v.steps : [{ label: "Not run yet", state: "pending" }];
  const flow = el("div", "verify-flow");
  steps.forEach((st, i) => {
    const ok = st.state === "done" || st.state === "verified_exploit" || st.state === "not_verified";
    const step = el("div", "vstep" + (ok ? " done" : st.state === "failed" || st.state === "verification_error" ? " failed" : ""));
    step.append(el("div", "vico", ok ? "✓" : st.state === "failed" ? "✕" : ""));
    step.append(el("div", "stage-body", `<div class="stage-label">${esc(st.label)}</div><div class="stage-detail">${esc(st.state.replace(/_/g, " "))}</div>`));
    flow.append(step);
    if (i < steps.length - 1) flow.append(el("div", "vconn"));
  });
  main.append(flow);
  main.append(el("div", "result-banner " + v.status, verificationIcon(v.status) + " " + esc(vStatusLabel(v.status))));
  main.append(el("div", "status-explain", esc(STATUS_EXPLAIN[v.status] || "")));
  if (v.summary) main.append(el("div", "disclaimer", esc(v.summary)));
  if (v.attack_exercised !== null && v.attack_exercised !== undefined)
    main.append(el("div", "finding-meta", v.attack_exercised ? "Attack path exercised during the run: yes" : "Attack path exercised during the run: NO — the result cannot speak to exploitability"));

  const grid = el("div", "two-col");
  const prov = el("div", "card");
  prov.append(el("div", "block-label", "Run provenance"));
  if (v.run) {
    const r = v.run, kv = el("dl", "kv");
    [["Run ID", r.run_id], ["Test", `${r.test_file} → ${r.test_contract}::${r.test_function}`], ["Outcome", r.outcome + (r.reason ? " — " + r.reason : "")],
      ["Exit code", r.exit_code], ["Sandboxed", r.sandboxed ? "yes (bubblewrap, no network)" : "NO"], ["Duration", r.duration_s + " s"],
      ["Started", new Date(r.started_at * 1000).toLocaleString()], ["Forge", r.forge_version || "?"], ["Test SHA-256", r.test_sha256], ["Sources SHA-256", r.source_sha256]]
      .forEach(([k, val]) => kv.append(el("dt", null, k), el("dd", "wrap", esc(String(val)))));
    prov.append(kv);
  } else prov.append(el("div", "finding-meta", "No execution recorded. " + esc(v.summary || "")));
  const imp = el("div", "card");
  if (v.impact && v.impact.length) imp.append(impactTable(v)); else { imp.append(el("div", "block-label", "Measured impact")); imp.append(el("div", "finding-meta", "No measurement: the test did not produce defensible values.")); }
  grid.append(prov, imp);
  main.append(grid);

  const drain = timelineOf(v.observations);
  if (drain) main.append(drainChart([{ name: "Contract balance", values: drain }], v.observations.victim_deposit_wei ? toEth(v.observations.victim_deposit_wei) : null, "Drain timeline — target contract ETH balance during the attack"));
  if (v.limitations && v.limitations.length) { main.append(el("div", "block-label", "Limitations")); main.append(checklistPlain(v.limitations)); }
  if (v.reproduction && v.reproduction.length) {
    main.append(el("div", "block-label", "Reproduce locally"));
    main.append(el("div", "pre", esc(v.reproduction.join("\n"))));
    if (v.test_source) { const a = el("a", "btn", "Download generated test"); a.href = findingUrl(f, "test.sol"); a.setAttribute("download", "Exploit.t.sol"); a.style.marginTop = "8px"; main.append(a); }
  }
  const tabs = el("div", "tabs"); tabs.style.marginTop = "18px";
  const panes = { trace: v.trace, test: v.test_source, log: v.log };
  [["trace", "Call trace"], ["test", "Generated test"], ["log", "Raw forge output"]].forEach(([k, label]) => {
    if (!panes[k]) return;
    const b = el("button", "tab" + (state.verifyTab === k ? " active" : ""), label);
    b.onclick = () => { state.verifyTab = k; render(); };
    tabs.append(b);
  });
  if (tabs.children.length) {
    main.append(tabs);
    const key = panes[state.verifyTab] ? state.verifyTab : Object.keys(panes).find((k) => panes[k]);
    main.append(el("div", "pre tall", esc(panes[key])));
  }
  main.append(findingNav(f, "verify"));
}
function checklistPlain(items) { const ul = el("ul", "plain-list"); items.forEach((i) => ul.append(el("li", null, esc(i)))); return ul; }

/* ---------- remediation page ---------- */
function renderRemediation(main) {
  const s = state.scan;
  main.append(el("div", "page-title", "Remediation"));
  main.append(el("div", "page-sub", "Suggested patches are validated in a throwaway workspace against the original exploit test and a legitimate-use test. Your source files are never modified."));
  const candidates = s.findings.filter((f) => f.impact !== "Optimization" && f.impact !== "Informational");
  if (!candidates.length) return main.append(emptyState("Nothing to remediate", "No High, Medium or Low findings."));
  if (!state.selectedFinding || !candidates.find((f) => f.id === state.selectedFinding))
    state.selectedFinding = (candidates.find((f) => f.verification.status === "verified_exploit") || candidates[0]).id;
  main.append(findingPicker(candidates, (id) => { state.selectedFinding = id; state.patchEditor = null; syncHash(); render(); }));
  const f = candidates.find((x) => x.id === state.selectedFinding);
  main.append(el("div", "section-title", esc(f.title + " — " + (f.function || f.detector))));

  const guide = block("static", "Remediation guidance");
  if (f.wiki_recommendation) { guide.append(el("div", "finding-meta", f.origin === "auditlens-graph" ? "AuditLens graph rule recommendation" : "Slither detector recommendation")); guide.append(el("div", null, esc(f.wiki_recommendation))); }
  if (f.assessment && f.assessment.remediation) { guide.append(el("div", "finding-meta", "AI / heuristic suggestion (hypothesis)")); guide.append(el("div", null, esc(f.assessment.remediation))); }
  main.append(guide);

  main.append(f.patch ? patchCard(f) : noPatchCard(f));
  if (state.patchEditor === f.id) main.append(patchEditor(f));
  if (f.remediation) main.append(validationCard(f.remediation));
  main.append(findingNav(f, "remediate"));
}

function noPatchCard(f) {
  const c = block("remediation", "Candidate patch");
  const hint = { "reentrancy-eth": "AuditLens can generate a checks-effects-interactions patch from Slither's call and write locations.",
    "auditlens-privilege-escalation": "AuditLens can generate an access check on the unprotected writer, using the guard variable the graph identified." };
  c.append(el("div", "finding-meta", hint[f.detector] || "Automatic patches are generated for reentrancy-eth and privilege escalation only. You can supply your own patched file."));
  const row = el("div", "btn-row"); row.style.marginTop = "10px";
  const gen = el("button", "btn primary", "Generate candidate patch");
  gen.disabled = !AUTO_PATCH.includes(f.detector) || !!state.busy["patch:" + f.id];
  if (!AUTO_PATCH.includes(f.detector)) gen.title = "Only available for reentrancy-eth and privilege-escalation findings";
  gen.onclick = () => runAction("patch:" + f.id, f.id, () => postJSON(findingUrl(f, "patch")), "Candidate patch generated (not applied).");
  const own = el("button", "btn", "Write my own patch");
  own.onclick = () => { state.patchEditor = f.id; render(); };
  row.append(gen, own);
  if (state.busy["patch:" + f.id]) row.append(spinnerInline("Generating…"));
  c.append(row);
  return c;
}

function patchCard(f) {
  const p = f.patch;
  const c = block("remediation", "Candidate patch");
  c.append(el("div", "suggested-label", "SUGGESTED — applied only inside the validation sandbox, never to your files"));
  const kv = el("dl", "kv");
  [["Patch ID", p.id], ["Origin", p.origin], ["Strategy", p.strategy], ["File", p.file], ["Patched SHA-256", p.patched_sha256]]
    .forEach(([k, v]) => kv.append(el("dt", null, k), el("dd", "wrap", esc(v))));
  c.append(kv);
  c.append(el("div", null, esc(p.description))); c.lastChild.style.margin = "10px 0";
  c.append(diffView(p.diff));
  const busy = state.busy["validate:" + f.id];
  const row = el("div", "btn-row"); row.style.marginTop = "12px";
  const val = el("button", "btn primary", f.remediation ? "Re-validate patch" : "Validate patch");
  val.disabled = !!busy || !(state.status && state.status.foundry);
  if (state.status && !state.status.foundry) val.title = "Foundry is not available on the server";
  val.onclick = () => runAction("validate:" + f.id, f.id, () => postJSON(findingUrl(f, "patch/validate")), "Patch validation recorded in the ledger.");
  const edit = el("button", "btn", "Edit patch"); edit.disabled = !!busy;
  edit.onclick = () => { state.patchEditor = f.id; render(); };
  row.append(val, edit);
  if (AUTO_PATCH.includes(f.detector)) {
    const regen = el("button", "btn ghost", "Regenerate"); regen.disabled = !!busy;
    regen.onclick = () => runAction("patch:" + f.id, f.id, () => postJSON(findingUrl(f, "patch")), "Candidate patch regenerated.");
    row.append(regen);
  }
  if (busy) row.append(spinnerInline("Compiling original and patched projects, running exploit + regression tests, re-running static analysis…"));
  c.append(row);
  return c;
}

function diffView(diff) {
  const pre = el("div", "pre diff");
  (diff || "(no changes)").split("\n").forEach((line) => {
    const cls = line.startsWith("+++") || line.startsWith("---") ? "meta" : line.startsWith("@@") ? "hunk" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "";
    pre.append(el("div", "dl " + cls, esc(line) || " "));
  });
  return pre;
}

function patchEditor(f) {
  const c = block("remediation", "Your patch");
  const files = Object.keys(state.scan.sources);
  const defaultFile = f.patch ? f.patch.file : (f.location ? f.location.file : files[0]);
  const pick = selectEl2(files, defaultFile, (v) => { area.value = state.scan.sources[v]; });
  const area = el("textarea", "patch-area");
  area.value = f.patch && f.patch.file === defaultFile ? f.patch.patched_source : state.scan.sources[defaultFile] || "";
  area.spellcheck = false;
  c.append(el("div", "finding-meta", "Edit the full file. It is validated in a throwaway workspace; the original stays untouched."), pick, area);
  const row = el("div", "btn-row"); row.style.marginTop = "10px";
  const submit = el("button", "btn primary", "Use this patch");
  submit.onclick = () => runAction("patch:" + f.id, f.id, async () => { await postJSON(findingUrl(f, "patch"), { file: pick.value, source: area.value }); state.patchEditor = null; }, "Patch recorded. Validate it to test the fix.");
  const cancel = el("button", "btn ghost", "Cancel"); cancel.onclick = () => { state.patchEditor = null; render(); };
  row.append(submit, cancel); c.append(row);
  return c;
}

const PATCH_LABEL = { validated: "✓ PATCH VALIDATED", failed: "✕ PATCH FAILED VALIDATION", inconclusive: "? VALIDATION INCONCLUSIVE", error: "⚠ VALIDATION ERROR" };
function validationCard(r) {
  const c = block("remediation", "Patch validation — remediation evidence");
  c.append(el("div", "result-banner patch-" + r.status, esc(PATCH_LABEL[r.status] || r.status)));
  c.append(el("div", "disclaimer", esc(r.summary) + ` (validation ${esc(r.id)}, ${r.duration_s}s)`));
  const t = el("table", "check-table");
  t.append(el("tr", null, "<th>Check</th><th>Result</th><th>Detail</th><th>Run</th>"));
  r.checks.forEach((ch) => {
    const tr = el("tr");
    tr.append(el("td", null, esc(ch.name)), el("td", null, `<span class="status-chip check-${ch.status}">${esc(ch.status)}</span>`),
      el("td", "detail", esc(ch.detail)), el("td", "mono", ch.run ? esc(ch.run.run_id) : "—"));
    t.append(tr);
  });
  c.append(t);
  const before = r.checks.find((ch) => ch.name.startsWith("Exploit reproduces on original"));
  const after = r.checks.find((ch) => ch.name.startsWith("Exploit blocked on patched"));
  const tb = before && timelineOf(before.observations), ta = after && timelineOf(after.observations);
  if (tb && ta) c.append(drainChart([{ name: "Original", values: tb }, { name: "Patched", values: ta }], before.observations.victim_deposit_wei ? toEth(before.observations.victim_deposit_wei) : null, "Same exploit, original vs patched — target contract ETH balance"));
  c.append(el("div", "block-label", "Properties tested")); c.append(checklistPlain(r.tested_properties));
  c.append(el("div", "block-label", "Limitations")); c.append(checklistPlain(r.limitations));
  return c;
}

/* ---------- report ---------- */
async function loadLedger(scanId) {
  state.ledger[scanId] = { loading: true };
  try { state.ledger[scanId] = await api(`/api/scans/${scanId}/ledger`); }
  catch (e) { state.ledger[scanId] = { error: e.message }; }
  if (state.view === "report") render();
}

function renderReport(main) {
  const s = state.scan;
  main.append(el("div", "page-title", "Security Report"));
  main.append(el("div", "page-sub", "Markdown and JSON exports include evidence classification, run provenance, measured impact, patch validation and ledger hashes."));
  const row = el("div", "btn-row");
  const md = el("button", "btn primary", "Download Markdown"); md.onclick = () => window.open(`/api/scans/${s.id}/report.md`);
  const json = el("button", "btn", "Download JSON"); json.onclick = () => window.open(`/api/scans/${s.id}/report.json`);
  const html = el("button", "btn", "Print / PDF"); html.onclick = () => window.print();
  row.append(md, json, html); main.append(row);
  const sum = s.summary;
  main.append(el("div", "section-title", "Executive summary"));
  const cards = el("div", "grid cards");
  cards.append(statCard("Score", sum.security_score, "accent"), statCard("Exploits demonstrated", sum.verified_exploits, "exploit"),
    statCard("Not reproduced", sum.not_reproduced || 0, ""), statCard("Inconclusive / error", sum.undetermined || 0, "medium"),
    statCard("Patches validated", sum.patches_validated || 0, "verified"), statCard("High", sum.high, "high"),
    statCard("AI-flagged (hypotheses)", sum.ai_confirmed, "accent"));
  main.append(cards);

  main.append(proofBundleCard(s));
  main.append(recheckCard(s));

  main.append(el("div", "section-title", "Evidence ledger"));
  const led = state.ledger[s.id];
  if (!led) { loadLedger(s.id); main.append(spinnerInline("Loading ledger…")); }
  else if (led.loading) main.append(spinnerInline("Loading ledger…"));
  else if (led.error) main.append(el("div", "flash error", "Could not load ledger: " + esc(led.error)));
  else {
    const c = el("div", "card");
    const kinds = {}; led.entries.forEach((e) => { kinds[e.kind] = (kinds[e.kind] || 0) + 1; });
    c.append(el("div", null, led.chain.valid ? `✓ Chain intact — ${led.chain.entries} entries` : `⚠ Chain broken at entry #${led.chain.broken_at}`));
    c.append(el("div", "finding-meta wrap", "Head " + esc(led.chain.head)));
    c.append(el("div", "finding-meta", esc(Object.entries(kinds).map(([k, n]) => `${k.replace(/_/g, " ")}: ${n}`).join(" · "))));
    c.append(el("div", "disclaimer", esc(led.chain.guarantee)));
    main.append(c);
  }

  main.append(el("div", "section-title", "Findings preview"));
  s.findings.filter((f) => f.impact !== "Optimization").forEach((f) => {
    const c = el("div", "card report-row");
    c.append(el("span", "sev-badge " + f.impact, f.impact));
    c.append(el("span", null, esc(f.title) + " — " + esc(f.function || f.detector)));
    const tags = el("span", "finding-tags");
    tags.append(el("span", "tag", "static"));
    if (f.assessment) tags.append(el("span", "tag ai", "AI hypothesis"));
    if (f.verification.status !== "not_run") tags.append(el("span", "tag " + (f.verification.status === "verified_exploit" ? "exploit" : ""), vStatusLabel(f.verification.status)));
    if (f.remediation) tags.append(el("span", "tag patch-" + f.remediation.status, "patch " + f.remediation.status));
    c.append(tags);
    c.onclick = () => { state.selectedFinding = f.id; setView("findings"); };
    main.append(c);
  });
}

function filePicker(accept, multiple, label, onPick, disabled) {
  const input = el("input"); input.type = "file"; input.accept = accept; input.multiple = multiple; input.className = "hidden";
  input.onchange = () => { if (input.files.length) onPick([...input.files]); input.value = ""; };
  const b = el("button", "btn", label); b.disabled = !!disabled; b.onclick = () => input.click();
  const span = el("span"); span.append(b, input);
  return span;
}

async function uploadForm(url, field, files) {
  const fd = new FormData(); files.forEach((f) => fd.append(field, f));
  return api(url, { method: "POST", body: fd });
}

function proofBundleCard(s) {
  const c = el("div", "card proof");
  c.append(el("div", "section-title", "Proof-carrying audit"));
  c.append(el("div", "page-sub", "Download a bundle with the sources, the exact generated tests, the evidence ledger and this report. Anyone can re-execute every claim: in this UI, or offline with `auditlens verify-bundle bundle.zip`."));
  const row = el("div", "btn-row");
  const dl = el("button", "btn primary", "Download proof bundle");
  dl.disabled = s.status !== "done";
  dl.onclick = () => window.open(`/api/scans/${s.id}/bundle.zip`);
  row.append(dl);
  const busy = state.busy["bundle-verify"];
  row.append(filePicker(".zip", false, "Verify a bundle…", (files) => runAction("bundle-verify", null, async () => {
    state.bundleResult = await uploadForm("/api/bundles/verify", "bundle", files);
  }), busy));
  if (busy) row.append(spinnerInline("Checking hashes and the ledger chain, re-executing every claim in the sandbox…"));
  c.append(row);
  const r = state.bundleResult;
  if (r) {
    const label = { reproduced: "✓ BUNDLE REPRODUCED", mismatch: "✕ CLAIMS DID NOT REPRODUCE", tampered: "⚠ BUNDLE TAMPERED", integrity_only: "? INTEGRITY ONLY — NOT RE-EXECUTED" }[r.verdict] || r.verdict;
    const cls = { reproduced: "ok", mismatch: "verification_error", tampered: "verification_error", integrity_only: "inconclusive" }[r.verdict] || "inconclusive";
    c.append(el("div", "result-banner " + cls, esc(label)));
    c.append(el("div", "disclaimer", `${esc(r.summary)} · ${esc(r.scan_name)} · bundle ${esc(r.bundle_sha256.slice(0, 16))}… · ledger chain ${r.ledger.valid ? "intact" : "broken"} · ${r.duration_s}s`));
    if (r.integrity_problems.length) c.append(checklistPlain(r.integrity_problems));
    if (r.claims.length) {
      const t = el("table", "check-table");
      t.append(el("tr", null, "<th>Claim</th><th>Recorded</th><th>Re-executed</th><th>Result</th>"));
      r.claims.forEach((cl) => t.append(el("tr", null, `<td>${esc(cl.description)}</td><td class="mono">${esc(cl.expected)}</td><td class="mono">${esc(cl.actual)}</td><td><span class="status-chip check-${cl.reproduced ? "pass" : "fail"}">${cl.reproduced ? "reproduced" : "mismatch"}</span></td>`)));
      c.append(t);
    }
  }
  return c;
}

function recheckCard(s) {
  const c = el("div", "card proof");
  c.append(el("div", "section-title", "Exploit regression check"));
  const proven = s.findings.filter((f) => f.verification.status === "verified_exploit").length;
  c.append(el("div", "page-sub", `Every proven exploit becomes a permanent regression test. Upload a new version of the contracts to re-run all ${proven} proven exploit(s) against it. CI: \`auditlens recheck bundle.zip src/\` exits 1 on a regression.`));
  const busy = state.busy["recheck"];
  const row = el("div", "btn-row");
  row.append(filePicker(".sol", true, "Recheck a new version…", (files) => runAction("recheck", null, async () => {
    state.recheckResult = await uploadForm(`/api/scans/${s.id}/recheck`, "files", files);
  }), busy || !proven));
  if (!proven) row.append(el("span", "finding-meta", "No demonstrated exploits in this scan."));
  if (busy) row.append(spinnerInline("Running proven exploits against the new version…"));
  c.append(row);
  const r = state.recheckResult;
  if (r) {
    const label = { all_blocked: "✓ ALL PROVEN EXPLOITS STILL BLOCKED", regression: "✕ REGRESSION — A PROVEN EXPLOIT WORKS AGAIN", inconclusive: "? INCONCLUSIVE" }[r.verdict] || r.verdict;
    const cls = { all_blocked: "ok", regression: "verification_error" }[r.verdict] || "inconclusive";
    c.append(el("div", "result-banner " + cls, esc(label)));
    c.append(el("div", "disclaimer", `${esc(r.summary)} · new sources ${esc(r.new_sources_sha256.slice(0, 16))}… · ${r.duration_s}s · recorded in the ledger`));
    const t = el("table", "check-table");
    t.append(el("tr", null, "<th>Proven exploit</th><th>Result</th><th>Detail</th>"));
    const chip = { blocked: "pass", exploitable: "fail", inconclusive: "error" };
    r.results.forEach((x) => t.append(el("tr", null, `<td>${esc(x.title)}</td><td><span class="status-chip check-${chip[x.verdict]}">${esc(x.verdict)}</span></td><td class="detail">${esc(x.detail)}</td>`)));
    c.append(t);
  }
  return c;
}

/* ---------- scans list ---------- */
async function renderScansList(main) {
  main.append(el("div", "page-title", "Scans"));
  main.append(el("div", "page-sub", "History of analyses in this session."));
  try {
    const scans = await api("/api/scans");
    if (!scans.length) { main.append(emptyState("No scans yet", "Run your first analysis.", "New Scan", () => setView("scan"))); return; }
    scans.forEach((sc) => {
      const row = el("div", "scan-row");
      row.append(el("span", "status-chip " + sc.status, sc.status));
      row.append(el("div", null, `<div style="font-weight:550">${esc(sc.name)}</div><div class="finding-meta">${sc.findings} findings · ${new Date(sc.created_at * 1000).toLocaleTimeString()}</div>`));
      row.onclick = () => { state.scanId = sc.id; pollScan(); setView("overview"); };
      main.append(row);
    });
  } catch (e) { main.append(emptyState("Could not load scans", e.message)); }
}

function refresh() { render(); }
