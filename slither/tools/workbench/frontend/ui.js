"use strict";

/* ---------- DOM + API helpers ---------- */
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
};
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
const truncate = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    const detail = Array.isArray(body.detail) ? body.detail.map((d) => d.msg).join("; ") : body.detail;
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}
const postJSON = (path, body) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

function announce(text) {
  const a = document.getElementById("announcer");
  a.textContent = "";
  setTimeout(() => { a.textContent = text; }, 30);
}

function button(label, opts = {}) {
  const b = el("button", "btn " + (opts.variant || ""), (opts.icon ? icon(opts.icon) : "") + `<span>${esc(label)}</span>`);
  b.type = "button";
  if (opts.onClick) b.onclick = opts.onClick;
  if (opts.disabled) b.disabled = true;
  if (opts.title) b.title = opts.title;
  return b;
}

function relTime(epochSeconds) {
  if (!epochSeconds) return "—";
  const d = new Date(epochSeconds * 1000);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* ---------- status vocabulary (one place, used everywhere) ---------- */
const SEVERITY = {
  High: { cls: "sev-high", label: "High" },
  Medium: { cls: "sev-medium", label: "Medium" },
  Low: { cls: "sev-low", label: "Low" },
  Informational: { cls: "sev-info", label: "Info" },
  Optimization: { cls: "sev-info", label: "Optimization" },
};
function severityBadge(impact) {
  const s = SEVERITY[impact] || SEVERITY.Informational;
  return `<span class="sev ${s.cls}">${esc(s.label)}</span>`;
}

/* A demonstrated exploit is a confirmed harmful outcome, never a "success". */
const VSTATUS = {
  verified_exploit: { cls: "st-critical", icon: "bolt", label: "Exploit demonstrated",
    help: "The exploit test's assertion succeeded: the harmful outcome was reproduced in the sandbox. This is bad news for the contract." },
  not_verified: { cls: "st-neutral", icon: "minus", label: "Not reproduced",
    help: "The attack ran and its security assertion failed — no violation observed in this fixture. The static warning still stands." },
  inconclusive: { cls: "st-warning", icon: "help", label: "Inconclusive",
    help: "The run could not decide: an unrelated revert, an unexercised attack path, no template, or no sandbox." },
  verification_error: { cls: "st-serious", icon: "alert", label: "Run error",
    help: "Compilation failure, setUp() failure, timeout or tooling problem. Not evidence either way." },
  not_run: { cls: "st-muted", icon: "dot", label: "Not run", help: "No exploit test has been executed for this finding." },
};
const PSTATUS = {
  validated: { cls: "st-good", icon: "check", label: "Fix validated",
    help: "Exploit blocked with the attack exercised, legitimate use passes on original and patched code." },
  failed: { cls: "st-critical", icon: "x", label: "Fix failed", help: "The exploit still works, or the patch breaks legitimate use." },
  inconclusive: { cls: "st-warning", icon: "help", label: "Fix inconclusive", help: "The checks could not establish that the fix works." },
  error: { cls: "st-serious", icon: "alert", label: "Fix error", help: "The patched project did not compile or the tooling failed." },
};
const CHECK = {
  pass: { cls: "st-good", icon: "check", label: "Pass" },
  fail: { cls: "st-critical", icon: "x", label: "Fail" },
  error: { cls: "st-serious", icon: "alert", label: "Error" },
  skipped: { cls: "st-muted", icon: "dot", label: "Skipped" },
};
function statusChip(def, extraLabel) {
  return `<span class="chip ${def.cls}">${icon(def.icon)}<span>${esc(extraLabel || def.label)}</span></span>`;
}
const vChip = (status) => statusChip(VSTATUS[status] || VSTATUS.not_run);
const pChip = (status) => statusChip(PSTATUS[status] || PSTATUS.inconclusive);
const checkChip = (status) => statusChip(CHECK[status] || CHECK.skipped);

const PATH_STATUS = {
  "static-hypothesis": { cls: "st-muted", icon: "dot", label: "Static hypothesis", help: "Graph connectivity only. Not proof that the path is executable." },
  "dynamically-demonstrated": { cls: "st-critical", icon: "bolt", label: "Demonstrated by a test run", help: "An executed exploit test followed this path and its assertion succeeded." },
  "not-reproduced": { cls: "st-neutral", icon: "minus", label: "Attempted, not reproduced", help: "A test attempted this path; the exploit assertion failed." },
  inconclusive: { cls: "st-warning", icon: "help", label: "Attempt inconclusive", help: "A test ran but could not decide." },
};
const pathChip = (status) => statusChip(PATH_STATUS[status] || PATH_STATUS["static-hypothesis"]);

/* ---------- evidence rail: Static · Hypothesis · Execution · Remediation ---------- */
function railStates(f) {
  const v = f.verification.status;
  const exec = { verified_exploit: "critical", not_verified: "neutral", inconclusive: "warning", verification_error: "serious" }[v] || "empty";
  const rem = f.remediation ? { validated: "good", failed: "critical", inconclusive: "warning", error: "serious" }[f.remediation.status] : f.patch ? "pending" : "empty";
  return [
    { key: "static", label: "Static", state: "present", text: f.origin === "auditlens-graph" ? "graph-rule inference" : "Slither finding" },
    { key: "hypothesis", label: "Hypothesis", state: f.assessment ? "present" : "empty",
      text: f.assessment ? `${f.assessment.classification.replace(/_/g, " ")}, ${f.assessment.confidence}%` : "none" },
    { key: "execution", label: "Execution", state: exec, text: (VSTATUS[v] || VSTATUS.not_run).label },
    { key: "remediation", label: "Remediation", state: rem,
      text: f.remediation ? (PSTATUS[f.remediation.status] || {}).label : f.patch ? "patch proposed, not validated" : "no patch" },
  ];
}
function evidenceRail(f, opts = {}) {
  const segs = railStates(f);
  const summary = segs.map((s) => `${s.label}: ${s.text}`).join("; ");
  const rail = el("div", "rail" + (opts.large ? " rail-lg" : ""));
  rail.setAttribute("role", "img");
  rail.setAttribute("aria-label", `Evidence chain. ${summary}`);
  rail.title = summary;
  segs.forEach((s) => {
    const seg = el(opts.onSegment ? "button" : "span", `rail-seg seg-${s.key} is-${s.state}`);
    if (opts.large) seg.innerHTML = `<span class="rail-k">${esc(s.label)}</span><span class="rail-v">${esc(s.text)}</span>`;
    if (opts.onSegment) {
      seg.type = "button";
      seg.setAttribute("aria-label", `${s.label}: ${s.text}. Jump to section`);
      seg.onclick = () => opts.onSegment(s.key);
    }
    rail.append(seg);
  });
  return rail;
}

/* ---------- small components ---------- */
function helpTip(text) {
  const b = el("button", "help-tip", icon("help"));
  b.type = "button";
  b.setAttribute("aria-label", text);
  b.dataset.tip = text;
  return b;
}

function hashChip(hash, label) {
  const wrap = el("span", "hash");
  if (!hash) { wrap.textContent = "—"; return wrap; }
  const text = el("button", "hash-text mono", esc(hash.slice(0, 12)) + "…");
  text.type = "button";
  text.title = `${label || "Hash"}: ${hash} (click to expand)`;
  text.setAttribute("aria-label", `${label || "Hash"} ${hash.slice(0, 12)}, expand`);
  text.onclick = () => {
    const expanded = wrap.classList.toggle("expanded");
    text.textContent = expanded ? hash : hash.slice(0, 12) + "…";
  };
  const copy = el("button", "icon-btn sm", icon("copy"));
  copy.type = "button";
  copy.setAttribute("aria-label", `Copy ${label || "hash"}`);
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(hash); } catch (e) {
      const t = el("textarea"); t.value = hash; document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
    }
    copy.innerHTML = icon("check"); announce("Copied to clipboard");
    setTimeout(() => { copy.innerHTML = icon("copy"); }, 1200);
  };
  wrap.append(text, copy);
  return wrap;
}

function section(title, opts = {}) {
  const s = el("section", "panel " + (opts.cls || ""));
  if (opts.id) s.id = opts.id;
  const head = el("div", "panel-head");
  head.append(el("h2", "panel-title", esc(title)));
  if (opts.meta) head.append(el("span", "panel-meta", opts.meta));
  if (opts.help) head.append(helpTip(opts.help));
  if (opts.actions) { const a = el("div", "panel-actions"); opts.actions.forEach((x) => a.append(x)); head.append(a); }
  s.append(head);
  return s;
}

function pageHeader(title, sub, actions) {
  const h = el("div", "page-head");
  const t = el("div");
  t.append(el("h1", "page-title", esc(title)));
  if (sub) t.append(el("p", "page-sub", sub));
  h.append(t);
  if (actions && actions.length) { const a = el("div", "btn-row"); actions.forEach((x) => a.append(x)); h.append(a); }
  return h;
}

function dataTable(columns, rows, opts = {}) {
  const wrap = el("div", "table-wrap");
  const t = el("table", "data " + (opts.cls || ""));
  const thead = el("thead");
  const hr = el("tr");
  columns.forEach((c) => hr.append(el("th", c.cls || "", esc(c.label))));
  thead.append(hr);
  const tbody = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr", r.cls || "");
    columns.forEach((c) => {
      const td = el("td", c.cls || "");
      const v = r.cells[c.key];
      if (v instanceof Node) td.append(v); else td.innerHTML = v == null ? "" : v;
      tr.append(td);
    });
    if (r.onClick) {
      tr.classList.add("clickable"); tr.tabIndex = 0;
      tr.onclick = r.onClick;
      tr.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); r.onClick(); } };
    }
    tbody.append(tr);
  });
  t.append(thead, tbody);
  wrap.append(t);
  return wrap;
}

function kvList(rows) {
  const dl = el("dl", "kv");
  rows.forEach(([k, v]) => {
    dl.append(el("dt", null, esc(k)));
    const dd = el("dd");
    if (v instanceof Node) dd.append(v); else dd.innerHTML = v == null || v === "" ? "—" : v;
    dl.append(dd);
  });
  return dl;
}

function emptyState(title, msg, action) {
  const e = el("div", "empty");
  e.append(el("h3", null, esc(title)), el("p", null, esc(msg)));
  if (action) e.append(action);
  return e;
}

function spinnerInline(label) {
  const s = el("span", "busy-inline", `<span class="spin" aria-hidden="true"></span><span>${esc(label)}</span>`);
  s.setAttribute("role", "status");
  return s;
}

function segmented(options, current, onChange, label) {
  const g = el("div", "segmented");
  g.setAttribute("role", "tablist");
  if (label) g.setAttribute("aria-label", label);
  options.forEach(([value, text]) => {
    const b = el("button", value === current ? "active" : "", esc(text));
    b.type = "button";
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", String(value === current));
    b.onclick = () => onChange(value);
    g.append(b);
  });
  return g;
}

function selectBox(options, current, onChange, label) {
  const s = el("select", "select");
  if (label) s.setAttribute("aria-label", label);
  options.forEach(([value, text]) => {
    const o = el("option", null, esc(text));
    o.value = value;
    if (value === current) o.selected = true;
    s.append(o);
  });
  s.onchange = () => onChange(s.value);
  return s;
}

function confirmDialog(title, body, confirmLabel) {
  const dlg = document.getElementById("dialog");
  document.getElementById("dialog-title").textContent = title;
  document.getElementById("dialog-body").textContent = body;
  document.getElementById("dialog-confirm").textContent = confirmLabel;
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "confirm"), { once: true });
    dlg.returnValue = "cancel";
    dlg.showModal();
  });
}

/* ---------- code: Solidity highlighting (escaped token-by-token) ---------- */
const SOL_TOKEN = new RegExp([
  "(\\/\\/.*$)",
  '("(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\')',
  "\\b(0x[0-9a-fA-F]+|\\d+(?:\\.\\d+)?)\\b",
  "\\b(pragma|solidity|contract|interface|library|abstract|function|modifier|event|error|struct|enum|mapping|returns|return|if|else|for|while|do|break|continue|new|delete|emit|import|from|is|override|virtual|external|public|internal|private|view|pure|payable|constant|immutable|memory|storage|calldata|constructor|fallback|receive|unchecked|try|catch|using|ether|wei|gwei)\\b",
  "\\b(address|bool|string|bytes\\d*|u?int\\d*)\\b",
  "\\b(msg|block|tx|this|require|revert|assert|selfdestruct|keccak256|abi)\\b",
].join("|"), "gm");
const SOL_CLASSES = [null, "tk-com", "tk-str", "tk-num", "tk-kw", "tk-type", "tk-glob"];

function highlightSolidity(line) {
  let out = "", last = 0;
  line.replace(SOL_TOKEN, (m, ...groups) => {
    const offset = groups[groups.length - 2];
    out += esc(line.slice(last, offset));
    const idx = groups.slice(0, 6).findIndex((g) => g !== undefined);
    out += `<span class="${SOL_CLASSES[idx + 1]}">${esc(m)}</span>`;
    last = offset + m.length;
    return m;
  });
  return out + esc(line.slice(last));
}

function codeBlock(code, opts = {}) {
  const pre = el("pre", "code-block" + (opts.wrap ? " wrap" : ""));
  const lines = String(code || "").split("\n");
  const start = opts.startLine || 1;
  const hl = new Set(opts.highlight || []);
  pre.innerHTML = lines.map((l, i) => {
    const n = start + i;
    const body = opts.plain ? esc(l) : highlightSolidity(l);
    return `<span class="cl${hl.has(n) ? " hl" : ""}">${opts.numbers ? `<span class="ln" aria-hidden="true">${n}</span>` : ""}${body || " "}</span>`;
  }).join("\n");
  return pre;
}

function diffView(diff) {
  const pre = el("pre", "code-block diff");
  pre.setAttribute("aria-label", "Unified diff of the proposed patch");
  pre.innerHTML = (diff || "(no changes)").split("\n").map((line) => {
    let cls = "", marker = " ";
    if (line.startsWith("+++") || line.startsWith("---")) cls = "d-meta";
    else if (line.startsWith("@@")) cls = "d-hunk";
    else if (line.startsWith("+")) { cls = "d-add"; marker = "+"; }
    else if (line.startsWith("-")) { cls = "d-del"; marker = "−"; }
    const body = cls === "d-add" || cls === "d-del" ? line.slice(1) : line;
    const srText = cls === "d-add" ? '<span class="sr-only">added: </span>' : cls === "d-del" ? '<span class="sr-only">removed: </span>' : "";
    return `<span class="cl ${cls}"><span class="dm" aria-hidden="true">${cls === "d-add" || cls === "d-del" ? marker : ""}</span>${srText}${cls.startsWith("d-add") || cls.startsWith("d-del") ? highlightSolidity(body) : esc(body) || " "}</span>`;
  }).join("\n");
  return pre;
}
