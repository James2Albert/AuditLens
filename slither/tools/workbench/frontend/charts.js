"use strict";

/* All colours come from CSS classes / variables, so a theme switch restyles these SVGs
   without re-rendering them. */
const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs, text) {
  const n = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs || {}).forEach(([k, v]) => n.setAttribute(k, v));
  if (text != null) n.textContent = text;
  return n;
}

/* ---------- attack path graph ---------- */
const NODE_KIND_LABEL = {
  attacker: "attacker",
  "entry-point": "entry point",
  "vulnerable-function": "vulnerable function",
  "external-call": "external call / sink",
  "state-mutation": "state",
  "attacker-controlled": "attacker-controlled",
};

function attackGraph(path, onSelect) {
  const nodes = path.nodes;
  const demonstrated = path.evidence_status === "dynamically-demonstrated";
  const W = 640, rowH = 84, boxW = 236, boxH = 48, cx = W / 2 - 40;
  const H = nodes.length * rowH + 24;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", class: "graph", role: "group",
    "aria-label": `Attack path graph: ${path.title}` });
  svg.append(svgEl("defs", {}));
  svg.firstChild.innerHTML =
    '<marker id="arrow-inferred" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path class="g-arrow" d="M0,0 L8,3 L0,6"/></marker>' +
    '<marker id="arrow-demo" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path class="g-arrow demo" d="M0,0 L8,3 L0,6"/></marker>';
  const pos = {};
  nodes.forEach((nd, i) => { pos[nd.id] = { x: cx, y: 28 + i * rowH }; });
  path.edges.forEach(([a, b, rel]) => {
    if (!pos[a] || !pos[b]) return;
    const p1 = pos[a], p2 = pos[b];
    const back = p2.y <= p1.y;
    const d = back
      ? `M${p1.x + boxW / 2},${p1.y} C${cx + boxW / 2 + 54},${p1.y} ${cx + boxW / 2 + 54},${p2.y} ${p2.x + boxW / 2},${p2.y}`
      : `M${p1.x},${p1.y + boxH / 2} L${p2.x},${p2.y - boxH / 2}`;
    const cls = ["g-edge", demonstrated ? "is-demonstrated" : "is-inferred", rel === "authorizes" ? "is-guard" : "", back ? "is-back" : ""].join(" ");
    svg.append(svgEl("path", { d, class: cls, "marker-end": `url(#${demonstrated ? "arrow-demo" : "arrow-inferred"})` }));
    if (rel) {
      svg.append(svgEl("text", { x: back ? cx + boxW / 2 + 60 : cx + 10, y: (p1.y + p2.y) / 2 + 4,
        class: "g-edge-label" + (rel === "authorizes" ? " is-guard" : "") }, rel === "authorizes" ? "guards (authorizes)" : rel));
    }
  });
  nodes.forEach((nd) => {
    const p = pos[nd.id];
    const g = svgEl("g", { transform: `translate(${p.x - boxW / 2},${p.y - boxH / 2})`, class: `g-node kind-${nd.kind}`,
      tabindex: "0", role: "button", "aria-label": `${nd.label}, ${NODE_KIND_LABEL[nd.kind] || nd.kind}. Show detail` });
    g.append(svgEl("rect", { width: boxW, height: boxH, rx: 4, class: "g-box" }));
    g.append(svgEl("rect", { width: 4, height: boxH, class: "g-bar" }));
    g.append(svgEl("text", { x: 14, y: 21, class: "g-label" }, truncate(nd.label, 28)));
    g.append(svgEl("text", { x: 14, y: 37, class: "g-kind" }, NODE_KIND_LABEL[nd.kind] || nd.kind));
    const select = () => {
      svg.querySelectorAll(".g-node.selected").forEach((n) => n.classList.remove("selected"));
      g.classList.add("selected");
      onSelect(nd);
    };
    g.addEventListener("click", select);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(); } });
    svg.append(g);
  });
  return svg;
}

function graphLegend(path) {
  const demonstrated = path.evidence_status === "dynamically-demonstrated";
  const l = el("div", "legend");
  l.innerHTML =
    `<span><i class="lg-edge inferred"></i>Statically inferred step</span>` +
    `<span><i class="lg-edge demonstrated"></i>Step of a demonstrated exploit${demonstrated ? "" : " (none here)"}</span>` +
    `<span><i class="lg-edge guard"></i>Access guard (authorizes)</span>` +
    Object.entries(NODE_KIND_LABEL).map(([k, v]) => `<span><i class="lg-node kind-${k}"></i>${esc(v)}</span>`).join("");
  return l;
}

/* ---------- drain timeline (values come only from the executed test's logs) ---------- */
const toEth = (wei) => Number((BigInt(wei) * 1000n) / 10n ** 18n) / 1000;
function timelineOf(obs) {
  return obs && obs.contract_balance_timeline ? obs.contract_balance_timeline.split(",").map(toEth) : null;
}
function stepLabel(i, n) { return i === 0 ? "before attack" : i === n - 1 ? "after attack" : `payout callback ${i}`; }

function drainChart(series, owedEth, title) {
  const wrap = el("figure", "chart");
  wrap.append(el("figcaption", "chart-title", esc(title)));
  if (series.length > 1) {
    const legend = el("div", "legend");
    series.forEach((s, i) => legend.append(el("span", null, `<i class="lg-series s${i + 1}"></i>${esc(s.name)}`)));
    wrap.append(legend);
  }
  const W = 680, H = 250, m = { l: 56, r: 150, t: 14, b: 32 };
  const maxN = Math.max(...series.map((s) => s.values.length));
  const top = Math.max(owedEth || 0, ...series.flatMap((s) => s.values)) || 1;
  const maxY = top * 1.2;
  const x = (i) => m.l + (maxN > 1 ? (i * (W - m.l - m.r)) / (maxN - 1) : 0);
  const y = (v) => m.t + (1 - v / maxY) * (H - m.t - m.b);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": title, class: "chart-svg" });
  [0, top / 2, top].forEach((v) => {
    svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: "c-grid" }));
    svg.append(svgEl("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end", class: "c-axis" }, `${+v.toFixed(2)} ETH`));
  });
  svg.append(svgEl("text", { x: m.l, y: H - 8, class: "c-axis" }, "before attack"));
  svg.append(svgEl("text", { x: W - m.r, y: H - 8, class: "c-axis", "text-anchor": "end" }, "after attack"));
  if (owedEth) {
    svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: y(owedEth), y2: y(owedEth), class: "c-ref" }));
    svg.append(svgEl("text", { x: m.l + 6, y: y(owedEth) - 8, class: "c-axis" }, `owed to honest depositor: ${owedEth} ETH`));
  }
  const tip = el("div", "chart-tip");
  tip.hidden = true;
  series.forEach((s, si) => {
    const last = s.values.length - 1;
    const pts = s.values.map((v, i) => [x(i === last ? maxN - 1 : i), y(v)]);
    svg.append(svgEl("polyline", { points: pts.map((p) => p.join(",")).join(" "), class: `c-line s${si + 1}` }));
    pts.forEach(([px, py], i) => {
      svg.append(svgEl("circle", { cx: px, cy: py, r: 4, class: `c-dot s${si + 1}` }));
      const hit = svgEl("circle", { cx: px, cy: py, r: 11, class: "c-hit" });
      hit.addEventListener("mouseenter", () => {
        tip.innerHTML = `<strong>${esc(s.name)}</strong><br>${esc(stepLabel(i, s.values.length))}: ${s.values[i]} ETH`;
        tip.style.left = `${(px / W) * 100}%`;
        tip.style.top = `${(py / H) * 100}%`;
        tip.hidden = false;
      });
      hit.addEventListener("mouseleave", () => { tip.hidden = true; });
      svg.append(hit);
    });
    const [lx, ly] = pts[pts.length - 1];
    const close = series.some((o, oi) => oi !== si && Math.abs(o.values[o.values.length - 1] - s.values[last]) < top * 0.08);
    svg.append(svgEl("text", { x: lx + 10, y: ly + 4 + (close ? (si ? 14 : -10) : 0), class: "c-label" }, `${s.name}: ${s.values[last]} ETH`));
  });
  const plot = el("div", "chart-plot");
  plot.append(svg, tip);
  wrap.append(plot);
  const table = el("details", "chart-table");
  table.append(el("summary", null, "Table view"));
  table.append(dataTable(
    [{ key: "s", label: "Series" }, { key: "step", label: "Step" }, { key: "v", label: "Contract balance", cls: "mono num" }],
    series.flatMap((s) => s.values.map((v, i) => ({ cells: { s: esc(s.name), step: esc(stepLabel(i, s.values.length)), v: `${v} ETH` } }))),
  ));
  wrap.append(table);
  wrap.append(el("p", "note", "Recorded inside the executed test (contract balance at each attacker callback). Local fixture values."));
  return wrap;
}
