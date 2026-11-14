// Evidence knowledge graph view. 3D (3d-force-graph) on wide screens, 2D (force-graph) on
// small ones or when the 3D library fails, a plain list when both fail.
// Security: no library tooltip or label receives a string it could parse as HTML.
// nodeLabel/linkLabel are disabled; our own tooltip and panels use textContent only.
import { api, el, clear, $, S, RAW, EVBYID, INCOF, SRC, chipList, timeEl, errBox, renderAnswer, askApi, entityLabel, REDUCED } from "./app.js";

const LIB3D = "https://unpkg.com/3d-force-graph@1.73.3/dist/3d-force-graph.min.js";
const LIB2D = "https://unpkg.com/force-graph@1.43.5/dist/force-graph.min.js";

// Casefile palette on a white stage: ink, blue accent, rust for the worst incident.
const KIND = {
  user: ["#15161a", "user"], account: ["#5b5e66", "account"], asset: ["#2340d9", "asset"], host: ["#4f63d6", "host name"],
  ip: ["#8fa0ff", "internal IP"], ext_ip: ["#c23b12", "external IP"], session: ["#1f8a4c", "session"], domain: ["#9b5fc0", "domain"],
  msg: ["#b7791f", "message"], alert: ["#e2643c", "alert"], change: ["#2c9c8f", "change"],
};
const INC = { "INC-1": "#c23b12", "INC-2": "#15161a", "INC-3": "#7a7d86", ANOM: "#2340d9", HARMLESS: "#c9c6bd" };
const DIM = "#e6e4dd", DIM_LINK = "rgba(201,198,189,0.35)", IDLINK = "rgba(91,94,102,0.55)";
const incColor = (i) => (!i ? null : INC[i] || (/^ANOM/.test(i) ? INC.ANOM : "#999"));

const G = {
  lib: null, mode: null, graph: null, data: null, nodes: new Map(), mounted: false, active: false, visible: true,
  filterInc: "*", kinds: new Set(), t: null, tMin: 0, tMax: 0, hl: null, selected: null, entLinks: null, pending: null,
};

function loadScript(src, globalName, ms) {
  if (window[globalName]) return Promise.resolve(window[globalName]);
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src; s.async = true; s.crossOrigin = "anonymous";
    const to = setTimeout(() => rej(new Error("timeout loading " + src)), ms || 9000);
    s.onload = () => { clearTimeout(to); window[globalName] ? res(window[globalName]) : rej(new Error(globalName + " missing")); };
    s.onerror = () => { clearTimeout(to); rej(new Error("failed to load " + src)); };
    document.head.append(s);
  });
}

// ---------- data prep ----------
const ts = (s) => { const v = s ? Date.parse(s) : NaN; return isNaN(v) ? null : v; };
function harmlessEventIds() {
  const ids = new Set();
  for (const h of (S.facts && S.facts.closed_as_harmless) || []) {
    for (const c of h.evidence || []) {
      const ev = c.line != null ? RAW.get(`${c.file}|L${c.line}`) : null;
      if (ev && ev.event_id) ids.add(ev.event_id);
    }
  }
  return ids;
}
function prepare(raw) {
  const harmless = harmlessEventIds();
  const nodes = (raw.nodes || []).map((n) => ({ id: String(n.id), type: String(n.type || "other"), label: String(n.label ?? n.id), inc: new Set() }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const pairCount = new Map();
  const links = [];
  for (const e of raw.edges || []) {
    if (!byId.has(e.source) || !byId.has(e.target)) continue;
    const inc = e.event_id ? (harmless.has(e.event_id) ? "HARMLESS" : INCOF.get(e.event_id) || null) : null;
    const pk = [e.source, e.target].sort().join("|");
    const idx = pairCount.get(pk) || 0; pairCount.set(pk, idx + 1);
    const start = ts(e.ts_utc) ?? ts(e.valid_from), end = ts(e.ts_end_utc) ?? ts(e.valid_to);
    const l = Object.assign({}, e, { inc, idx, start, end, inferred: e.kind === "identity" && e.basis && e.basis !== "direct" });
    l.source = e.source; l.target = e.target;
    links.push(l);
    if (inc && inc !== "HARMLESS") { byId.get(e.source).inc.add(inc); byId.get(e.target).inc.add(inc); }
  }
  // incident-affected assets and accounts are part of the incident even without an edge
  for (const i of Array.isArray(S.incidents) ? S.incidents : []) {
    for (const a of i.affected_assets || []) { const n = byId.get("asset:" + (a.tag || a)); if (n) n.inc.add(i.incident_id); }
    for (const a of i.affected_accounts || []) { const n = byId.get("user:" + (a.username || a)); if (n) n.inc.add(i.incident_id); }
  }
  for (const n of nodes) n.primary = [...n.inc].filter((i) => /^INC/.test(i)).sort()[0] || [...n.inc][0] || null;
  for (const l of links) l.curv = l.idx ? 0.12 * Math.ceil(l.idx / 2) * (l.idx % 2 ? 1 : -1) : 0;
  const times = links.flatMap((l) => [l.start, l.end]).filter((x) => x != null);
  G.tMin = times.length ? Math.min(...times) : 0; G.tMax = times.length ? Math.max(...times) : 0;
  G.nodes = byId;
  return { nodes, links };
}

// ---------- visibility and colour ----------
const linkEnds = (l) => [typeof l.source === "object" ? l.source.id : l.source, typeof l.target === "object" ? l.target.id : l.target];
function linkInTime(l) {
  if (G.t == null || G.t >= G.tMax) return true;
  if (l.start == null) return true;
  if (l.start > G.t) return false;
  if (l.kind === "identity" && l.end != null && l.end < G.t) return false;
  return true;
}
function nodeShown(n) {
  if (G.kinds.size && !G.kinds.has(n.type)) return false;
  return true;
}
function linkShown(l) {
  const [a, b] = linkEnds(l);
  const na = G.nodes.get(a), nb = G.nodes.get(b);
  if (!na || !nb || !nodeShown(na) || !nodeShown(nb)) return false;
  return linkInTime(l);
}
function nodeFocused(n) {
  if (G.hl) return G.hl.nodes.has(n.id);
  if (G.filterInc !== "*") return n.inc.has(G.filterInc);
  return true;
}
function linkFocused(l) {
  const [a, b] = linkEnds(l);
  if (G.hl) return G.hl.links.has(l.key) || (G.hl.nodes.has(a) && G.hl.nodes.has(b) && !G.hl.strictLinks);
  if (G.filterInc !== "*") return l.inc === G.filterInc || (l.kind === "identity" && G.nodes.get(a)?.inc.has(G.filterInc) && G.nodes.get(b)?.inc.has(G.filterInc));
  return true;
}
function nodeColor(n) {
  if (G.selected && G.selected.id === n.id) return "#2340d9";
  if (!nodeFocused(n)) return DIM;
  return (KIND[n.type] || ["#9a978f"])[0];
}
function nodeVal(n) { return (n.primary && /^INC/.test(n.primary) ? 3.2 : 1.2) + (G.hl && G.hl.nodes.has(n.id) ? 2.5 : 0); }
function linkColor(l) {
  if (!linkFocused(l)) return DIM_LINK;
  if (l.inc === "HARMLESS") return "rgba(170,168,160,0.6)";
  return incColor(l.inc) || (l.kind === "identity" ? IDLINK : "rgba(120,122,130,0.6)");
}
function linkWidth(l) {
  const f = linkFocused(l);
  if (G.hl && f) return 2.4;
  return l.inc && l.inc !== "HARMLESS" && f ? 1.6 : l.kind === "identity" ? 0.7 : 0.5;
}

function refresh() {
  const g = G.graph;
  if (!g) { if (G.mode === "list") renderList(); return; }
  g.nodeColor(g.nodeColor()).linkColor(g.linkColor()).linkWidth(g.linkWidth()).nodeVal(g.nodeVal())
    .nodeVisibility(g.nodeVisibility()).linkVisibility(g.linkVisibility());
  if (G.mode === "3d") g.linkDirectionalParticles(g.linkDirectionalParticles());
}

// ---------- tooltip (plain text) ----------
let mouse = { x: 0, y: 0 };
function tipShow(title, sub) {
  const t = $("graph-tip");
  if (!title) { t.hidden = true; return; }
  clear(t).append(el("b", { text: title }), sub ? el("span", { text: sub }) : null);
  t.hidden = false;
  const r = $("graph-stage").getBoundingClientRect();
  const x = Math.min(mouse.x - r.left + 14, r.width - 220), y = Math.min(mouse.y - r.top + 14, r.height - 60);
  t.style.left = Math.max(4, x) + "px"; t.style.top = Math.max(4, y) + "px";
}
function linkTitle(l) {
  const [a, b] = linkEnds(l);
  return `${entityLabel(a)} -> ${entityLabel(b)}`;
}
function linkSub(l) { return [l.event_kind || l.type || l.kind, l.inc, l.ts_utc ? l.ts_utc.slice(11, 19) + " UTC" : null].filter(Boolean).join(" . "); }

// ---------- details panel ----------
function evidenceOf(l) {
  if (l.event_id) {
    const ev = EVBYID.get(l.event_id);
    if (ev) return [{ file: ev.source_file, line: ev.line, row: ev.row }];
  }
  if (l.kind === "identity" && G.entLinks) {
    const [a, b] = linkEnds(l);
    const hit = G.entLinks.find((x) => x.a === a && x.b === b && (!l.type || x.type === l.type)) || G.entLinks.find((x) => (x.a === a && x.b === b) || (x.a === b && x.b === a));
    if (hit) return hit.evidence || [];
  }
  return [];
}
function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) if (v !== null && v !== undefined && v !== "") dl.append(el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v)));
  return dl;
}
function showLink(l) {
  G.selected = null;
  const box = clear($("g-detail"));
  const ev = l.event_id ? EVBYID.get(l.event_id) : null;
  box.append(el("div", { class: "cap", text: l.kind === "identity" ? "identity link" : "activity edge" }), el("h4", { text: linkTitle(l) }),
    kv([["type", l.event_kind || l.type], ["incident", l.inc === "HARMLESS" ? "closed as harmless" : l.inc], ["basis", l.kind === "identity" ? (l.basis || "?") + (l.inferred ? " (inferred)" : "") : "observed in a log line"],
      ["event", l.event_id], ["file", ev ? ev.source_file : null], ["line", ev ? ev.line ?? ev.row : null],
      ["time", l.ts_utc ? timeEl(l.ts_utc, l.ts_end_utc) : null],
      ["valid", l.valid_from || l.valid_to ? el("span", {}, timeEl(l.valid_from), " to ", l.valid_to ? timeEl(l.valid_to) : "open") : null]]));
  const cites = evidenceOf(l);
  if (cites.length) box.append(el("div", { class: "cap", text: "Evidence (click for the raw line)" }), chipList(cites));
  else box.append(el("div", { class: "muted small", text: "No evidence citation recorded for this link (reference table)." }));
  refresh();
}
function showNode(n) {
  G.selected = n;
  const box = clear($("g-detail"));
  const links = G.data.links.filter((l) => { const [a, b] = linkEnds(l); return a === n.id || b === n.id; });
  box.append(el("div", { class: "cap", text: (KIND[n.type] || [0, n.type])[1] }), el("h4", { text: n.label }),
    kv([["id", n.id], ["incidents", [...n.inc].join(", ") || "none"], ["links", links.length]]));
  const list = el("ul", { class: "plain small" });
  for (const l of links.slice(0, 30)) {
    const [a, b] = linkEnds(l);
    const other = a === n.id ? b : a;
    const li = el("li", {}, el("button", { type: "button", class: "link", onclick: () => showLink(l) }, `${a === n.id ? "->" : "<-"} ${entityLabel(other)}`),
      el("span", { class: "muted", text: " " + (l.event_kind || l.type || l.kind) + (l.ts_utc ? " " + l.ts_utc.slice(11, 19) : "") }));
    list.append(li);
  }
  if (links.length) box.append(el("div", { class: "cap", text: "Connections" }), list);
  const cites = links.flatMap(evidenceOf).slice(0, 24);
  if (cites.length) box.append(el("div", { class: "cap", text: "Evidence" }), chipList(cites));
  refresh();
}

// ---------- camera ----------
function flyTo(n) {
  const g = G.graph;
  if (!g || n.x === undefined) return;
  if (G.mode === "3d") {
    const d = 90, r = 1 + d / Math.max(1, Math.hypot(n.x, n.y, n.z));
    g.cameraPosition({ x: n.x * r, y: n.y * r, z: n.z * r }, n, REDUCED ? 0 : 1400);
  } else { g.centerAt(n.x, n.y, REDUCED ? 0 : 900); g.zoom(3, REDUCED ? 0 : 900); }
}
function findNode(q) {
  q = String(q || "").trim().toLowerCase();
  if (!q) return null;
  const all = [...G.nodes.values()];
  return all.find((n) => n.id.toLowerCase() === q) || all.find((n) => n.label.toLowerCase() === q) || all.find((n) => entityLabel(n.id).toLowerCase() === q)
    || all.find((n) => n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q)) || null;
}

// ---------- highlight (used by the query box and by chat entity chips) ----------
export async function highlight(sel) {
  if (!G.mounted) { G.pending = sel; return; }
  const nodes = new Set(), links = new Set();
  for (const id of (sel && sel.entities) || []) {
    const n = G.nodes.get(id) || findNode(entityLabel(id));
    if (n) nodes.add(n.id);
  }
  for (const c of (sel && sel.citations) || []) {
    const ev = c.line != null ? RAW.get(`${c.file}|L${c.line}`) : null;
    if (!ev) continue;
    for (const l of G.data.links) if (l.event_id === ev.event_id) { links.add(l.key); for (const x of linkEnds(l)) nodes.add(x); }
  }
  for (const id of (sel && sel.nodes) || []) if (G.nodes.has(id)) nodes.add(id);
  if (!nodes.size && !links.size) { setStatus("Nothing in that answer maps to a node in the graph."); return; }
  G.hl = { nodes, links, strictLinks: links.size > 0 };
  $("gq-clear").hidden = false;
  refresh();
  const first = G.nodes.get([...nodes][0]);
  if (first) { setTimeout(() => flyTo(first), 60); if (nodes.size === 1) showNode(first); }
}
function clearHighlight() { G.hl = null; $("gq-clear").hidden = true; clear($("gq-status")); refresh(); }
function setStatus(t) { clear($("gq-status")).append(el("div", { text: t })); }

const IDENT = /^[\w.:@\-]+$/;
async function query(text) {
  text = text.trim();
  if (!text) return;
  const st = clear($("gq-status"));
  st.append(el("div", { text: IDENT.test(text) ? "Resolving " + text + "..." : "Asking the fact store..." }));
  if (IDENT.test(text)) {
    try {
      const r = await api("GET", "/resolve?identifier=" + encodeURIComponent(text));
      const nodes = [r.node].filter(Boolean);
      for (const l of r.links || []) { nodes.push(l.a, l.b); }
      if (r.user && r.user.username) nodes.push("user:" + r.user.username);
      if (r.asset && r.asset.tag) nodes.push("asset:" + r.asset.tag);
      if (r.session && r.session.session_id) nodes.push("session:" + r.session.session_id);
      clear(st).append(el("div", { text: `${r.identifier || text}: ${r.kind || "?"}${r.user ? " . user " + (r.user.username || "") : ""}${r.asset ? " . asset " + (r.asset.hostname || r.asset.tag) : ""}` }));
      await highlight({ entities: nodes });
      return;
    } catch (e) {
      if (!(e && e.status === 404)) { clear(st).append(errBox(e)); return; }
      const n = findNode(text);
      if (n) { clear(st).append(el("div", { text: "Not in the resolver; matched node " + n.label })); await highlight({ nodes: [n.id] }); return; }
    }
  }
  try {
    const { a, fallback } = await askApi(text);
    const s = a.structured || {};
    clear(st).append(renderAnswer(a, { instant: true, fallback }));
    await highlight({ entities: s.entities || [], citations: s.citations || [] });
    if (G.hl) st.prepend(el("div", { text: `${G.hl.nodes.size} nodes and ${G.hl.links.size} edges named in the answer are highlighted.` }));
  } catch (e) { clear(st).append(errBox(e)); }
}

// ---------- controls ----------
function buildControls() {
  const incs = ["*", ...(Array.isArray(S.incidents) ? S.incidents.map((i) => i.incident_id) : []), "HARMLESS"];
  const seg = clear($("g-inc"));
  for (const i of incs) {
    const b = el("button", { type: "button", "aria-pressed": String(i === G.filterInc), style: i !== "*" ? "--c:" + incColor(i) : null }, i === "*" ? "All" : i === "HARMLESS" ? "Harmless" : i);
    b.addEventListener("click", () => { G.filterInc = i; for (const x of seg.children) x.setAttribute("aria-pressed", String(x === b)); clearHighlight(); });
    seg.append(b);
  }
  const kinds = clear($("g-kinds"));
  const present = [...new Set([...G.nodes.values()].map((n) => n.type))].sort();
  for (const k of present) {
    const cb = el("input", { type: "checkbox", checked: true });
    cb.addEventListener("change", () => {
      const on = [...kinds.querySelectorAll("input")].map((x, j) => (x.checked ? present[j] : null)).filter(Boolean);
      G.kinds = on.length === present.length ? new Set() : new Set(on.length ? on : ["__none__"]);
      refresh();
    });
    kinds.append(el("label", {}, cb, el("i", { style: "background:" + (KIND[k] || ["#999"])[0] }), (KIND[k] || [0, k])[1]));
  }
  const dl = clear($("g-search-list"));
  for (const n of G.nodes.values()) dl.append(el("option", { value: n.label === entityLabel(n.id) ? n.label : `${n.label} (${n.id})` }));
  const search = $("g-search");
  const go = () => {
    const v = search.value.replace(/\s*\(([^)]+)\)\s*$/, (m, id) => " " + id).trim();
    const n = G.nodes.get(v.split(" ").pop()) || findNode(v);
    if (n) { G.hl = { nodes: new Set([n.id]), links: new Set(), strictLinks: false }; $("gq-clear").hidden = false; refresh(); flyTo(n); showNode(n); }
  };
  search.addEventListener("change", go);
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
  const range = $("g-time");
  const lab = () => { $("g-time-l").textContent = G.t == null || G.t >= G.tMax ? "all" : new Date(G.t).toISOString().slice(11, 16) + " UTC"; };
  range.addEventListener("input", () => { G.t = G.tMin + (G.tMax - G.tMin) * (range.value / 1000); lab(); refresh(); });
  lab();
  $("gq-form").addEventListener("submit", (e) => { e.preventDefault(); query($("gq").value); });
  $("gq-clear").addEventListener("click", () => { $("gq").value = ""; clearHighlight(); });
  const leg = clear($("graph-legend"));
  for (const [k, c] of Object.entries(INC)) leg.append(el("span", {}, el("i", { style: "background:" + c }), k === "HARMLESS" ? "harmless (approved)" : k));
  leg.append(el("span", {}, el("i", { class: "ln" }), "direct"), el("span", {}, el("i", { class: "ln dash" }), G.mode === "3d" ? "inferred (moving dots)" : "inferred"));
}

// ---------- renderers ----------
function common(g) {
  const stage = $("graph-stage");
  g.width(stage.clientWidth).height(stage.clientHeight)
    .nodeId("id").nodeLabel(() => "").linkLabel(() => "")
    .nodeColor(nodeColor).nodeVal(nodeVal).nodeRelSize(4)
    .linkColor(linkColor).linkWidth(linkWidth).linkCurvature((l) => l.curv)
    .nodeVisibility(nodeShown).linkVisibility(linkShown)
    .onNodeHover((n) => { stage.style.cursor = n ? "pointer" : ""; n ? tipShow(n.label, (KIND[n.type] || [0, n.type])[1] + (n.inc.size ? " . " + [...n.inc].join(", ") : "")) : tipShow(null); })
    .onLinkHover((l) => { stage.style.cursor = l ? "pointer" : ""; l ? tipShow(linkTitle(l), linkSub(l)) : tipShow(null); })
    .onNodeClick((n) => { showNode(n); flyTo(n); })
    .onLinkClick((l) => showLink(l))
    .onBackgroundClick(() => { G.selected = null; refresh(); })
    .graphData(G.data);
  new ResizeObserver(() => { if (stage.clientWidth) g.width(stage.clientWidth).height(stage.clientHeight); }).observe(stage);
}
function make3d(F) {
  const g = F({ controlType: "orbit" })($("graph-canvas"));
  g.backgroundColor("rgba(0,0,0,0)").showNavInfo(false).nodeOpacity(0.95).nodeResolution(14).linkOpacity(0.7)
    .linkDirectionalParticles((l) => (l.inferred ? 4 : linkFocused(l) && l.inc && l.inc !== "HARMLESS" && l.kind === "activity" ? 2 : 0))
    .linkDirectionalParticleWidth(1.6).linkDirectionalParticleSpeed(0.006)
    .linkDirectionalParticleColor(linkColor);
  common(g);
  g.d3Force("charge").strength(-60);
  setTimeout(() => g.zoomToFit(REDUCED ? 0 : 900, 40), 1600);
  return g;
}
function make2d(F) {
  const g = F()($("graph-canvas"));
  g.backgroundColor("rgba(0,0,0,0)").linkLineDash((l) => (l.inferred ? [4, 3] : null))
    .linkDirectionalArrowLength((l) => (l.kind === "activity" ? 3 : 0)).linkDirectionalArrowRelPos(1)
    .nodeCanvasObjectMode(() => "after")
    .nodeCanvasObject((n, ctx, scale) => {
      if (!nodeShown(n) || (scale < 1.6 && !(n.primary && /^INC/.test(n.primary)) && !(G.hl && G.hl.nodes.has(n.id)))) return;
      ctx.font = `${11 / scale}px "JetBrains Mono", monospace`;
      ctx.fillStyle = nodeFocused(n) ? "rgba(21,22,26,0.85)" : "rgba(120,120,110,0.3)";
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      ctx.fillText(n.label, n.x, n.y + 6); // canvas text: never parsed as HTML
    });
  common(g);
  setTimeout(() => g.zoomToFit(REDUCED ? 0 : 600, 30), 1200);
  return g;
}
function renderList() {
  const c = clear($("graph-canvas"));
  const ul = el("ul", { class: "g-list" });
  for (const n of [...G.nodes.values()].filter(nodeShown).sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label))) {
    ul.append(el("li", { class: nodeFocused(n) ? "" : "dimmed" }, el("span", { class: "k", text: n.type }),
      el("button", { type: "button", class: "link", onclick: () => showNode(n) }, n.label), n.inc.size ? el("span", { class: "muted", text: "  " + [...n.inc].join(", ") }) : null));
  }
  c.append(el("div", { class: "muted small", style: "position:absolute;top:70px;left:14px", text: "Graph library unavailable, showing a list." }), ul);
}

// ---------- lifecycle ----------
let mounting = null;
export function mount() {
  setActive(true);
  if (G.mounted) return Promise.resolve();
  if (mounting) return mounting;
  mounting = (async () => {
    const c = clear($("graph-canvas"));
    c.append(el("div", { class: "muted small", style: "padding:80px 16px", text: "Loading the evidence graph..." }));
    if (!SRC.live) { clear(c).append(el("div", { class: "empty", style: "padding:80px 16px", text: "The graph needs the live API. Mock mode has no graph data." })); return; }
    const raw = S.graph || (S.graph = await api("GET", "/graph"));
    G.data = prepare(raw);
    api("GET", "/entities").then((r) => { G.entLinks = (r.entities || []).flatMap((e) => e.links || []); }).catch(() => {});
    const small = matchMedia("(max-width: 720px)").matches;
    clear(c);
    try {
      if (small) throw new Error("small screen");
      G.graph = make3d(await loadScript(LIB3D, "ForceGraph3D"));
      G.mode = "3d";
    } catch (e3) {
      try { G.graph = make2d(await loadScript(LIB2D, "ForceGraph")); G.mode = "2d"; }
      catch (e2) { G.mode = "list"; console.warn("graph libraries unavailable", e3, e2); }
    }
    buildControls();
    if (G.mode === "list") renderList();
    G.mounted = true;
    new IntersectionObserver((es) => { G.visible = es[0].isIntersecting; applyRun(); }).observe($("graph-stage"));
    document.addEventListener("visibilitychange", applyRun);
    $("graph-stage").addEventListener("pointermove", (e) => { mouse = { x: e.clientX, y: e.clientY }; });
    if (G.pending) { const p = G.pending; G.pending = null; setTimeout(() => highlight(p), 900); }
  })();
  return mounting;
}
// Pause rendering when the graph is off screen, the tab is hidden, or another view is open.
function applyRun() {
  const g = G.graph;
  if (!g) return;
  const run = G.active && G.visible && !document.hidden;
  if (run) g.resumeAnimation(); else g.pauseAnimation();
}
export function setActive(on) { G.active = !!on; applyRun(); }
