// Casefile pitch page: live numbers from the API, anime.js reveals, three.js hero (20 slabs, one pulled out).
import { el, clear, $, S, RAW, EVBYID, REDUCED, chipList } from "./app.js";

const THREE_URL = "https://cdnjs.cloudflare.com/ajax/libs/three.js/0.160.0/three.min.js";
const SEVC = { P1: "#c23b12", P2: "#15161a", P3: "#5b5e66", P4: "#5b5e66" };
const p2 = (n) => String(n).padStart(2, "0");
const minOf = (iso) => { const d = new Date(iso); return isNaN(d) ? null : d.getUTCHours() * 60 + d.getUTCMinutes() + d.getUTCSeconds() / 60; };
let filled = false;

function stats() {
  const f = S.facts || {};
  const events = f.events || [];
  const incs = (Array.isArray(S.incidents) ? S.incidents : []).filter((i) => /^INC/.test(i.incident_id));
  const sevs = incs.map((i) => (typeof i.severity === "string" ? i.severity : i.severity && i.severity.value)).filter(Boolean).sort();
  const files = new Set(events.map((e) => e.source_file));
  return { f, events, incs, sevs, files };
}

function fill() {
  const { f, events, incs, sevs, files } = stats();
  if (f.date) {
    $("hero-tag").textContent = `Security incident triage . ${f.date}`;
    $("foot-l").textContent = `Proof of concept. The data covers ${f.date} only. No outside knowledge is used.`;
  }
  $("foot-r").textContent = S.facts ? `facts ${f.facts_hash || "?"} . ${files.size} log files . ${events.length} events` : "API not reachable";
  $("hero-cap").textContent = `${files.size || "The"} log files go in. Each answer pulls out the one line that proves it.`;
  const vals = { files: files.size, events: events.length, incidents: incs.length, harmless: (f.closed_as_harmless || []).length, missing: (f.missing_sources || []).length };
  for (const n of document.querySelectorAll("#stats [data-key]")) { n.dataset.count = String(vals[n.dataset.key] ?? 0); n.textContent = String(vals[n.dataset.key] ?? 0); }
  if (sevs.length) $("stat-inc-l").textContent = `incidents found, the worst is ${sevs[0]}`;
  if (incs.length) $("day-h1").textContent = `${["Zero", "One", "Two", "Three", "Four", "Five"][incs.length] || incs.length} incidents overlap.`;
  traps();
  day(incs, f);
  how(f, incs, sevs, files);
}

// The traps are the owner's copy; their citation chips open the real lines from the fact store.
function traps() {
  const T = [
    ["The big transfer happened at 11:21.", "It started at 06:03:12 UTC.", "The internal firewall logs a session when it closes, in Pakistan time, with no zone written. Casefile subtracts the duration.", [{ file: "15_firewall_internal_log.md", line: 6 }, { file: "20_log_source_coverage.md", row: "Internal firewall" }]],
    ["10.10.3.45 is Ayesha Malik.", "Only while her VPN session was open.", "A VPN address belongs to a person only while their session is open. Ask about 09:00 and the answer is nobody.", [{ file: "11_vpn_auth_log.md", line: 7 }, { file: "11_vpn_auth_log.md", line: 8 }]],
    ["Finance data was stolen.", "2.4 GB left the file server. Which files: not enough evidence.", "The file server keeps no audit log, so a large transfer is never reported as theft.", [{ file: "15_firewall_internal_log.md", line: 6 }, { file: "20_log_source_coverage.md", row: "SRV-FS01 file access (audit) log" }]],
    ["A night-time admin alert is an attack.", "Approved. Closed as harmless.", "A change matches the system, the person and the time window. All three are required.", null],
  ];
  // last trap: take the real harmless closure from the API
  const h = ((S.facts && S.facts.closed_as_harmless) || [])[0];
  if (h) { T[3][0] = `${h.alert} is an attack.`; T[3][1] = `Approved by ${h.change_id}. Closed as harmless.`; T[3][3] = (h.evidence || []).slice(0, 3); }
  const box = clear($("traps"));
  T.forEach(([wrong, right, why, cites], i) => {
    box.append(el("div", { class: "trap", "data-rv": "wipe" },
      el("div", {}, el("span", { class: "k", text: `${p2(i + 1)} . The easy reading` }), el("span", { class: "wrong", text: wrong })),
      el("div", {}, el("span", { class: "k r", text: "What Casefile says" }), el("span", { class: "right", text: right }), el("span", { class: "why", text: why }), cites && cites.length ? chipList(cites) : null)));
  });
}

function day(incs, f) {
  const g = clear($("day-grid"));
  g.append(el("span"));
  const axis = el("div", { class: "day-axis" });
  for (const h of [0, 3, 6, 9, 12, 15, 18, 21]) axis.append(el("span", { style: `left:${(h / 24) * 100}%`, text: p2(h) + ":00" }));
  g.append(axis);
  // Outages inside the day only; a source that simply starts late or stops early is not a band.
  const gaps = (f.gaps || []).filter((x) => x.from_utc && x.to_utc && !/T00:00:00/.test(x.from_utc) && !/T23:59:59/.test(x.to_utc));
  const rows = [];
  for (const i of incs) {
    const sev = typeof i.severity === "string" ? i.severity : i.severity && i.severity.value;
    rows.push({ name: i.incident_id, sub: i.title || "", sev: sev || "-", color: SEVC[sev] || "#5b5e66", events: (i.timeline || []).map((x) => (typeof x === "string" ? EVBYID.get(x) : x)).filter(Boolean) });
  }
  for (const a of (Array.isArray(S.incidents) ? S.incidents : []).filter((i) => /^ANOM/.test(i.incident_id))) {
    rows.push({ name: a.incident_id, sub: a.title || "anomaly, kept apart", sev: "Susp", color: "#2340d9", events: (a.timeline || []).map((x) => (typeof x === "string" ? EVBYID.get(x) : x)).filter(Boolean) });
  }
  const hl = f.closed_as_harmless || [];
  if (hl.length) {
    const evs = [];
    for (const h of hl) for (const c of h.evidence || []) { const e = c.line != null ? RAW.get(`${c.file}|L${c.line}`) : null; if (e) evs.push(e); }
    rows.push({ name: "Approved", sub: hl.map((h) => h.alert).join(" and ") + ", closed as harmless", sev: "OK", color: "#8b8e96", events: evs });
  }
  for (const r of rows) {
    g.append(el("div", { class: "day-name" }, el("span", { class: "sev-tag", style: "background:" + r.color, text: r.sev }), el("span", { class: "nm" }, el("b", { text: r.name }), el("span", { text: r.sub }))));
    const lane = el("div", { class: "day-lane" });
    for (const gp of gaps) { const a = minOf(gp.from_utc), b = minOf(gp.to_utc); lane.append(el("span", { class: "day-gap", style: `left:${(a / 1440) * 100}%;width:${((b - a) / 1440) * 100}%` })); }
    for (const e of r.events) {
      const a = minOf(e.ts_utc); if (a == null) continue;
      const b = e.ts_end_utc ? minOf(e.ts_end_utc) : a;
      const thick = b - a > 3;
      lane.append(el("span", { class: "day-mark", "data-bar": "1", style: `left:${((a / 1440) * 100).toFixed(3)}%;width:${Math.max(((b - a) / 1440) * 100, 0.25).toFixed(3)}%;top:${thick ? 22 : 30}px;height:${thick ? 24 : 8}px;background:${r.color}` }));
    }
    g.append(lane);
  }
  $("day-note").textContent = gaps.length
    ? "Striped band: " + gaps.map((x) => `${x.source.replace(/^\d+_/, "").replace(/\.md$/, "").replace(/_/g, " ")} had no data from ${x.from_utc.slice(11, 19)} to ${x.to_utc.slice(11, 19)} UTC (${x.reason})`).join("; ") + '. Anything in it is reported as "not enough evidence in the logs".'
    : "";
}

function how(f, incs, sevs, files) {
  const steps = [
    ["Parse", "Each log format with its own time zone rule.", `${(f.events || []).length} events from ${files.size} files`],
    ["Load tables", "Inventory, severity matrix, escalation, calendar, runbooks.", "policy as data"],
    ["Coverage", "What each source can see, and when it could not.", `${(f.gaps || []).length} gaps, ${(f.missing_sources || []).length} missing`],
    ["Link", "IP to session to user, each link with a validity window.", S.graph ? `${(S.graph.nodes || []).length} nodes, ${(S.graph.edges || []).length} links` : "identity graph"],
    ["Rules", "Each finding gets a label, evidence and numbered steps.", sevs.length ? sevs.join(", ") : `${(f.findings || []).length} findings`],
    ["Answer", "Route, collect facts, word them, then check every citation.", "template if any step fails"],
  ];
  const ol = clear($("how-steps"));
  steps.forEach(([t, d, o], i) => ol.append(el("li", { "data-it": "1" }, el("span", { class: "n", text: p2(i + 1) }), el("span", { class: "t", text: t }), el("span", { class: "d", text: d }), el("span", { class: "o", text: o }))));
}

// ---------- reveals (same mechanics as the Casefile mock) ----------
let io = null;
function prep() {
  if (REDUCED || !window.anime) return;
  for (const n of document.querySelectorAll("#pitch [data-rv]:not([data-rvd])")) {
    n.setAttribute("data-rvd", "0");
    const k = n.getAttribute("data-rv");
    if (k === "up") { n.style.opacity = "0"; n.style.transform = "translateY(36px)"; }
    if (k === "lines") n.querySelectorAll("[data-ln]").forEach((l) => { l.style.transform = "translateY(115%)"; });
    if (k === "wipe") { n.style.clipPath = "inset(0 100% 0 0)"; n.style.opacity = "0"; }
    if (k === "line") n.style.transform = "scaleX(0)";
    if (k === "stagger") n.querySelectorAll("[data-it]").forEach((l) => { l.style.opacity = "0"; l.style.transform = "translateY(36px)"; });
    n.querySelectorAll("[data-bar]").forEach((b) => { b.style.transform = "scaleX(0)"; });
    n.querySelectorAll("[data-count]").forEach((c) => { c.textContent = "0"; });
  }
}
function reveal(n) {
  const A = window.anime;
  if (n.getAttribute("data-rvd") === "1") return;
  n.setAttribute("data-rvd", "1");
  const k = n.getAttribute("data-rv"), E = "easeOutExpo";
  if (k === "up") A({ targets: n, opacity: [0, 1], translateY: [36, 0], duration: 1000, easing: E });
  if (k === "lines") A({ targets: n.querySelectorAll("[data-ln]"), translateY: ["115%", "0%"], duration: 1200, easing: E, delay: A.stagger(110) });
  if (k === "wipe") { const o = { v: 100 }; n.style.opacity = "1"; A({ targets: o, v: 0, duration: 1100, easing: "easeOutQuart", update: () => { n.style.clipPath = `inset(0 ${o.v.toFixed(1)}% 0 0)`; }, complete: () => { n.style.clipPath = "none"; } }); }
  if (k === "line") A({ targets: n, scaleX: [0, 1], duration: 1400, easing: "easeInOutQuart" });
  if (k === "stagger") A({ targets: n.querySelectorAll("[data-it]"), opacity: [0, 1], translateY: [36, 0], duration: 900, easing: E, delay: A.stagger(90) });
  n.querySelectorAll("[data-bar]").forEach((b, i) => A({ targets: b, scaleX: [0, 1], duration: 1100, delay: 300 + i * 30, easing: "easeOutQuart" }));
  n.querySelectorAll("[data-count]").forEach((c) => { const end = +c.dataset.count || 0, o = { v: 0 }; A({ targets: o, v: end, round: 1, duration: 1600, easing: E, update: () => { c.textContent = String(o.v); } }); });
}
function watch() {
  if (REDUCED || !window.anime) return;
  if (!io) io = new IntersectionObserver((es) => es.forEach((en) => { if (en.isIntersecting) { io.unobserve(en.target); reveal(en.target); } }), { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
  document.querySelectorAll('#pitch [data-rvd="0"]').forEach((n) => io.observe(n));
}

// ---------- hero 3D: one slab per log file, the one that proves it slides out ----------
let three = null;
function loadThree() {
  if (window.THREE) return Promise.resolve(window.THREE);
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = THREE_URL; s.async = true; s.crossOrigin = "anonymous";
    const t = setTimeout(() => rej(new Error("three timeout")), 8000);
    s.onload = () => { clearTimeout(t); window.THREE ? res(window.THREE) : rej(new Error("no THREE")); };
    s.onerror = () => { clearTimeout(t); rej(new Error("three failed")); };
    document.head.append(s);
  });
}
let px = 0, py = 0;
addEventListener("pointermove", (e) => { px = e.clientX / innerWidth - 0.5; py = e.clientY / innerHeight - 0.5; });
async function start3D() {
  if (three) { three.run = true; three.loop(); return; }
  let T;
  try { T = await loadThree(); } catch (e) { return; } // the white card stays; the page works without it
  const cv = $("hero-canvas"), box = $("hero-box");
  try {
    const r = new T.WebGLRenderer({ canvas: cv, antialias: true, alpha: true });
    r.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
    const scene = new T.Scene(), cam = new T.PerspectiveCamera(30, 1, 0.1, 100);
    cam.position.set(0, 0.4, 13.5); cam.lookAt(0, 0, 0);
    scene.add(new T.HemisphereLight(0xffffff, 0xcfd3e6, 0.95));
    const d = new T.DirectionalLight(0xffffff, 0.7); d.position.set(5, 9, 7); scene.add(d);
    const g = new T.Group(); g.rotation.x = 0.42; scene.add(g);
    const n = Math.max(8, Math.min(24, (S.facts && new Set((S.facts.events || []).map((e) => e.source_file)).size + 13) || 20));
    const hitI = Math.floor(n * 0.65);
    const geo = new T.BoxGeometry(3.4, 0.11, 2.3), edge = new T.EdgesGeometry(geo);
    const slabs = [];
    for (let i = 0; i < n; i++) {
      const hit = i === hitI;
      const m = new T.Mesh(geo, new T.MeshStandardMaterial({ color: hit ? 0x2340d9 : i % 2 ? 0xe9e7df : 0xf7f6f2, roughness: 0.85, metalness: 0, transparent: true, opacity: 0 }));
      const y = (i - (n - 1) / 2) * 0.24;
      m.position.set(0, y + 5, 0); m.rotation.y = Math.sin(i * 2.4) * 0.07;
      const ln = new T.LineSegments(edge, new T.LineBasicMaterial({ color: hit ? 0x101c6e : 0x15161a, transparent: true, opacity: 0 }));
      m.add(ln);
      if (hit) { const strip = new T.Mesh(new T.BoxGeometry(2.6, 0.03, 0.16), new T.MeshBasicMaterial({ color: 0xffffff })); strip.position.set(-0.1, 0.07, 0.3); m.add(strip); }
      g.add(m); slabs.push({ m, ln, y, hit });
    }
    const A = window.anime;
    slabs.forEach((s, i) => {
      if (REDUCED || !A) { s.m.position.y = s.y; s.m.material.opacity = 1; s.ln.material.opacity = 0.22; if (s.hit) s.m.position.x = 1.5; return; }
      const o = { y: s.y + 5, a: 0 };
      A({ targets: o, y: s.y, a: 1, duration: 1100, delay: 200 + i * 55, easing: "easeOutExpo", update: () => { s.m.position.y = o.y; s.m.material.opacity = o.a; s.ln.material.opacity = o.a * 0.22; } });
      if (s.hit) { const p = { x: 0 }; A({ targets: p, x: 1.5, duration: 1300, delay: 1900, easing: "easeInOutQuart", update: () => { s.m.position.x = p.x; } }); }
    });
    let w3 = 0, h3 = 0, mx = 0, my = 0, raf = 0, visible = true;
    const t0 = performance.now();
    three = { run: true, loop: null };
    const loop = (ts) => {
      if (!three.run || !visible || document.hidden) { raf = 0; return; }
      raf = requestAnimationFrame(loop);
      const w = box.clientWidth, h = box.clientHeight;
      if (w && (w !== w3 || h !== h3)) { w3 = w; h3 = h; r.setSize(w, h, false); cam.aspect = w / h; cam.updateProjectionMatrix(); }
      const t = ((ts || performance.now()) - t0) / 1000;
      mx += (px - mx) * 0.05; my += (py - my) * 0.05;
      g.rotation.y = -0.55 + (REDUCED ? 0 : Math.sin(t * 0.35) * 0.22) + mx * 0.5;
      g.rotation.x = 0.42 + my * 0.25;
      r.render(scene, cam);
    };
    three.loop = () => { if (!raf) raf = requestAnimationFrame(loop); };
    // pause when the hero is off screen
    new IntersectionObserver((es) => { visible = es[0].isIntersecting; if (visible) three.loop(); }).observe(box);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) three.loop(); });
    three.loop();
  } catch (e) { three = null; }
}

export function start() {
  if (!filled) { fill(); filled = true; }
  prep(); watch(); start3D();
}
export function stop() { if (three) three.run = false; }
