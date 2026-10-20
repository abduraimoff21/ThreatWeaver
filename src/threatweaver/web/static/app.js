/* ThreatWeaver dashboard. Vanilla JS, no dependencies, no network except this server.
 * SECURITY: data from logs and feeds is attacker-influenced. It is only ever put into the page
 * through textContent / createTextNode (see h() below). The page is never built from HTML strings. */
(() => {
'use strict';

const TOKEN = document.querySelector('meta[name="tw-token"]').content;
const LEVELS = ['high', 'medium', 'low', 'info'];
const RULE_HELP = {
  url_host: 'URL and its host (structural)',
  email_domain: 'E-mail address and its domain (structural)',
  same_line: 'Appear on the same log line (co-occurrence, not proof)',
  hostname_ip: 'Host name spells out this IP address',
  shared_family: 'Listed by a feed under the same malware family',
};
const state = { exact: false, theme: null, uploadLimit: 1024 * 1024 * 1024 };

/* ---------- tiny DOM helpers ---------- */
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = v; // CSSOM is allowed by the CSP; a style="" attribute is not
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = Boolean(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, kids);
  return el;
}
const SVG_NS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
  append(el, kids);
  return el;
}
const $ = (sel, root = document) => root.querySelector(sel);

function remember(key, value) { try { if (value === undefined) return localStorage.getItem('tw.' + key) || ''; localStorage.setItem('tw.' + key, value); } catch { return ''; } return ''; }

/* ---------- API ---------- */
async function api(path, body) {
  const init = { headers: { 'X-TW-Token': TOKEN } };
  if (body !== undefined) {
    init.method = 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

function toast(message, kind = '') {
  const box = $('.toasts');
  const t = h('div', { class: 'toast ' + kind, role: kind === 'err' ? 'alert' : 'status' }, message);
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 9000 : 5000);
}
async function guarded(fn) { try { return await fn(); } catch (e) { toast(e.message, 'err'); return null; } }

/* ---------- shared bits ---------- */
const val = (i) => (state.exact ? i.value : i.display);
const badge = (level) => h('span', { class: 'badge ' + level }, level);
const typeTag = (t) => h('span', { class: 'tag' }, t);
const fmtBytes = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB' : n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB');
function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '';
  if (seconds < 90) return `${Math.max(1, Math.round(seconds))} s`;
  return seconds < 5400 ? `${Math.round(seconds / 60)} min` : `${(seconds / 3600).toFixed(1)} h`;
}
function age(iso) {
  if (!iso) return '';
  const hrs = (Date.now() - Date.parse(iso)) / 36e5;
  if (!isFinite(hrs)) return '';
  return hrs < 1 ? 'less than an hour ago' : hrs < 48 ? `${Math.round(hrs)} hours ago` : `${Math.round(hrs / 24)} days ago`;
}
function empty(message, action) { return h('div', { class: 'panel muted' }, message, ' ', action || ''); }
function table(headers, rows, onRow) {
  const body = h('tbody');
  for (const r of rows) {
    const tr = h('tr', onRow ? { class: 'click', tabindex: 0, onclick: () => onRow(r.data), onkeydown: (e) => { if (e.key === 'Enter') onRow(r.data); } } : {}, r.cells.map((c) => h('td', c.class ? { class: c.class } : {}, c.node ?? c.text)));
    body.append(tr);
  }
  return h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, headers.map((x) => h('th', {}, x)))), body));
}
function cell(text, cls) { return { text, class: cls }; }
function nodeCell(node, cls) { return { node, class: cls }; }

/* ---------- indicator drawer ---------- */
function closeDrawer() { $('.drawer-back')?.remove(); $('.drawer')?.remove(); }
async function openIndicator(id) {
  const d = await guarded(() => api('/api/indicator/' + id));
  if (!d) return;
  closeDrawer();
  const close = h('button', { onclick: closeDrawer, 'aria-label': 'Close details' }, 'Close');
  const drawer = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': 'Indicator details' },
    h('div', { class: 'toolbar', style: 'justify-content:space-between' }, h('div', {}, typeTag(d.type), badge(d.level), ' ', h('span', { class: 'muted' }, `score ${d.score}`)), close),
    h('h2', { class: 'mono' }, val(d)),
    h('p', {}, d.suggested_action),
    d.scope && d.scope !== 'global' ? h('p', { class: 'small muted' }, `Address scope: ${d.scope}`) : null,
    h('p', { class: 'small' }, 'Case: ', h('button', { class: 'link', onclick: () => { closeDrawer(); location.hash = '#/case/' + d.case_id; } }, d.case_id),
      d.feedback && d.feedback.length ? [' Latest verdict: ', verdictTag(d.feedback[0].label)] : null),
    d.feedback ? drawerFeedback(d) : null,
    h('h3', {}, 'Why this level'),
    d.rules.length ? d.rules.map((r) => h('div', { class: 'rule ' + (r.points >= 0 ? 'pos' : 'neg') },
      h('span', { class: 'pts' }, (r.points >= 0 ? '+' : '') + r.points), ' ', h('b', {}, r.rule), ' ', h('span', { class: 'muted' }, r.description),
      h('div', {}, r.reason), h('div', { class: 'small muted' }, `${r.evidence_total} evidence item(s)`)))
      : h('p', { class: 'muted' }, 'No triage rule fired for this indicator.'),
    d.feed_matches.length ? h('h3', {}, 'Public feed records') : null,
    d.feed_matches.map((m) => h('div', { class: 'panel' },
      h('b', {}, m.feed), ' ', h('span', { class: 'muted' }, m.via === 'exact' ? 'lists this indicator' : 'lists a URL hosted here: ' + m.listed_url),
      h('div', { class: 'small muted' }, `snapshot ${m.snapshot}, collected ${m.collected_at}`),
      h('div', { class: 'mono small' }, Object.entries(m.fields).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\n').split('\n').map((l) => h('div', {}, l))))),
    d.links.length ? h('h3', {}, 'Connected indicators') : null,
    d.links_total > d.links.length ? h('p', { class: 'small muted' }, `Showing the strongest ${d.links.length} of ${d.links_total.toLocaleString()} links.`) : null,
    d.links.length ? table(['Rule', 'Type', 'Indicator', 'Evidence'], d.links.map((l) => ({ data: l, cells: [cell(l.rule), cell(l.other_type), cell(l.other, 'val'), cell(String(l.evidence))] })), (l) => openIndicator(l.other_id)) : null,
    h('h3', {}, `Where it was seen (${d.sightings_total})`),
    d.sightings_total > d.sightings.length ? h('p', { class: 'small muted' }, `Showing the first ${d.sightings.length}.`) : null,
    d.sightings.map((x) => h('div', { class: 'panel' },
      h('div', { class: 'small' }, h('b', {}, x.source), ` line ${x.line}`, x.defanged ? ' (written defanged)' : '', x.from_url ? ' (host of a URL)' : ''),
      x.has_context ? h('div', { class: 'ctx' }, x.context) : h('div', { class: 'small muted' }, 'Log line not stored (ingested by an older version). Re-ingest to see it.'))));
  document.body.append(h('div', { class: 'drawer-back', onclick: closeDrawer }), drawer);
  close.focus();
}
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

/* ---------- graph ---------- */
const EDGE_STYLE = {
  url_host: { w: 2.6, dash: null }, email_domain: { w: 2.6, dash: '10 3 2 3' }, same_line: { w: 1.4, dash: null },
  hostname_ip: { w: 1.8, dash: '7 4' }, shared_family: { w: 1.4, dash: '2 5' },
};
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
function nodeRadius(d) { return 6 + Math.min(d.score / 12, 7); }
function shapeFor(node, r) {
  const fill = `var(--${node.level}-bg)`;
  const common = { fill, stroke: 'var(--text)', 'stroke-width': 1.5 };
  if (node.type === 'domain') return s('rect', { ...common, x: -r, y: -r, width: 2 * r, height: 2 * r, rx: 3 });
  if (node.type === 'url') return s('polygon', { ...common, points: `0,${-r * 1.3} ${r * 1.3},0 0,${r * 1.3} ${-r * 1.3},0` });
  if (node.type.startsWith('ip')) return s('circle', { ...common, r });
  if (node.type === 'email') return s('polygon', { ...common, points: `0,${-r * 1.3} ${r * 1.25},${r} ${-r * 1.25},${r}` }); // triangle
  if (node.type === 'filename') return s('polygon', { ...common, points: `${-r * 0.85},${-r * 1.15} ${r * 0.3},${-r * 1.15} ${r * 0.85},${-r * 0.55} ${r * 0.85},${r * 1.15} ${-r * 0.85},${r * 1.15}` }); // page with a folded corner
  const pts = [0, 1, 2, 3, 4, 5].map((i) => `${(r * 1.2 * Math.cos(Math.PI / 3 * i)).toFixed(1)},${(r * 1.2 * Math.sin(Math.PI / 3 * i)).toFixed(1)}`).join(' ');
  return s('polygon', { ...common, points: pts });
}

/* Force layout for one connected group, in free space (no walls, so nothing piles up against an edge).
 * Pull along a link is divided by the endpoints' link counts, so a node with hundreds of neighbours spreads
 * them around itself instead of dragging everything into one ball; a final pass pushes overlaps apart.
 * Work is O(nodes^2) per step, which is why the server caps how many nodes it sends. */
function force(nodes, edges) {
  const n = nodes.length;
  const k = 56; // the length a lone link would settle at, in world units
  const byId = new Map(nodes.map((d) => [d.id, d]));
  const pairs = [];
  for (const e of edges) {
    const a = byId.get(e.a), b = byId.get(e.b);
    if (a && b) { a.deg = (a.deg || 0) + 1; b.deg = (b.deg || 0) + 1; pairs.push([a, b]); }
  }
  // start on a spiral ordered by score: the strongest nodes begin in the middle
  const order = [...nodes].sort((p, q) => q.score - p.score);
  order.forEach((d, i) => { const a = i * 2.399963, rad = k * 0.6 * Math.sqrt(i + 0.5); d.x = Math.cos(a) * rad; d.y = Math.sin(a) * rad; });
  const steps = n > 400 ? 110 : n > 150 ? 180 : 280;
  const t0 = k * 4, t1 = k * 0.02;
  let temp = t0;
  const cool = Math.pow(t1 / t0, 1 / steps);
  for (let it = 0; it < steps; it++) {
    for (const d of nodes) { d.dx = 0; d.dy = 0; }
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let dist = Math.hypot(dx, dy);
        if (dist < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; dist = 1; }
        const f = (k * k) / dist;
        a.dx += (dx / dist) * f; a.dy += (dy / dist) * f; b.dx -= (dx / dist) * f; b.dy -= (dy / dist) * f;
      }
    }
    for (const [a, b] of pairs) {
      const dx = a.x - b.x, dy = a.y - b.y, dist = Math.max(Math.hypot(dx, dy), 0.01);
      const f = (dist * dist) / k / Math.max(1, Math.sqrt((a.deg || 1) * (b.deg || 1)));
      a.dx -= (dx / dist) * f; a.dy -= (dy / dist) * f; b.dx += (dx / dist) * f; b.dy += (dy / dist) * f;
    }
    for (const d of nodes) {
      d.dx -= d.x * 0.35; d.dy -= d.y * 0.35; // gentle pull to the middle keeps the group compact
      const len = Math.max(Math.hypot(d.dx, d.dy), 0.01);
      d.x += (d.dx / len) * Math.min(len, temp);
      d.y += (d.dy / len) * Math.min(len, temp);
    }
    temp *= cool;
  }
  for (let pass = 0; pass < 14; pass++) {
    let moved = false;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = nodes[i], b = nodes[j];
        const min = nodeRadius(a) + nodeRadius(b) + 5;
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.hypot(dx, dy);
        if (dist >= min) continue;
        if (dist < 0.01) { dx = 1; dy = 0; dist = 1; }
        const push = (min - dist) / 2;
        a.x -= (dx / dist) * push; a.y -= (dy / dist) * push; b.x += (dx / dist) * push; b.y += (dy / dist) * push;
        moved = true;
      }
    }
    if (!moved) break;
  }
}

/* Lay out each connected group on its own, then pack the groups in rows, strongest first. The "world" can be
 * far bigger than the screen: the viewer zooms and pans over it. Returns { groups, width, height }. */
function layoutAll(nodes, edges) {
  const byId = new Map(nodes.map((d) => [d.id, d]));
  const parent = new Map(nodes.map((d) => [d.id, d.id]));
  const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
  for (const e of edges) if (byId.has(e.a) && byId.has(e.b)) parent.set(find(e.a), find(e.b));
  const buckets = new Map();
  for (const d of nodes) { const r = find(d.id); if (!buckets.has(r)) buckets.set(r, []); buckets.get(r).push(d); }
  const comps = [...buckets.values()].sort((a, b) => Math.max(...b.map((d) => d.score)) - Math.max(...a.map((d) => d.score)) || b.length - a.length);
  const PAD = 44; // room for the group outline and its caption
  const boxes = comps.map((comp) => {
    if (comp.length > 1) { const ids = new Set(comp.map((d) => d.id)); force(comp, edges.filter((e) => ids.has(e.a) && ids.has(e.b))); }
    else { comp[0].x = 0; comp[0].y = 0; }
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const d of comp) { const r = nodeRadius(d) + 14; x0 = Math.min(x0, d.x - r); y0 = Math.min(y0, d.y - r); x1 = Math.max(x1, d.x + r); y1 = Math.max(y1, d.y + r); }
    for (const d of comp) { d.x -= x0 - PAD / 2; d.y -= y0 - PAD / 2; }
    return { comp, w: x1 - x0 + PAD, h: y1 - y0 + PAD };
  });
  const totalArea = boxes.reduce((t, b) => t + b.w * b.h, 0);
  const W = Math.max(900, Math.max(...boxes.map((b) => b.w)) + 40, Math.sqrt(totalArea) * 1.5);
  let x = 20, y = 20, rowH = 0;
  const groups = [];
  for (const { comp, w, h: hh } of boxes) {
    if (x + w > W - 20 && x > 20) { x = 20; y += rowH + 16; rowH = 0; }
    for (const d of comp) { d.x += x; d.y += y; }
    groups.push({ nodes: comp, caseId: comp.reduce((best, d) => (d.score > best.score ? d : best), comp[0]).case_id });
    x += w + 16; rowH = Math.max(rowH, hh);
  }
  return { groups, width: W, height: y + rowH + 20 };
}

function legend() {
  const item = (shape, text) => h('span', {}, shape, ' ', text);
  const small = (node) => { const sv = s('svg', { width: 18, height: 18, viewBox: '-10 -10 20 20', 'aria-hidden': 'true' }); sv.append(node); return sv; };
  const sh = (type) => small(shapeFor({ type, level: 'info' }, 6));
  const line = (rule) => { const st = EDGE_STYLE[rule]; const sv = s('svg', { width: 34, height: 12, 'aria-hidden': 'true' }); sv.append(s('line', { x1: 1, y1: 6, x2: 33, y2: 6, stroke: 'var(--muted)', 'stroke-width': st.w, 'stroke-dasharray': st.dash })); return sv; };
  return h('div', { class: 'legend' },
    item(sh('ipv4'), 'IP'), item(sh('domain'), 'domain'), item(sh('url'), 'URL'), item(sh('email'), 'e-mail'), item(sh('filename'), 'file name'), item(sh('sha256'), 'hash'), ' | ',
    LEVELS.map((l) => badge(l)), ' | ',
    Object.keys(EDGE_STYLE).map((r) => item(line(r), r.replace('_', ' '))));
}

/* The interactive graph: wheel or +/- to zoom, drag the background to pan, drag a node to move it, pinch on a
 * touch screen. Hover (or Tab to) a node to light up its neighbours and fade the rest; zoom in to read labels. */
function drawGraph(data) {
  const nodes = data.nodes.map((n) => ({ ...n }));
  if (!nodes.length) return empty('Nothing to draw with these settings. Links appear when indicators share a log line, a URL and its host, or a host name that spells out an IP. Try a lower priority level.');
  const edgesIn = data.edges.filter((e) => e.a !== e.b);
  const lay = layoutAll(nodes, edgesIn);
  const byId = new Map(nodes.map((d) => [d.id, d]));
  const rank = new Map([...nodes].sort((p, q) => q.score - p.score).map((d, i) => [d.id, i]));
  const edges = edgesIn.filter((e) => byId.has(e.a) && byId.has(e.b));
  const neighbours = new Map(nodes.map((d) => [d.id, new Set()]));
  for (const e of edges) { neighbours.get(e.a).add(e.b); neighbours.get(e.b).add(e.a); }

  let VW = 1000, VH = 640; // the view box tracks the element's pixel size, so one unit is one screen pixel
  const view = { k: 1, tx: 0, ty: 0 };
  let touched = false; // once the person zooms or pans, a resize no longer re-fits
  const svg = s('svg', { class: 'graph', viewBox: `0 0 ${VW} ${VH}`, role: 'group', tabindex: 0, 'aria-label': `Link graph with ${nodes.length} indicators. Use plus and minus to zoom, arrow keys to move.` });
  const vp = s('g', { class: 'viewport' });
  const hullLayer = s('g', { class: 'hulls' }), edgeLayer = s('g', { class: 'edges' }), nodeLayer = s('g', { class: 'nodes' });
  vp.append(hullLayer, edgeLayer, nodeLayer);
  svg.append(vp);

  const edgeOpacity = clamp(0.85 - edges.length / 1200, 0.28, 0.85);
  const edgeEls = edges.map((e) => {
    const st = EDGE_STYLE[e.rule] || EDGE_STYLE.same_line;
    const line = s('line', { stroke: 'var(--muted)', 'stroke-width': st.w, 'stroke-dasharray': st.dash, opacity: edgeOpacity }, s('title', {}, e.rule.replace('_', ' ')));
    edgeLayer.append(line);
    return { e, line };
  });
  const edgesOf = new Map(nodes.map((d) => [d.id, []]));
  for (const x of edgeEls) { edgesOf.get(x.e.a).push(x.line); edgesOf.get(x.e.b).push(x.line); }

  const nodeEls = new Map();
  for (const d of nodes) {
    const r = nodeRadius(d);
    const full = val(d);
    const label = s('text', { x: 0, y: r, dy: '1.3em', 'text-anchor': 'middle' }, full.length > 34 ? full.slice(0, 33) + '...' : full);
    const more = d.degree > neighbours.get(d.id).size ? `, ${d.degree} links in total (${d.degree - neighbours.get(d.id).size} not drawn)` : '';
    // only the strongest nodes are tab stops; the Find box and the Indicators page reach the rest
    // .ns is scaled by CSS (--ns) so a node grows only as the square root of the zoom and its label keeps its size
    const g = s('g', { class: 'node', 'data-id': d.id, tabindex: rank.get(d.id) < 40 ? 0 : -1, role: 'button', 'aria-label': `${d.type} ${d.display}, ${d.level}` },
      s('title', {}, `${full} (${d.level}, score ${d.score}${more})`), s('g', { class: 'ns' }, shapeFor(d, r), label));
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') openIndicator(d.id); });
    g.addEventListener('focus', () => light(d.id));
    g.addEventListener('blur', () => unlight());
    nodeLayer.append(g);
    nodeEls.set(d.id, { d, g, label, r });
  }

  // one faint outline per group of three or more, with a clickable case label
  const hullEls = lay.groups.filter((gr) => gr.nodes.length >= 3).map((gr) => {
    const ring = s('circle', { class: 'hull' });
    const cap = s('text', { class: 'hull-label', 'text-anchor': 'middle', 'data-case': gr.caseId || '' }, `${gr.nodes.length} indicators${gr.caseId ? ' - open case' : ''}`);
    hullLayer.append(ring, cap);
    return { gr, ring, cap };
  });

  function place() {
    for (const { e, line } of edgeEls) {
      const a = byId.get(e.a), b = byId.get(e.b);
      line.setAttribute('x1', a.x.toFixed(1)); line.setAttribute('y1', a.y.toFixed(1)); line.setAttribute('x2', b.x.toFixed(1)); line.setAttribute('y2', b.y.toFixed(1));
    }
    for (const { d, g } of nodeEls.values()) g.setAttribute('transform', `translate(${d.x.toFixed(1)},${d.y.toFixed(1)})`);
    for (const { gr, ring, cap } of hullEls) {
      let cx = 0, cy = 0;
      for (const d of gr.nodes) { cx += d.x; cy += d.y; }
      cx /= gr.nodes.length; cy /= gr.nodes.length;
      let rad = 0;
      for (const d of gr.nodes) rad = Math.max(rad, Math.hypot(d.x - cx, d.y - cy));
      rad += 26;
      ring.setAttribute('cx', cx.toFixed(1)); ring.setAttribute('cy', cy.toFixed(1)); ring.setAttribute('r', rad.toFixed(1));
      cap.setAttribute('x', cx.toFixed(1)); cap.setAttribute('y', (cy - rad - 6).toFixed(1));
    }
  }

  /* --- zoom and pan --- */
  let frame = 0;
  function apply() {
    vp.setAttribute('transform', `translate(${view.tx.toFixed(2)},${view.ty.toFixed(2)}) scale(${view.k.toFixed(4)})`);
    svg.style.setProperty('--inv', (1 / view.k).toFixed(4)); // group captions keep a constant size on screen
    svg.style.setProperty('--ns', (1 / Math.sqrt(view.k)).toFixed(4)); // nodes and their labels grow with the square root of the zoom
    if (!frame) frame = requestAnimationFrame(() => { frame = 0; labels(); });
  }
  const bounds = (list) => {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const d of list) { x0 = Math.min(x0, d.x); y0 = Math.min(y0, d.y); x1 = Math.max(x1, d.x); y1 = Math.max(y1, d.y); }
    if (list === nodes) { // "fit all" also keeps the group outlines in view
      for (const { ring } of hullEls) {
        const cx = Number(ring.getAttribute('cx')), cy = Number(ring.getAttribute('cy')), r = Number(ring.getAttribute('r'));
        x0 = Math.min(x0, cx - r); y0 = Math.min(y0, cy - r - 24); x1 = Math.max(x1, cx + r); y1 = Math.max(y1, cy + r);
      }
    }
    return { x0, y0, x1, y1 };
  };
  let fitK = 1;
  function fit(list, maxK = 3) {
    const b = bounds(list);
    const pad = 50, w = Math.max(b.x1 - b.x0, 60), hh = Math.max(b.y1 - b.y0, 60);
    const k = clamp(Math.min((VW - 2 * pad) / w, (VH - 2 * pad) / hh), 0.02, maxK);
    view.k = k; view.tx = VW / 2 - ((b.x0 + b.x1) / 2) * k; view.ty = VH / 2 - ((b.y0 + b.y1) / 2) * k;
    if (list === nodes) fitK = k;
    apply();
  }
  const kMin = () => Math.max(0.01, fitK * 0.4), kMax = () => Math.max(8, fitK * 40);
  function toView(cx, cy) {
    const box = svg.getBoundingClientRect();
    return { x: ((cx - box.left) / Math.max(box.width, 1)) * VW, y: ((cy - box.top) / Math.max(box.height, 1)) * VH };
  }
  function zoomAt(cx, cy, factor) {
    const p = toView(cx, cy);
    const nk = clamp(view.k * factor, kMin(), kMax());
    const f = nk / view.k;
    view.tx = p.x - (p.x - view.tx) * f; view.ty = p.y - (p.y - view.ty) * f; view.k = nk;
    touched = true; apply();
  }
  const zoomCentre = (factor) => { const b = svg.getBoundingClientRect(); zoomAt(b.left + b.width / 2, b.top + b.height / 2, factor); };

  /* --- labels: the strongest few when zoomed out, more as you zoom in; hovering lights a node's neighbours and CSS shows their labels --- */
  let lit = null;
  function labels() {
    const budget = nodes.length <= 30 ? nodes.length : Math.ceil(8 * (view.k / fitK) ** 2);
    for (const { d, g } of nodeEls.values()) g.classList.toggle('labelled', rank.get(d.id) < budget);
  }
  function light(id) {
    unlight();
    const near = neighbours.get(id);
    lit = { els: [nodeEls.get(id).g, ...[...near].map((n) => nodeEls.get(n).g)], lines: edgesOf.get(id) };
    svg.classList.add('focus');
    for (const g of lit.els) g.classList.add('on');
    for (const l of lit.lines) l.classList.add('on');
  }
  function unlight() {
    if (!lit) return;
    svg.classList.remove('focus');
    for (const g of lit.els) g.classList.remove('on');
    for (const l of lit.lines) l.classList.remove('on');
    lit = null;
  }

  /* --- pointer handling: pan, drag a node, pinch --- */
  const pointers = new Map();
  let mode = null, dragged = null, moved = false, pinch = 0, start = null;
  svg.addEventListener('pointerdown', (ev) => {
    if (ev.button > 0) return;
    pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    try { svg.setPointerCapture(ev.pointerId); } catch { /* synthetic pointers cannot be captured */ }
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      pinch = Math.hypot(a.x - b.x, a.y - b.y); mode = 'pinch'; return;
    }
    const target = ev.target.closest ? ev.target.closest('.node') : null;
    const cap = ev.target.closest ? ev.target.closest('.hull-label') : null;
    moved = false; start = { x: ev.clientX, y: ev.clientY };
    if (cap) { mode = 'caption'; dragged = cap; return; }
    if (target) { mode = 'node'; dragged = nodeEls.get(Number(target.getAttribute('data-id'))).d; light(dragged.id); }
    else { mode = 'pan'; dragged = null; svg.classList.add('panning'); }
  });
  svg.addEventListener('pointermove', (ev) => {
    const prev = pointers.get(ev.pointerId);
    if (!prev) return;
    const dx = ev.clientX - prev.x, dy = ev.clientY - prev.y;
    pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (mode === 'pinch' && pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch > 0) zoomAt((a.x + b.x) / 2, (a.y + b.y) / 2, dist / pinch);
      pinch = dist; return;
    }
    if (start && Math.hypot(ev.clientX - start.x, ev.clientY - start.y) > 4) moved = true;
    if (mode === 'pan' && moved) {
      const box = svg.getBoundingClientRect();
      view.tx += (dx / Math.max(box.width, 1)) * VW; view.ty += (dy / Math.max(box.height, 1)) * VH; touched = true; apply();
    } else if (mode === 'node' && moved) {
      const p = toView(ev.clientX, ev.clientY);
      dragged.x = (p.x - view.tx) / view.k; dragged.y = (p.y - view.ty) / view.k; place();
    }
  });
  const release = (ev) => {
    if (!pointers.delete(ev.pointerId)) return;
    if (pointers.size === 0) {
      if (mode === 'node' && dragged && !moved && ev.type === 'pointerup') openIndicator(dragged.id);
      if (mode === 'caption' && dragged && !moved && ev.type === 'pointerup') { const id = dragged.getAttribute('data-case'); if (id) location.hash = '#/case/' + id; }
      if (mode === 'node') unlight();
      svg.classList.remove('panning'); mode = null; dragged = null; pinch = 0;
    } else if (pointers.size === 1) { mode = 'pan'; pinch = 0; start = null; moved = true; }
  };
  svg.addEventListener('pointerup', release);
  svg.addEventListener('pointercancel', release);
  svg.addEventListener('pointerover', (ev) => { const n = ev.target.closest ? ev.target.closest('.node') : null; if (n && mode === null) light(Number(n.getAttribute('data-id'))); });
  svg.addEventListener('pointerout', (ev) => { const n = ev.target.closest ? ev.target.closest('.node') : null; if (n && mode === null) unlight(); });
  svg.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    const unit = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? 400 : 1;
    zoomAt(ev.clientX, ev.clientY, Math.exp(-ev.deltaY * unit * (ev.ctrlKey ? 0.01 : 0.0016)));
  }, { passive: false });
  svg.addEventListener('dblclick', (ev) => { if (!ev.target.closest('.node') && !ev.target.closest('.hull-label')) zoomAt(ev.clientX, ev.clientY, 1.8); });
  svg.addEventListener('keydown', (ev) => {
    if (ev.target !== svg) return;
    const step = 60, move = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[ev.key];
    if (move) { view.tx += move[0]; view.ty += move[1]; touched = true; apply(); ev.preventDefault(); }
    else if (ev.key === '+' || ev.key === '=') { zoomCentre(1.4); ev.preventDefault(); }
    else if (ev.key === '-' || ev.key === '_') { zoomCentre(1 / 1.4); ev.preventDefault(); }
    else if (ev.key === '0') { touched = false; fit(nodes); ev.preventDefault(); }
  });

  /* --- controls around the canvas --- */
  const box = h('div', { class: 'graphbox' });
  const status = h('span', { class: 'small muted', role: 'status' });
  const find = h('input', { type: 'search', placeholder: 'Find an indicator...', 'aria-label': 'Find an indicator in this graph', class: 'graph-find' });
  find.addEventListener('input', () => {
    const q = find.value.trim().toLowerCase();
    for (const { d, g } of nodeEls.values()) g.classList.remove('match');
    if (!q) { status.textContent = ''; svg.classList.remove('finding'); return; }
    const hits = nodes.filter((d) => d.value.toLowerCase().includes(q) || d.display.toLowerCase().includes(q));
    svg.classList.toggle('finding', hits.length > 0);
    for (const d of hits) nodeEls.get(d.id).g.classList.add('match');
    status.textContent = hits.length ? `${hits.length} match${hits.length === 1 ? '' : 'es'} in this view` : 'No match in this view (the graph shows only the highest-priority indicators)';
    if (hits.length) { touched = true; fit(hits, 4); }
  });
  const expand = h('button', { type: 'button', 'aria-pressed': 'false', onclick: () => {
    const on = box.classList.toggle('expanded');
    expand.setAttribute('aria-pressed', String(on)); expand.textContent = on ? 'Close full screen' : 'Full screen';
    document.body.classList.toggle('graph-open', on);
    resize();
  } }, 'Full screen');
  const bar = h('div', { class: 'toolbar graphbar' },
    h('button', { type: 'button', 'aria-label': 'Zoom in', onclick: () => zoomCentre(1.5) }, '+'),
    h('button', { type: 'button', 'aria-label': 'Zoom out', onclick: () => zoomCentre(1 / 1.5) }, '−'),
    h('button', { type: 'button', onclick: () => { touched = false; fit(nodes); } }, 'Fit all'),
    expand, find, status);
  box.append(bar, svg);
  box.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && box.classList.contains('expanded')) { ev.stopPropagation(); expand.click(); } });

  function resize() {
    const r = svg.getBoundingClientRect();
    if (r.width < 10 || r.height < 10) return;
    VW = r.width; VH = r.height;
    svg.setAttribute('viewBox', `0 0 ${VW.toFixed(1)} ${VH.toFixed(1)}`);
    if (!touched) fit(nodes);
  }
  if (typeof ResizeObserver === 'function') new ResizeObserver(() => resize()).observe(svg);
  place();
  // the element is not in the page yet, so fit once it has a size
  fit(nodes);
  requestAnimationFrame(resize);

  return h('div', {}, legend(), box,
    h('p', { class: 'small muted' }, 'Scroll or pinch to zoom, drag the background to move, drag a node to rearrange. Hover a node to see only what it connects to; click it for details. Zoom in to read more labels. Colour is the suggested level, shape is the type. Faint circles group indicators that belong together: click the caption to open that case.'),
    h('p', { class: 'small muted' },
      `Showing ${nodes.length} indicators`,
      data.truncated ? ` (${data.matching.toLocaleString()} are linked at this priority or higher; the highest-scoring are drawn with what they connect to)` : '',
      data.edges_total > edges.length ? `, and the ${edges.length.toLocaleString()} strongest of ${data.edges_total.toLocaleString()} links between them. Every link is still listed in an indicator's details.` : `, with all ${edges.length.toLocaleString()} links between them.`));
}

/* ---------- views ---------- */
/* ---------- the intelligence cycle ----------
 * The dashboard follows the six stages of the intelligence cycle, in order. Each stage says in plain words what
 * it is for, what you do, and what ThreatWeaver does; the home page shows where you are and the one thing to do next. */
const STAGES = [
  { key: 'plan', n: 1, name: 'Plan', short: 'Decide what you need to know', href: '#/plan' },
  { key: 'collect', n: 2, name: 'Collect', short: 'Gather your logs, reports and public feeds', href: '#/collect' },
  { key: 'process', n: 3, name: 'Process', short: 'Pull out the facts and clean them up', href: '#/process' },
  { key: 'analyse', n: 4, name: 'Analyse', short: 'See what is connected and what matters', href: '#/analyse' },
  { key: 'share', n: 5, name: 'Share', short: 'Write it up; a second person approves advice', href: '#/share' },
  { key: 'feedback', n: 6, name: 'Feedback', short: 'Say what was right or wrong, then go round again', href: '#/feedback' },
];
const STAGE_TEXT = {
  plan: { purpose: 'Decide what you need to know before you look at any data. A clear question keeps the rest of the work pointed at something.',
    you: 'Write one question and say who it is for.', tool: 'Keeps your question with the report, so the answer is tied to it.' },
  collect: { purpose: 'Gather the raw material: your own logs, reports and emails, and, if you want, public lists of known-bad infrastructure.',
    you: 'Drop in files or paste text. Downloading the feeds is optional.', tool: 'Keeps every file with a fingerprint (SHA-256), so any result can be traced back to its source.' },
  process: { purpose: 'Turn messy text into clean, comparable facts.',
    you: 'Nothing: this happens on its own. Check the summary looks right.', tool: 'Finds IP addresses, domains, URLs, e-mail addresses, file names and hashes, writes each one in a standard way, and counts repeats once while remembering every place it was seen.' },
  analyse: { purpose: 'Work out what is connected and what matters most.',
    you: 'Start at the top of the list and open what looks important.', tool: 'Groups related indicators into cases, checks them against the feeds, and rates them with simple named rules. It suggests; it never acts.' },
  share: { purpose: 'Turn what you found into something other people can use.',
    you: 'Download the report. If you want to warn others, draft an advisory; a different person must approve it.', tool: 'Defangs every indicator, checks advisories for confidential content, and writes files only on this computer.' },
  feedback: { purpose: 'Tell ThreatWeaver what was right and what was wrong, then go round again with a better question.',
    you: 'Mark a few indicators: real threat, false alarm, keep watching, or expected.', tool: 'Shows how well the ratings held up and keeps false alarms out of advisory drafts. It never changes a score by itself.' },
};
const VERDICTS = [
  ['confirmed', 'Real threat', 'Malicious, or needs action.'],
  ['false_positive', 'False alarm', 'The rating was wrong: this is harmless.'],
  ['watch', 'Keep watching', 'Not sure yet.'],
  ['expected', 'Expected / normal', 'It is ours, or normal activity.'],
];
const STATE_LABEL = { done: 'Done', ready: 'Ready', todo: 'To do', working: 'Working', waiting: 'Waiting' };
const TYPE_LABEL = { ipv4: 'IPv4 addresses', ipv6: 'IPv6 addresses', domain: 'Domains', url: 'URLs', email: 'E-mail addresses', filename: 'File names', md5: 'MD5 hashes', sha1: 'SHA-1 hashes', sha256: 'SHA-256 hashes' };
const verdictTag = (label) => h('span', { class: 'tag verdict' }, label);

let statusCache = null;
async function getStatus() {
  statusCache = await api('/api/status');
  state.uploadLimit = statusCache.limits.upload_bytes;
  paintNav();
  return statusCache;
}
function paintNav() {
  if (!statusCache) return;
  for (const st of statusCache.stages) {
    const dot = document.querySelector(`.nav a[data-k="${st.key}"] .dot`);
    if (dot) { dot.className = 'dot ' + st.state; dot.title = `${STATE_LABEL[st.state]}: ${st.line}`; }
  }
  const next = statusCache.next && statusCache.next.stage;
  document.querySelectorAll('.nav a[data-k]').forEach((a) => a.classList.toggle('next', a.dataset.k === next));
}

function tabBar(tabs, active) {
  return h('div', { class: 'tabs', role: 'tablist' }, tabs.map(([key, label, href]) =>
    h('a', { href, role: 'tab', class: 'tab', 'aria-selected': String(key === active), 'aria-current': key === active ? 'page' : null }, label)));
}

/* The same frame for every stage: what it is for, who does what, then the work, then a way on. */
function stagePage(key, { tabs = null, active = null, body }) {
  const i = STAGES.findIndex((s) => s.key === key);
  const st = STAGES[i], t = STAGE_TEXT[key], prev = STAGES[i - 1], next = STAGES[i + 1];
  return h('div', {},
    h('div', { class: 'stagehead' },
      h('div', { class: 'stepno' }, `Step ${st.n} of ${STAGES.length}`),
      h('p', { class: 'purpose' }, t.purpose),
      h('div', { class: 'roles' }, h('div', {}, h('b', {}, 'You: '), t.you), h('div', {}, h('b', {}, 'ThreatWeaver: '), t.tool))),
    tabs ? tabBar(tabs, active) : null,
    body,
    h('div', { class: 'stagefoot' },
      prev ? h('a', { class: 'btnlink', href: prev.href }, `← ${prev.name}`) : h('span', {}),
      h('a', { class: 'btnlink primary', href: next ? next.href : '#/plan' }, next ? `Next: ${next.name} →` : 'Go round again: Plan →')));
}

/* ---------- home: where you are in the cycle ---------- */
async function viewHome() {
  const s = await getStatus();
  const n = s.next;
  const working = [...activity.values()].some((a) => ['uploading', 'queued', 'processing'].includes(a.phase));
  return h('div', {},
    h('div', { class: 'nextcard' },
      h('div', { class: 'stepno' }, 'Your next step'),
      h('h2', {}, n.headline), h('p', {}, n.text),
      h('a', { class: 'btnlink primary', href: n.href }, n.button + ' →')),
    working ? h('div', { class: 'banner' }, h('b', {}, 'A file is being processed. '), 'You can keep using the dashboard; results appear when it finishes.') : null,
    h('h2', { class: 'cyclehead' }, 'The intelligence cycle'),
    h('p', { class: 'muted' }, 'Six steps, always in this order. Each one feeds the next, and the last feeds back into the first.'),
    h('div', { class: 'cyclecards' }, s.stages.map((st, i) => {
      const info = STAGES[i];
      return h('a', { class: 'stagecard ' + st.state + (s.next.stage === st.key ? ' next' : ''), href: info.href },
        h('span', { class: 'num' }, String(st.n)),
        h('div', {}, h('b', {}, st.name), h('div', { class: 'small muted' }, info.short),
          h('div', { class: 'statusline' }, h('span', { class: 'state ' + st.state }, STATE_LABEL[st.state]), ' ', st.line.length > 90 ? st.line.slice(0, 89) + '…' : st.line)));
    })));
}

/* ---------- 1 Plan ---------- */
async function viewPlan() {
  const s = await getStatus();
  const cur = s.plan;
  const q = h('textarea', { class: 'short prose', 'aria-label': 'Your question', placeholder: 'For example: Which addresses in these logs need attention first?', maxlength: 500 });
  q.value = cur ? cur.requirement : '';
  const aud = h('input', { type: 'text', class: 'wide', 'aria-label': 'Who is it for', placeholder: 'For example: the SOC team, or IT management', maxlength: 200, value: cur ? cur.audience : '' });
  const mark = h('select', { 'aria-label': 'How far it may be shared' }, Object.entries(s.markings).map(([k, v]) => h('option', { value: k, selected: k === (cur ? cur.marking : 'TLP:GREEN') }, `${k}: ${v}`)));
  const name = h('input', { type: 'text', 'aria-label': 'Your name', placeholder: 'your name', maxlength: 80, value: remember('name') });
  const save = h('button', { class: 'primary', onclick: async () => {
    if (!name.value.trim()) { toast('Enter your name first', 'err'); name.focus(); return; }
    remember('name', name.value);
    const r = await guarded(() => api('/api/plan', { requirement: q.value, audience: aud.value, marking: mark.value, author: name.value }));
    if (r) { toast('Question saved. Next: collect something to look at.', 'ok'); route(); }
  } }, cur ? 'Save a new version' : 'Save the question');
  return stagePage('plan', { body: h('div', {},
    cur ? h('div', { class: 'panel current' }, h('div', { class: 'small muted' }, `Current question (version ${cur.revisions}, set by ${cur.author} on ${cur.created_at.slice(0, 10)})`),
      h('p', { class: 'bigtext' }, cur.requirement),
      h('div', { class: 'small' }, `For: ${cur.audience || 'not stated'}. Handling: `, h('b', {}, cur.marking), ` (${cur.marking_meaning})`)) : null,
    h('div', { class: 'panel' }, h('h2', {}, cur ? 'Change the question' : 'What do you want to find out?'),
      h('div', { class: 'field' }, h('label', {}, 'Your question'), q),
      h('div', { class: 'small muted' }, 'Or start from an example:'),
      h('div', { class: 'chips' }, s.examples.map((t) => h('button', { type: 'button', class: 'chip', onclick: () => { q.value = t; q.focus(); } }, t))),
      h('div', { class: 'field' }, h('label', {}, 'Who is it for? (optional)'), aud),
      h('div', { class: 'field' }, h('label', {}, 'How far may the findings be shared?'), mark,
        h('div', { class: 'small muted' }, 'This is the Traffic Light Protocol. It is printed on the report so readers know what they may do with it. Advisories are always TLP:CLEAR, because they use only public feed evidence.')),
      h('div', { class: 'field' }, h('label', {}, 'Your name'), name),
      h('div', { class: 'toolbar' }, save))) });
}

/* ---------- 2 Collect ---------- */
async function viewCollect() {
  const s = await getStatus();
  const sources = s.sources.length ? h('div', { class: 'panel' }, h('h2', {}, 'What you have collected'),
    table(['Name', 'Added', 'SHA-256 (pins the exact content)'], s.sources.map((x) => ({ data: x, cells: [cell(x.name), cell(x.ingested_at), cell(x.sha256, 'val')] }))))
    : h('div', { class: 'panel muted' }, 'Nothing collected yet. Drop a file above, or paste some text.');
  return stagePage('collect', { body: h('div', {}, h('div', { class: 'grid cols-2' }, addDataPanel(), feedsPanel(s.feeds)), sources) });
}

/* ---------- 3 Process ---------- */
const PROCESS_TABS = [['process', 'Summary', '#/process'], ['indicators', 'Indicators', '#/indicators']];
async function viewProcess() {
  const s = await getStatus();
  const p = s.process;
  if (!p.indicators) return stagePage('process', { tabs: PROCESS_TABS, active: 'process',
    body: h('div', { class: 'panel muted' }, 'Nothing to process yet. Add a file or some text in ', h('a', { href: '#/collect' }, 'step 2'), '. This step runs on its own once there is data.') });
  const steps = [
    ['Found', p.sightings.toLocaleString(), 'places in your data where something looked like an indicator'],
    ['Cleaned', '', 'the same thing written two ways becomes one (upper or lower case, [.] defanging, IPv6 shorthand)'],
    ['De-duplicated', p.indicators.toLocaleString(), 'distinct indicators, each remembering every place it was seen'],
  ];
  return stagePage('process', { tabs: PROCESS_TABS, active: 'process', body: h('div', {},
    h('div', { class: 'pipeline' }, steps.map(([name, n, text], i) => h('div', { class: 'pipestep' },
      h('div', { class: 'small muted' }, `${i + 1}. ${name}`), n ? h('div', { class: 'bignum' }, n) : h('div', { class: 'bignum' }, '✓'), h('div', { class: 'small' }, text)))),
    h('div', { class: 'panel' }, h('h2', {}, 'What was found'),
      table(['Kind', 'Distinct'], Object.entries(p.by_type).map(([k, v]) => ({ data: k, cells: [cell(TYPE_LABEL[k] || k), cell(v.toLocaleString())] }))),
      h('p', { class: 'small muted' }, 'Look through them on the Indicators tab. Nothing is lost by de-duplicating: every sighting is kept, with the original text and its position.'))) });
}
async function viewIndicatorsStage() {
  return stagePage('process', { tabs: PROCESS_TABS, active: 'indicators', body: await viewIndicators() });
}

/* ---------- 4 Analyse ---------- */
const ANALYSE_TABS = [['analyse', 'Priorities', '#/analyse'], ['graph', 'Link graph', '#/graph']];
async function viewAnalyse() { return stagePage('analyse', { tabs: ANALYSE_TABS, active: 'analyse', body: await viewCases() }); }
async function viewGraphStage() { return stagePage('analyse', { tabs: ANALYSE_TABS, active: 'graph', body: await viewGraph() }); }
async function viewCaseStage(id) { return stagePage('analyse', { tabs: ANALYSE_TABS, active: 'analyse', body: await viewCase(id) }); }

/* ---------- 5 Share ---------- */
const SHARE_TABS = [['share', 'Report', '#/share'], ['advisories', 'Advisories', '#/advisories']];
async function shareBody(active, inner) {
  const s = await getStatus();
  const plan = s.plan;
  const note = plan ? h('div', { class: 'banner ok' }, h('b', {}, `Handling: ${plan.marking}. `), plan.marking_meaning, ' ',
    'Advisories are always TLP:CLEAR: they use only public feed evidence, never your own logs.')
    : h('div', { class: 'banner' }, h('b', {}, 'No handling level set. '), 'Choose one in ', h('a', { href: '#/plan' }, 'step 1'), ' so readers know how far the report may travel.');
  return stagePage('share', { tabs: SHARE_TABS, active, body: h('div', {}, note, await inner()) });
}
const viewShareReport = () => shareBody('share', viewReport);
const viewShareAdvisories = () => shareBody('advisories', viewAdvisories);
const viewShareAdvisory = (id) => shareBody('advisories', () => viewAdvisory(id));

/* ---------- 6 Feedback ---------- */
function reviewButtons(iocId, getName, getNote, after) {
  const send = async (verdict, label) => {
    const who = getName().trim();
    if (!who) { toast('Enter your name first', 'err'); return; }
    remember('name', who);
    const r = await guarded(() => api('/api/feedback', { ioc_id: iocId, verdict, note: getNote ? getNote() : '', reviewer: who }));
    if (r) { toast(`Saved: ${label}`, 'ok'); if (after) after(r.feedback); }
  };
  return h('div', { class: 'verdicts' }, VERDICTS.map(([v, label, help]) => h('button', { type: 'button', title: help, class: 'verdict ' + v, onclick: () => send(v, label) }, label)));
}

async function viewFeedback() {
  const f = await api('/api/feedback');
  await getStatus();
  const name = h('input', { type: 'text', placeholder: 'your name', maxlength: 80, value: remember('name'), 'aria-label': 'Your name' });
  const sm = f.summary;
  const tiles = h('div', { class: 'tiles' }, [['Reviewed', sm.reviewed], ...VERDICTS.map(([v, label]) => [label, sm.by_verdict[v]])]
    .map(([l, n]) => h('div', { class: 'tile' }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, l))));

  const queueRows = f.queue.map((i) => h('div', { class: 'queue-item' },
    h('div', { class: 'queue-main' }, badge(i.level), ' ', typeTag(i.type), ' ', h('button', { class: 'link mono', onclick: () => openIndicator(i.id) }, val(i)), h('span', { class: 'small muted' }, ` score ${i.score}`)),
    reviewButtons(i.id, () => name.value, null, () => route())));
  const queue = h('div', { class: 'panel' }, h('h2', {}, 'Worth reviewing next'),
    h('p', { class: 'small muted' }, f.queue.length ? (f.queue_is_quiet
      ? 'Nothing here was rated above "info", so these are simply the most-seen indicators. Open one to see where it appeared.'
      : 'The highest-rated indicators nobody has judged yet. Open one to see why it was rated that way, then say what you think.') : 'Nothing left to review.'),
    h('div', { class: 'field', style: 'max-width:22rem' }, h('label', {}, 'Your name (saved with each verdict)'), name),
    queueRows.length ? queueRows : null);

  const reading = (r) => {
    if (r.reviewed < 3) return '';
    const bad = (r.false_positive + r.expected) / r.reviewed, good = r.confirmed / r.reviewed;
    return bad >= 0.5 ? 'mostly false alarms' : good >= 0.5 ? 'mostly real' : 'mixed';
  };
  const accuracy = sm.reviewed ? h('div', { class: 'panel' }, h('h2', {}, 'How well did the ratings hold up?'),
    table(['Suggested level', 'Reviewed', 'Real threat', 'False alarm', 'Keep watching', 'Expected', 'Reading'],
      f.accuracy.map((r) => ({ data: r, cells: [nodeCell(badge(r.level)), cell(String(r.reviewed)), cell(String(r.confirmed)), cell(String(r.false_positive)), cell(String(r.watch)), cell(String(r.expected)), cell(reading(r))] }))),
    h('p', { class: 'small muted' }, 'This is a guide, not a score: ThreatWeaver does not change a rating because of a verdict. If a level is mostly false alarms on your data, open an indicator of that level and read "Why this level": the rule that keeps firing is the one to question.')) : null;

  const reviewed = h('div', { class: 'panel' }, h('h2', {}, 'Reviewed so far'),
    f.items.length ? table(['Verdict', 'Level', 'Indicator', 'Note', 'By', 'When'], f.items.map((x) => ({ data: x, cells: [nodeCell(verdictTag(x.label)), x.level ? nodeCell(badge(x.level)) : cell('-'), cell(val(x), 'val'), cell(x.note), cell(x.reviewer), cell(x.at.slice(0, 16).replace('T', ' '))] })), (x) => openIndicator(x.id))
      : h('p', { class: 'muted' }, 'No verdicts yet.'),
    f.total > f.items.length ? h('p', { class: 'small muted' }, `Showing the newest ${f.items.length} of ${f.total}.`) : null,
    h('p', { class: 'small muted' }, 'Indicators you mark "False alarm" or "Expected / normal" are left out of new advisory drafts. Every verdict is kept, with who said it and when, and the newest one counts.'));

  const again = h('div', { class: 'panel nextcard' }, h('h2', {}, 'Go round again'),
    h('p', {}, 'What you learned here should change what you ask or what you collect.'),
    h('div', { class: 'toolbar' }, h('a', { class: 'btnlink primary', href: '#/plan' }, 'Refine the question'), h('a', { class: 'btnlink', href: '#/collect' }, 'Add more data')));
  return stagePage('feedback', { body: h('div', {}, tiles, queue, accuracy, reviewed, again) });
}

/* The verdict box inside an indicator's detail panel. */
function drawerFeedback(d) {
  const name = h('input', { type: 'text', placeholder: 'your name', maxlength: 80, value: remember('name'), 'aria-label': 'Your name' });
  const note = h('input', { type: 'text', placeholder: 'why? (optional)', maxlength: 500, 'aria-label': 'Note' });
  return h('div', { class: 'panel' }, h('h3', {}, 'What do you think of this one?'),
    h('p', { class: 'small muted' }, 'Your verdict is kept for the report and the Feedback step. It does not change the rating.'),
    h('div', { class: 'toolbar' }, name, note),
    reviewButtons(d.id, () => name.value, () => note.value, () => openIndicator(d.id)),
    d.feedback.length ? h('div', { class: 'history' }, h('div', { class: 'small muted' }, 'Earlier verdicts, newest first'),
      d.feedback.map((x) => h('div', { class: 'small' }, verdictTag(x.label), ` ${x.reviewer}, ${x.at.slice(0, 16).replace('T', ' ')}`, x.note ? ': ' + x.note : ''))) : null);
}

function addDataPanel() {
  const input = h('input', { type: 'file', multiple: true, class: 'hidden', id: 'filepick', onchange: (e) => { uploadFiles([...e.target.files]); e.target.value = ''; } });
  const zone = h('div', { class: 'drop', tabindex: 0, role: 'button', 'aria-label': 'Choose log files to add',
    onclick: () => input.click(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') input.click(); },
    ondragover: (e) => { e.preventDefault(); zone.classList.add('over'); }, ondragleave: () => zone.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); zone.classList.remove('over'); uploadFiles([...e.dataTransfer.files]); } },
    h('b', {}, 'Drop log files here'), h('div', {}, `or click to choose (text logs, CSV, JSON; up to ${fmtBytes(state.uploadLimit)} each)`));
  const name = h('input', { type: 'text', placeholder: 'name, e.g. analyst-notes.txt', value: 'pasted-text.txt', 'aria-label': 'Name for pasted text' });
  const text = h('textarea', { placeholder: 'Or paste a report, email or log excerpt here', class: 'short', 'aria-label': 'Pasted text' });
  const addPasted = async () => {
    if (!text.value.trim()) return;
    const r = await guarded(() => api('/api/ingest', { name: name.value || 'pasted-text.txt', text: text.value }));
    if (!r) return;
    text.value = '';
    toast(r.already_ingested ? `${r.name}: identical content was already added` : `${r.name}: ${r.new_indicators} new indicators, ${r.sightings} sightings`, 'ok');
    route();
  };
  return h('div', { class: 'panel' }, h('h2', {}, 'Add data'), input, zone,
    h('p', { class: 'small muted' }, 'Large files are uploaded straight to disk and processed in the background, so you can keep using the dashboard. A 1 GB log can take 10 to 20 minutes.'),
    h('details', {}, h('summary', {}, 'Paste text instead'), h('div', { class: 'field' }, name), text, h('button', { class: 'primary', onclick: addPasted }, 'Add pasted text')),
    h('p', { class: 'small muted' }, 'Files go only to this local dashboard. Nothing leaves your machine.'));
}

/* ---------- uploads and background jobs ----------
 * A file is sent as the raw request body (the browser streams it from disk; it is never read into
 * the page). The server writes it to a temporary file and processes it in the background; we then
 * poll /api/jobs for progress. */
const activity = new Map(); // key -> { name, phase: uploading|queued|processing|done|error, percent, note, eta, size }
const notified = new Set(); // finished job ids already announced
let pollTimer = null;
let uploadSeq = 0;

function sendFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload?name=' + encodeURIComponent(file.name));
    xhr.setRequestHeader('X-TW-Token', TOKEN);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
    xhr.onerror = () => reject(new Error('the upload failed (is the dashboard still running?)'));
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300 && data) resolve(data);
      else reject(new Error((data && data.error) || `HTTP ${xhr.status}`));
    };
    xhr.send(file);
  });
}

async function uploadFiles(files) {
  for (const f of files) {
    if (f.size === 0) { toast(`${f.name} is empty`, 'err'); continue; }
    if (f.size > state.uploadLimit) { toast(`${f.name} is ${fmtBytes(f.size)}; the limit is ${fmtBytes(state.uploadLimit)}`, 'err'); continue; }
    const key = 'upload:' + (++uploadSeq);
    const entry = { name: f.name, phase: 'uploading', percent: 0, size: f.size };
    activity.set(key, entry);
    renderActivity();
    try {
      await sendFile(f, (done, total) => { entry.percent = (100 * done) / total; renderActivity(); });
      activity.delete(key); // the server-side job takes over from here
    } catch (e) {
      entry.phase = 'error'; entry.note = e.message; renderActivity();
      toast(`${f.name}: ${e.message}`, 'err');
    }
    await pollJobs();
  }
}

async function pollJobs() {
  let data;
  try { data = await api('/api/jobs'); } catch { return; }
  const firstLoad = !pollJobs.seen;
  pollJobs.seen = true;
  let finishedNow = false;
  for (const job of data.jobs) {
    const key = 'job:' + job.id;
    if (job.state === 'done' || job.state === 'error') {
      if (!notified.has(job.id)) {
        notified.add(job.id);
        if (!firstLoad) {
          finishedNow = true;
          if (job.state === 'done') toast(job.result.already_ingested ? `${job.name}: identical content was already added` : `${job.name}: ${job.result.new_indicators} new indicators, ${job.result.sightings} sightings`, 'ok');
          else toast(`${job.name} failed: ${job.error}`, 'err');
        } else continue; // old finished jobs from before this page load are not shown
      }
    }
    const note = job.state === 'done' ? (job.result.already_ingested ? 'already added' : `${job.result.new_indicators} new indicators`) : job.error;
    activity.set(key, { name: job.name, phase: job.state, percent: job.percent, eta: job.eta_seconds, size: job.size, note });
  }
  renderActivity();
  clearTimeout(pollTimer);
  const busy = data.active > 0 || [...activity.values()].some((a) => a.phase === 'uploading');
  if (busy) pollTimer = setTimeout(pollJobs, 1000);
  if (finishedNow && /^#\/?(overview|home|collect|process|indicators|analyse|cases|graph|feedback)?$/.test(location.hash)) route();
}

function renderActivity() {
  const box = $('#activity');
  if (!box) return;
  box.replaceChildren(...[...activity.entries()].map(([key, a]) => {
    const label = { uploading: 'Uploading', queued: 'Waiting', processing: 'Processing', done: 'Finished', error: 'Failed' }[a.phase];
    const detail = a.phase === 'processing' ? `${a.percent.toFixed(0)}%${a.eta ? ', about ' + fmtDuration(a.eta) + ' left' : ''}`
      : a.phase === 'uploading' ? `${a.percent.toFixed(0)}% of ${fmtBytes(a.size)}` : (a.note || '');
    return h('div', { class: 'job ' + a.phase, role: 'status' },
      h('div', { class: 'toolbar', style: 'justify-content:space-between' },
        h('span', {}, h('b', {}, label + ' '), a.name, ' ', h('span', { class: 'muted small' }, detail)),
        (a.phase === 'done' || a.phase === 'error') ? h('button', { 'aria-label': 'Dismiss', onclick: () => { activity.delete(key); renderActivity(); } }, 'Dismiss') : null),
      (a.phase === 'uploading' || a.phase === 'processing' || a.phase === 'queued')
        ? h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(a.percent) }, h('div', { style: `width:${Math.min(100, a.percent)}%` })) : null);
  }));
}

function feedsPanel(feeds) {
  const blurb = { feodotracker: 'Botnet command-and-control IPs (Emotet, QakBot, ...). No key needed.', urlhaus: 'URLs distributing malware. Needs a free abuse.ch key.' };
  return h('div', { class: 'panel' }, h('h2', {}, 'Threat intelligence feeds'),
    feeds.map((f) => {
      const blocked = f.needs_key && !f.key_set;
      const btn = h('button', { class: f.loaded ? '' : 'primary', disabled: blocked, onclick: async () => {
        if (!confirm(`Contact abuse.ch now to download the latest ${f.feed} list?\n\nThis is the only action that uses the network. Results are cached to respect the feed's rate limit.`)) return;
        btn.disabled = true;
        const r = await guarded(() => api('/api/feeds/fetch', { feed: f.feed }));
        if (r) { toast(`${f.feed}: ${r.already_loaded ? 'no change since the last snapshot' : r.records + ' records loaded'}${r.from_cache ? ' (from cache)' : ''}`, 'ok'); route(); } else btn.disabled = false;
      } }, f.loaded ? 'Update' : 'Download');
      return h('div', { style: 'margin-bottom:.9rem' }, h('b', {}, f.feed), ' ', h('span', { class: 'small muted' }, blurb[f.feed] || ''),
        h('div', { class: 'small' }, f.loaded ? `Loaded ${age(f.collected_at)}: ${f.records} records.` : 'Not loaded yet.'),
        blocked ? h('div', { class: 'small', style: 'color:var(--warn)' }, `Set ${f.key_variable} in the terminal that starts the dashboard, then restart it. The key is never shown or stored here.`) : null,
        h('div', { class: 'toolbar', style: 'margin-top:.3rem' }, btn, h('a', { href: f.terms_url, target: '_blank', rel: 'noopener noreferrer', class: 'small' }, 'terms')));
    }));
}

/* How many indicators sit at each suggested level, and how much is linked: the first thing to read in step 4. */
function prioritySummary(sm) {
  const max = Math.max(1, ...LEVELS.map((l) => sm.by_level[l]));
  return h('div', { class: 'panel' }, h('h2', {}, 'What ThreatWeaver found'),
    h('div', { class: 'tiles' }, [['Indicators', sm.indicators], ['Cases', sm.cases], ['Links', sm.links], ['Feed matches', sm.feed_matches]]
      .map(([l, n]) => h('div', { class: 'tile' }, h('div', { class: 'n' }, n.toLocaleString()), h('div', { class: 'l' }, l)))),
    h('div', { class: 'bars' }, LEVELS.map((l) => h('div', { class: 'row' }, badge(l), h('div', { class: 'track' }, h('div', { class: 'fill ' + l, style: `width:${(sm.by_level[l] / max) * 100}%` })), h('span', { class: 'mono' }, sm.by_level[l].toLocaleString())))),
    h('p', { class: 'small muted' }, 'Levels are suggestions from simple, named rules (open any indicator to read them). A person decides what to do. Start with the cases below, highest first.'));
}
async function viewCases() {
  const first = await api('/api/cases');
  if (!first.all_cases) return empty('No cases yet. Add data in step 2 (Collect), then come back.');
  const list = h('div', { class: 'cards' });
  const count = h('span', { class: 'small muted' });
  const nav = h('div', { class: 'toolbar', style: 'margin-top:.75rem' });
  const state2 = { quiet: false, offset: 0, data: first };
  const toggle = h('input', { type: 'checkbox', onchange: () => { state2.quiet = toggle.checked; state2.offset = 0; load(); } });
  async function load() {
    const d = await guarded(() => api(`/api/cases?quiet=${state2.quiet ? 1 : 0}&offset=${state2.offset}&limit=${first.limit}`));
    if (!d) return;
    state2.data = d;
    const to = Math.min(d.total, d.offset + d.cases.length);
    count.textContent = d.total ? `showing ${d.offset + 1}-${to} of ${d.total.toLocaleString()} cases` : 'no cases to show';
    list.replaceChildren(...d.cases.map(caseCard));
    nav.replaceChildren(
      h('button', { disabled: d.offset === 0, onclick: () => { state2.offset = Math.max(0, d.offset - d.limit); load(); } }, 'Previous'),
      h('button', { disabled: d.offset + d.limit >= d.total, onclick: () => { state2.offset = d.offset + d.limit; load(); } }, 'Next'));
  }
  const label = `Also show quiet cases (${first.quiet_cases.toLocaleString()}: a single indicator, nothing linked, nothing suspicious)`;
  const wrap = h('div', {}, prioritySummary(first.summary),
    h('p', { class: 'muted' }, 'A case is a group of indicators connected by strong links (a URL and its host, an e-mail address and its domain, the same log line, or a host name that spells out an IP). Highest suggested priority first. To search everything, use the Indicators tab in step 3.'),
    h('div', { class: 'toolbar', style: 'margin-bottom:.75rem' }, h('label', { style: 'display:flex;gap:.35rem;align-items:center;margin:0' }, toggle, label), count), list, nav);
  state2.offset = 0;
  await load();
  return wrap;
}
function caseCard(c) {
  const open = () => { location.hash = '#/case/' + c.case_id; };
  return h('div', { class: 'card', tabindex: 0, role: 'link', onclick: open, onkeydown: (e) => { if (e.key === 'Enter') open(); } },
    h('div', { class: 'toolbar', style: 'justify-content:space-between' }, badge(c.max_level), h('span', { class: 'id' }, c.case_id)),
    h('div', { class: 'small muted' }, `${c.size} indicator(s), ${c.links} link(s), top score ${c.max_score}`),
    h('ul', {}, c.indicators.slice(0, 4).map((i) => h('li', {}, val(i))), c.size > 4 ? h('li', { class: 'muted' }, `+ ${c.size - 4} more`) : null));
}
async function viewCase(id) {
  const [c, g] = await Promise.all([api('/api/case/' + id), api('/api/graph?case=' + encodeURIComponent(id))]);
  return h('div', {}, h('p', {}, h('button', { class: 'link', onclick: () => (location.hash = '#/cases') }, 'All cases'), ' / ', h('b', {}, c.case_id), ' ', badge(c.max_level)),
    h('div', { class: 'panel' }, h('h2', {}, 'Indicators'),
      c.indicators_total > c.indicators.length ? h('p', { class: 'small muted' }, `Showing the ${c.indicators.length} highest-scoring of ${c.indicators_total.toLocaleString()} indicators in this case. Search all of them on the Indicators page.`) : null,
      table(['Level', 'Score', 'Type', 'Indicator'], c.indicators.map((i) => ({ data: i, cells: [nodeCell(badge(i.level)), cell(String(i.score)), cell(i.type), cell(val(i), 'val')] })), (i) => openIndicator(i.id))),
    h('div', { class: 'panel' }, h('h2', {}, 'How they connect'), drawGraph(g)));
}

async function viewIndicators() {
  const f = { q: '', type: '', level: '', source: '', offset: 0 };
  const results = h('div', {});
  const qInput = h('input', { type: 'search', placeholder: 'Search value...', 'aria-label': 'Search', oninput: debounce(() => { f.q = qInput.value; f.offset = 0; load(); }, 250) });
  const typeSel = h('select', { 'aria-label': 'Type', onchange: () => { f.type = typeSel.value; f.offset = 0; load(); } }, h('option', { value: '' }, 'All types'), ['ipv4', 'ipv6', 'domain', 'url', 'email', 'filename', 'md5', 'sha1', 'sha256'].map((t) => h('option', { value: t }, t)));
  const lvlSel = h('select', { 'aria-label': 'Level', onchange: () => { f.level = lvlSel.value; f.offset = 0; load(); } }, h('option', { value: '' }, 'All levels'), LEVELS.map((l) => h('option', { value: l }, l)));
  const srcInput = h('input', { type: 'search', placeholder: 'Source name...', 'aria-label': 'Source', oninput: debounce(() => { f.source = srcInput.value; f.offset = 0; load(); }, 250) });
  async function load() {
    const qs = new URLSearchParams({ q: f.q, type: f.type, level: f.level, source: f.source, offset: f.offset, limit: 50 });
    const d = await guarded(() => api('/api/indicators?' + qs));
    if (!d) return;
    results.replaceChildren(
      h('p', { class: 'small muted' }, `${d.total} indicator(s)`),
      d.rows.length ? table(['Level', 'Score', 'Type', 'Indicator', 'Seen', 'Sources', 'Feeds', 'Your verdict'], d.rows.map((i) => ({ data: i, cells: [nodeCell(badge(i.level)), cell(String(i.score)), cell(i.type), cell(val(i), 'val'), cell(String(i.sightings)), cell(i.sources.join(', ')), cell(i.feed_matches ? String(i.feed_matches) : '-'), i.verdict ? nodeCell(verdictTag(i.verdict)) : cell('-')] })), (i) => openIndicator(i.id)) : empty('Nothing matches these filters.'),
      h('div', { class: 'toolbar', style: 'margin-top:.75rem' },
        h('button', { disabled: f.offset === 0, onclick: () => { f.offset = Math.max(0, f.offset - 50); load(); } }, 'Previous'),
        h('button', { disabled: f.offset + 50 >= d.total, onclick: () => { f.offset += 50; load(); } }, 'Next')));
  }
  load();
  return h('div', {}, h('div', { class: 'panel toolbar' }, qInput, typeSel, lvlSel, srcInput), results);
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

async function viewGraph() {
  const { cases } = await api('/api/cases');
  const holder = h('div', {});
  const note = h('p', { class: 'small muted', role: 'status' });
  const prefs = { level: 'medium', limit: '150', per: '3' };
  const caseSel = h('select', { 'aria-label': 'Which indicators', onchange: draw }, h('option', { value: '' }, 'All linked indicators'),
    cases.filter((c) => c.links).map((c) => h('option', { value: c.case_id }, `${c.case_id} (${c.size} indicators, ${c.max_level})`)));
  const lvlSel = h('select', { 'aria-label': 'Priority', onchange: () => { prefs.level = lvlSel.value; draw(); } },
    [['high', 'High only'], ['medium', 'Medium and above'], ['low', 'Low and above'], ['info', 'Everything']].map(([v, t]) => h('option', { value: v, selected: v === prefs.level }, t)));
  const limSel = h('select', { 'aria-label': 'How many indicators', onchange: () => { prefs.limit = limSel.value; draw(); } },
    [50, 100, 150, 250, 400].map((n) => h('option', { value: String(n), selected: String(n) === prefs.limit }, `up to ${n}`)));
  const perSel = h('select', { 'aria-label': 'Links drawn per indicator', onchange: () => { prefs.per = perSel.value; draw(); } },
    [['2', 'strongest 2 links each'], ['3', 'strongest 3 links each'], ['6', 'strongest 6 links each'], ['12', 'strongest 12 links each']].map(([v, t]) => h('option', { value: v, selected: v === prefs.per }, t)));
  const ruleBoxes = Object.keys(EDGE_STYLE).map((r) => h('label', { class: 'check', title: RULE_HELP[r] }, h('input', { type: 'checkbox', value: r, checked: true, onchange: draw }), r.replace('_', ' ')));
  let seq = 0;
  async function draw() {
    const mine = ++seq;
    const rules = ruleBoxes.map((b) => b.firstChild).filter((i) => i.checked).map((i) => i.value);
    if (!rules.length) { holder.replaceChildren(empty('Tick at least one link type.')); return; }
    holder.replaceChildren(h('p', { class: 'muted' }, 'Loading the graph...'));
    const qs = new URLSearchParams({ min_level: prefs.level, limit: prefs.limit, per_node: prefs.per, rules: rules.join(',') });
    if (caseSel.value) qs.set('case', caseSel.value);
    let g = await guarded(() => api('/api/graph?' + qs));
    if (!g || mine !== seq) return;
    note.textContent = '';
    // nothing linked at this priority: widen step by step, automatically, and say so
    if (!caseSel.value) {
      for (const wider of LEVELS.slice(LEVELS.indexOf(prefs.level) + 1)) {
        if (g.nodes.length) break;
        qs.set('min_level', wider);
        g = await guarded(() => api('/api/graph?' + qs));
        if (!g || mine !== seq) return;
        if (g.nodes.length) { lvlSel.value = wider; prefs.level = wider; note.textContent = 'Nothing is linked at the earlier priority, so the filter was widened.'; }
      }
    }
    holder.replaceChildren(drawGraph(g));
  }
  draw();
  return h('div', {},
    h('div', { class: 'panel graphfilters' },
      h('div', { class: 'toolbar' }, h('span', { class: 'muted small' }, 'Show'), caseSel, lvlSel, limSel, perSel),
      h('div', { class: 'toolbar', style: 'margin-top:.5rem' }, h('span', { class: 'muted small' }, 'Link types'), ruleBoxes),
      h('p', { class: 'small muted', style: 'margin:.5rem 0 0' }, 'A large log produces far more links than a screen can show, so this draws the highest-priority indicators and the ones they connect to. Narrow it to look closely, or open a case for its own picture.'), note),
    holder);
}

async function viewSources() {
  const { sources } = await api('/api/sources');
  return sources.length ? h('div', { class: 'panel' }, table(['Name', 'Indicators', 'Added', 'SHA-256 (pins the exact content analysed)'], sources.map((x) => ({ data: x, cells: [cell(x.name), cell(String(x.indicators)), cell(x.ingested_at), cell(x.sha256, 'val')] }))))
    : empty('No sources yet.');
}

async function download(path, name) {
  const res = await fetch(path, { headers: { 'X-TW-Token': TOKEN } });
  if (!res.ok) throw new Error(`download failed (HTTP ${res.status})`);
  const url = URL.createObjectURL(await res.blob());
  const a = h('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function viewReport() {
  const r = await api('/api/report');
  const t = r.traceability;
  return h('div', {},
    h('div', { class: 'banner ' + (t.unresolved ? 'bad' : 'ok') }, t.unresolved ? `${t.unresolved} of ${t.claims} claims could not be matched to stored evidence.` : `Traceability check passed: all ${t.claims} claims point to stored evidence.`),
    h('div', { class: 'toolbar', style: 'margin-bottom:.75rem' },
      h('button', { class: 'primary', onclick: () => guarded(() => download('/api/report.md', 'threatweaver-report.md')) }, 'Download Markdown'),
      h('button', { onclick: () => guarded(() => download('/api/report.json', 'threatweaver-report.json')) }, 'Download JSON')),
    h('p', { class: 'small muted' }, 'The Markdown report has every indicator defanged, so it is safe to paste into tickets and chat. The JSON keeps exact values for tools. Each indicator shows up to 20 sightings and evidence items; the true totals are stated, and everything is kept in the database.'),
    r.truncated ? h('p', { class: 'small muted' }, `Preview of the first ${r.preview.split(String.fromCharCode(10)).length} of ${r.lines} lines. Download for the whole report.`) : null,
    h('pre', { class: 'md' }, r.preview));
}

/* ---------- advisories ---------- */
const STEPS = ['draft', 'submitted', 'approved', 'published'];
async function viewAdvisories() {
  const { advisories } = await api('/api/advisories');
  const author = h('input', { type: 'text', placeholder: 'your name', value: remember('name'), 'aria-label': 'Your name' });
  return h('div', {},
    h('div', { class: 'panel' }, h('h2', {}, 'Advisories'),
      h('p', { class: 'muted' }, 'A draft uses only indicators that a public feed lists. It never includes your logs, internal hosts or file names. A different person must review and approve it before it can be written out as a file. Nothing is sent anywhere.'),
      h('div', { class: 'toolbar' }, author, h('button', { class: 'primary', onclick: async () => {
        if (!author.value.trim()) return toast('Enter your name first', 'err');
        remember('name', author.value);
        const a = await guarded(() => api('/api/advisory/draft', { author: author.value }));
        if (a) location.hash = '#/advisory/' + a.id;
      } }, 'Draft from current evidence'))),
    advisories.length ? h('div', { class: 'panel' }, table(['#', 'Title', 'Status', 'Author', 'Reviewer'], advisories.map((a) => ({ data: a, cells: [cell(String(a.id)), cell(a.title), cell(a.status), cell(a.author), cell(a.reviewer || '-')] })), (a) => (location.hash = '#/advisory/' + a.id))) : empty('No advisories yet.'));
}
async function viewAdvisory(id) {
  const a = await api('/api/advisory/' + id);
  const blocking = a.findings.filter((f) => f.blocking);
  const name = h('input', { type: 'text', value: remember('name'), placeholder: 'your name', 'aria-label': 'Your name' });
  const refresh = () => route();
  const act = async (verb, body, ok) => { remember('name', name.value); const r = await guarded(() => api(`/api/advisory/${id}/${verb}`, body)); if (r) { toast(ok, 'ok'); refresh(); } };

  const editable = a.status === 'draft' || a.status === 'rejected';
  const title = h('input', { type: 'text', value: a.title, style: 'width:100%', disabled: !editable, 'aria-label': 'Title' });
  const body = h('textarea', { disabled: !editable, 'aria-label': 'Advisory text' }); body.value = a.body;

  const findings = h('div', {});
  const showFindings = (list) => findings.replaceChildren(list.length ? h('div', { class: 'banner ' + (list.some((f) => f.blocking) ? 'bad' : '') }, h('b', {}, 'Confidentiality check'), h('ul', { class: 'findings' }, list.map((f) => h('li', {}, h('b', {}, f.kind.replaceAll('_', ' ')), f.blocking ? ' (blocks submission): ' : ' (warning): ', h('span', { class: 'mono' }, f.excerpt))))) : h('div', { class: 'banner ok' }, 'Confidentiality check: nothing found.'));
  showFindings(a.findings);

  const actions = h('div', { class: 'panel' }, h('h2', {}, 'Actions'), h('div', { class: 'field' }, h('label', {}, 'Your name (the reviewer must be a different person from the author)'), name));
  if (editable) {
    actions.append(h('div', { class: 'toolbar' },
      h('button', { onclick: async () => { const r = await guarded(() => api('/api/advisory/check', { text: title.value + '\n' + body.value })); if (r) showFindings(r.findings); } }, 'Check text'),
      h('button', { onclick: () => act('edit', { title: title.value, body: body.value, actor: name.value }, 'Saved') }, 'Save changes'),
      h('button', { class: 'primary', disabled: blocking.length > 0, onclick: () => act('submit', { actor: name.value }, 'Submitted for review') }, 'Submit for review')));
    if (blocking.length) actions.append(h('p', { class: 'small', style: 'color:var(--bad)' }, 'Fix the blocking findings (and save) before submitting. There is no override.'));
    if (a.status === 'rejected') actions.append(h('p', { class: 'small' }, `Rejected by ${a.reviewer}: ${a.review_note || ''}`));
  } else if (a.status === 'submitted') {
    const phrase = h('input', { type: 'text', placeholder: `type APPROVE ${id}`, 'aria-label': 'Approval confirmation' });
    const note = h('input', { type: 'text', placeholder: 'reason if rejecting', 'aria-label': 'Rejection reason' });
    actions.append(h('p', {}, 'Read the text above. Approving confirms you reviewed exactly this content: ', h('span', { class: 'mono small' }, a.content_sha256.slice(0, 16) + '...')),
      h('div', { class: 'field' }, h('label', {}, `To approve, type APPROVE ${id}`), phrase),
      h('div', { class: 'toolbar' },
        h('button', { class: 'primary', onclick: () => act('approve', { reviewer: name.value, seen_sha256: a.content_sha256, confirmation: phrase.value.trim() }, 'Approved') }, 'Approve'),
        note, h('button', { class: 'danger', onclick: () => act('reject', { reviewer: name.value, note: note.value }, 'Rejected') }, 'Reject')));
  } else if (a.status === 'approved') {
    actions.append(h('p', {}, `Approved by ${a.reviewer} at ${a.reviewed_at}.`),
      h('div', { class: 'toolbar' }, h('button', { class: 'primary', onclick: () => act('publish', { actor: name.value }, 'Written to a local file') }, 'Write to local file'),
        h('span', { class: 'small muted' }, 'This only creates files in the out folder. Distributing them is up to you.')));
  } else if (a.status === 'published') {
    actions.append(h('p', {}, 'Written to local file: ', h('span', { class: 'mono' }, a.published_path || '')));
  }

  return h('div', {},
    h('p', {}, h('button', { class: 'link', onclick: () => (location.hash = '#/advisories') }, 'All advisories'), ` / #${a.id}`),
    h('div', { class: 'steps' }, STEPS.map((x) => h('span', { class: 'step' + (x === a.status || (a.status === 'rejected' && x === 'draft') ? ' on' : '') }, x)), a.status === 'rejected' ? h('span', { class: 'step on' }, 'rejected') : null),
    h('div', { class: 'panel' }, h('div', { class: 'field' }, h('label', {}, 'Title'), title), h('label', {}, 'Text'), body, h('p', { class: 'small muted' }, `Author: ${a.author}. Content hash ${a.content_sha256.slice(0, 16)}...`)),
    findings, actions,
    h('div', { class: 'panel' }, h('h2', {}, 'Audit log'), table(['When', 'Action', 'Who', 'Content', 'Note'], a.events.map((e) => ({ data: e, cells: [cell(e.at), cell(e.action), cell(e.actor), cell(e.content_sha256.slice(0, 10), 'val'), cell(e.note)] })))));
}

/* ---------- shell and routing ---------- */
// every address maps to a stage of the cycle (the older addresses still work) and the view that shows it
const ROUTES = {
  '': ['home', viewHome], home: ['home', viewHome], overview: ['home', viewHome],
  plan: ['plan', viewPlan],
  collect: ['collect', viewCollect], sources: ['collect', viewCollect], feeds: ['collect', viewCollect],
  process: ['process', viewProcess], indicators: ['process', viewIndicatorsStage],
  analyse: ['analyse', viewAnalyse], cases: ['analyse', viewAnalyse], case: ['analyse', viewCaseStage], graph: ['analyse', viewGraphStage],
  share: ['share', viewShareReport], report: ['share', viewShareReport], advisories: ['share', viewShareAdvisories], advisory: ['share', viewShareAdvisory],
  feedback: ['feedback', viewFeedback],
};
const TITLES = { home: 'Home', plan: '1. Plan', collect: '2. Collect', process: '3. Process', analyse: '4. Analyse', share: '5. Share', feedback: '6. Feedback' };
const SLOW = new Set(['analyse', 'cases', 'case', 'graph', 'indicators', 'share', 'report', 'advisories', 'advisory', 'feedback']); // these need the analysis

function shell() {
  const app = $('#app');
  app.replaceChildren(h('div', { class: 'shell' },
    h('nav', { class: 'side', 'aria-label': 'The intelligence cycle' }, h('div', { class: 'brand' }, 'ThreatWeaver', h('small', {}, 'local analyst assistant')),
      h('div', { class: 'nav' },
        h('a', { href: '#/', 'data-k': 'home' }, h('span', { class: 'num' }, '⌂'), h('span', { class: 'lbl' }, 'Home')),
        h('div', { class: 'navhead' }, 'The cycle, in order'),
        STAGES.map((st) => h('a', { href: st.href, 'data-k': st.key }, h('span', { class: 'num' }, String(st.n)), h('span', { class: 'lbl' }, st.name), h('span', { class: 'dot waiting', 'aria-hidden': 'true' })))),
      h('div', { class: 'foot' }, 'Everything runs on this computer. Nothing is blocked, sent or published automatically.')),
    h('main', { class: 'main' },
      h('div', { class: 'topbar' }, h('h1', { id: 'title' }, ''), h('div', { class: 'toolbar' },
        h('span', { class: 'safe' }, 'Local only. Suggestions, not actions.'),
        h('label', { style: 'display:flex;gap:.35rem;align-items:center;margin:0' }, h('input', { type: 'checkbox', checked: state.exact, onchange: (e) => { state.exact = e.target.checked; route(); } }), 'Show exact values'),
        h('button', { onclick: () => route(), 'aria-label': 'Refresh' }, 'Refresh'))),
      h('div', { id: 'activity', class: 'activity', 'aria-live': 'polite' }),
      h('div', { id: 'view' }))),
    h('div', { class: 'toasts', 'aria-live': 'polite' }));
}
let routeSeq = 0;
async function route() {
  closeDrawer();
  document.body.classList.remove('graph-open');
  const [, key = '', arg] = location.hash.split('/');
  const [stage, view] = ROUTES[key] || ROUTES[''];
  document.querySelectorAll('.nav a').forEach((a) => (a.dataset.k === stage ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  $('#title').textContent = TITLES[stage];
  const box = $('#view'), seq = ++routeSeq;
  box.replaceChildren(h('p', { class: 'muted' }, SLOW.has(key) ? 'Loading... After adding a large file, the first view can take up to a minute while everything is analysed.' : 'Loading...'));
  try {
    const node = await view(arg);
    if (seq === routeSeq) {
      box.replaceChildren(node);
      // the stages that do not fetch the status themselves keep the step markers in the menu current
      if (SLOW.has(key)) api('/api/status').then((s) => { statusCache = s; paintNav(); }).catch(() => {});
    }
  } catch (e) {
    if (seq === routeSeq) box.replaceChildren(h('div', { class: 'banner bad' }, 'Could not load this page: ' + e.message));
  }
}
window.addEventListener('hashchange', route);
shell();
route();
pollJobs(); // pick up anything still running from before a page reload
})();
