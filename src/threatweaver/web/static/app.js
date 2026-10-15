/* ThreatWeaver dashboard. Vanilla JS, no dependencies, no network except this server.
 * SECURITY: data from logs and feeds is attacker-influenced. It is only ever put into the page
 * through textContent / createTextNode (see h() below). The page is never built from HTML strings. */
(() => {
'use strict';

const TOKEN = document.querySelector('meta[name="tw-token"]').content;
const LEVELS = ['high', 'medium', 'low', 'info'];
const RULE_HELP = {
  url_host: 'URL and its host (structural)',
  same_line: 'Appear on the same log line (co-occurrence, not proof)',
  hostname_ip: 'Host name spells out this IP address',
  shared_family: 'Listed by a feed under the same malware family',
};
const state = { exact: false, theme: null };

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
const fmtBytes = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB');
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
    h('p', { class: 'small' }, 'Case: ', h('button', { class: 'link', onclick: () => { closeDrawer(); location.hash = '#/case/' + d.case_id; } }, d.case_id)),
    h('h3', {}, 'Why this level'),
    d.rules.length ? d.rules.map((r) => h('div', { class: 'rule ' + (r.points >= 0 ? 'pos' : 'neg') },
      h('span', { class: 'pts' }, (r.points >= 0 ? '+' : '') + r.points), ' ', h('b', {}, r.rule), ' ', h('span', { class: 'muted' }, r.description),
      h('div', {}, r.reason), h('div', { class: 'small muted' }, `${r.evidence.length} evidence item(s)`)))
      : h('p', { class: 'muted' }, 'No triage rule fired for this indicator.'),
    d.feed_matches.length ? h('h3', {}, 'Public feed records') : null,
    d.feed_matches.map((m) => h('div', { class: 'panel' },
      h('b', {}, m.feed), ' ', h('span', { class: 'muted' }, m.via === 'exact' ? 'lists this indicator' : 'lists a URL hosted here: ' + m.listed_url),
      h('div', { class: 'small muted' }, `snapshot ${m.snapshot}, collected ${m.collected_at}`),
      h('div', { class: 'mono small' }, Object.entries(m.fields).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\n').split('\n').map((l) => h('div', {}, l))))),
    d.links.length ? h('h3', {}, 'Connected indicators') : null,
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
  url_host: { w: 2.6, dash: null }, same_line: { w: 1.4, dash: null },
  hostname_ip: { w: 1.8, dash: '7 4' }, shared_family: { w: 1.4, dash: '2 5' },
};
function shapeFor(node, r) {
  const fill = `var(--${node.level}-bg)`;
  const common = { fill, stroke: 'var(--text)', 'stroke-width': 1.5 };
  if (node.type === 'domain') return s('rect', { ...common, x: -r, y: -r, width: 2 * r, height: 2 * r, rx: 3 });
  if (node.type === 'url') return s('polygon', { ...common, points: `0,${-r * 1.3} ${r * 1.3},0 0,${r * 1.3} ${-r * 1.3},0` });
  if (node.type.startsWith('ip')) return s('circle', { ...common, r });
  const pts = [0, 1, 2, 3, 4, 5].map((i) => `${(r * 1.2 * Math.cos(Math.PI / 3 * i)).toFixed(1)},${(r * 1.2 * Math.sin(Math.PI / 3 * i)).toFixed(1)}`).join(' ');
  return s('polygon', { ...common, points: pts });
}
function force(nodes, edges, W, H) {
  const n = nodes.length;
  const k = Math.sqrt((W * H) / Math.max(n, 1)) * 0.65;
  nodes.forEach((d, i) => { const a = (2 * Math.PI * i) / n; d.x = W / 2 + Math.cos(a) * W / 3; d.y = H / 2 + Math.sin(a) * H / 3; });
  const byId = new Map(nodes.map((d) => [d.id, d]));
  let temp = W / 8;
  for (let it = 0; it < 300; it++) {
    for (const d of nodes) { d.dx = 0; d.dy = 0; }
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let dist = Math.hypot(dx, dy);
        if (dist < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; dist = 1; }
        const f = (k * k) / dist;
        a.dx += (dx / dist) * f; a.dy += (dy / dist) * f; b.dx -= (dx / dist) * f; b.dy -= (dy / dist) * f;
      }
    }
    for (const e of edges) {
      const a = byId.get(e.a), b = byId.get(e.b);
      if (!a || !b) continue;
      const dx = a.x - b.x, dy = a.y - b.y, dist = Math.max(Math.hypot(dx, dy), 0.01);
      const f = (dist * dist) / k;
      a.dx -= (dx / dist) * f; a.dy -= (dy / dist) * f; b.dx += (dx / dist) * f; b.dy += (dy / dist) * f;
    }
    for (const d of nodes) {
      d.dx += (W / 2 - d.x) * 0.05; d.dy += (H / 2 - d.y) * 0.05;
      const len = Math.max(Math.hypot(d.dx, d.dy), 0.01);
      d.x = Math.min(W - 30, Math.max(30, d.x + (d.dx / len) * Math.min(len, temp)));
      d.y = Math.min(H - 24, Math.max(24, d.y + (d.dy / len) * Math.min(len, temp)));
    }
    temp *= 0.98;
  }
}
/* Lay out each connected component on its own, then pack the components in rows
 * (highest priority and largest first). Returns the total height used. */
function layoutAll(nodes, edges, W) {
  const byId = new Map(nodes.map((d) => [d.id, d]));
  const parent = new Map(nodes.map((d) => [d.id, d.id]));
  const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
  for (const e of edges) if (byId.has(e.a) && byId.has(e.b)) parent.set(find(e.a), find(e.b));
  const groups = new Map();
  for (const d of nodes) { const r = find(d.id); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(d); }
  const comps = [...groups.values()].sort((a, b) => Math.max(...b.map((n) => n.score)) - Math.max(...a.map((n) => n.score)) || b.length - a.length);
  let x = 20, y = 20, rowH = 0;
  for (const comp of comps) {
    const m = comp.length;
    const bw = m === 1 ? 70 : Math.min(W - 40, 90 + 70 * Math.sqrt(m)), bh = m === 1 ? 50 : 70 + 60 * Math.sqrt(m);
    if (m > 1) { const ids = new Set(comp.map((n) => n.id)); force(comp, edges.filter((e) => ids.has(e.a) && ids.has(e.b)), bw, bh); }
    else { comp[0].x = bw / 2; comp[0].y = bh / 2; }
    if (x + bw > W - 20 && x > 20) { x = 20; y += rowH + 16; rowH = 0; }
    for (const n of comp) { n.x += x; n.y += y; }
    x += bw + 16; rowH = Math.max(rowH, bh);
  }
  return Math.max(300, y + rowH + 20);
}
function legend() {
  const item = (shape, text) => h('span', {}, shape, ' ', text);
  const small = (node) => { const sv = s('svg', { width: 18, height: 18, viewBox: '-10 -10 20 20', 'aria-hidden': 'true' }); sv.append(node); return sv; };
  const sh = (type) => small(shapeFor({ type, level: 'info' }, 6));
  const line = (rule) => { const st = EDGE_STYLE[rule]; const sv = s('svg', { width: 34, height: 12, 'aria-hidden': 'true' }); sv.append(s('line', { x1: 1, y1: 6, x2: 33, y2: 6, stroke: 'var(--muted)', 'stroke-width': st.w, 'stroke-dasharray': st.dash })); return sv; };
  return h('div', { class: 'legend' },
    item(sh('ipv4'), 'IP'), item(sh('domain'), 'domain'), item(sh('url'), 'URL'), item(sh('sha256'), 'hash'), ' | ',
    LEVELS.map((l) => badge(l)), ' | ',
    Object.keys(EDGE_STYLE).map((r) => item(line(r), r.replace('_', ' '))));
}
function drawGraph(data) {
  const W = 900;
  const nodes = data.nodes.map((n) => ({ ...n }));
  if (!nodes.length) return empty('Nothing is linked yet. Links appear when indicators share a log line, a URL and its host, or a host name that spells out an IP.');
  const H = layoutAll(nodes, data.edges, W);
  const byId = new Map(nodes.map((d) => [d.id, d]));
  const svg = s('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Link graph with ${nodes.length} indicators` });
  const edgeEls = data.edges.filter((e) => byId.has(e.a) && byId.has(e.b)).map((e) => {
    const st = EDGE_STYLE[e.rule] || EDGE_STYLE.same_line;
    const line = s('line', { stroke: 'var(--muted)', 'stroke-width': st.w, 'stroke-dasharray': st.dash, opacity: 0.8 }, s('title', {}, e.rule));
    svg.append(line);
    return { e, line };
  });
  const showLabels = nodes.length <= 40;
  const nodeEls = nodes.map((d) => {
    const r = 6 + Math.min(d.score / 12, 7);
    const g = s('g', { class: 'node', tabindex: 0, role: 'button', 'aria-label': `${d.type} ${d.display}, ${d.level}` }, shapeFor(d, r), s('title', {}, `${val(d)} (${d.level}, score ${d.score})`));
    if (showLabels) g.append(s('text', { x: 0, y: r + 12, 'text-anchor': 'middle' }, val(d).length > 30 ? val(d).slice(0, 29) + '...' : val(d)));
    let moved = false, dragging = false;
    g.addEventListener('pointerdown', (ev) => {
      moved = false; dragging = true;
      try { g.setPointerCapture(ev.pointerId); } catch { /* synthetic pointers cannot be captured; dragging just degrades */ }
    });
    g.addEventListener('pointermove', (m) => {
      if (!dragging) return;
      const box = svg.getBoundingClientRect();
      const x = Math.min(W - 10, Math.max(10, ((m.clientX - box.left) / box.width) * W));
      const y = Math.min(H - 10, Math.max(10, ((m.clientY - box.top) / box.height) * H));
      if (Math.hypot(x - d.x, y - d.y) > 4) { moved = true; d.x = x; d.y = y; place(); }
    });
    g.addEventListener('pointerup', () => { dragging = false; });
    g.addEventListener('click', () => { if (!moved) openIndicator(d.id); moved = false; });
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') openIndicator(d.id); });
    svg.append(g);
    return { d, g };
  });
  function place() {
    for (const { e, line } of edgeEls) {
      const a = byId.get(e.a), b = byId.get(e.b);
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y); line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    }
    for (const { d, g } of nodeEls) g.setAttribute('transform', `translate(${d.x.toFixed(1)},${d.y.toFixed(1)})`);
  }
  place();
  return h('div', {}, legend(), svg,
    h('p', { class: 'small muted' }, 'Drag nodes to rearrange. Click one for details. Colour and outline show the suggested level; shape shows the type. Dashed lines are host-name-encodes-IP links, dotted lines are shared malware family.'),
    data.truncated ? h('p', { class: 'small muted' }, 'Showing the 300 highest-scoring linked indicators.') : null);
}

/* ---------- views ---------- */
async function viewOverview() {
  const o = await api('/api/overview');
  const sm = o.summary;
  const max = Math.max(1, ...LEVELS.map((l) => sm.by_level[l]));
  const root = h('div', {});
  if (o.empty) {
    root.append(h('div', { class: 'banner' }, h('b', {}, 'No data yet. '), 'Add a log file or report below. ThreatWeaver extracts indicators, de-duplicates them, and shows what is connected.'));
  }
  root.append(h('div', { class: 'tiles' },
    [['Indicators', sm.indicators], ['Cases', sm.cases], ['High', sm.by_level.high], ['Medium', sm.by_level.medium], ['Links', sm.links], ['Feed matches', sm.feed_matches]]
      .map(([l, n]) => h('div', { class: 'tile' }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, l)))));
  root.append(h('div', { class: 'grid cols-2' },
    h('div', { class: 'panel' }, h('h2', {}, 'Suggested priority'),
      h('div', { class: 'bars' }, LEVELS.map((l) => h('div', { class: 'row' }, badge(l), h('div', { class: 'track' }, h('div', { class: 'fill ' + l, style: `width:${(sm.by_level[l] / max) * 100}%` })), h('span', { class: 'mono' }, sm.by_level[l])))),
      h('p', { class: 'small muted' }, 'Levels are suggestions from simple, named rules. A person decides what to do.'),
      h('div', { class: 'toolbar' }, h('button', { onclick: () => (location.hash = '#/cases') }, 'Open cases'), h('button', { onclick: () => (location.hash = '#/graph') }, 'Open link graph'))),
    addDataPanel(),
    feedsPanel(o.feeds)));
  root.append(h('div', { class: 'panel' }, h('h2', {}, 'Your sources'),
    o.sources.length ? table(['Name', 'Indicators', 'Added', 'SHA-256'], o.sources.map((x) => ({ data: x, cells: [cell(x.name), cell(String(x.indicators)), cell(x.ingested_at), cell(x.sha256.slice(0, 12), 'val')] })))
      : h('p', { class: 'muted' }, 'No sources yet.')));
  return root;
}

function addDataPanel() {
  const input = h('input', { type: 'file', multiple: true, class: 'hidden', id: 'filepick', onchange: (e) => upload([...e.target.files]) });
  const zone = h('div', { class: 'drop', tabindex: 0, role: 'button', 'aria-label': 'Choose log files to add',
    onclick: () => input.click(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') input.click(); },
    ondragover: (e) => { e.preventDefault(); zone.classList.add('over'); }, ondragleave: () => zone.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); zone.classList.remove('over'); upload([...e.dataTransfer.files]); } },
    h('b', {}, 'Drop log files here'), h('div', {}, 'or click to choose (text, logs, CSV, JSON; up to 20 MB each)'));
  const name = h('input', { type: 'text', placeholder: 'name, e.g. analyst-notes.txt', value: 'pasted-text.txt', 'aria-label': 'Name for pasted text' });
  const text = h('textarea', { placeholder: 'Or paste a report, email or log excerpt here', style: 'min-height:6rem', 'aria-label': 'Pasted text' });
  return h('div', { class: 'panel' }, h('h2', {}, 'Add data'), input, zone,
    h('details', { style: 'margin-top:.75rem' }, h('summary', {}, 'Paste text instead'), h('div', { class: 'field' }, name), text,
      h('button', { class: 'primary', onclick: async () => { if (text.value.trim()) { await upload([{ name: name.value || 'pasted-text.txt', size: text.value.length, text: async () => text.value }]); text.value = ''; } } }, 'Add pasted text')),
    h('p', { class: 'small muted' }, 'Files are read in your browser and sent only to this local dashboard. Nothing leaves your machine.'));
}
async function upload(files) {
  let any = false;
  for (const f of files) {
    if (f.size > 20 * 1024 * 1024) { toast(`${f.name} is ${fmtBytes(f.size)}; the limit is 20 MB`, 'err'); continue; }
    const body = { name: f.name, text: await f.text() };
    const r = await guarded(() => api('/api/ingest', body));
    if (!r) continue;
    any = true;
    toast(r.already_ingested ? `${r.name}: identical content was already added` : `${r.name}: ${r.new_indicators} new indicators, ${r.sightings} sightings`, 'ok');
  }
  if (any) route();
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

async function viewCases() {
  const { cases: all } = await api('/api/cases');
  if (!all.length) return empty('No cases yet. Add data on the Overview page.');
  const quiet = (c) => c.links === 0 && c.max_level === 'info';
  const list = h('div', { class: 'cards' });
  const count = h('span', { class: 'small muted' });
  const toggle = h('input', { type: 'checkbox', onchange: draw });
  function draw() {
    const cases = toggle.checked ? all : all.filter((c) => !quiet(c));
    count.textContent = `${cases.length} of ${all.length} cases`;
    list.replaceChildren(...cases.map(caseCard));
  }
  const wrap = h('div', {}, h('p', { class: 'muted' }, 'A case is a group of indicators connected by strong links (a URL and its host, the same log line, or a host name that spells out an IP). Highest suggested priority first.'),
    h('div', { class: 'toolbar', style: 'margin-bottom:.75rem' }, h('label', { style: 'display:flex;gap:.35rem;align-items:center;margin:0' }, toggle, 'Also show quiet cases (a single indicator, nothing linked, nothing suspicious)'), count), list);
  draw();
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
      table(['Level', 'Score', 'Type', 'Indicator'], c.indicators.map((i) => ({ data: i, cells: [nodeCell(badge(i.level)), cell(String(i.score)), cell(i.type), cell(val(i), 'val')] })), (i) => openIndicator(i.id))),
    h('div', { class: 'panel' }, h('h2', {}, 'How they connect'), drawGraph(g)));
}

async function viewIndicators() {
  const f = { q: '', type: '', level: '', source: '', offset: 0 };
  const results = h('div', {});
  const qInput = h('input', { type: 'search', placeholder: 'Search value...', 'aria-label': 'Search', oninput: debounce(() => { f.q = qInput.value; f.offset = 0; load(); }, 250) });
  const typeSel = h('select', { 'aria-label': 'Type', onchange: () => { f.type = typeSel.value; f.offset = 0; load(); } }, h('option', { value: '' }, 'All types'), ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'].map((t) => h('option', { value: t }, t)));
  const lvlSel = h('select', { 'aria-label': 'Level', onchange: () => { f.level = lvlSel.value; f.offset = 0; load(); } }, h('option', { value: '' }, 'All levels'), LEVELS.map((l) => h('option', { value: l }, l)));
  const srcInput = h('input', { type: 'search', placeholder: 'Source name...', 'aria-label': 'Source', oninput: debounce(() => { f.source = srcInput.value; f.offset = 0; load(); }, 250) });
  async function load() {
    const qs = new URLSearchParams({ q: f.q, type: f.type, level: f.level, source: f.source, offset: f.offset, limit: 50 });
    const d = await guarded(() => api('/api/indicators?' + qs));
    if (!d) return;
    results.replaceChildren(
      h('p', { class: 'small muted' }, `${d.total} indicator(s)`),
      d.rows.length ? table(['Level', 'Score', 'Type', 'Indicator', 'Seen', 'Sources', 'Feeds'], d.rows.map((i) => ({ data: i, cells: [nodeCell(badge(i.level)), cell(String(i.score)), cell(i.type), cell(val(i), 'val'), cell(String(i.sightings)), cell(i.sources.join(', ')), cell(i.feed_matches ? String(i.feed_matches) : '-')] })), (i) => openIndicator(i.id)) : empty('Nothing matches these filters.'),
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
  const sel = h('select', { 'aria-label': 'Case', onchange: draw }, h('option', { value: '' }, 'All linked indicators'), cases.filter((c) => c.links).map((c) => h('option', { value: c.case_id }, `${c.case_id} (${c.size} indicators, ${c.max_level})`)));
  async function draw() { const g = await guarded(() => api('/api/graph' + (sel.value ? '?case=' + encodeURIComponent(sel.value) : ''))); if (g) holder.replaceChildren(drawGraph(g)); }
  draw();
  return h('div', {}, h('div', { class: 'toolbar', style: 'margin-bottom:.75rem' }, h('label', { for: 'x', style: 'margin:0' }, 'Show'), sel), holder);
}

async function viewSources() {
  const { sources } = await api('/api/sources');
  return sources.length ? h('div', { class: 'panel' }, table(['Name', 'Indicators', 'Added', 'SHA-256 (pins the exact content analysed)'], sources.map((x) => ({ data: x, cells: [cell(x.name), cell(String(x.indicators)), cell(x.ingested_at), cell(x.sha256, 'val')] }))))
    : empty('No sources yet.');
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = h('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function viewReport() {
  const r = await api('/api/report');
  const t = r.traceability;
  return h('div', {},
    h('div', { class: 'banner ' + (t.unresolved ? 'bad' : 'ok') }, t.unresolved ? `${t.unresolved} of ${t.claims} claims could not be matched to stored evidence.` : `Traceability check passed: all ${t.claims} claims point to stored evidence.`),
    h('div', { class: 'toolbar', style: 'margin-bottom:.75rem' },
      h('button', { class: 'primary', onclick: () => download('threatweaver-report.md', r.markdown, 'text/markdown') }, 'Download Markdown'),
      h('button', { onclick: () => download('threatweaver-report.json', JSON.stringify(r.json, null, 2), 'application/json') }, 'Download JSON')),
    h('p', { class: 'small muted' }, 'The Markdown report has every indicator defanged, so it is safe to paste into tickets and chat. The JSON keeps exact values for tools.'),
    h('pre', { class: 'md' }, r.markdown));
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
const NAV = [['overview', 'Overview'], ['cases', 'Cases'], ['indicators', 'Indicators'], ['graph', 'Link graph'], ['sources', 'Sources'], ['report', 'Report'], ['advisories', 'Advisories']];
function shell() {
  const app = $('#app');
  app.replaceChildren(h('div', { class: 'shell' },
    h('nav', { class: 'side', 'aria-label': 'Main' }, h('div', { class: 'brand' }, 'ThreatWeaver', h('small', {}, 'local analyst assistant')),
      h('div', { class: 'nav' }, NAV.map(([k, label]) => h('a', { href: '#/' + k, 'data-k': k }, label))),
      h('div', { class: 'foot' }, 'Everything runs on this computer. Nothing is blocked, sent or published automatically.')),
    h('main', { class: 'main' },
      h('div', { class: 'topbar' }, h('h1', { id: 'title' }, ''), h('div', { class: 'toolbar' },
        h('span', { class: 'safe' }, 'Local only. Suggestions, not actions.'),
        h('label', { style: 'display:flex;gap:.35rem;align-items:center;margin:0' }, h('input', { type: 'checkbox', checked: state.exact, onchange: (e) => { state.exact = e.target.checked; route(); } }), 'Show exact values'),
        h('button', { onclick: () => route(), 'aria-label': 'Refresh' }, 'Refresh'))),
      h('div', { id: 'view' }))),
    h('div', { class: 'toasts', 'aria-live': 'polite' }));
}
const TITLES = { overview: 'Overview', cases: 'Cases', case: 'Case', indicators: 'Indicators', graph: 'Link graph', sources: 'Sources', report: 'Report', advisories: 'Advisories', advisory: 'Advisory' };
let routeSeq = 0;
async function route() {
  closeDrawer();
  const [, key = 'overview', arg] = location.hash.split('/');
  const top = { case: 'cases', advisory: 'advisories' }[key] || key;
  document.querySelectorAll('.nav a').forEach((a) => (a.dataset.k === top ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  $('#title').textContent = TITLES[key] || 'Overview';
  const view = $('#view'), seq = ++routeSeq;
  view.replaceChildren(h('p', { class: 'muted' }, 'Loading...'));
  try {
    const views = { overview: viewOverview, cases: viewCases, case: () => viewCase(arg), indicators: viewIndicators, graph: viewGraph, sources: viewSources, report: viewReport, advisories: viewAdvisories, advisory: () => viewAdvisory(arg) };
    const node = await (views[key] || viewOverview)();
    if (seq === routeSeq) view.replaceChildren(node);
  } catch (e) {
    if (seq === routeSeq) view.replaceChildren(h('div', { class: 'banner bad' }, 'Could not load this page: ' + e.message));
  }
}
window.addEventListener('hashchange', route);
shell();
route();
})();
