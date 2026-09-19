/*
 * Provenant dashboard client.
 *
 * Everything that comes from an agent — commands, paths, reasons — is
 * attacker-influenced text. It is only ever placed with textContent, through
 * el(); nothing here assigns innerHTML.
 */
'use strict';

const POLL_MS = 2000;
const HARNESS_NAMES = { 'claude-code': 'Claude Code', codex: 'Codex', opencode: 'OpenCode', cline: 'Cline' };
const MARK = { allow: '✓', ask: '?', deny: '✗' };

const $ = (id) => document.getElementById(id);
let token = null;
let last = null;
let frozen = false;
let seenFeed = new Set();
let openSession = null;
let timer = null;

/* ---------------------------------------------------------------- token */

function readToken() {
  // The token arrives in the URL fragment, which the browser never sends to a
  // server. Keep it for this tab only, and take it out of the address bar.
  const m = location.hash.match(/(?:^#|&)t=([A-Za-z0-9_-]{20,})/);
  if (m) {
    try { sessionStorage.setItem('provenant-token', m[1]); } catch { /* private mode */ }
    history.replaceState(null, '', location.pathname);
    return m[1];
  }
  try { return sessionStorage.getItem('provenant-token'); } catch { return null; }
}

/* ------------------------------------------------------------------ api */

async function api(method, path) {
  const res = await fetch(`/api/${path}`, {
    method,
    headers: { 'X-Provenant-Token': token },
    cache: 'no-store',
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) {
    showGate();
    throw new Error('the access token was rejected');
  }
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

/* ------------------------------------------------------------------ dom */

/** Build an element. Children that are strings become text nodes. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    // CSSOM, not a style attribute: the CSP forbids inline style attributes.
    else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const harnessName = (h) => HARNESS_NAMES[h] ?? h ?? 'unknown';
const chip = (h) => el('span', { class: 'chip', 'data-h': h }, harnessName(h));
const shortId = (id) => (id ? id.replace(/^sess-/, '').slice(0, 8) : '');

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour12: false }) : '');

function toast(message, bad = false) {
  const t = el('div', { class: `toast${bad ? ' bad' : ''}`, role: 'status' }, message);
  $('toasts').append(t);
  setTimeout(() => t.remove(), bad ? 6000 : 3200);
}

/* ------------------------------------------------------------ rendering */

function render(s) {
  last = s;
  $('machine').textContent = s.machine;
  $('app').hidden = false;
  $('pause-all').hidden = s.control.paused;
  $('paused-banner').hidden = !s.control.paused;
  renderHarnesses(s);
  renderApprovals(s);
  renderSessions(s);
  renderPolicy(s);
  if (!frozen) renderFeed(s.feed, $('feed'), true);
}

function renderHarnesses(s) {
  const cards = s.harnesses.map((h) => {
    const total = h.day.allow + h.day.ask + h.day.deny;
    const pct = (n) => (total ? `${(100 * n) / total}%` : '0');
    return el('article', { class: `hcard${h.sessions === 0 ? ' idle' : ''}`, 'data-h': h.id },
      el('div', { class: 'hcard-top' },
        el('span', { class: 'hname' }, harnessName(h.id)),
        el('span', { class: 'hlast' }, h.lastAt ? ago(h.lastAt) : 'no activity yet')),
      el('div', { class: 'hstats' },
        el('div', { class: 'hstat' }, el('b', {}, h.active), el('span', {}, 'active')),
        el('div', { class: `hstat${h.pending ? ' warn' : ''}` }, el('b', {}, h.pending), el('span', {}, 'waiting')),
        el('div', { class: 'hstat' }, el('b', {}, h.sessions), el('span', {}, 'sessions'))),
      el('div', { class: 'split', title: 'Decisions in the last 24 hours' },
        el('i', { class: 'a', style: { width: pct(h.day.allow) } }),
        el('i', { class: 'q', style: { width: pct(h.day.ask) } }),
        el('i', { class: 'd', style: { width: pct(h.day.deny) } })),
      el('div', { class: 'legend' },
        el('span', {}, `${h.day.allow} allowed`), el('span', {}, `${h.day.ask} asked`), el('span', {}, `${h.day.deny} denied`)));
  });
  $('harnesses').replaceChildren(...cards);
}

function renderApprovals(s) {
  const pending = s.approvals.filter((a) => a.status === 'pending');
  const count = $('needs-count');
  count.textContent = pending.length;
  count.className = `count${pending.length ? ' hot' : ''}`;
  document.title = pending.length ? `(${pending.length}) Provenant Control` : 'Provenant Control';

  if (pending.length === 0) {
    $('approvals').replaceChildren(el('div', { class: 'empty' },
      el('b', {}, 'Nothing is waiting for you.'), ' Actions that need a human decision in Codex, OpenCode or Cline appear here.'));
    return;
  }
  $('approvals').replaceChildren(...pending.map((a) =>
    el('div', { class: 'approval' },
      el('div', { class: 'meta' }, chip(a.harness), el('span', { class: 'mono' }, a.class), el('span', {}, `asked ${ago(a.requestedAt)}`),
        el('span', { class: 'mono' }, a.id)),
      el('div', { class: 'cmd' }, a.resource),
      el('div', { class: 'why' }, a.reason),
      el('div', { class: 'actions' },
        el('button', { class: 'btn ghost sm', type: 'button', onclick: () => confirmDeny(a) }, 'Deny'),
        el('button', { class: 'btn ok sm', type: 'button', onclick: () => confirmApprove(a) }, 'Approve once')))));
}

function renderSessions(s) {
  const showClosed = $('show-closed').checked;
  const list = s.sessions.filter((x) => showClosed || !x.endedAt);
  if (list.length === 0) {
    $('sessions').replaceChildren(el('div', { class: 'empty' }, showClosed ? 'No sessions recorded yet.' : 'No open sessions. Tick “closed” to see earlier ones.'));
    return;
  }
  $('sessions').replaceChildren(...list.map((x) =>
    el('div', { class: 'sess' },
      el('div', { class: 'sess-top' },
        chip(x.harness),
        el('button', { class: 'sess-id', type: 'button', onclick: () => openDrawer(x.id) }, shortId(x.id)),
        el('span', { class: `pill ${x.taint}` }, x.taint),
        x.paused && el('span', { class: 'pill paused' }, 'paused'),
        x.endedAt && el('span', { class: 'pill closed' }, 'closed')),
      el('div', { class: 'sess-meta' },
        el('span', {}, `${x.events} events`),
        el('span', {}, `${x.counts.allow} allowed`),
        el('span', { class: x.counts.ask ? 'q' : '' }, `${x.counts.ask} asked`),
        el('span', { class: x.counts.deny ? 'd' : '' }, `${x.counts.deny} denied`),
        el('span', {}, ago(x.lastAt))),
      !x.endedAt && el('div', { class: 'sess-actions' },
        x.paused
          ? el('button', { class: 'btn ok sm', type: 'button', onclick: () => sessionAction(x.id, 'resume') }, 'Resume')
          : el('button', { class: 'btn danger sm', type: 'button', onclick: () => sessionAction(x.id, 'pause') }, 'Pause'),
        el('button', { class: 'btn ghost sm', type: 'button', onclick: () => verifySession(x.id) }, 'Verify'),
        el('button', { class: 'btn ghost sm', type: 'button', onclick: () => openDrawer(x.id) }, 'Open')))));
}

function renderPolicy(s) {
  const p = s.policy;
  // Show the file name, not the full path: a path carries the user's name, and
  // dashboards get screenshotted. The full path is one hover away.
  const base = p.source ? p.source.split(/[\\/]/).pop() : '';
  const rows = p.error
    ? [['error', p.error, null]]
    : [['name', p.name, null], ['rules', String(p.rules), null], ['digest', `${p.digest.slice(0, 23)}…`, p.digest], ['file', base, p.source]];
  $('policy').replaceChildren(...rows.flatMap(([k, v, title]) => [
    el('dt', {}, k),
    el('dd', { class: k === 'digest' || k === 'file' ? 'mono' : '', title }, v),
  ]));
}

function feedMatches(f) {
  const h = $('f-harness').value;
  const e = $('f-effect').value;
  const q = $('f-text').value.trim().toLowerCase();
  if (h && f.harness !== h) return false;
  if (e && f.effect !== e) return false;
  if (q && !`${f.resource ?? ''} ${f.class ?? ''} ${f.type}`.toLowerCase().includes(q)) return false;
  return true;
}

function renderFeed(items, tbody, filtered) {
  const rows = (filtered ? items.filter(feedMatches) : items).slice(0, 250).map((f) => {
    const key = `${f.session}:${f.seq}`;
    const fresh = filtered && seenFeed.size > 0 && !seenFeed.has(key);
    return el('tr', { class: `${f.effect ?? ''}${fresh ? ' fresh' : ''}` },
      el('td', { class: 't', title: f.ts }, clock(f.ts)),
      filtered ? el('td', {}, chip(f.harness)) : null,
      el('td', { class: 'm', 'aria-label': f.effect ?? '' }, MARK[f.effect] ?? '·'),
      el('td', { class: 'ty' }, f.type),
      el('td', { class: 'c' }, f.class ?? ''),
      el('td', { class: 'r' }, f.resource ?? '', f.redacted ? ' (redacted)' : '',
        f.effect && f.effect !== 'allow' && f.reason ? el('span', { class: 'why' }, f.reason) : null));
  });
  if (filtered) seenFeed = new Set(items.map((f) => `${f.session}:${f.seq}`));
  if (rows.length === 0) {
    rows.push(el('tr', {}, el('td', { colspan: 6, class: 'empty' }, filtered && last?.feed.length ? 'Nothing matches these filters.' : 'No activity yet. Start an agent in a repo where Provenant is wired.')));
  }
  tbody.replaceChildren(...rows);
}

/* -------------------------------------------------------------- actions */

function confirmBox({ title, body, ok, okClass }) {
  return new Promise((resolve) => {
    $('modal-title').textContent = title;
    $('modal-body').replaceChildren(...body);
    const btn = $('modal-ok');
    btn.textContent = ok;
    btn.className = `btn ${okClass ?? ''}`;
    $('modal').hidden = false;
    btn.focus();
    const done = (value) => {
      $('modal').hidden = true;
      btn.onclick = null;
      document.querySelectorAll('#modal [data-cancel]').forEach((n) => { n.onclick = null; });
      resolve(value);
    };
    btn.onclick = () => done(true);
    document.querySelectorAll('#modal [data-cancel]').forEach((n) => { n.onclick = () => done(false); });
  });
}

async function confirmApprove(a) {
  const yes = await confirmBox({
    title: 'Approve this action once?',
    body: [
      el('div', { class: 'meta' }, chip(a.harness), ' ', el('span', { class: 'mono' }, a.class)),
      el('div', { class: 'cmd' }, a.resource),
      el('p', { class: 'muted' }, a.reason),
      el('p', {}, 'The agent may run exactly this, once, within the next 10 minutes. It must retry the action itself.'),
    ],
    ok: 'Approve once',
    okClass: 'ok',
  });
  if (!yes) return;
  try {
    await api('POST', `approvals/${a.id}/approve`);
    toast(`Approved ${a.id}. Tell the agent to retry.`);
    refresh();
  } catch (err) {
    toast(`Could not approve: ${err.message}`, true);
  }
}

async function confirmDeny(a) {
  const yes = await confirmBox({
    title: 'Deny this action?',
    body: [el('div', { class: 'cmd' }, a.resource), el('p', {}, 'The agent is refused if it retries this exact action in the next 10 minutes.')],
    ok: 'Deny',
    okClass: 'danger',
  });
  if (!yes) return;
  try {
    await api('POST', `approvals/${a.id}/deny`);
    toast(`Denied ${a.id}.`);
    refresh();
  } catch (err) {
    toast(`Could not deny: ${err.message}`, true);
  }
}

async function sessionAction(id, action) {
  try {
    await api('POST', `sessions/${id}/${action}`);
    toast(action === 'pause' ? `Paused ${shortId(id)}: only reads are allowed now.` : `Resumed ${shortId(id)}.`);
    refresh();
    if (openSession === id) openDrawer(id);
  } catch (err) {
    toast(`Could not ${action}: ${err.message}`, true);
  }
}

async function verifySession(id, target) {
  try {
    const r = await api('POST', `sessions/${id}/verify`);
    const warn = r.checks.filter((c) => c.warn);
    const box = r.ok
      ? el('div', { class: 'verify ok' }, `✓ ${r.events} events verified: signatures, chain, checkpoint and inclusion proofs.`,
        warn.length ? el('ul', {}, ...warn.map((w) => el('li', {}, w.detail))) : null)
      : el('div', { class: 'verify bad' }, `✗ Verification failed. The log was changed after it was written.`,
        el('ul', {}, ...r.failures.map((f) => el('li', {}, `${f.name}: ${f.detail}`))));
    if (target) target.replaceChildren(box);
    else toast(r.ok ? `${shortId(id)} verified: ${r.events} events intact.` : `${shortId(id)} FAILED verification.`, !r.ok);
  } catch (err) {
    toast(`Could not verify: ${err.message}`, true);
  }
}

async function openDrawer(id) {
  openSession = id;
  try {
    const d = await api('GET', `sessions/${id}`);
    $('drawer-harness').replaceChildren(chip(d.harness));
    $('drawer-title').textContent = d.id;
    $('drawer-meta').textContent = [d.cwd, d.model, `started ${ago(d.startedAt)}`, d.endedAt ? 'closed' : 'open'].filter(Boolean).join(' · ');
    $('drawer-verify').replaceChildren();
    $('drawer-actions').replaceChildren(
      !d.endedAt && (d.paused
        ? el('button', { class: 'btn ok sm', type: 'button', onclick: () => sessionAction(id, 'resume') }, 'Resume session')
        : el('button', { class: 'btn danger sm', type: 'button', onclick: () => sessionAction(id, 'pause') }, 'Pause session')),
      el('button', { class: 'btn ghost sm', type: 'button', onclick: () => verifySession(id, $('drawer-verify')) }, 'Verify log'),
      el('button', {
        class: 'btn ghost sm', type: 'button', onclick: async () => {
          try { await api('POST', `sessions/${id}/checkpoint`); toast('Checkpoint signed. Copy roots.jsonl off this machine to anchor it.'); }
          catch (err) { toast(`Could not checkpoint: ${err.message}`, true); }
        },
      }, 'Sign checkpoint'));
    renderFeed(d.feed, $('drawer-feed'), false);
    $('drawer').hidden = false;
  } catch (err) {
    toast(`Could not open session: ${err.message}`, true);
  }
}

function closeDrawer() {
  $('drawer').hidden = true;
  openSession = null;
}

async function setGlobal(pause) {
  if (pause) {
    const yes = await confirmBox({
      title: 'Pause every agent?',
      body: [el('p', {}, 'Every agent Provenant gates, in every harness, will be refused every action except reading until you resume. Running agents are not killed; they are told to stop and wait.')],
      ok: 'Pause all agents',
      okClass: 'danger',
    });
    if (!yes) return;
  }
  try {
    await api('POST', `control/${pause ? 'pause' : 'resume'}`);
    toast(pause ? 'All agents paused.' : 'All agents resumed.');
    refresh();
  } catch (err) {
    toast(`Could not ${pause ? 'pause' : 'resume'}: ${err.message}`, true);
  }
}

/* -------------------------------------------------------------- polling */

function setConn(state, text) {
  $('conn').dataset.state = state;
  $('conn-text').textContent = text;
}

async function refresh() {
  try {
    const s = await api('GET', 'state');
    render(s);
    setConn('live', `live · ${clock(s.now)}`);
  } catch (err) {
    setConn('down', err.message === 'the access token was rejected' ? 'token rejected' : 'dashboard unreachable');
  }
}

function showGate() {
  $('app').hidden = true;
  $('pause-all').hidden = true;
  $('no-token').hidden = false;
  clearInterval(timer);
  setConn('down', 'no access');
}

function start() {
  token = readToken();
  if (!token) return showGate();

  $('pause-all').addEventListener('click', () => setGlobal(true));
  $('resume-all').addEventListener('click', () => setGlobal(false));
  $('show-closed').addEventListener('change', () => last && renderSessions(last));
  for (const id of ['f-harness', 'f-effect', 'f-text']) {
    $(id).addEventListener('input', () => last && renderFeed(last.feed, $('feed'), true));
  }
  $('feed-freeze').addEventListener('click', (e) => {
    frozen = !frozen;
    e.currentTarget.setAttribute('aria-pressed', String(frozen));
    e.currentTarget.textContent = frozen ? 'Frozen' : 'Freeze';
    if (!frozen && last) renderFeed(last.feed, $('feed'), true);
  });
  document.querySelectorAll('#drawer [data-close]').forEach((n) => n.addEventListener('click', closeDrawer));
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('modal').hidden) document.querySelector('#modal [data-cancel]')?.click();
    else if (!$('drawer').hidden) closeDrawer();
  });

  refresh();
  timer = setInterval(refresh, POLL_MS);
}

start();
