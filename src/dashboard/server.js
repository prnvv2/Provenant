/**
 * Local dashboard: monitor and control every agent Provenant gates.
 *
 * This server can approve actions and pause agents, so it is attack surface
 * aimed at the very thing Provenant defends against — an agent running as the
 * user. Every layer below assumes the agent can reach it:
 *
 *   loopback only       binds 127.0.0.1; there is no option to bind elsewhere
 *   bearer token        256-bit, generated per run, held only in this
 *                       process's memory and handed to the browser in the URL
 *                       fragment (never sent to the server, never logged);
 *                       every /api request must present it, compared in
 *                       constant time
 *   DNS rebinding       the Host header must name this loopback address, so a
 *                       hostile page cannot reach the API through a
 *                       rebinding hostname
 *   CSRF                writes are POST with a custom header, which a
 *                       cross-origin page cannot send without a preflight
 *                       this server never approves; Origin, when present,
 *                       must be this server
 *   XSS                 the UI builds the DOM with textContent only — agent
 *                       commands are attacker-controlled strings — and a strict
 *                       CSP forbids inline script and every other origin
 *   classifier          `provenant dashboard` and requests to the default
 *                       port from an agent's tools are denied as policy edits
 *
 * No framework and no dependencies: node:http plus three static files.
 */

import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { listSessions, readEnvelopes, verifySession, writeCheckpoint, loadConfig } from '../store/store.js';
import { paths } from '../store/paths.js';
import { decodePayload } from '../core/dsse.js';
import { loadPolicy } from '../policy/engine.js';
import { listApprovals, approveAction, denyAction } from '../gate.js';
import { readControl, setGlobalPause, setSessionPause } from '../control.js';

const STATIC = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/app.css': { file: 'app.css', type: 'text/css; charset=utf-8' },
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

const HARNESS_ORDER = ['claude-code', 'codex', 'opencode', 'cline'];
const FEED_LIMIT = 250;
const MAX_BODY = 4096;

/**
 * @param {{port?: number, token?: string}} [opts] port 0 picks a free port
 * @returns {Promise<{server: import('node:http').Server, port: number, origin: string, url: string, token: string, close: () => Promise<void>}>}
 */
export async function startDashboard({ port = 7717, token = randomBytes(32).toString('base64url') } = {}) {
  const tokenBuf = Buffer.from(token);
  const cache = new Map();
  let actualPort = port;

  const allowedHosts = () => new Set([`127.0.0.1:${actualPort}`, `localhost:${actualPort}`]);
  const allowedOrigins = () => new Set([`http://127.0.0.1:${actualPort}`, `http://localhost:${actualPort}`]);

  const server = createServer(async (req, res) => {
    try {
      await handle(req, res);
    } catch (err) {
      send(res, 500, { error: String(err?.message ?? err) });
    }
  });

  async function handle(req, res) {
    // DNS rebinding: a hostile hostname resolving to 127.0.0.1 still carries
    // its own name in Host.
    if (!allowedHosts().has(String(req.headers.host ?? '').toLowerCase())) {
      return send(res, 403, { error: 'unexpected Host header' });
    }
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins().has(origin)) {
      return send(res, 403, { error: 'cross-origin request refused' });
    }

    const url = new URL(req.url, `http://127.0.0.1:${actualPort}`);

    if (!url.pathname.startsWith('/api/')) {
      const asset = STATIC[url.pathname];
      if (!asset || req.method !== 'GET') return send(res, 404, { error: 'not found' });
      const body = readFileSync(fileURLToPath(new URL(`./${asset.file}`, import.meta.url)));
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': asset.type });
      return res.end(body);
    }

    if (!authorised(req)) return send(res, 401, { error: 'missing or wrong token' });

    const parts = url.pathname.split('/').filter(Boolean).slice(1); // drop "api"

    if (req.method === 'GET') {
      if (parts[0] === 'state' && parts.length === 1) return send(res, 200, state());
      if (parts[0] === 'sessions' && parts.length === 2) return send(res, 200, sessionDetail(parts[1]));
      return send(res, 404, { error: 'not found' });
    }

    if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
    await readBody(req); // bounded; no endpoint needs a body today

    // POST /api/approvals/:id/(approve|deny)
    if (parts[0] === 'approvals' && parts.length === 3) {
      const id = parts[1];
      if (!/^apr-[0-9a-f]{10}$/.test(id)) return send(res, 400, { error: 'bad approval id' });
      if (parts[2] === 'approve') return send(res, 200, approveAction(id, { method: 'dashboard' }));
      if (parts[2] === 'deny') return send(res, 200, denyAction(id, { method: 'dashboard' }));
    }

    // POST /api/sessions/:id/(pause|resume|verify|checkpoint)
    if (parts[0] === 'sessions' && parts.length === 3) {
      const id = parts[1];
      if (!knownSession(id)) return send(res, 404, { error: 'no such session' });
      switch (parts[2]) {
        case 'pause':
          return send(res, 200, setSessionPause(id, true, { by: 'dashboard' }));
        case 'resume':
          return send(res, 200, setSessionPause(id, false, { by: 'dashboard' }));
        case 'verify': {
          const r = verifySession(id);
          return send(res, 200, { ok: r.ok, events: r.events, root: r.root, checks: r.checks, failures: r.failures });
        }
        case 'checkpoint':
          return send(res, 200, writeCheckpoint(id));
        default:
          break;
      }
    }

    // POST /api/control/(pause|resume) — every agent at once
    if (parts[0] === 'control' && parts.length === 2 && (parts[1] === 'pause' || parts[1] === 'resume')) {
      return send(res, 200, setGlobalPause(parts[1] === 'pause', { by: 'dashboard' }));
    }

    return send(res, 404, { error: 'not found' });
  }

  function authorised(req) {
    const given = Buffer.from(String(req.headers['x-provenant-token'] ?? ''));
    return given.length === tokenBuf.length && timingSafeEqual(given, tokenBuf);
  }

  /* ---------------------------------------------------------------- reads */

  /** Decoded events for a session, re-read only when its log file changes. */
  function eventsOf(id) {
    const file = paths.events(id);
    if (!existsSync(file)) return [];
    const st = statSync(file);
    const hit = cache.get(id);
    if (hit && hit.size === st.size && hit.mtimeMs === st.mtimeMs) return hit.events;
    const events = readEnvelopes(id).map((e) => {
      try {
        return decodePayload(e);
      } catch {
        return null;
      }
    }).filter(Boolean);
    cache.set(id, { size: st.size, mtimeMs: st.mtimeMs, events });
    return events;
  }

  function knownSession(id) {
    return /^sess-[0-9a-f]{12}$/.test(id) && listSessions().some((s) => s.session === id);
  }

  function summarise(s) {
    const events = eventsOf(s.session);
    const start = events.find((e) => e.type === 'session.start');
    const last = events[events.length - 1];
    return {
      id: s.session,
      harness: start?.context?.harness ?? 'unknown',
      cwd: start?.context?.cwd ?? null,
      model: start?.context?.model ?? null,
      startedAt: s.startedAt,
      endedAt: s.endedAt ?? null,
      lastAt: last?.ts ?? s.startedAt,
      events: events.length,
      taint: s.taint,
      counts: { allow: s.counts?.allow ?? 0, ask: s.counts?.ask ?? 0, deny: s.counts?.deny ?? 0 },
      paused: Boolean(s.paused),
      pending: Object.values(s.approvals ?? {}).filter((a) => a.status === 'pending').length,
    };
  }

  function state() {
    const sessions = listSessions().map(summarise);
    const byId = new Map(sessions.map((s) => [s.id, s]));

    const feed = [];
    for (const s of sessions) {
      for (const e of eventsOf(s.id).slice(-FEED_LIMIT)) feed.push(feedItem(e, s.harness));
    }
    feed.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));

    const approvals = listApprovals({ includeResolved: true })
      .map((a) => ({ ...a, harness: byId.get(a.session)?.harness ?? 'unknown' }))
      .slice(0, 50);

    const dayAgo = Date.now() - 24 * 3600 * 1000;
    const harnesses = HARNESS_ORDER.concat(
      [...new Set(sessions.map((s) => s.harness))].filter((h) => !HARNESS_ORDER.includes(h)),
    ).map((h) => {
      const mine = sessions.filter((s) => s.harness === h);
      const recent = feed.filter((f) => f.harness === h && Date.parse(f.ts) >= dayAgo);
      return {
        id: h,
        sessions: mine.length,
        active: mine.filter((s) => !s.endedAt).length,
        paused: mine.filter((s) => s.paused && !s.endedAt).length,
        pending: mine.reduce((n, s) => n + s.pending, 0),
        lastAt: mine.map((s) => s.lastAt).sort().pop() ?? null,
        day: {
          allow: recent.filter((f) => f.effect === 'allow').length,
          ask: recent.filter((f) => f.effect === 'ask').length,
          deny: recent.filter((f) => f.effect === 'deny').length,
        },
      };
    });

    let policy = null;
    try {
      const p = loadPolicy();
      policy = { name: p.policy.name, digest: p.digest, rules: p.policy.rules.length, source: p.source };
    } catch (err) {
      policy = { error: err.message };
    }

    return {
      now: new Date().toISOString(),
      machine: loadConfig().machine,
      control: readControl(),
      policy,
      harnesses,
      sessions: sessions.sort((a, b) => String(b.lastAt).localeCompare(String(a.lastAt))),
      approvals,
      feed: feed.slice(0, FEED_LIMIT),
    };
  }

  function sessionDetail(id) {
    if (!knownSession(id)) return { error: 'no such session' };
    const s = listSessions().find((x) => x.session === id);
    const summary = summarise(s);
    return { ...summary, feed: eventsOf(id).map((e) => feedItem(e, summary.harness)).reverse() };
  }

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  actualPort = server.address().port;

  const origin = `http://127.0.0.1:${actualPort}`;
  return {
    server,
    port: actualPort,
    origin,
    // The token rides in the fragment: browsers never send it to the server or
    // in a Referer, and the page moves it out of the address bar on load.
    url: `${origin}/#t=${token}`,
    token,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** The fields the UI needs from one event, and nothing else. */
function feedItem(e, harness) {
  return {
    ts: e.ts,
    session: e.session,
    seq: e.seq,
    harness,
    type: e.type,
    effect: e.decision?.effect ?? null,
    class: e.action?.class ?? e.context?.label ?? null,
    tool: e.action?.tool ?? null,
    resource: e.action?.resource ?? e.context?.action ?? e.context?.reason ?? null,
    redacted: Boolean(e.action?.redacted),
    reason: e.decision?.reason ?? null,
    policy: e.decision?.policy ?? null,
    approval: e.decision?.approval ?? null,
    taint: e.taint ?? null,
  };
}

function send(res, status, body) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
