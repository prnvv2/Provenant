import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync, statSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request } from 'node:http';

const HOME = mkdtempSync(join(tmpdir(), 'provenant-dash-'));
process.env.PROVENANT_HOME = HOME;
process.env.PROVENANT_POLICY = fileURLToPath(new URL('../policies/default.json', import.meta.url));
delete process.env.PROVENANT_HOOK_MODE;

const { initStore, readEnvelopes, loadSession } = await import('../src/store/store.js');
const { gateToolCall } = await import('../src/gate.js');
const { decodePayload } = await import('../src/core/dsse.js');
const { paths } = await import('../src/store/paths.js');
const { readControl } = await import('../src/control.js');
const { startDashboard } = await import('../src/dashboard/server.js');
const cline = await import('../src/adapters/cline.js');
const { main } = await import('../src/cli.js');

const TOKEN = 'test-token-0123456789abcdefghijklmnopqrstuv';
let dash;

before(async () => {
  initStore();
  dash = await startDashboard({ port: 0, token: TOKEN });
});
after(async () => {
  await dash.close();
});

/** Raw HTTP so tests can set Host and Origin, which fetch() forbids. */
function call(path, { method = 'GET', token = TOKEN, host, origin, body } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { Host: host ?? `127.0.0.1:${dash.port}` };
    if (token) headers['X-Provenant-Token'] = token;
    if (origin) headers.Origin = origin;
    const req = request({ host: '127.0.0.1', port: dash.port, path, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch {
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: data, json });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const codexAsk = (sid, command) =>
  gateToolCall({ harnessSessionId: sid, harness: 'codex', cwd: '/work/repo', askMode: 'approval', tool: 'Bash', input: { command } });

/* ================================================================ security */

test('dashboard: static assets load without a token, under a strict CSP', async () => {
  const r = await call('/', { token: null });
  assert.equal(r.status, 200);
  assert.match(r.text, /Provenant/);
  const csp = r.headers['content-security-policy'];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.equal(r.headers['referrer-policy'], 'no-referrer');

  for (const asset of ['/app.js', '/app.css']) {
    assert.equal((await call(asset, { token: null })).status, 200, asset);
  }
});

test('dashboard: the page contains no inline script or style', () => {
  const html = readFileSync(new URL('../src/dashboard/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, 'inline <script> would be blocked by the CSP');
  assert.doesNotMatch(html, /\sstyle=/i, 'inline style attributes would be blocked by the CSP');
  assert.doesNotMatch(html, /\son[a-z]+=/i, 'inline event handlers would be blocked by the CSP');
});

test('dashboard: the client never uses innerHTML, since agent text is hostile', () => {
  const js = readFileSync(new URL('../src/dashboard/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(js, /\.innerHTML\s*=|insertAdjacentHTML|document\.write/);
});

test('dashboard: the API refuses a missing or wrong token', async () => {
  assert.equal((await call('/api/state', { token: null })).status, 401);
  assert.equal((await call('/api/state', { token: 'wrong' })).status, 401);
  assert.equal((await call('/api/state', { token: `${TOKEN}x` })).status, 401);
  assert.equal((await call('/api/control/pause', { method: 'POST', token: null })).status, 401);
  assert.equal(readControl().paused, false, 'an unauthenticated pause must not take effect');
});

test('dashboard: a rebinding hostname is refused even with the token', async () => {
  const r = await call('/api/state', { host: `evil.example:${dash.port}` });
  assert.equal(r.status, 403);
  assert.match(r.json.error, /Host/);
});

test('dashboard: a cross-origin request is refused even with the token', async () => {
  const r = await call('/api/control/pause', { method: 'POST', origin: 'https://evil.example' });
  assert.equal(r.status, 403);
  assert.equal(readControl().paused, false);
  // same origin is fine
  const ok = await call('/api/state', { origin: `http://127.0.0.1:${dash.port}` });
  assert.equal(ok.status, 200);
});

test('dashboard: writes need POST, and oversized bodies are rejected', async () => {
  assert.equal((await call('/api/control/pause')).status, 404);
  assert.equal((await call('/api/state', { method: 'DELETE' })).status, 405);
  const big = await call('/api/control/resume', { method: 'POST', body: 'x'.repeat(10_000) }).catch(() => ({ status: 'reset' }));
  assert.ok(big.status === 500 || big.status === 'reset', `oversized body accepted: ${big.status}`);
});

test('dashboard: malformed ids are rejected before touching the store', async () => {
  assert.equal((await call('/api/approvals/../../etc/approve', { method: 'POST' })).status, 404);
  assert.equal((await call('/api/approvals/apr-XYZ/approve', { method: 'POST' })).status, 400);
  assert.equal((await call('/api/sessions/sess-000000000000/pause', { method: 'POST' })).status, 404);
  assert.equal((await call('/api/sessions/..%2F..%2Fconfig', {})).json.error, 'no such session');
});

test('dashboard: the token is only in memory, never written to the store', () => {
  const walk = (dir) => {
    for (const name of existsSync(dir) ? readdirSync(dir) : []) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else assert.equal(readFileSync(p, 'utf8').includes(TOKEN), false, `token found in ${p}`);
    }
  };
  walk(HOME);
});

/* ================================================================== reads */

test('dashboard: state reports every harness, sessions, and the live feed', async () => {
  codexAsk('dash-read', 'git push origin main');
  cline.handle('pre-tool', JSON.parse(readFileSync(new URL('./fixtures/cline/pre-tool-read-env.json', import.meta.url), 'utf8')));

  const s = (await call('/api/state')).json;
  assert.deepEqual(s.harnesses.slice(0, 4).map((h) => h.id), ['claude-code', 'codex', 'opencode', 'cline']);
  assert.ok(s.harnesses.find((h) => h.id === 'codex').pending >= 1);
  assert.ok(s.harnesses.find((h) => h.id === 'cline').sessions >= 1);
  assert.ok(s.sessions.some((x) => x.harness === 'cline'));
  assert.ok(s.feed.some((f) => f.harness === 'cline' && f.effect === 'deny' && f.class === 'secret.read'));
  assert.ok(s.approvals.some((a) => a.status === 'pending' && a.harness === 'codex'));
  assert.equal(s.control.paused, false);
  assert.equal(s.policy.name, 'provenant-default');
});

test('dashboard: a session detail returns its whole log, newest first', async () => {
  const asked = codexAsk('dash-detail', 'terraform apply');
  const d = (await call(`/api/sessions/${asked.session}`)).json;
  assert.equal(d.id, asked.session);
  assert.equal(d.harness, 'codex');
  assert.equal(d.feed[0].type, 'tool.ask');
  assert.equal(d.feed[d.feed.length - 1].type, 'session.start');
});

/* =============================================================== controls */

test('dashboard: approving from the dashboard lets the exact action run once', async () => {
  const asked = codexAsk('dash-approve', 'git push --force origin feature/y');
  const r = await call(`/api/approvals/${asked.approval}/approve`, { method: 'POST' });
  assert.equal(r.status, 200);

  const retry = codexAsk('dash-approve', 'git push --force origin feature/y');
  assert.equal(retry.effect, 'allow');
  assert.equal(codexAsk('dash-approve', 'git push --force origin feature/y').effect, 'ask', 'single use');

  const approval = readEnvelopes(asked.session).map(decodePayload).find((b) => b.type === 'approval');
  assert.equal(approval.context.method, 'dashboard');
});

test('dashboard: denying makes the identical retry fail with the human reason', async () => {
  const asked = codexAsk('dash-deny', 'kubectl apply -f prod.yaml');
  assert.equal((await call(`/api/approvals/${asked.approval}/deny`, { method: 'POST' })).status, 200);

  const retry = codexAsk('dash-deny', 'kubectl apply -f prod.yaml');
  assert.equal(retry.effect, 'deny');
  assert.match(retry.reason, /A human denied this exact action/);

  const s = (await call('/api/state')).json;
  assert.equal(s.approvals.find((a) => a.id === asked.approval).status, 'denied');
});

test('dashboard: pausing a session refuses everything but reads, until resumed', async () => {
  const common = { harnessSessionId: 'dash-pause', harness: 'opencode', cwd: '/work/repo', askMode: 'approval' };
  const first = gateToolCall({ ...common, tool: 'bash', input: { command: 'npm test' } });
  assert.equal(first.effect, 'allow');

  assert.equal((await call(`/api/sessions/${first.session}/pause`, { method: 'POST' })).status, 200);
  const blocked = gateToolCall({ ...common, tool: 'bash', input: { command: 'npm test' } });
  assert.equal(blocked.effect, 'deny');
  assert.equal(blocked.policy, 'paused-session');
  assert.equal(gateToolCall({ ...common, tool: 'read', input: { filePath: '/work/repo/a.ts' } }).effect, 'allow', 'reads still allowed');

  // other sessions are unaffected
  assert.equal(
    gateToolCall({ harnessSessionId: 'dash-other', harness: 'codex', cwd: '/work/repo', tool: 'Bash', input: { command: 'npm test' } }).effect,
    'allow',
  );

  assert.equal((await call(`/api/sessions/${first.session}/resume`, { method: 'POST' })).status, 200);
  assert.equal(gateToolCall({ ...common, tool: 'bash', input: { command: 'npm test' } }).effect, 'allow');

  const controls = readEnvelopes(first.session).map(decodePayload).filter((b) => b.type === 'control');
  assert.deepEqual(controls.map((c) => c.context.action), ['pause', 'resume']);
  assert.ok(controls.every((c) => c.context.by === 'dashboard'));
});

test('dashboard: pausing all agents applies across every harness and is signed', async () => {
  assert.equal((await call('/api/control/pause', { method: 'POST' })).status, 200);
  try {
    for (const [harness, tool, input] of [
      ['claude-code', 'Bash', { command: 'npm test' }],
      ['codex', 'Bash', { command: 'npm test' }],
      ['opencode', 'bash', { command: 'npm test' }],
      ['cline', 'execute_command', { command: 'npm test' }],
    ]) {
      const d = gateToolCall({ harnessSessionId: `global-${harness}`, harness, cwd: '/work/repo', tool, input });
      assert.equal(d.effect, 'deny', harness);
      assert.equal(d.policy, 'paused-global', harness);
    }
    const log = readFileSync(paths.controlLog(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const lastLine = log[log.length - 1];
    assert.equal(lastLine.type, 'pause');
    assert.equal(lastLine.by, 'dashboard');
    assert.match(lastLine.sig, /^[A-Za-z0-9+/=]{80,}$/);
  } finally {
    assert.equal((await call('/api/control/resume', { method: 'POST' })).status, 200);
  }
  assert.equal(readControl().paused, false);
});

test('dashboard: verify and checkpoint work per session', async () => {
  const asked = codexAsk('dash-verify', 'git push origin main');
  const cp = await call(`/api/sessions/${asked.session}/checkpoint`, { method: 'POST' });
  assert.equal(cp.status, 200);
  const v = (await call(`/api/sessions/${asked.session}/verify`, { method: 'POST' })).json;
  assert.equal(v.ok, true);
  assert.ok(v.events >= 2);
});

/* ================================================================== CLI */

function captureIo() {
  const out = [];
  const err = [];
  return {
    io: { out: (s) => out.push(s), err: (s) => err.push(s), stdin: () => '', isTTY: () => false, prompt: async () => '' },
    get stdout() { return out.join('\n'); },
    get stderr() { return err.join('\n'); },
  };
}

test('cli pause and resume, globally and per session', async () => {
  const cap = captureIo();
  assert.equal(await main(['pause'], cap.io), 0);
  assert.equal(readControl().paused, true);
  assert.equal(await main(['resume'], cap.io), 0);
  assert.equal(readControl().paused, false);

  const d = codexAsk('cli-pause', 'npm test');
  const cap2 = captureIo();
  assert.equal(await main(['pause', '--session', d.session], cap2.io), 0);
  assert.equal(loadSession(d.session).paused, true);
  assert.equal(await main(['resume', '--session', d.session], cap2.io), 0);
  assert.equal(loadSession(d.session).paused, false);
});

test('an unreadable control file fails closed', () => {
  writeFileSync(paths.control(), '{ not json');
  try {
    assert.equal(readControl().paused, true);
    const d = gateToolCall({ harnessSessionId: 'corrupt-control', harness: 'codex', cwd: '/work/repo', tool: 'Bash', input: { command: 'npm test' } });
    assert.equal(d.effect, 'deny');
  } finally {
    writeFileSync(paths.control(), JSON.stringify({ paused: false }));
  }
});

/* =================================================================== Cline */

const clineFixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/cline/${name}.json`, import.meta.url), 'utf8'));

test('cline: nested payloads normalise to the gate\'s shape', () => {
  const n = cline.normalize(clineFixture('pre-tool-execute-push'));
  assert.equal(n.harnessSessionId, 'cline-task-001');
  assert.equal(n.cwd, '/work/repo');
  assert.equal(n.tool, 'execute_command');
  assert.equal(n.input.command, 'git push origin main');
});

test('cline: allow proceeds, deny cancels with the reason, ask cancels with an approval id', () => {
  cline.handle('task-start', clineFixture('task-start'));
  assert.deepEqual(cline.handle('pre-tool', clineFixture('pre-tool-write')).stdout, { cancel: false });

  const env = cline.handle('pre-tool', clineFixture('pre-tool-read-env')).stdout;
  assert.equal(env.cancel, true);
  assert.match(env.errorMessage, /secret\.read/);
  assert.equal(env.contextModification, env.errorMessage);

  cline.handle('post-tool', clineFixture('post-tool-fetch'));
  const push = cline.handle('pre-tool', clineFixture('pre-tool-execute-push')).stdout;
  assert.equal(push.cancel, true);
  assert.match(push.errorMessage, /provenant approve apr-[0-9a-f]{10}/);

  const done = cline.handle('task-complete', clineFixture('task-complete'));
  assert.deepEqual(done.stdout, { cancel: false });
});

test('cline: the CLI fails closed with a cancel when the payload is unreadable', async () => {
  const out = [];
  const code = await main(['hook', 'cline', 'pre-tool'], {
    out: (s) => out.push(s), err: () => {}, stdin: () => '{ broken', isTTY: () => false, prompt: async () => '',
  });
  assert.equal(code, 0);
  const r = JSON.parse(out.join(''));
  assert.equal(r.cancel, true);
  assert.match(r.errorMessage, /unreadable hook payload/);
});

test('cline: init writes one executable per hook and never overwrites foreign ones', async () => {
  const repo = mkdtempSync(join(tmpdir(), 'provenant-cline-'));
  const before = process.cwd();
  process.chdir(repo);
  try {
    const cap = captureIo();
    assert.equal(await main(['init', '--harness', 'cline'], cap.io), 0);
    const dir = join(repo, '.clinerules', 'hooks');
    for (const [file, event] of Object.entries(cline.HOOK_FILES)) {
      const src = readFileSync(join(dir, file), 'utf8');
      assert.match(src, /^#!\/bin\/sh/);
      assert.ok(src.includes(`hook cline ${event}`), file);
      assert.ok(src.includes(process.execPath.replace(/'/g, `'\\''`)), 'absolute node path');
      if (process.platform !== 'win32') assert.ok(statSync(join(dir, file)).mode & 0o111, `${file} executable`);
    }
    const again = captureIo();
    await main(['init', '--harness', 'cline'], again.io);
    assert.match(again.stdout, /already current/);

    // a user's own PreToolUse is left alone, and init reports Cline as NOT gated
    const repo2 = mkdtempSync(join(tmpdir(), 'provenant-cline2-'));
    process.chdir(repo2);
    mkdirSync(join(repo2, '.clinerules', 'hooks'), { recursive: true });
    writeFileSync(join(repo2, '.clinerules', 'hooks', 'PreToolUse'), '#!/bin/sh\necho "{\\"cancel\\":false}"\n');
    const foreign = captureIo();
    assert.equal(await main(['init', '--harness', 'cline'], foreign.io), 1);
    assert.match(foreign.stderr, /NOT gated/);
    assert.match(readFileSync(join(repo2, '.clinerules', 'hooks', 'PreToolUse'), 'utf8'), /cancel/);
  } finally {
    process.chdir(before);
  }
});

test('cline: the generated hook script runs and answers Cline', { skip: process.platform === 'win32' && 'needs /bin/sh' }, async () => {
  const { spawnSync } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'provenant-clinehook-'));
  const file = join(dir, 'PreToolUse');
  const bin = fileURLToPath(new URL('../bin/provenant.js', import.meta.url));
  writeFileSync(file, cline.hookScript({ node: process.execPath, bin, event: 'pre-tool' }), { mode: 0o755 });
  const r = spawnSync(file, [], {
    input: JSON.stringify(clineFixture('pre-tool-read-env')),
    env: process.env,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).cancel, true);
});
