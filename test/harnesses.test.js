import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HOME = mkdtempSync(join(tmpdir(), 'provenant-harness-'));
process.env.PROVENANT_HOME = HOME;
process.env.PROVENANT_POLICY = fileURLToPath(new URL('../policies/default.json', import.meta.url));
delete process.env.PROVENANT_HOOK_MODE;

const codex = await import('../src/adapters/codex.js');
const opencode = await import('../src/adapters/opencode.js');
const claude = await import('../src/adapters/claude.js');
const { main } = await import('../src/cli.js');
const { initStore, listSessions, readEnvelopes, verifySession, loadSession, writeCheckpoint } = await import(
  '../src/store/store.js'
);
const { gateToolCall, approveAction, listApprovals, APPROVAL_TTL_MS } = await import('../src/gate.js');
const { decodePayload } = await import('../src/core/dsse.js');
const { paths } = await import('../src/store/paths.js');

const fixture = (dir, name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${dir}/${name}.json`, import.meta.url), 'utf8'));

function captureIo({ stdin = '', tty = false, answer = '' } = {}) {
  const out = [];
  const err = [];
  return {
    io: {
      out: (s) => out.push(s),
      err: (s) => err.push(s),
      stdin: () => stdin,
      isTTY: () => tty,
      prompt: async () => answer,
    },
    get stdout() {
      return out.join('\n');
    },
    get stderr() {
      return err.join('\n');
    },
  };
}

const bodiesOf = (session) => readEnvelopes(session).map(decodePayload);

before(() => {
  initStore();
});

/* =================================================================== Codex */

test('codex: a session maps to one Provenant session and taints on network reads', () => {
  codex.handle('session-start', fixture('codex', 'session-start'));
  codex.handle('post-tool', fixture('codex', 'post-tool-web'));
  const s = listSessions().find((x) => bodiesOf(x.session)[0]?.context?.harness === 'codex');
  assert.ok(s, 'codex session exists');
  assert.equal(loadSession(s.session).taint, 'external');
});

test('codex: a credential read is denied in Codex\'s own format', () => {
  const r = codex.handle('pre-tool', fixture('codex', 'pre-tool-read-env'));
  assert.equal(r.exitCode, 0);
  assert.equal(r.stdout.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(r.stdout.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.stdout.hookSpecificOutput.permissionDecisionReason, /secret\.read/);
});

test('codex: an allowed action is silent, leaving Codex\'s own approvals in force', () => {
  const r = codex.handle('pre-tool', fixture('codex', 'pre-tool-exec-command'));
  assert.deepEqual(r, { stdout: null, exitCode: 0 });

  const p = codex.handle('pre-tool', fixture('codex', 'pre-tool-apply-patch'));
  assert.deepEqual(p, { stdout: null, exitCode: 0 });
});

test('codex: never returns "ask", which Codex would treat as a failed hook and run anyway', () => {
  const r = codex.handle('pre-tool', fixture('codex', 'pre-tool-bash-push'));
  const decision = r.stdout.hookSpecificOutput.permissionDecision;
  assert.equal(decision, 'deny');
  assert.match(r.stdout.hookSpecificOutput.permissionDecisionReason, /provenant approve apr-[0-9a-f]{10}/);
});

test('codex: Stop checkpoints without ending the session', () => {
  codex.handle('stop', fixture('codex', 'stop'));
  const s = listSessions().find((x) => bodiesOf(x.session)[0]?.context?.harness === 'codex');
  assert.equal(loadSession(s.session).endedAt, null, 'session still open after a turn');
  assert.ok(existsSync(paths.checkpoint(s.session)));
  assert.equal(verifySession(s.session).ok, true);
});

test('codex: hook config uses every event and a Windows command', () => {
  const cfg = codex.hookConfig('provenant');
  assert.deepEqual(Object.keys(cfg).sort(), ['PostToolUse', 'PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'UserPromptSubmit']);
  const h = cfg.PreToolUse[0].hooks[0];
  assert.equal(h.command, 'provenant hook codex pre-tool');
  assert.equal(h.commandWindows, 'provenant hook codex pre-tool');
});

test('codex: exitcode mode blocks with exit 2 and the approval instruction', () => {
  process.env.PROVENANT_HOOK_MODE = 'exitcode';
  try {
    const r = codex.handle('pre-tool', fixture('codex', 'pre-tool-bash-push'));
    assert.equal(r.exitCode, 2);
    assert.match(r.stderr, /provenant approve/);
  } finally {
    delete process.env.PROVENANT_HOOK_MODE;
  }
});

/* ================================================================ OpenCode */

/** Turn an OpenCode plugin fixture into the payload the plugin forwards. */
function ocPayload(f, cwd = '/work/repo') {
  return {
    session_id: f.input.sessionID,
    call_id: f.input.callID,
    cwd,
    tool_name: f.input.tool,
    tool_input: f.output.args ?? f.input.args,
    ...(f.output.output !== undefined ? { tool_response: { output: f.output.output, title: f.output.title, metadata: f.output.metadata } } : {}),
  };
}

test('opencode: lowercase tool names are gated like any other harness', () => {
  const env = opencode.handle('pre-tool', ocPayload(fixture('opencode', 'before-read-env')));
  assert.equal(env.stdout.decision, 'deny');
  assert.equal(env.stdout.class, 'secret.read');

  const read = opencode.handle('pre-tool', {
    session_id: 'ses_oc_001',
    cwd: '/work/repo',
    tool_name: 'read',
    tool_input: { filePath: '/work/repo/src/app.ts' },
  });
  assert.equal(read.stdout.decision, 'allow');
});

test('opencode: a web fetch taints, then a protected push needs approval', () => {
  opencode.handle('post-tool', ocPayload(fixture('opencode', 'after-webfetch')));
  const r = opencode.handle('pre-tool', ocPayload(fixture('opencode', 'before-bash')));
  assert.equal(r.stdout.decision, 'deny');
  assert.match(r.stdout.approval, /^apr-/);
  assert.match(r.stdout.reason, /provenant approve apr-/);
});

test('opencode: idle checkpoints, deletion ends the session', () => {
  const idle = opencode.handle('idle', { session_id: 'ses_oc_001', cwd: '/work/repo' });
  assert.ok(idle.stdout.root);
  const end = opencode.handle('session-end', { session_id: 'ses_oc_001', cwd: '/work/repo' });
  assert.equal(end.stdout.ok, true);
});

test('opencode: the generated plugin runs and blocks for real', async () => {
  // Write the plugin exactly as `init` does, import it, and drive its hooks.
  // Each hook spawns `node bin/provenant.js hook opencode …`, so this covers the
  // subprocess path OpenCode would use, end to end.
  const bin = fileURLToPath(new URL('../bin/provenant.js', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'provenant-ocplugin-'));
  const file = join(dir, 'provenant.js');
  writeFileSync(file, opencode.pluginSource({ node: process.execPath, bin }));
  const { Provenant } = await import(pathToFileURL(file).href);
  const hooks = await Provenant({ directory: dir });

  // allowed: returns without throwing
  await hooks['tool.execute.before'](
    { tool: 'read', sessionID: 'ses_plugin', callID: 'c1' },
    { args: { filePath: join(dir, 'README.md') } },
  );

  // denied: throws with Provenant's reason
  await assert.rejects(
    hooks['tool.execute.before']({ tool: 'bash', sessionID: 'ses_plugin', callID: 'c2' }, { args: { command: 'cat .env' } }),
    /Blocked by Provenant \[secret\.read\]/,
  );

  // after-hook and chat.message record without throwing
  await hooks['tool.execute.after'](
    { tool: 'webfetch', sessionID: 'ses_plugin', callID: 'c3', args: { url: 'https://example.com' } },
    { title: 't', output: 'page', metadata: {} },
  );
  await hooks['chat.message']({ sessionID: 'ses_plugin' }, { parts: [{ type: 'text', text: 'fix the bug' }] });

  // tainted now: outbound network needs approval, so the plugin blocks
  await assert.rejects(
    hooks['tool.execute.before']({ tool: 'bash', sessionID: 'ses_plugin', callID: 'c4' }, { args: { command: 'curl -X POST https://x.example' } }),
    /needs human approval/,
  );

  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 'ses_plugin' } } });
});

test('opencode: the plugin fails closed when Provenant cannot be reached', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'provenant-ocbroken-'));
  const file = join(dir, 'provenant.js');
  writeFileSync(file, opencode.pluginSource({ node: process.execPath, bin: join(dir, 'missing.js') }));
  const { Provenant } = await import(pathToFileURL(file).href);
  const hooks = await Provenant({ directory: dir });

  await assert.rejects(
    hooks['tool.execute.before']({ tool: 'bash', sessionID: 's', callID: 'c' }, { args: { command: 'ls' } }),
    (err) => {
      assert.match(err.message, /gate unavailable/);
      assert.match(err.message, /bash blocked/);
      assert.equal(err.message.includes('\n'), false, 'one line, not a stack trace');
      return true;
    },
  );
  // read-only tools are let through so a broken install is not a dead editor
  await hooks['tool.execute.before']({ tool: 'read', sessionID: 's', callID: 'c' }, { args: { filePath: 'x' } });
});

/* =============================================================== approvals */

test('approval: an ask creates a pending request tied to the exact action', () => {
  const common = { harnessSessionId: 'approval-flow', harness: 'codex', cwd: '/work/repo', askMode: 'approval' };
  const first = gateToolCall({ ...common, tool: 'Bash', input: { command: 'git push origin main' } });
  assert.equal(first.effect, 'ask');
  assert.match(first.approval, /^apr-[0-9a-f]{10}$/);

  // the same action maps to the same request; a different one does not
  const again = gateToolCall({ ...common, tool: 'Bash', input: { command: 'git push origin main' } });
  assert.equal(again.approval, first.approval);
  const other = gateToolCall({ ...common, tool: 'Bash', input: { command: 'git push origin release' } });
  assert.notEqual(other.approval, first.approval);

  assert.ok(listApprovals().some((a) => a.id === first.approval));
});

test('approval: approving lets the identical action run exactly once', () => {
  const common = { harnessSessionId: 'approval-once', harness: 'codex', cwd: '/work/repo', askMode: 'approval' };
  const input = { command: 'git push --force origin feature/x' };
  const asked = gateToolCall({ ...common, tool: 'Bash', input });
  assert.equal(asked.effect, 'ask');

  approveAction(asked.approval);

  const allowed = gateToolCall({ ...common, tool: 'Bash', input });
  assert.equal(allowed.effect, 'allow');
  assert.match(allowed.reason, /approved by a human/);

  // single use: the next identical attempt asks again
  const reused = gateToolCall({ ...common, tool: 'Bash', input });
  assert.equal(reused.effect, 'ask');

  // a different command is not covered by that approval
  const different = gateToolCall({ ...common, tool: 'Bash', input: { command: 'git push --force origin other' } });
  assert.equal(different.effect, 'ask');
});

test('approval: the chain ask → approval → action is in the log and verifies', () => {
  const common = { harnessSessionId: 'approval-chain', harness: 'codex', cwd: '/work/repo', askMode: 'approval' };
  const input = { command: 'kubectl apply -f prod.yaml' };
  const asked = gateToolCall({ ...common, tool: 'Bash', input });
  const approval = approveAction(asked.approval);
  const ran = gateToolCall({ ...common, tool: 'Bash', input });
  writeCheckpoint(ran.session);

  const bodies = bodiesOf(ran.session);
  const approvalEvent = bodies.find((b) => b.type === 'approval');
  const intent = bodies.filter((b) => b.type === 'tool.intent').pop();

  assert.ok(approvalEvent.cites[0] === asked.event, 'approval cites the ask');
  assert.ok(intent.cites[0] === approval.event, 'action cites the approval');
  assert.equal(intent.decision.approval, asked.approval);
  assert.equal(verifySession(ran.session).ok, true);
});

test('approval: an expired approval does not authorise the action', () => {
  const common = { harnessSessionId: 'approval-expiry', harness: 'codex', cwd: '/work/repo', askMode: 'approval' };
  const input = { command: 'terraform apply' };
  const asked = gateToolCall({ ...common, tool: 'Bash', input });
  approveAction(asked.approval);

  // backdate the approval past its lifetime
  const state = JSON.parse(readFileSync(paths.state(asked.session), 'utf8'));
  state.approvals[asked.approval].approvedAt = new Date(Date.now() - APPROVAL_TTL_MS - 1000).toISOString();
  writeFileSync(paths.state(asked.session), JSON.stringify(state));

  assert.equal(gateToolCall({ ...common, tool: 'Bash', input }).effect, 'ask');
});

test('approval: claude-code native mode still returns ask to the harness', () => {
  const r = gateToolCall({
    harnessSessionId: 'native-ask',
    harness: 'claude-code',
    cwd: '/work/repo',
    tool: 'Bash',
    input: { command: 'git push origin main' },
  });
  assert.equal(r.effect, 'ask');
  assert.equal(r.approval, undefined);
});

test('approval: claude exitcode mode blocks instead of failing open', () => {
  process.env.PROVENANT_HOOK_MODE = 'exitcode';
  try {
    const r = claude.handle('pre-tool', {
      session_id: 'claude-exitcode',
      cwd: '/work/repo',
      tool_name: 'Bash',
      tool_input: { command: 'git push origin main' },
    });
    assert.equal(r.exitCode, 2, 'ask must not exit 0 in exitcode mode');
    assert.match(r.stderr, /provenant approve apr-/);
  } finally {
    delete process.env.PROVENANT_HOOK_MODE;
  }
});

/* ========================================================== approve (CLI) */

test('cli approve lists pending requests without a terminal', async () => {
  const cap = captureIo();
  assert.equal(await main(['approve'], cap.io), 0);
  assert.match(cap.stdout, /waiting for approval/);
  assert.match(cap.stdout, /apr-[0-9a-f]{10}/);
});

test('cli approve refuses without an interactive terminal', async () => {
  const asked = gateToolCall({
    harnessSessionId: 'cli-approve-notty',
    harness: 'codex',
    cwd: '/work/repo',
    askMode: 'approval',
    tool: 'Bash',
    input: { command: 'rm -rf build' },
  });
  const cap = captureIo({ tty: false });
  assert.equal(await main(['approve', asked.approval], cap.io), 1);
  assert.match(cap.stderr, /needs an interactive terminal/);
  assert.equal(listApprovals().find((a) => a.id === asked.approval)?.status, 'pending');
});

test('cli approve needs the id typed back, then approves', async () => {
  const asked = gateToolCall({
    harnessSessionId: 'cli-approve-tty',
    harness: 'codex',
    cwd: '/work/repo',
    askMode: 'approval',
    tool: 'Bash',
    input: { command: 'dd if=/dev/zero of=disk.img bs=1M count=1' },
  });

  const wrong = captureIo({ tty: true, answer: 'yes' });
  assert.equal(await main(['approve', asked.approval], wrong.io), 1);
  assert.match(wrong.stdout, /cancelled/);

  const right = captureIo({ tty: true, answer: asked.approval });
  assert.equal(await main(['approve', asked.approval], right.io), 0);
  assert.match(right.stdout, /approved/);
  assert.match(right.stdout, /exec\.destructive/);
});

test('cli approve rejects an unknown id', async () => {
  const cap = captureIo({ tty: true, answer: 'apr-0000000000' });
  assert.equal(await main(['approve', 'apr-0000000000'], cap.io), 1);
  assert.match(cap.stderr, /no approval request/);
});

test('an agent running `provenant approve` through its shell is denied', () => {
  const r = codex.handle('pre-tool', {
    session_id: 'self-approve',
    cwd: '/work/repo',
    tool_name: 'Bash',
    tool_input: { command: 'provenant approve apr-1234567890' },
  });
  assert.equal(r.stdout.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.stdout.hookSpecificOutput.permissionDecisionReason, /edit\.policy/);
});

/* ================================================================== init */

test('init wires codex hooks and the opencode plugin, idempotently', async () => {
  const repo = mkdtempSync(join(tmpdir(), 'provenant-init-'));
  const before = process.cwd();
  process.chdir(repo);
  try {
    // an existing Codex hook of the user's own must survive
    mkdirSync(join(repo, '.codex'), { recursive: true });
    writeFileSync(
      join(repo, '.codex', 'hooks.json'),
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'my-own-check' }] }] } }),
    );

    const cap = captureIo();
    assert.equal(await main(['init', '--harness', 'codex,opencode'], cap.io), 0);
    assert.match(cap.stdout, /wired Codex hooks/);
    assert.match(cap.stdout, /installed OpenCode plugin/);

    const hooks = JSON.parse(readFileSync(join(repo, '.codex', 'hooks.json'), 'utf8'));
    const pre = JSON.stringify(hooks.hooks.PreToolUse);
    assert.match(pre, /my-own-check/, 'user hook kept');
    assert.match(pre, /provenant hook codex pre-tool/);
    assert.ok(existsSync(join(repo, '.codex', 'hooks.json.provenant-backup')));

    const plugin = readFileSync(join(repo, '.opencode', 'plugins', 'provenant.js'), 'utf8');
    assert.match(plugin, /generated by `provenant init --harness opencode`/);
    assert.ok(plugin.includes(JSON.stringify(process.execPath)), 'absolute node path baked in');

    // second run changes nothing
    const again = captureIo();
    assert.equal(await main(['init', '--harness', 'codex,opencode'], again.io), 0);
    assert.match(again.stdout, /already wired/);
    assert.match(again.stdout, /already current/);

    // doctor sees both
    const doc = captureIo();
    await main(['doctor'], doc.io);
    assert.match(doc.stdout, /codex wired/);
    assert.match(doc.stdout, /opencode wired/);
  } finally {
    process.chdir(before);
  }
});

test('init will not overwrite an OpenCode plugin it did not write', async () => {
  const repo = mkdtempSync(join(tmpdir(), 'provenant-init-foreign-'));
  const before = process.cwd();
  process.chdir(repo);
  try {
    mkdirSync(join(repo, '.opencode', 'plugins'), { recursive: true });
    writeFileSync(join(repo, '.opencode', 'plugins', 'provenant.js'), 'export const Mine = async () => ({})\n');
    const cap = captureIo();
    assert.equal(await main(['init', '--harness', 'opencode'], cap.io), 1);
    assert.match(cap.stderr, /not written by Provenant; not overwritten/);
  } finally {
    process.chdir(before);
  }
});

test('init rejects an unknown harness', async () => {
  const cap = captureIo();
  assert.equal(await main(['init', '--harness', 'cursor'], cap.io), 1);
  assert.match(cap.stderr, /unknown harness "cursor"/);
});
