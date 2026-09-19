/**
 * `provenant` command line.
 *
 * Fail-closed rule: if the gate throws while deciding a tool call, mutating
 * classes are blocked rather than allowed. A broken guard must not become an
 * open door.
 */

import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';

import { paths } from './store/paths.js';
import {
  initStore,
  loadConfig,
  listSessions,
  currentSession,
  readEnvelopes,
  verifySession,
  writeCheckpoint,
} from './store/store.js';
import { decodePayload } from './core/dsse.js';
import { redact } from './core/redact.js';
import { loadPolicy, evaluate, bundledPolicyPath } from './policy/engine.js';
import { classify } from './policy/classify.js';
import * as claude from './adapters/claude.js';
import * as codex from './adapters/codex.js';
import * as opencode from './adapters/opencode.js';
import { normalize } from './adapters/common.js';
import { approveAction, listApprovals, APPROVAL_TTL_MS } from './gate.js';

export const VERSION = '0.2.0';

/** Hook adapters by the name used on the command line: `provenant hook <name> <event>`. */
const ADAPTERS = { claude, codex, opencode };

/** Harness names accepted by `init --harness`. */
const HARNESSES = ['claude-code', 'codex', 'opencode'];

const USAGE = `provenant ${VERSION} — policy gate and lineage log for AI coding agents

usage: provenant <command> [options]

  init [--harness claude-code,codex,opencode|all] [--global] [--force]
                       create the store, install the default policy, wire hooks
  approve [<id>]       list actions waiting for human approval, or approve one
                       (interactive terminal only; an agent cannot approve)
  status [--json]      identity, active policy, current session, taint
  log [--session <id>|current|all] [--json] [--limit N]
                       readable lineage for a session
  verify [--session <id>|all] [--root <hex|base64>] [--json]
                       check signatures, chain links, checkpoint and proofs
  checkpoint [--session <id>|current]
                       sign the current root and append it to roots.jsonl
  policy [show|test] [--policy <file>]
                       show the active policy, or test one action against it
  explain --tool <name> [--input <json>] [--cwd <dir>]
                       show how an action would be classified and decided
  hook <claude|codex|opencode> <event>
                       hook entry point (reads JSON on stdin)
  doctor               check the installation
  help | --version

Environment:
  PROVENANT_HOME       store location (default ~/.provenant)
  PROVENANT_POLICY     policy file override
  PROVENANT_HOOK_MODE  json (default) | exitcode
`;

/** Classes that must be blocked when the gate itself fails. */
const MUTATING = new Set([
  'edit', 'edit.outside', 'edit.policy', 'secret.read', 'exec', 'exec.test',
  'exec.destructive', 'net.egress', 'git.commit', 'git.push', 'git.push.protected',
  'deploy', 'unknown', 'mcp',
]);

export async function main(argv = process.argv.slice(2), io = defaultIo()) {
  const [command, ...rest] = argv;
  const flags = parseFlags(rest);

  try {
    switch (command) {
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        io.out(USAGE);
        return 0;

      case '--version':
      case 'version':
        io.out(VERSION);
        return 0;

      case 'init':
        return cmdInit(flags, io);
      case 'status':
        return cmdStatus(flags, io);
      case 'log':
        return cmdLog(flags, io);
      case 'verify':
        return cmdVerify(flags, io);
      case 'checkpoint':
        return cmdCheckpoint(flags, io);
      case 'policy':
        return cmdPolicy(rest, flags, io);
      case 'explain':
        return cmdExplain(flags, io);
      case 'hook':
        return cmdHook(rest, flags, io);
      case 'approve':
        return await cmdApprove(rest, flags, io);
      case 'doctor':
        return cmdDoctor(io);

      default:
        io.err(`unknown command: ${command}\n\n${USAGE}`);
        return 64;
    }
  } catch (err) {
    io.err(`provenant: ${err.message}`);
    return 1;
  }
}

/* -------------------------------------------------------------------- init */

function cmdInit(flags, io) {
  const { created, config } = initStore({ force: Boolean(flags.force) });
  io.out(created ? `✓ created store at ${paths.home()}` : `· store already exists at ${paths.home()}`);
  io.out(`  machine ${config.machine}`);

  // Copy the bundled default policy so it can be edited without touching the package.
  if (!existsSync(paths.policy()) || flags.force) {
    const src = bundledPolicyPath();
    copyFileSync(src, paths.policy());
    io.out(`✓ installed default policy at ${paths.policy()}`);
  } else {
    io.out(`· policy already present at ${paths.policy()}`);
  }

  const requested = String(flags.harness ?? 'claude-code')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const harnesses = requested.includes('all') ? HARNESSES : requested;

  let failed = 0;
  for (const harness of harnesses) {
    const result = installHarness(harness, flags);
    if (result.ok) io.out(result.message);
    else {
      failed += 1;
      io.err(result.message);
    }
  }

  if (harnesses.includes('codex') || harnesses.includes('opencode')) {
    io.out(
      '\nIn Codex and OpenCode an action that needs your approval is blocked with an id.\n' +
        'Run `provenant approve <id>` in your own terminal, then let the agent retry.',
    );
  }
  io.out('\nNext: start your agent, then run `provenant log` and `provenant verify`.');
  return failed === 0 ? 0 : 1;
}

/** Where each harness keeps its hook wiring, project-level or global. */
function harnessTarget(harness, global) {
  const home = homeDir();
  const cwd = process.cwd();
  switch (harness) {
    case 'claude-code':
      return global ? join(home, '.claude', 'settings.json') : join(cwd, '.claude', 'settings.json');
    case 'codex':
      return global ? join(home, '.codex', 'hooks.json') : join(cwd, '.codex', 'hooks.json');
    case 'opencode':
      return global
        ? join(home, '.config', 'opencode', 'plugins', 'provenant.js')
        : join(cwd, '.opencode', 'plugins', 'provenant.js');
    default:
      return null;
  }
}

function installHarness(harness, flags) {
  const target = harnessTarget(harness, Boolean(flags.global));
  if (!target) {
    return { ok: false, message: `! unknown harness "${harness}" — choose from ${HARNESSES.join(', ')} or all` };
  }
  if (harness === 'claude-code') {
    return installHookFile(target, claude.hookConfig('provenant'), 'hook claude', 'Claude Code', flags);
  }
  if (harness === 'codex') {
    return installHookFile(target, codex.hookConfig('provenant'), 'hook codex', 'Codex', flags);
  }
  return installOpenCodePlugin(target);
}

/**
 * Merge Provenant's hooks into a Claude Code or Codex style hooks file. The
 * user's own hooks are kept, and the original file is backed up first.
 */
function installHookFile(target, hooks, marker, label, flags) {
  let settings = {};
  if (existsSync(target)) {
    const raw = readFileSync(target, 'utf8').replace(/^﻿/, '');
    try {
      settings = JSON.parse(raw);
    } catch (err) {
      return { ok: false, message: `! ${target} is not valid JSON (${err.message}); not modified` };
    }
    const already = JSON.stringify(settings.hooks ?? {}).includes(`provenant ${marker}`);
    if (already && !flags.force) {
      return { ok: true, message: `· ${label} hooks already wired in ${target}` };
    }
    copyFileSync(target, `${target}.provenant-backup`);
  }

  settings.hooks = mergeHooks(settings.hooks ?? {}, hooks, marker);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(settings, null, 2)}\n`);
  return { ok: true, message: `✓ wired ${label} hooks in ${target}` };
}

function mergeHooks(existing, ours, marker) {
  const out = { ...existing };
  for (const [event, entries] of Object.entries(ours)) {
    const current = Array.isArray(out[event]) ? out[event] : [];
    const kept = current.filter((e) => !JSON.stringify(e).includes(`provenant ${marker}`));
    out[event] = [...kept, ...entries];
  }
  return out;
}

/**
 * Write the OpenCode plugin with absolute paths to this Node and this
 * Provenant, so it works regardless of the PATH OpenCode was started with.
 */
function installOpenCodePlugin(target) {
  const bin = fileURLToPath(new URL('../bin/provenant.js', import.meta.url));
  const source = opencode.pluginSource({ node: process.execPath, bin });
  if (existsSync(target)) {
    const current = readFileSync(target, 'utf8');
    if (current === source) return { ok: true, message: `· OpenCode plugin already current at ${target}` };
    if (!current.includes('generated by `provenant init --harness opencode`')) {
      return {
        ok: false,
        message: `! ${target} exists and was not written by Provenant; not overwritten`,
      };
    }
  }
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, source);
  return { ok: true, message: `✓ installed OpenCode plugin at ${target}` };
}

/* ------------------------------------------------------------------ status */

function cmdStatus(flags, io) {
  const config = loadConfig();
  const { policy, source, digest } = loadPolicy(flags.policy);
  const session = currentSession();
  const data = {
    version: VERSION,
    home: paths.home(),
    machine: config.machine,
    machineKeyid: `ed25519:${config.machineKey.slice(0, 12)}…`,
    policy: { name: policy.name, source, digest, rules: policy.rules.length },
    session: session
      ? {
          id: session.session,
          startedAt: session.startedAt,
          endedAt: session.endedAt,
          events: readEnvelopes(session.session).length,
          taint: session.taint,
          counts: session.counts,
        }
      : null,
    sessions: listSessions().length,
  };

  if (flags.json) {
    io.out(JSON.stringify(data, null, 2));
    return 0;
  }

  io.out(`provenant ${VERSION}`);
  io.out(`store     ${data.home}`);
  io.out(`machine   ${data.machine}`);
  io.out(`policy    ${policy.name} (${policy.rules.length} rules) ${digest.slice(0, 19)}…`);
  io.out(`sessions  ${data.sessions}`);
  if (data.session) {
    const s = data.session;
    io.out('');
    io.out(`current   ${s.id}${s.endedAt ? ' (closed)' : ''}`);
    io.out(`events    ${s.events}`);
    io.out(`taint     ${s.taint}`);
    io.out(`decisions allow ${s.counts.allow ?? 0} · ask ${s.counts.ask ?? 0} · deny ${s.counts.deny ?? 0}`);
  } else {
    io.out('\nno sessions recorded yet');
  }
  return 0;
}

/* --------------------------------------------------------------------- log */

function cmdLog(flags, io) {
  const target = flags.session ?? 'current';
  const sessions =
    target === 'all'
      ? listSessions().map((s) => s.session)
      : [resolveSession(target)].filter(Boolean);

  if (sessions.length === 0) {
    io.out('no sessions recorded yet');
    return 0;
  }

  const limit = flags.limit ? Number(flags.limit) : Infinity;
  const rows = [];

  for (const id of sessions) {
    for (const envelope of readEnvelopes(id)) {
      const body = decodePayload(envelope);
      rows.push(body);
    }
  }

  const shown = Number.isFinite(limit) ? rows.slice(-limit) : rows;

  if (flags.json) {
    io.out(JSON.stringify(shown, null, 2));
    return 0;
  }

  for (const b of shown) {
    const time = String(b.ts).slice(11, 23);
    const effect = b.decision?.effect ?? '';
    const mark = effect === 'deny' ? '✗' : effect === 'ask' ? '?' : effect === 'allow' ? '✓' : '·';
    const cls = b.action?.class ?? b.context?.label ?? '';
    const what = b.action?.resource ?? b.context?.reason ?? b.context?.harness ?? '';
    io.out(
      `${b.session}  ${time}  ${String(b.seq).padStart(4)}  ${mark} ${pad(b.type, 13)} ${pad(cls, 19)} ${trim(what, 60)}`,
    );
    if (effect && effect !== 'allow') io.out(`${' '.repeat(34)}↳ ${b.decision.reason}`);
  }
  io.out('');
  io.out(`${shown.length} event(s) across ${sessions.length} session(s)`);
  return 0;
}

/* ------------------------------------------------------------------ verify */

function cmdVerify(flags, io) {
  const target = flags.session ?? 'all';
  const sessions =
    target === 'all'
      ? listSessions().map((s) => s.session)
      : [resolveSession(target)].filter(Boolean);

  if (sessions.length === 0) {
    io.out('nothing to verify: no sessions recorded');
    return 0;
  }

  const results = sessions.map((id) => verifySession(id, { expectRoot: flags.root }));

  if (flags.json) {
    io.out(JSON.stringify(results, null, 2));
    return results.every((r) => r.ok) ? 0 : 1;
  }

  let bad = 0;
  for (const r of results) {
    if (r.ok) {
      const warnings = r.checks.filter((c) => c.warn);
      io.out(`✓ ${r.session}  ${r.events} events  root ${r.root.slice(0, 16)}…${warnings.length ? '  (open, unanchored)' : ''}`);
      for (const w of warnings) io.out(`    ! ${w.name}: ${w.detail}`);
      if (flags.verbose) for (const c of r.checks.filter((x) => !x.warn)) io.out(`    ✓ ${c.name}: ${c.detail}`);
    } else {
      bad += 1;
      io.err(`✗ ${r.session}  ${r.events} events  root ${r.root.slice(0, 16)}…`);
      for (const f of r.failures) io.err(`    ✗ ${f.name}: ${f.detail}`);
    }
  }

  io.out('');
  if (bad === 0) {
    io.out(`${results.length} session(s) verified`);
    return 0;
  }
  io.err(`${bad} of ${results.length} session(s) FAILED verification`);
  return 1;
}

function cmdCheckpoint(flags, io) {
  const id = resolveSession(flags.session ?? 'current');
  if (!id) {
    io.err('no session to checkpoint');
    return 1;
  }
  const cp = writeCheckpoint(id);
  io.out(`✓ ${cp.origin} size=${cp.size}`);
  io.out(`  root ${cp.root}`);
  io.out(`  appended to ${paths.roots()} — copy this file somewhere the agent cannot write`);
  return 0;
}

/* ------------------------------------------------------------------ policy */

function cmdPolicy(rest, flags, io) {
  const sub = rest.find((a) => !a.startsWith('-')) ?? 'show';
  const { policy, source, digest } = loadPolicy(flags.policy);

  if (sub === 'show') {
    if (flags.json) {
      io.out(JSON.stringify({ source, digest, policy }, null, 2));
      return 0;
    }
    io.out(`${policy.name}  (${source})`);
    io.out(`digest ${digest}`);
    io.out(`default effect: ${policy.defaultEffect ?? 'ask'}`);
    io.out('');
    for (const r of policy.rules) {
      const cond = [
        r.classes ? r.classes.join('|') : 'any class',
        r.whenTaintAtOrBelow ? `taint ≤ ${r.whenTaintAtOrBelow}` : null,
        r.resourceMatches ? `resource ~ /${r.resourceMatches}/` : null,
      ]
        .filter(Boolean)
        .join('  ');
      io.out(`${pad(r.effect, 6)} ${pad(r.id, 28)} ${cond}`);
    }
    return 0;
  }

  io.err(`unknown policy subcommand: ${sub}`);
  return 64;
}

function cmdExplain(flags, io) {
  if (!flags.tool) {
    io.err('explain requires --tool <name>');
    return 64;
  }
  let input = {};
  if (flags.input) {
    try {
      input = JSON.parse(flags.input);
    } catch (err) {
      io.err(`--input is not valid JSON: ${err.message}`);
      return 64;
    }
  }
  const cwd = flags.cwd ?? process.cwd();
  const classification = classify({ tool: flags.tool, input, cwd });
  const { policy } = loadPolicy(flags.policy);
  const session = currentSession();
  const taint = flags.taint ?? session?.taint ?? 'trusted';

  const decision = evaluate({
    policy,
    actionClass: classification.class,
    taint,
    resource: classification.resource,
  });

  // Show what would be recorded, not the raw string: `explain` output gets
  // pasted into bug reports.
  const shown = redact(classification.resource);
  const data = { classification: { ...classification, resource: shown }, taint, decision };
  if (flags.json) {
    io.out(JSON.stringify(data, null, 2));
    return 0;
  }
  io.out(`tool       ${flags.tool}`);
  io.out(`class      ${classification.class}`);
  io.out(`resource   ${trim(shown, 70)}`);
  io.out(`why        ${classification.reasons.join('; ')}`);
  io.out(`taint      ${taint}`);
  io.out(`decision   ${decision.effect}  (rule ${decision.policy})`);
  io.out(`reason     ${decision.reason}`);
  return 0;
}

/* -------------------------------------------------------------------- hook */

function cmdHook(rest, flags, io) {
  const positional = rest.filter((a) => !a.startsWith('--'));
  const [harness, event] = positional;
  const adapter = ADAPTERS[harness];
  if (!adapter) {
    io.err(`unsupported harness: ${harness ?? '(none)'} — use claude, codex or opencode`);
    return 64;
  }
  if (!event) {
    io.err('hook requires an event name');
    return 64;
  }

  const raw = String(io.stdin() ?? '').replace(/^﻿/, '');
  let payload = {};
  if (raw.trim() !== '') {
    try {
      payload = JSON.parse(raw);
    } catch (err) {
      // Malformed hook input is a bug or an attack: fail closed for pre-tool.
      if (event === 'pre-tool') return emitDeny(harness, `unreadable hook payload: ${err.message}`, io);
      io.err(`provenant: unreadable hook payload: ${err.message}`);
      return 0;
    }
  }

  try {
    const { stdout, exitCode, stderr } = adapter.handle(event, payload);
    if (stdout) io.out(JSON.stringify(stdout));
    if (stderr) io.err(stderr);
    return exitCode;
  } catch (err) {
    return hookFailure(harness, event, payload, err, io);
  }
}

/**
 * Fail closed: a gate that cannot decide must not allow a mutating action.
 */
function hookFailure(harness, event, payload, err, io) {
  if (event !== 'pre-tool') {
    io.err(`provenant: ${event} hook failed: ${err.message}`);
    // OpenCode's plugin reads a JSON reply for every event.
    if (harness === 'opencode') io.out(JSON.stringify({ ok: false, error: err.message }));
    return 0;
  }

  let cls = 'unknown';
  try {
    const p = normalize(payload);
    cls = classify({ tool: p.tool, input: p.input, cwd: p.cwd }).class;
  } catch {
    cls = 'unknown';
  }

  if (MUTATING.has(cls)) {
    return emitDeny(harness, `gate unavailable (${err.message}); ${cls} blocked`, io);
  }

  // Read-only classes are allowed through, and the failure is reported.
  io.err(`provenant: gate unavailable (${err.message}); allowing ${cls}`);
  if (harness === 'claude') io.out(JSON.stringify({ continue: true }));
  if (harness === 'opencode') io.out(JSON.stringify({ decision: 'allow' }));
  return 0;
}

/** A deny in each harness's own reply format. */
function emitDeny(harness, reason, io) {
  const text = `Provenant: ${reason}`;
  if (harness === 'opencode') {
    io.out(JSON.stringify({ decision: 'deny', reason: text }));
    return 0;
  }
  io.out(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: text,
      },
    }),
  );
  return 0;
}

/* ----------------------------------------------------------------- approve */

/**
 * List pending approvals, or approve one.
 *
 * Approving requires an interactive terminal and a typed confirmation. Agents
 * run shell commands without a TTY, so this is a real barrier to an agent
 * approving its own escalation, alongside the classifier refusing
 * `provenant approve` as a policy edit.
 */
async function cmdApprove(rest, flags, io) {
  const id = rest.find((a) => !a.startsWith('--'));

  if (!id) {
    const pending = listApprovals();
    if (flags.json) {
      io.out(JSON.stringify(pending, null, 2));
      return 0;
    }
    if (pending.length === 0) {
      io.out('no actions are waiting for approval');
      return 0;
    }
    io.out(`${pending.length} action(s) waiting for approval:\n`);
    for (const a of pending) {
      io.out(`  ${a.id}  ${pad(a.class, 19)} ${trim(a.resource, 60)}`);
      io.out(`  ${' '.repeat(a.id.length)}  ↳ ${a.reason}`);
      io.out(`  ${' '.repeat(a.id.length)}    session ${a.session} · requested ${a.requestedAt}`);
    }
    io.out('\nApprove one with: provenant approve <id>');
    return 0;
  }

  const request = listApprovals({ includeResolved: true }).find((a) => a.id === id);
  if (!request) {
    io.err(`no approval request ${id} — run \`provenant approve\` to list pending ones`);
    return 1;
  }
  if (request.status === 'consumed') {
    io.err(`${id} was already approved and used. The agent must ask again for a new approval.`);
    return 1;
  }

  if (!io.isTTY()) {
    io.err(
      'provenant approve needs an interactive terminal. Run it yourself, in your own terminal —\n' +
        'an approval run by an agent or a script is refused.',
    );
    return 1;
  }

  io.out('Approve this action?\n');
  io.out(`  class     ${request.class}`);
  io.out(`  tool      ${request.tool}`);
  io.out(`  action    ${request.resource}`);
  io.out(`  why asked ${request.reason}`);
  io.out(`  session   ${request.session}`);
  io.out(`\nThe approval covers this exact action once, for ${Math.round(APPROVAL_TTL_MS / 60000)} minutes.`);
  const answer = String(await io.prompt(`Type the id (${id}) to approve, anything else to cancel: `)).trim();
  if (answer !== id) {
    io.out('cancelled — nothing approved');
    return 1;
  }

  const result = approveAction(id);
  io.out(result.already ? `· ${id} was already approved` : `✓ approved ${id} — the agent can retry now`);
  return 0;
}

/* ------------------------------------------------------------------ doctor */

function cmdDoctor(io) {
  const problems = [];
  const ok = [];

  const majorNode = Number(process.versions.node.split('.')[0]);
  (majorNode >= 22 ? ok : problems).push(`node ${process.versions.node} (need >= 22)`);

  if (existsSync(paths.config())) ok.push(`store at ${paths.home()}`);
  else problems.push(`no store at ${paths.home()} — run \`provenant init\``);

  if (existsSync(paths.machineKey())) ok.push('machine key present');
  else problems.push('machine key missing');

  try {
    const { policy, source } = loadPolicy();
    ok.push(`policy ${policy.name} (${source})`);
  } catch (err) {
    problems.push(err.message);
  }

  // A harness counts as wired if its project-level or global config names us.
  const markers = {
    'claude-code': 'provenant hook claude',
    codex: 'provenant hook codex',
    opencode: 'generated by `provenant init --harness opencode`',
  };
  const notes = [];
  let wiredCount = 0;
  for (const harness of HARNESSES) {
    const files = [harnessTarget(harness, false), harnessTarget(harness, true)];
    const wired = files.filter((f) => existsSync(f) && readFileSync(f, 'utf8').includes(markers[harness]));
    if (wired.length > 0) {
      wiredCount += 1;
      ok.push(`${harness} wired in ${wired.join(', ')}`);
      if (harness === 'opencode') {
        // The plugin bakes in absolute paths; a moved Node or checkout breaks it.
        const src = readFileSync(wired[0], 'utf8');
        const node = src.match(/const NODE = (".*?");/);
        const bin = src.match(/const BIN = (".*?");/);
        const paths_ = [node && JSON.parse(node[1]), bin && JSON.parse(bin[1])].filter(Boolean);
        const missing = paths_.filter((p) => !existsSync(p));
        if (missing.length > 0) {
          problems.push(`OpenCode plugin points at missing ${missing.join(', ')} — re-run \`provenant init --harness opencode\``);
        }
      }
    } else {
      notes.push(`${harness} not wired`);
    }
  }
  if (wiredCount === 0) {
    problems.push('no agent is wired — run `provenant init --harness claude-code,codex,opencode`');
  }

  for (const line of ok) io.out(`✓ ${line}`);
  for (const line of notes) io.out(`· ${line}`);
  for (const line of problems) io.err(`✗ ${line}`);
  return problems.length === 0 ? 0 : 1;
}

/* ------------------------------------------------------------------- utils */

function resolveSession(target) {
  if (!target || target === 'current') return currentSession()?.session ?? null;
  const all = listSessions().map((s) => s.session);
  if (all.includes(target)) return target;
  const matches = all.filter((id) => id.includes(target));
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) throw new Error(`session "${target}" is ambiguous: ${matches.join(', ')}`);
  throw new Error(`no such session: ${target}`);
}

function parseFlags(args) {
  const flags = {};
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = args[i + 1];
    if (next === undefined || next.startsWith('--')) flags[key] = true;
    else {
      flags[key] = next;
      i += 1;
    }
  }
  return flags;
}

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || '.';
}

function pad(s, n) {
  const str = String(s ?? '');
  return str.length >= n ? str : str + ' '.repeat(n - str.length);
}

function trim(s, n) {
  const str = String(s ?? '').replace(/\s+/g, ' ');
  return str.length <= n ? str : `${str.slice(0, n - 1)}…`;
}

function defaultIo() {
  return {
    out: (s) => process.stdout.write(`${s}\n`),
    err: (s) => process.stderr.write(`${s}\n`),
    // Both ends must be a terminal: an agent's shell tool pipes stdin and
    // captures stdout, so it fails this check.
    isTTY: () => Boolean(process.stdin.isTTY && process.stdout.isTTY),
    prompt: async (question) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(question);
      } finally {
        rl.close();
      }
    },
    stdin: () => {
      try {
        // Strip a UTF-8 BOM: some Windows shells add one when piping.
        return readFileSync(0, 'utf8').replace(/^﻿/, '');
      } catch {
        return '';
      }
    },
  };
}
