#!/usr/bin/env node
/**
 * Latency benchmark for the hot path.
 *
 * Two numbers matter:
 *
 *   in-process gate   classify + policy + sign + append, no process start
 *   full hook         `provenant hook claude pre-tool` as Claude Code runs it
 *
 * The second is what a developer feels on every tool call, so it is the number
 * that belongs in the README.
 *
 *   node scripts/bench.js [iterations]
 */

import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const iterations = Number(process.argv[2] ?? 200);
const HOME = mkdtempSync(join(tmpdir(), 'provenant-bench-'));
process.env.PROVENANT_HOME = HOME;
process.env.PROVENANT_POLICY = fileURLToPath(new URL('../policies/default.json', import.meta.url));

const { initStore } = await import('../src/store/store.js');
const { gateToolCall, startSession } = await import('../src/gate.js');

initStore();

const payload = {
  session_id: 'bench',
  cwd: process.cwd(),
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'npm test' },
};

function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const at = (p) => s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
  return {
    n: s.length,
    min: s[0],
    p50: at(50),
    p95: at(95),
    p99: at(99),
    max: s[s.length - 1],
    mean: s.reduce((a, b) => a + b, 0) / s.length,
  };
}

function fmt(label, r) {
  const f = (x) => `${x.toFixed(2)} ms`;
  console.log(
    `${label.padEnd(18)} n=${String(r.n).padEnd(5)} min ${f(r.min)}  p50 ${f(r.p50)}  p95 ${f(r.p95)}  p99 ${f(r.p99)}  max ${f(r.max)}`,
  );
}

/* ---------------------------------------------------------- in-process gate */

startSession({ harnessSessionId: 'bench', harness: 'bench', cwd: process.cwd() });
const gate = [];
for (let i = 0; i < iterations; i += 1) {
  const t = performance.now();
  gateToolCall({
    harnessSessionId: 'bench',
    harness: 'bench',
    cwd: process.cwd(),
    tool: 'Bash',
    input: { command: `npm test -- --shard ${i}` },
  });
  gate.push(performance.now() - t);
}

/* ---------------------------------------------------------------- full hook */

const bin = fileURLToPath(new URL('../bin/provenant.js', import.meta.url));
const payloadFile = join(HOME, 'payload.json');
writeFileSync(payloadFile, JSON.stringify(payload));
const input = JSON.stringify(payload);

const hook = [];
const hookIterations = Math.min(iterations, 60); // each one spawns a process
for (let i = 0; i < hookIterations; i += 1) {
  const t = performance.now();
  const res = spawnSync(process.execPath, [bin, 'hook', 'claude', 'pre-tool'], {
    input,
    env: process.env,
    encoding: 'utf8',
  });
  hook.push(performance.now() - t);
  if (res.status !== 0) {
    console.error(`hook exited ${res.status}: ${res.stderr}`);
    break;
  }
}

console.log(`\nprovenant bench — node ${process.versions.node} on ${process.platform}/${process.arch}\n`);
fmt('in-process gate', stats(gate));
fmt('full hook', stats(hook));
console.log(
  `\nprocess start overhead ≈ ${(stats(hook).p50 - stats(gate).p50).toFixed(2)} ms (p50)`,
);
console.log('store:', HOME);

rmSync(HOME, { recursive: true, force: true });
