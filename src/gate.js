/**
 * The gate: classify, decide, record.
 *
 * This is the only place where a decision is made and an event is written, so
 * every harness adapter gets identical behaviour. It is intentionally
 * synchronous: a hook process starts, decides, appends and exits.
 */

import { digestRef } from './core/hash.js';
import { canonicalBytes } from './core/canonical.js';
import { buildEvent } from './core/event.js';
import { classify } from './policy/classify.js';
import { decide, loadPolicy, lowerTaint } from './policy/engine.js';
import { appendEvent, loadSession, writeCheckpoint } from './store/store.js';
import { sessionId } from './core/ids.js';

/** Map a decision effect to the event type that records it. */
const EFFECT_EVENT = { allow: 'tool.intent', ask: 'tool.ask', deny: 'tool.denied' };

/**
 * Start (or resume) a session and record session.start once.
 *
 * @param {object} args
 * @param {string} [args.harnessSessionId]
 * @param {string} [args.harness]
 * @param {string} [args.cwd]
 * @param {string} [args.model]
 * @returns {{session: string, created: boolean}}
 */
export function startSession({ harnessSessionId, harness = 'unknown', cwd = process.cwd(), model } = {}) {
  const id = sessionId(harnessSessionId);
  const existing = loadSession(id, { create: false });
  if (existing) return { session: id, created: false };

  const { digest: policyDigest, policy } = loadPolicy();
  loadSession(id); // creates state + session key

  appendEvent(id, (state) =>
    buildEvent({
      type: 'session.start',
      session: id,
      seq: state.seq,
      parent: state.parent,
      taint: state.taint,
      context: {
        harness,
        cwd,
        ...(model ? { model } : {}),
        policy: policyDigest,
        policyName: policy.name ?? 'unnamed',
        keyid: state.key.keyid,
      },
    }),
  );

  return { session: id, created: true };
}

/**
 * Decide whether a tool call may run, and record the decision.
 *
 * @param {object} args
 * @param {string} args.tool
 * @param {object} [args.input]
 * @param {string} [args.cwd]
 * @param {string} [args.harnessSessionId]
 * @param {string} [args.harness]
 * @param {string} [args.policyFile]
 * @returns {{effect: string, reason: string, class: string, session: string, event: string, policy: string, taint: string}}
 */
export function gateToolCall({
  tool,
  input = {},
  cwd = process.cwd(),
  harnessSessionId,
  harness = 'unknown',
  policyFile,
}) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  const state = loadSession(session);
  const { policy, digest: policyDigest } = loadPolicy(policyFile);

  const classification = classify({ tool, input, cwd });
  const decision = decide({ policy, classification, taint: state.taint });

  const record = appendEvent(
    session,
    (s) =>
      buildEvent({
        type: EFFECT_EVENT[decision.effect] ?? 'tool.intent',
        session,
        seq: s.seq,
        parent: s.parent,
        taint: s.taint,
        action: {
          class: classification.class,
          tool,
          resource: truncate(classification.resource, 400),
        },
        input: digestRef(canonicalBytes(input ?? {})),
        decision: {
          effect: decision.effect,
          policy: decision.policy,
          reason: decision.reason,
          bundle: policyDigest,
        },
      }),
    // Counts for `provenant status`, updated under the same lock and write.
    (s) => {
      s.counts[decision.effect] = (s.counts[decision.effect] ?? 0) + 1;
    },
  );

  return {
    ...decision,
    session,
    event: record.leafRef,
    taint: state.taint,
    classification,
  };
}

/**
 * Record the result of a tool call and update session taint.
 *
 * Trust drops when content the agent did not author enters its context. v0.1
 * observes this at the network boundary: fetched pages, search results and
 * commands that pull from the network.
 *
 * @param {object} args
 * @returns {{session: string, taint: string, event: string}}
 */
export function recordOutcome({
  tool,
  input = {},
  output,
  ok = true,
  cwd = process.cwd(),
  harnessSessionId,
  harness = 'unknown',
}) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  const classification = classify({ tool, input, cwd });

  const taintsSession = classification.class === 'net.egress' || Boolean(classification.taintSource);
  const newTaint = taintsSession ? 'external' : null;

  const record = appendEvent(
    session,
    (state) =>
      buildEvent({
        type: 'tool.outcome',
        session,
        seq: state.seq,
        parent: state.parent,
        taint: newTaint ? lowerTaint(state.taint, newTaint) : state.taint,
        action: {
          class: classification.class,
          tool,
          resource: truncate(classification.resource, 400),
        },
        outcome: {
          ok: Boolean(ok),
          output: output === undefined ? null : digestRef(Buffer.from(String(output))),
          bytes: output === undefined ? 0 : Buffer.byteLength(String(output)),
        },
      }),
    (state) => {
      if (newTaint) state.taint = lowerTaint(state.taint, newTaint);
    },
  );

  if (taintsSession) {
    // A separate ctx.add event makes the trust change visible in `provenant log`
    // rather than hiding it inside an outcome.
    appendEvent(session, (state) =>
      buildEvent({
        type: 'ctx.add',
        session,
        seq: state.seq,
        parent: state.parent,
        taint: state.taint,
        action: { class: classification.class, tool, resource: truncate(classification.taintSource ?? classification.resource, 400) },
        context: { label: 'external', source: tool },
      }),
    );
  }

  const state = loadSession(session);
  return { session, taint: state.taint, event: record.leafRef };
}

/** Record a user prompt (trusted input) as a context item. */
export function recordPrompt({ prompt = '', harnessSessionId, harness = 'unknown', cwd = process.cwd() }) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  const record = appendEvent(session, (state) =>
    buildEvent({
      type: 'prompt',
      session,
      seq: state.seq,
      parent: state.parent,
      taint: state.taint,
      input: digestRef(Buffer.from(String(prompt))),
      context: { label: 'trusted', chars: String(prompt).length },
    }),
  );
  return { session, event: record.leafRef };
}

/** Close a session and write its checkpoint. */
export function endSession({ harnessSessionId, harness = 'unknown', cwd = process.cwd(), reason = 'stop' }) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  appendEvent(
    session,
    (state) =>
      buildEvent({
        type: 'session.end',
        session,
        seq: state.seq,
        parent: state.parent,
        taint: state.taint,
        context: { reason },
      }),
    (state) => {
      state.endedAt = new Date().toISOString();
    },
  );
  const checkpoint = writeCheckpoint(session);
  return { session, checkpoint };
}

function truncate(s, n) {
  const str = String(s ?? '');
  return str.length <= n ? str : `${str.slice(0, n)}…`;
}
