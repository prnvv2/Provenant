/**
 * The gate: classify, decide, record.
 *
 * This is the only place where a decision is made and an event is written, so
 * every harness adapter gets identical behaviour. It is intentionally
 * synchronous: a hook process starts, decides, appends and exits.
 */

import { digestRef, sha256 } from './core/hash.js';
import { canonicalBytes } from './core/canonical.js';
import { buildEvent } from './core/event.js';
import { redactWithFlag } from './core/redact.js';
import { classify } from './policy/classify.js';
import { decide, loadPolicy, lowerTaint } from './policy/engine.js';
import { appendEvent, loadSession, listSessions, writeCheckpoint } from './store/store.js';
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
 * @param {'native'|'approval'} [args.askMode] how this harness resolves `ask`:
 *   `native` hands it to the harness's own prompt (Claude Code); `approval`
 *   blocks until a human runs `provenant approve <id>` for this exact action
 *   (Codex and OpenCode, whose pre-tool hooks cannot pause for a human)
 * @returns {{effect: string, reason: string, class: string, session: string, event: string, policy: string, taint: string, approval?: string}}
 */
export function gateToolCall({
  tool,
  input = {},
  cwd = process.cwd(),
  harnessSessionId,
  harness = 'unknown',
  policyFile,
  askMode = 'native',
}) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  const state = loadSession(session);
  const { policy, digest: policyDigest } = loadPolicy(policyFile);

  const classification = classify({ tool, input, cwd });
  const decision = decide({ policy, classification, taint: state.taint });
  const inputDigest = digestRef(canonicalBytes(input ?? {}));

  // Policy sees the raw command; only what gets recorded is redacted.
  const { resource, redacted } = resourceFor(classification.resource);

  const approvalId =
    decision.effect === 'ask' && askMode === 'approval'
      ? approvalIdFor(session, inputDigest, classification.class)
      : null;

  // Decided under the session lock, so one approval can be consumed only once
  // even when a harness runs tool calls in parallel.
  let effective = decision;
  let cited = null;

  const record = appendEvent(
    session,
    (s) => {
      if (approvalId) {
        const a = s.approvals?.[approvalId];
        if (isUsableApproval(a)) {
          effective = {
            ...decision,
            effect: 'allow',
            reason: `approved by a human (${approvalId}): ${decision.reason}`,
          };
          cited = a.event;
        }
      }
      return buildEvent({
        type: EFFECT_EVENT[effective.effect] ?? 'tool.intent',
        session,
        seq: s.seq,
        parent: s.parent,
        taint: s.taint,
        action: {
          class: classification.class,
          tool,
          resource,
          ...(redacted ? { redacted: true } : {}),
        },
        input: inputDigest,
        decision: {
          effect: effective.effect,
          policy: effective.policy,
          reason: effective.reason,
          bundle: policyDigest,
          ...(approvalId ? { approval: approvalId } : {}),
        },
        cites: cited ? [cited] : undefined,
      });
    },
    // Counts and approval state, updated under the same lock and write.
    (s, rec) => {
      s.counts[effective.effect] = (s.counts[effective.effect] ?? 0) + 1;
      if (!approvalId) return;
      s.approvals ??= {};
      if (cited) {
        s.approvals[approvalId].status = 'consumed';
        s.approvals[approvalId].consumedAt = new Date().toISOString();
        s.approvals[approvalId].consumedBy = rec.leafRef;
      } else {
        // First ask, or a re-ask after expiry or consumption: open a fresh request.
        s.approvals[approvalId] = {
          id: approvalId,
          status: 'pending',
          class: classification.class,
          tool,
          resource,
          reason: decision.reason,
          input: inputDigest,
          requestedAt: new Date().toISOString(),
          requestedBy: rec.leafRef,
        };
      }
    },
  );

  return {
    ...effective,
    session,
    event: record.leafRef,
    taint: state.taint,
    classification,
    ...(approvalId ? { approval: approvalId } : {}),
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
          ...resourceAction(classification.resource),
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
        action: {
          class: classification.class,
          tool,
          ...resourceAction(classification.taintSource ?? classification.resource),
        },
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

/**
 * Sign the current root without ending the session. Harnesses that report
 * "turn finished" rather than "session over" (Codex's Stop, OpenCode's
 * session.idle) checkpoint here, so each turn is anchored and the session
 * carries on.
 */
export function checkpointSession({ harnessSessionId, harness = 'unknown', cwd = process.cwd() }) {
  const { session } = startSession({ harnessSessionId, harness, cwd });
  return { session, checkpoint: writeCheckpoint(session) };
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

/* -------------------------------------------------------------- approvals */

/** How long a human approval stays usable. Long enough to switch windows. */
export const APPROVAL_TTL_MS = 10 * 60 * 1000;

/**
 * Approval ids are derived from the session, the exact tool input and its
 * class, so an approval covers one action and a retry of that same action maps
 * back to it. A changed command is a different id and needs its own approval.
 */
export function approvalIdFor(session, inputDigest, actionClass) {
  const h = sha256(Buffer.from(`${session}\n${inputDigest}\n${actionClass}`)).toString('hex');
  return `apr-${h.slice(0, 10)}`;
}

function isUsableApproval(a, now = Date.now()) {
  return Boolean(
    a &&
      a.status === 'approved' &&
      a.approvedAt &&
      now - Date.parse(a.approvedAt) <= APPROVAL_TTL_MS,
  );
}

/** Pending approval requests across all sessions, newest first. */
export function listApprovals({ includeResolved = false } = {}) {
  const out = [];
  for (const s of listSessions()) {
    for (const a of Object.values(s.approvals ?? {})) {
      if (!includeResolved && a.status !== 'pending') continue;
      out.push({ ...a, session: s.session });
    }
  }
  return out.sort((x, y) => String(y.requestedAt).localeCompare(String(x.requestedAt)));
}

/**
 * Record a human approval for one pending request.
 *
 * The approval is an event in the session's log, citing the ask it answers, and
 * the next attempt at the identical action cites the approval. The chain from
 * "agent asked" to "human approved" to "agent acted" is therefore verifiable.
 *
 * What this does not prove is *which* human approved: in v0.x the event is
 * signed by the session key. The CLI requires an interactive terminal and the
 * classifier refuses `provenant approve` from an agent's shell, which stops an
 * agent approving itself in practice; passkey-signed approvals are planned.
 *
 * @param {string} id
 * @param {{method?: string}} [opts]
 */
export function approveAction(id, { method = 'cli-tty' } = {}) {
  const owner = listSessions().find((s) => s.approvals?.[id]);
  if (!owner) throw new Error(`no approval request ${id}`);
  const request = owner.approvals[id];
  if (request.status === 'consumed') throw new Error(`${id} was already used`);
  if (request.status === 'approved' && isUsableApproval(request)) {
    return { id, session: owner.session, already: true, request };
  }

  const record = appendEvent(
    owner.session,
    (s) =>
      buildEvent({
        type: 'approval',
        session: owner.session,
        seq: s.seq,
        parent: s.parent,
        taint: s.taint,
        action: { class: request.class, tool: request.tool, resource: request.resource },
        input: request.input,
        decision: { effect: 'allow', policy: 'human-approval', reason: request.reason, approval: id },
        context: { method },
        cites: [request.requestedBy],
      }),
    (s, rec) => {
      s.approvals[id].status = 'approved';
      s.approvals[id].approvedAt = new Date().toISOString();
      s.approvals[id].event = rec.leafRef;
    },
  );

  return { id, session: owner.session, event: record.leafRef, request };
}

/**
 * Prepare a resource string for recording: redact secret-looking material, then
 * bound its length. Redaction happens first so a truncated token is not stored.
 *
 * @param {unknown} s
 * @param {number} [n]
 * @returns {{resource: string, redacted: boolean}}
 */
function resourceFor(s, n = 400) {
  const { value, redacted } = redactWithFlag(s);
  const resource = value.length <= n ? value : `${value.slice(0, n)}…`;
  return { resource, redacted };
}

/** The `resource` (and `redacted` flag) fields of an action, ready to spread. */
function resourceAction(s) {
  const { resource, redacted } = resourceFor(s);
  return redacted ? { resource, redacted: true } : { resource };
}
