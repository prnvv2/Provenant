/**
 * Human controls over running agents: pause everything, or pause one session.
 *
 * A pause does not kill an agent; Provenant cannot. It makes the gate deny
 * every action except reads, so the agent can still look around but cannot
 * change anything until a human resumes it. That works the same way in every
 * harness, because every harness already asks the gate.
 *
 * Every change is recorded: a session pause as a signed `control` event in
 * that session's log, a global pause as a machine-signed line in
 * control.jsonl. An agent cannot lift a pause itself: the files live under
 * `.provenant/`, which the classifier treats as policy, and `provenant resume`
 * from an agent's shell is a policy edit.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { paths } from './store/paths.js';
import { appendEvent, loadSession, machineSigner } from './store/store.js';
import { buildEvent } from './core/event.js';
import { canonicalBytes } from './core/canonical.js';

/** Classes still allowed while paused: looking is harmless, acting is not. */
export const ALLOWED_WHILE_PAUSED = new Set(['read']);

/** @returns {{paused: boolean, since?: string, by?: string, reason?: string}} */
export function readControl() {
  const file = paths.control();
  if (!existsSync(file)) return { paused: false };
  try {
    const c = JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
    return { paused: Boolean(c.paused), since: c.since, by: c.by, reason: c.reason };
  } catch {
    // An unreadable control file is treated as paused: failing closed is the
    // safe reading of "someone may have asked for a stop".
    return { paused: true, reason: 'control.json is unreadable' };
  }
}

/**
 * Pause or resume every agent on this machine.
 *
 * @param {boolean} paused
 * @param {{by?: string, reason?: string}} [opts]
 */
export function setGlobalPause(paused, { by = 'cli', reason } = {}) {
  const record = {
    paused: Boolean(paused),
    since: new Date().toISOString(),
    by,
    ...(reason ? { reason } : {}),
  };
  mkdirSync(dirname(paths.control()), { recursive: true });
  writeFileSync(paths.control(), `${JSON.stringify(record, null, 2)}\n`);

  const signer = machineSigner();
  const line = { type: paused ? 'pause' : 'resume', scope: 'global', ...record, keyid: signer.keyid };
  const sig = signer.sign(canonicalBytes(line)).toString('base64');
  appendFileSync(paths.controlLog(), `${JSON.stringify({ ...line, sig })}\n`);
  return record;
}

/**
 * Pause or resume one session, recording the change in its own log.
 *
 * @param {string} session
 * @param {boolean} paused
 * @param {{by?: string}} [opts]
 */
export function setSessionPause(session, paused, { by = 'cli' } = {}) {
  const state = loadSession(session, { create: false });
  if (!state) throw new Error(`no such session: ${session}`);
  if (Boolean(state.paused) === Boolean(paused)) return { session, paused: Boolean(paused), changed: false };

  const record = appendEvent(
    session,
    (s) =>
      buildEvent({
        type: 'control',
        session,
        seq: s.seq,
        parent: s.parent,
        taint: s.taint,
        context: { action: paused ? 'pause' : 'resume', by },
      }),
    (s) => {
      s.paused = Boolean(paused);
      s.pausedAt = paused ? new Date().toISOString() : null;
    },
  );
  return { session, paused: Boolean(paused), changed: true, event: record.leafRef };
}

/**
 * Is this session paused, and why? Global pause wins over session pause.
 *
 * @param {object} state session state
 * @returns {{scope: 'global'|'session', reason: string}|null}
 */
export function pauseFor(state) {
  const c = readControl();
  if (c.paused) {
    return {
      scope: 'global',
      reason: 'All agents are paused from Provenant. Stop and wait for the user to resume; do not retry.',
    };
  }
  if (state?.paused) {
    return {
      scope: 'session',
      reason: 'This session is paused from Provenant. Stop and wait for the user to resume; do not retry.',
    };
  }
  return null;
}
