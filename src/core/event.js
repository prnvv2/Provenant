/**
 * The Agent Action Protocol (AAP) event, v1 — the unit of lineage.
 *
 * Events hold digests, never payloads: enough to prove what happened and under
 * what policy, without copying source code, prompts or command output into a
 * log. `parent` chains events within a session so a gap is detectable.
 */

import { canonicalBytes } from './canonical.js';
import { leafHash } from './hash.js';
import { signEnvelope } from './dsse.js';
import { ulid } from './ids.js';

export const PAYLOAD_TYPE = 'application/vnd.provenant.event.v1+json';
export const SPEC_VERSION = 1;

/** Event types recorded in v0.1. */
export const EVENT_TYPES = Object.freeze([
  'session.start',
  'prompt',
  'ctx.add',
  'tool.intent',
  'tool.outcome',
  'tool.denied',
  'tool.ask',
  'approval',
  'control',
  'session.end',
]);

/**
 * Build an unsigned event body.
 *
 * @param {object} args
 * @param {string} args.type
 * @param {string} args.session
 * @param {number} args.seq
 * @param {string|null} args.parent leaf hash of the previous event, `sha256:…`
 * @param {object} [args.action] {class, tool, resource}
 * @param {string} [args.input] digest of the canonical tool input
 * @param {string} [args.taint]
 * @param {object} [args.decision] {effect, policy, reason}
 * @param {object} [args.outcome] {ok, output}
 * @param {object} [args.context] {cwd, git}
 * @param {string[]} [args.cites] leaf hashes of events this one relies on
 * @param {string} [args.ts] ISO-8601; defaults to now
 * @returns {object}
 */
export function buildEvent(args) {
  const {
    type,
    session,
    seq,
    parent,
    action,
    input,
    taint,
    decision,
    outcome,
    context,
    cites,
    ts = new Date().toISOString(),
  } = args;

  if (!EVENT_TYPES.includes(type)) throw new TypeError(`unknown event type: ${type}`);
  if (typeof session !== 'string' || session.length === 0) {
    throw new TypeError('event requires a session id');
  }
  if (!Number.isInteger(seq) || seq < 0) throw new TypeError('event requires an integer seq');

  const body = {
    v: SPEC_VERSION,
    alg: 'ed25519',
    type,
    session,
    id: ulid(),
    seq,
    ts,
    parent: parent ?? null,
  };

  // Only set optional fields when present: canonical bytes must not depend on
  // whether a caller passed an explicit undefined.
  if (action) body.action = action;
  if (input) body.input = input;
  if (taint) body.taint = taint;
  if (decision) body.decision = decision;
  if (outcome) body.outcome = outcome;
  if (context) body.context = context;
  if (Array.isArray(cites) && cites.length > 0) body.cites = cites;

  return body;
}

/**
 * Canonicalise, sign and wrap an event body.
 *
 * @param {object} body
 * @param {{keyid: string, sign: (d: Buffer) => Buffer}} signer
 * @returns {{envelope: object, leaf: Buffer, leafRef: string, canonical: Buffer}}
 */
export function sealEvent(body, signer) {
  const canonical = canonicalBytes(body);
  const envelope = signEnvelope({ payloadType: PAYLOAD_TYPE, payload: canonical, signer });
  const leaf = leafHash(canonicalBytes(envelope));
  return { envelope, leaf, leafRef: `sha256:${leaf.toString('hex')}`, canonical };
}

/**
 * Leaf hash of a stored envelope. Must match sealEvent, or verification of a
 * log written by another implementation fails.
 *
 * @param {object} envelope
 * @returns {Buffer}
 */
export function envelopeLeaf(envelope) {
  return leafHash(canonicalBytes(envelope));
}
