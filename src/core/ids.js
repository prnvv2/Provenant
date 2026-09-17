/**
 * Identifiers.
 *
 * Event ids are ULIDs: 48-bit millisecond timestamp + 80 bits of randomness,
 * Crockford base32. They sort lexicographically in time order, which makes them
 * usable as both an idempotency key and a stable sort key in a log file.
 */

import { randomBytes, createHash } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** @param {number} [now] epoch ms @returns {string} 26-char ULID */
export function ulid(now = Date.now()) {
  return encodeTime(now, 10) + encodeRandom(16);
}

function encodeTime(now, len) {
  if (!Number.isFinite(now) || now < 0) throw new RangeError('invalid timestamp');
  let t = Math.floor(now);
  let out = '';
  for (let i = 0; i < len; i++) {
    out = CROCKFORD[t % 32] + out;
    t = Math.floor(t / 32);
  }
  return out;
}

function encodeRandom(len) {
  const bytes = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += CROCKFORD[bytes[i] % 32];
  return out;
}

/**
 * Session id. Derived from the harness session id when one is supplied, so the
 * same agent run always maps to the same Provenant session even though hooks
 * are separate processes.
 *
 * @param {string|undefined|null} harnessSessionId
 * @returns {string}
 */
export function sessionId(harnessSessionId) {
  if (harnessSessionId) {
    const h = createHash('sha256').update(String(harnessSessionId)).digest('hex');
    return `sess-${h.slice(0, 12)}`;
  }
  return `sess-${randomBytes(6).toString('hex')}`;
}

/** Stable machine id, recorded in checkpoints so roots name their origin. */
export function machineId(publicKeyRaw) {
  const h = createHash('sha256').update(publicKeyRaw).digest('hex');
  return `m-${h.slice(0, 16)}`;
}
