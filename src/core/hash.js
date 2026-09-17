/**
 * Hashing primitives with RFC 6962 domain separation.
 *
 * The 0x00 / 0x01 prefixes are not decoration. Without them an internal node
 * (64 bytes of `left || right`) can be presented as a leaf, which forges
 * inclusion of data that was never logged.
 */

import { createHash } from 'node:crypto';

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;
export const HASH_ALG = 'sha256';
export const HASH_LEN = 32;

/** @param {...(Buffer|Uint8Array)} parts @returns {Buffer} */
export function sha256(...parts) {
  const h = createHash(HASH_ALG);
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Leaf hash: H(0x00 || data). @param {Buffer|Uint8Array} data */
export function leafHash(data) {
  return sha256(Buffer.from([LEAF_PREFIX]), data);
}

/** Internal node hash: H(0x01 || left || right). */
export function nodeHash(left, right) {
  assertDigest(left, 'left');
  assertDigest(right, 'right');
  return sha256(Buffer.from([NODE_PREFIX]), left, right);
}

/** `sha256:<hex>` form used in event fields. */
export function digestRef(data) {
  return `sha256:${sha256(data).toString('hex')}`;
}

/** @param {Buffer} digest @returns {string} */
export function hex(digest) {
  return Buffer.from(digest).toString('hex');
}

export function fromHex(s) {
  const buf = Buffer.from(String(s).replace(/^sha256:/, ''), 'hex');
  assertDigest(buf, 'digest');
  return buf;
}

function assertDigest(buf, name) {
  if (!buf || buf.length !== HASH_LEN) {
    throw new TypeError(`${name} must be a ${HASH_LEN}-byte digest`);
  }
}
