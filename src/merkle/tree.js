/**
 * RFC 6962 / RFC 9162 Merkle tree over an append-only list of leaf hashes.
 *
 * Splitting at the largest power of two below n is what makes the tree
 * append-only: existing subtrees never change shape as leaves arrive, so old
 * inclusion proofs stay valid in the larger tree.
 *
 * All functions take and return leaf *hashes* (32-byte Buffers). Hashing event
 * bytes into a leaf is the caller's job (see core/hash.js leafHash).
 */

import { sha256, nodeHash, HASH_LEN } from '../core/hash.js';

/** Largest power of two strictly less than n. */
export function splitPoint(n) {
  if (n < 2) throw new RangeError('splitPoint requires n >= 2');
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n) {
  return n > 0 && (n & (n - 1)) === 0;
}

function assertLeaves(leaves) {
  if (!Array.isArray(leaves)) throw new TypeError('leaves must be an array');
  for (const [i, l] of leaves.entries()) {
    if (!Buffer.isBuffer(l) && !(l instanceof Uint8Array)) {
      throw new TypeError(`leaf ${i} is not a buffer`);
    }
    if (l.length !== HASH_LEN) throw new TypeError(`leaf ${i} is not ${HASH_LEN} bytes`);
  }
}

/**
 * Merkle Tree Hash. The empty tree hashes to SHA-256 of the empty string,
 * as specified in RFC 6962 section 2.1.
 *
 * @param {Buffer[]} leaves
 * @returns {Buffer}
 */
export function treeRoot(leaves) {
  assertLeaves(leaves);
  return mth(leaves, 0, leaves.length);
}

function mth(leaves, start, end) {
  const n = end - start;
  if (n === 0) return sha256(Buffer.alloc(0));
  if (n === 1) return Buffer.from(leaves[start]);
  const k = splitPoint(n);
  return nodeHash(mth(leaves, start, start + k), mth(leaves, start + k, end));
}

/**
 * Audit path for leaf `index` in a tree of `leaves`: the sibling hash at each
 * level, bottom to top. Length is ceil(log2(n)) for most positions.
 *
 * @param {number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]}
 */
export function inclusionPath(index, leaves) {
  assertLeaves(leaves);
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(`index ${index} out of range for ${leaves.length} leaves`);
  }
  return path(index, leaves, 0, leaves.length);
}

function path(m, leaves, start, end) {
  const n = end - start;
  if (n <= 1) return [];
  const k = splitPoint(n);
  if (m < k) {
    return [...path(m, leaves, start, start + k), mth(leaves, start + k, end)];
  }
  return [...path(m - k, leaves, start + k, end), mth(leaves, start, start + k)];
}

/**
 * Verify an inclusion proof (RFC 9162 section 2.1.3.2). The verifier never sees
 * the other leaves; it recomputes the root from the leaf plus siblings.
 *
 * @param {object} args
 * @param {Buffer} args.leaf leaf hash
 * @param {number} args.index
 * @param {number} args.treeSize
 * @param {Buffer[]} args.path
 * @param {Buffer} args.root
 * @returns {boolean}
 */
export function verifyInclusion({ leaf, index, treeSize, path: proof, root }) {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize)) return false;
  if (index < 0 || treeSize <= 0 || index >= treeSize) return false;
  if (!Array.isArray(proof)) return false;

  let fn = index;
  let sn = treeSize - 1;
  let r = Buffer.from(leaf);

  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }

  return sn === 0 && r.equals(Buffer.from(root));
}

/**
 * Consistency proof that a tree of `first` leaves is a prefix of the tree of
 * all `leaves` (RFC 6962 section 2.1.2). This is what makes "append-only"
 * checkable rather than a promise.
 *
 * @param {number} first size of the older tree
 * @param {Buffer[]} leaves leaves of the newer tree
 * @returns {Buffer[]}
 */
export function consistencyProof(first, leaves) {
  assertLeaves(leaves);
  const second = leaves.length;
  if (!Number.isInteger(first) || first <= 0 || first > second) {
    throw new RangeError(`first ${first} out of range for ${second} leaves`);
  }
  if (first === second) return [];
  return subproof(first, leaves, 0, second, true);
}

function subproof(m, leaves, start, end, b) {
  const n = end - start;
  if (m === n) return b ? [] : [mth(leaves, start, end)];
  const k = splitPoint(n);
  if (m <= k) {
    return [...subproof(m, leaves, start, start + k, b), mth(leaves, start + k, end)];
  }
  return [...subproof(m - k, leaves, start + k, end, false), mth(leaves, start, start + k)];
}

/**
 * Verify a consistency proof (RFC 9162 section 2.1.4.2).
 *
 * @param {object} args
 * @param {number} args.first
 * @param {Buffer} args.firstRoot
 * @param {number} args.second
 * @param {Buffer} args.secondRoot
 * @param {Buffer[]} args.proof
 * @returns {boolean}
 */
export function verifyConsistency({ first, firstRoot, second, secondRoot, proof }) {
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first <= 0 || first > second) return false;
  if (!Array.isArray(proof)) return false;

  if (first === second) {
    return proof.length === 0 && Buffer.from(firstRoot).equals(Buffer.from(secondRoot));
  }

  // A tree whose size is a power of two has its root as an implicit first
  // element of the path.
  const nodes = isPowerOfTwo(first) ? [Buffer.from(firstRoot), ...proof] : [...proof];
  if (nodes.length === 0) return false;

  let fn = first - 1;
  let sn = second - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }

  let fr = Buffer.from(nodes[0]);
  let sr = Buffer.from(nodes[0]);

  for (const p of nodes.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(p, fr);
      sr = nodeHash(p, sr);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = nodeHash(sr, p);
    }
    fn >>= 1;
    sn >>= 1;
  }

  return (
    sn === 0 &&
    fr.equals(Buffer.from(firstRoot)) &&
    sr.equals(Buffer.from(secondRoot))
  );
}
