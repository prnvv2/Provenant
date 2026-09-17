import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

import {
  treeRoot,
  inclusionPath,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  splitPoint,
} from '../src/merkle/tree.js';
import { leafHash, sha256 } from '../src/core/hash.js';

const vectors = JSON.parse(
  readFileSync(new URL('../spec/vectors/merkle.json', import.meta.url), 'utf8'),
);
const leaves = vectors.entries.map((e) => leafHash(Buffer.from(e.data, 'utf8')));
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Buffer.from(s, 'hex');

test('leaf hashes match the Python reference vectors', () => {
  for (const [i, entry] of vectors.entries.entries()) {
    assert.equal(hex(leaves[i]), entry.leaf, `leaf ${i}`);
  }
});

test('empty tree hashes to SHA-256 of the empty string (RFC 6962 §2.1)', () => {
  assert.equal(hex(treeRoot([])), hex(sha256(Buffer.alloc(0))));
  assert.equal(hex(treeRoot([])), vectors.roots[0].root);
});

test('roots match the reference vectors at every size', () => {
  for (const { size, root } of vectors.roots) {
    assert.equal(hex(treeRoot(leaves.slice(0, size))), root, `size ${size}`);
  }
});

test('single-leaf root is the leaf hash itself', () => {
  assert.equal(hex(treeRoot([leaves[0]])), hex(leaves[0]));
});

test('inclusion paths match the reference vectors and verify', () => {
  for (const v of vectors.inclusion) {
    const subset = leaves.slice(0, v.size);
    const path = inclusionPath(v.index, subset);
    assert.deepEqual(
      path.map(hex),
      v.path,
      `path for index ${v.index} of ${v.size}`,
    );
    assert.equal(
      verifyInclusion({
        leaf: unhex(v.leaf),
        index: v.index,
        treeSize: v.size,
        path,
        root: unhex(v.root),
      }),
      true,
      `verify index ${v.index} of ${v.size}`,
    );
  }
});

test('inclusion proof fails for a tampered leaf', () => {
  const subset = leaves.slice(0, 7);
  const root = treeRoot(subset);
  const path = inclusionPath(3, subset);
  const tampered = leafHash(Buffer.from('provenant-event-3-tampered'));
  assert.equal(
    verifyInclusion({ leaf: tampered, index: 3, treeSize: 7, path, root }),
    false,
  );
});

test('inclusion proof fails for the wrong index or a mutated path', () => {
  const subset = leaves.slice(0, 7);
  const root = treeRoot(subset);
  const path = inclusionPath(3, subset);

  assert.equal(verifyInclusion({ leaf: leaves[3], index: 4, treeSize: 7, path, root }), false);

  const mutated = path.map((h, i) => (i === 0 ? randomBytes(32) : h));
  assert.equal(verifyInclusion({ leaf: leaves[3], index: 3, treeSize: 7, path: mutated, root }), false);

  assert.equal(
    verifyInclusion({ leaf: leaves[3], index: 3, treeSize: 7, path: path.slice(1), root }),
    false,
  );
});

test('domain separation: a node hash cannot be replayed as a leaf', () => {
  // Without the 0x00/0x01 prefixes, H(left||right) would be indistinguishable
  // from a leaf over the same 64 bytes.
  const twoLeaf = treeRoot([leaves[0], leaves[1]]);
  const forged = leafHash(Buffer.concat([leaves[0], leaves[1]]));
  assert.notEqual(hex(twoLeaf), hex(forged));
});

test('consistency proofs match the reference vectors and verify', () => {
  for (const v of vectors.consistency) {
    const proof = consistencyProof(v.first, leaves.slice(0, v.second));
    assert.deepEqual(proof.map(hex), v.proof, `proof ${v.first}→${v.second}`);
    assert.equal(
      verifyConsistency({
        first: v.first,
        firstRoot: unhex(v.firstRoot),
        second: v.second,
        secondRoot: unhex(v.secondRoot),
        proof,
      }),
      true,
      `verify ${v.first}→${v.second}`,
    );
  }
});

test('consistency proof fails when the older root is wrong', () => {
  const proof = consistencyProof(3, leaves.slice(0, 7));
  assert.equal(
    verifyConsistency({
      first: 3,
      firstRoot: randomBytes(32),
      second: 7,
      secondRoot: treeRoot(leaves.slice(0, 7)),
      proof,
    }),
    false,
  );
});

test('property: appending never invalidates earlier inclusion proofs', () => {
  const all = [];
  const snapshots = [];

  for (let n = 1; n <= 40; n += 1) {
    all.push(leafHash(randomBytes(16)));
    snapshots.push({ size: n, root: treeRoot(all) });

    // every leaf still proves against the current root
    for (let i = 0; i < n; i += 1) {
      const path = inclusionPath(i, all);
      assert.equal(
        verifyInclusion({ leaf: all[i], index: i, treeSize: n, path, root: snapshots[n - 1].root }),
        true,
        `leaf ${i} in tree of ${n}`,
      );
    }
  }

  // every earlier snapshot is provably a prefix of the final tree
  const final = snapshots[snapshots.length - 1];
  for (const snap of snapshots) {
    const proof = consistencyProof(snap.size, all);
    assert.equal(
      verifyConsistency({
        first: snap.size,
        firstRoot: snap.root,
        second: final.size,
        secondRoot: final.root,
        proof,
      }),
      true,
      `consistency ${snap.size}→${final.size}`,
    );
  }
});

test('property: a changed leaf changes the root', () => {
  for (let trial = 0; trial < 20; trial += 1) {
    const n = 2 + (trial % 15);
    const base = Array.from({ length: n }, () => leafHash(randomBytes(16)));
    const before = treeRoot(base);
    const idx = trial % n;
    const after = treeRoot(base.map((l, i) => (i === idx ? leafHash(randomBytes(16)) : l)));
    assert.notEqual(hex(before), hex(after));
  }
});

test('splitPoint picks the largest power of two below n', () => {
  assert.equal(splitPoint(2), 1);
  assert.equal(splitPoint(3), 2);
  assert.equal(splitPoint(4), 2);
  assert.equal(splitPoint(5), 4);
  assert.equal(splitPoint(8), 4);
  assert.equal(splitPoint(9), 8);
  assert.throws(() => splitPoint(1));
});

test('rejects malformed leaves and out-of-range indexes', () => {
  assert.throws(() => treeRoot([Buffer.alloc(31)]), /32 bytes/);
  assert.throws(() => inclusionPath(5, leaves.slice(0, 3)), /out of range/);
  assert.equal(verifyInclusion({ leaf: leaves[0], index: 0, treeSize: 0, path: [], root: leaves[0] }), false);
});
