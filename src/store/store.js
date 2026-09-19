/**
 * Append-only local lineage store.
 *
 * One JSONL file per session, one DSSE envelope per line. Plain files were
 * chosen over SQLite so v0.1 has no native build step and the log stays
 * readable and diffable; see docs/adr/0002-nodejs-and-jsonl.md.
 *
 * Hooks are separate short-lived processes and a harness may run tools in
 * parallel, so sequence allocation takes a lock directory (atomic mkdir) while
 * it reads and writes session state.
 */

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';

import { paths } from './paths.js';
import { canonicalBytes } from '../core/canonical.js';
import { treeRoot, inclusionPath, verifyInclusion } from '../merkle/tree.js';
import { envelopeLeaf, sealEvent } from '../core/event.js';
import { verifyEnvelope, decodePayload } from '../core/dsse.js';
import { generateKeypair, signerFromPem, verifierFromB64 } from '../core/keys.js';
import { machineId } from '../core/ids.js';

const LOCK_STALE_MS = 5000;
const LOCK_WAIT_MS = 2000;

/* ------------------------------------------------------------------ files */

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function writeJson(path, value, { mode } = {}) {
  ensureDir(dirname(path));
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, mode ? { mode } : undefined);
}

function readJson(path, fallback = null) {
  if (!existsSync(path)) return fallback;
  try {
    // Windows editors and shells write a UTF-8 BOM; JSON.parse rejects it.
    return JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    throw new Error(`${path} is not valid JSON: ${err.message}`);
  }
}

/* ------------------------------------------------------------- machine id */

/**
 * Create the store if it does not exist. Idempotent unless `force` is set.
 * @returns {{created: boolean, config: object}}
 */
export function initStore({ force = false } = {}) {
  const existing = readJson(paths.config());
  if (existing && !force) return { created: false, config: existing };

  const { privatePem, publicRaw } = generateKeypair();
  ensureDir(paths.keyDir());
  // 0600: owner read/write. No effect on Windows ACLs, which is stated in the
  // security notes rather than silently assumed.
  writeFileSync(paths.machineKey(), privatePem, { mode: 0o600 });

  const config = {
    version: 1,
    machine: machineId(publicRaw),
    machineKey: publicRaw.toString('base64'),
    createdAt: new Date().toISOString(),
  };
  writeJson(paths.config(), config);
  ensureDir(paths.sessionsDir());
  ensureDir(paths.checkpointDir());
  return { created: true, config };
}

export function loadConfig() {
  const config = readJson(paths.config());
  if (!config) {
    throw new Error(`no Provenant store at ${paths.home()} — run \`provenant init\` first`);
  }
  return config;
}

export function machineSigner() {
  const pem = readFileSync(paths.machineKey(), 'utf8');
  return signerFromPem(pem);
}

/* ------------------------------------------------------------------ locks */

function withLock(dir, fn) {
  const lock = `${dir}.lock`;
  const started = Date.now();
  for (;;) {
    try {
      mkdirSync(lock, { recursive: false });
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      // Reclaim a lock left behind by a process that died mid-write.
      try {
        if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) {
          rmSync(lock, { recursive: true, force: true });
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() - started > LOCK_WAIT_MS) {
        throw new Error(`timed out waiting for lock ${lock}`);
      }
      // Short spin: hook processes hold this for well under a millisecond.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
    }
  }
  try {
    return fn();
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}

/* --------------------------------------------------------------- sessions */

/**
 * Load session state, creating the session (and its session key) on first use.
 * @param {string} id
 */
export function loadSession(id, { create = true } = {}) {
  const statePath = paths.state(id);
  let state = readJson(statePath);
  if (state) return state;
  if (!create) return null;

  const { privatePem, publicRaw, keyid } = generateKeypair();
  const machine = machineSigner();

  // The machine key certifies the session key, so an event chain reaches a
  // key that existed before the session started.
  const binding = {
    type: 'session.key',
    session: id,
    keyid,
    publicKey: publicRaw.toString('base64'),
    machine: loadConfig().machine,
    createdAt: new Date().toISOString(),
  };
  const sig = machine.sign(canonicalBytes(binding)).toString('base64');

  state = {
    session: id,
    seq: 0,
    parent: null,
    taint: 'trusted',
    startedAt: binding.createdAt,
    endedAt: null,
    key: { ...binding, sig, machineKeyid: machine.keyid, privatePem },
    counts: { allow: 0, deny: 0, ask: 0 },
  };

  ensureDir(paths.sessionDir(id));
  writeJson(statePath, state, { mode: 0o600 });
  return state;
}

export function saveSession(state) {
  writeJson(paths.state(state.session), state, { mode: 0o600 });
}

export function listSessions() {
  const dir = paths.sessionsDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .map((id) => readJson(paths.state(id)))
    .filter(Boolean)
    .sort((a, b) => String(a.startedAt).localeCompare(String(b.startedAt)));
}

export function currentSession() {
  const open = listSessions().filter((s) => !s.endedAt);
  if (open.length > 0) return open[open.length - 1];
  const all = listSessions();
  return all.length > 0 ? all[all.length - 1] : null;
}

/* ----------------------------------------------------------------- append */

/**
 * Seal and append one event. Returns the sealed record.
 *
 * @param {string} sessionIdValue
 * @param {(state: object) => object} buildBody called with locked state; returns an event body
 * @param {(state: object, record: object) => void} [mutate] update state after append
 */
export function appendEvent(sessionIdValue, buildBody, mutate) {
  return withLock(paths.sessionDir(sessionIdValue), () => {
    const state = loadSession(sessionIdValue);
    const signer = signerFromPem(state.key.privatePem);

    const body = buildBody(state);
    const { envelope, leafRef } = sealEvent(body, signer);

    appendFileSync(paths.events(sessionIdValue), `${JSON.stringify(envelope)}\n`);

    state.seq = body.seq + 1;
    state.parent = leafRef;
    if (mutate) mutate(state, { body, envelope, leafRef });
    saveSession(state);

    return { body, envelope, leafRef, state };
  });
}

/** Read stored envelopes for a session. @returns {object[]} */
export function readEnvelopes(id) {
  const file = paths.events(id);
  if (!existsSync(file)) return [];
  const out = [];
  const lines = readFileSync(file, 'utf8').split('\n');
  for (const [i, line] of lines.entries()) {
    if (line.trim() === '') continue;
    try {
      out.push(JSON.parse(line));
    } catch (err) {
      throw new Error(`${file}:${i + 1} is not valid JSON: ${err.message}`);
    }
  }
  return out;
}

/* ------------------------------------------------------------ checkpoints */

/**
 * Sign the current root of a session's log with the machine key and append it
 * to roots.jsonl.
 */
export function writeCheckpoint(id) {
  const envelopes = readEnvelopes(id);
  const leaves = envelopes.map(envelopeLeaf);
  const root = treeRoot(leaves);
  const config = loadConfig();
  const machine = machineSigner();

  const note = {
    origin: `provenant/local/${config.machine}`,
    session: id,
    size: leaves.length,
    root: root.toString('base64'),
    ts: new Date().toISOString(),
  };
  const sig = machine.sign(canonicalBytes(note)).toString('base64');
  const checkpoint = { ...note, keyid: machine.keyid, sig };

  writeJson(paths.checkpoint(id), checkpoint);
  ensureDir(paths.checkpointDir());
  appendFileSync(paths.roots(), `${JSON.stringify(checkpoint)}\n`);
  return checkpoint;
}

export function readCheckpoint(id) {
  return readJson(paths.checkpoint(id));
}

/* ---------------------------------------------------------------- verify */

/**
 * Verify one session's log end to end:
 *
 *   1. every envelope signature is valid under the session key
 *   2. the session key is certified by the machine key
 *   3. seq numbers are contiguous and parent links match the previous leaf
 *   4. the recomputed root matches the signed checkpoint, and the checkpoint
 *      signature is valid
 *   5. every leaf has a valid inclusion proof against that root
 *
 * @param {string} id
 * @param {{expectRoot?: string}} [opts] root (hex or base64) from an external copy
 * @returns {{ok: boolean, session: string, events: number, root: string, checks: object[], failures: object[]}}
 */
export function verifySession(id, opts = {}) {
  const checks = [];
  const failures = [];
  const add = (name, ok, detail) => {
    const entry = { name, ok, detail };
    checks.push(entry);
    if (!ok) failures.push(entry);
    return ok;
  };

  const state = readJson(paths.state(id));
  const envelopes = readEnvelopes(id);
  const config = loadConfig();

  if (!state) {
    add('session.state', false, `no state.json for ${id}`);
    return { ok: false, session: id, events: envelopes.length, root: null, checks, failures };
  }

  // 2. session key certified by the machine key
  const { sig, privatePem, machineKeyid, ...binding } = state.key;
  const machineVerifier = verifierFromB64(config.machineKey);
  let keyOk = false;
  try {
    keyOk = machineVerifier.verify(canonicalBytes(binding), Buffer.from(sig, 'base64'));
  } catch {
    keyOk = false;
  }
  add('key.binding', keyOk, keyOk ? `session key certified by ${machineKeyid}` : 'session key is not certified by the machine key');

  const sessionVerifier = verifierFromB64(state.key.publicKey);
  const resolve = (keyid) => (keyid === state.key.keyid ? sessionVerifier : null);

  // 1 + 3. signatures, ordering and chain links
  const leaves = [];
  let expectedParent = null;
  let sigFailures = 0;
  let chainFailures = 0;

  for (const [i, envelope] of envelopes.entries()) {
    const leaf = envelopeLeaf(envelope);
    const res = verifyEnvelope(envelope, resolve);
    if (!res.ok) {
      sigFailures += 1;
      add(`event[${i}].signature`, false, res.reason);
    }

    let payload = null;
    try {
      payload = decodePayload(envelope);
    } catch (err) {
      chainFailures += 1;
      add(`event[${i}].payload`, false, err.message);
    }

    if (payload) {
      if (payload.seq !== i) {
        chainFailures += 1;
        add(`event[${i}].seq`, false, `expected seq ${i}, found ${payload.seq}`);
      }
      const parent = payload.parent ?? null;
      if (parent !== expectedParent) {
        chainFailures += 1;
        add(
          `event[${i}].parent`,
          false,
          `expected parent ${expectedParent ?? 'null'}, found ${parent ?? 'null'}`,
        );
      }
    }

    expectedParent = `sha256:${leaf.toString('hex')}`;
    leaves.push(leaf);
  }

  add('event.signatures', sigFailures === 0, `${envelopes.length - sigFailures}/${envelopes.length} valid`);
  add('event.chain', chainFailures === 0, chainFailures === 0 ? 'seq and parent links contiguous' : `${chainFailures} broken link(s)`);

  // 4. root matches the signed checkpoint
  const root = treeRoot(leaves);
  const rootHex = root.toString('hex');
  const checkpoint = readCheckpoint(id);

  if (!checkpoint) {
    if (state.endedAt) {
      // A closed session always has a checkpoint; a missing one was removed.
      add('checkpoint.present', false, 'no checkpoint for a closed session: it was removed, or never written');
    } else {
      // An open session is simply between checkpoints. Its events are still
      // checked by signature and chain, just not yet against a signed root.
      const entry = {
        name: 'checkpoint.present',
        ok: true,
        warn: true,
        detail: 'session still open and not yet checkpointed: verified by signature and chain only (run `provenant checkpoint` to anchor it)',
      };
      checks.push(entry);
    }
  } else {
    const { sig: cpSig, keyid: cpKeyid, ...note } = checkpoint;
    let cpOk = false;
    try {
      cpOk = machineVerifier.verify(canonicalBytes(note), Buffer.from(cpSig, 'base64'));
    } catch {
      cpOk = false;
    }
    add('checkpoint.signature', cpOk, cpOk ? `signed by ${cpKeyid}` : 'checkpoint signature invalid');

    if (checkpoint.size > leaves.length) {
      add(
        'checkpoint.size',
        false,
        `checkpoint covers ${checkpoint.size} events but only ${leaves.length} remain: entries were removed`,
      );
    } else {
      const prefixRoot = treeRoot(leaves.slice(0, checkpoint.size));
      const match = prefixRoot.toString('base64') === checkpoint.root;
      add(
        'checkpoint.root',
        match,
        match
          ? `root matches checkpoint at size ${checkpoint.size}`
          : `recomputed root for the first ${checkpoint.size} events does not match the signed checkpoint`,
      );
    }
  }

  // Optional external anchor
  if (opts.expectRoot) {
    const want = opts.expectRoot.replace(/^sha256:/, '');
    const match = want === rootHex || want === root.toString('base64');
    add('root.expected', match, match ? 'matches supplied root' : `expected ${want}, computed ${rootHex}`);
  }

  // 5. inclusion proofs
  let proofFailures = 0;
  for (let i = 0; i < leaves.length; i += 1) {
    const path = inclusionPath(i, leaves);
    const ok = verifyInclusion({
      leaf: leaves[i],
      index: i,
      treeSize: leaves.length,
      path,
      root,
    });
    if (!ok) {
      proofFailures += 1;
      add(`event[${i}].inclusion`, false, 'inclusion proof failed');
    }
  }
  add('inclusion.proofs', proofFailures === 0, `${leaves.length - proofFailures}/${leaves.length} verified`);

  return {
    ok: failures.length === 0,
    session: id,
    events: envelopes.length,
    root: rootHex,
    checkpoint,
    checks,
    failures,
  };
}
