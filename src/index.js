/**
 * Library surface. Everything here is usable without the CLI, which is how
 * other harness adapters (v0.2: OpenCode, Codex) will drive the same gate.
 */

export { canonicalize, canonicalBytes } from './core/canonical.js';
export { sha256, leafHash, nodeHash, digestRef, HASH_LEN } from './core/hash.js';
export { pae, signEnvelope, verifyEnvelope, decodePayload } from './core/dsse.js';
export { ulid, sessionId, machineId } from './core/ids.js';
export { generateKeypair, signerFromPem, verifierFromRaw, verifierFromB64, keyidFor } from './core/keys.js';
export { buildEvent, sealEvent, envelopeLeaf, EVENT_TYPES, PAYLOAD_TYPE } from './core/event.js';

export {
  treeRoot,
  inclusionPath,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  splitPoint,
} from './merkle/tree.js';

export { classify, classifyShell, isSecretPath, isInside, CLASSES } from './policy/classify.js';
export {
  loadPolicy,
  validatePolicy,
  evaluate,
  decide,
  lowerTaint,
  taintRank,
  EFFECTS,
  TAINT_ORDER,
} from './policy/engine.js';

export { paths } from './store/paths.js';
export {
  initStore,
  loadConfig,
  loadSession,
  listSessions,
  currentSession,
  appendEvent,
  readEnvelopes,
  writeCheckpoint,
  readCheckpoint,
  verifySession,
} from './store/store.js';

export {
  startSession,
  gateToolCall,
  recordOutcome,
  recordPrompt,
  endSession,
} from './gate.js';

export * as claudeAdapter from './adapters/claude.js';
export { main as cli, VERSION } from './cli.js';
