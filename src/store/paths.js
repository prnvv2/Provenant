/**
 * Where Provenant keeps its state.
 *
 *   $PROVENANT_HOME (default ~/.provenant)
 *   ├── config.json                  machine id, public key, version
 *   ├── keys/machine.key             PKCS#8 PEM, mode 0600
 *   ├── policy.json                  active policy (copied by `init`)
 *   ├── sessions/<id>/events.jsonl   append-only, one DSSE envelope per line
 *   ├── sessions/<id>/state.json     seq, taint, parent leaf, session key
 *   ├── checkpoints/<id>.json        signed root for that session
 *   └── checkpoints/roots.jsonl      append-only roots: copy this off-box
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

export function home() {
  return process.env.PROVENANT_HOME || join(homedir(), '.provenant');
}

export const paths = {
  home,
  config: () => join(home(), 'config.json'),
  keyDir: () => join(home(), 'keys'),
  machineKey: () => join(home(), 'keys', 'machine.key'),
  policy: () => join(home(), 'policy.json'),
  sessionsDir: () => join(home(), 'sessions'),
  sessionDir: (id) => join(home(), 'sessions', id),
  events: (id) => join(home(), 'sessions', id, 'events.jsonl'),
  state: (id) => join(home(), 'sessions', id, 'state.json'),
  checkpointDir: () => join(home(), 'checkpoints'),
  checkpoint: (id) => join(home(), 'checkpoints', `${id}.json`),
  roots: () => join(home(), 'checkpoints', 'roots.jsonl'),
  log: () => join(home(), 'provenant.log'),
};
