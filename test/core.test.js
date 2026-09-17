import { test } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalize, canonicalBytes } from '../src/core/canonical.js';
import { pae, signEnvelope, verifyEnvelope, decodePayload } from '../src/core/dsse.js';
import { generateKeypair, signerFromPem, verifierFromB64, keyidFor } from '../src/core/keys.js';
import { buildEvent, sealEvent, envelopeLeaf } from '../src/core/event.js';
import { ulid, sessionId } from '../src/core/ids.js';

/* --------------------------------------------------------- canonical JSON */

test('object keys are sorted and whitespace removed', () => {
  assert.equal(canonicalize({ b: 2, a: 1 }), '{"a":1,"b":2}');
  assert.equal(canonicalize({ a: { z: 1, y: 2 } }), '{"a":{"y":2,"z":1}}');
});

test('key order in the source object does not change the bytes', () => {
  const one = { type: 'tool.intent', seq: 3, action: { tool: 'Bash', class: 'exec' } };
  const two = { action: { class: 'exec', tool: 'Bash' }, seq: 3, type: 'tool.intent' };
  assert.equal(canonicalize(one), canonicalize(two));
});

test('arrays keep their order', () => {
  assert.equal(canonicalize({ a: [3, 1, 2] }), '{"a":[3,1,2]}');
});

test('sorting is by UTF-16 code unit, so uppercase sorts before lowercase', () => {
  assert.equal(canonicalize({ b: 1, B: 2, a: 3 }), '{"B":2,"a":3,"b":1}');
});

test('rejects values that would silently disappear', () => {
  assert.throws(() => canonicalize({ a: undefined }), /undefined value at \$\.a/);
  assert.throws(() => canonicalize({ a: NaN }), /non-finite number/);
  assert.throws(() => canonicalize({ a: new Date() }), /Date at/);
  assert.throws(() => canonicalize({ a: () => 1 }), /unsupported function/);
});

test('canonical bytes are UTF-8', () => {
  assert.deepEqual(canonicalBytes({ a: 'é' }), Buffer.from('{"a":"é"}', 'utf8'));
});

/* -------------------------------------------------------------------- DSSE */

test('PAE binds the payload type to the payload', () => {
  assert.equal(pae('t', Buffer.from('body')).toString(), 'DSSEv1 1 t 4 body');
  // Same concatenated bytes, different split: encodings must differ.
  assert.notEqual(
    pae('ab', Buffer.from('c')).toString(),
    pae('a', Buffer.from('bc')).toString(),
  );
});

test('signs and verifies an envelope, and detects payload tampering', () => {
  const { privatePem } = generateKeypair();
  const signer = signerFromPem(privatePem);
  const resolve = (keyid) =>
    keyid === signer.keyid ? verifierFromB64(signer.publicKeyB64) : null;

  const payload = canonicalBytes({ hello: 'world' });
  const envelope = signEnvelope({ payloadType: 'application/test+json', payload, signer });

  assert.equal(verifyEnvelope(envelope, resolve).ok, true);
  assert.deepEqual(decodePayload(envelope), { hello: 'world' });

  const tampered = { ...envelope, payload: canonicalBytes({ hello: 'mars' }).toString('base64') };
  const res = verifyEnvelope(tampered, resolve);
  assert.equal(res.ok, false);
  assert.match(res.reason, /bad signature/);
});

test('verification fails for an unknown key, a wrong key and a malformed envelope', () => {
  const a = signerFromPem(generateKeypair().privatePem);
  const b = signerFromPem(generateKeypair().privatePem);
  const payload = canonicalBytes({ x: 1 });
  const envelope = signEnvelope({ payloadType: 'application/test+json', payload, signer: a });

  assert.match(verifyEnvelope(envelope, () => null).reason, /unknown keyid/);
  assert.match(
    verifyEnvelope(envelope, () => verifierFromB64(b.publicKeyB64)).reason,
    /bad signature/,
  );
  assert.match(verifyEnvelope({}, () => null).reason, /missing payloadType/);
  assert.match(
    verifyEnvelope({ payloadType: 't', payload: 'x', signatures: [] }, () => null).reason,
    /no signatures/,
  );
});

test('changing the payload type invalidates the signature', () => {
  const signer = signerFromPem(generateKeypair().privatePem);
  const resolve = () => verifierFromB64(signer.publicKeyB64);
  const envelope = signEnvelope({
    payloadType: 'application/a+json',
    payload: canonicalBytes({ x: 1 }),
    signer,
  });
  const retyped = { ...envelope, payloadType: 'application/b+json' };
  assert.equal(verifyEnvelope(retyped, resolve).ok, false);
});

test('key ids are stable and derived from the public key', () => {
  const { publicRaw } = generateKeypair();
  assert.equal(keyidFor(publicRaw), keyidFor(publicRaw));
  assert.match(keyidFor(publicRaw), /^ed25519:/);
});

/* ------------------------------------------------------------------ events */

test('an event seals to a stable leaf hash', () => {
  const signer = signerFromPem(generateKeypair().privatePem);
  const body = buildEvent({
    type: 'tool.intent',
    session: 'sess-test',
    seq: 0,
    parent: null,
    action: { class: 'read', tool: 'Read', resource: 'src/a.js' },
  });
  const sealed = sealEvent(body, signer);

  assert.equal(sealed.leaf.length, 32);
  assert.equal(sealed.leafRef, `sha256:${sealed.leaf.toString('hex')}`);
  assert.deepEqual(envelopeLeaf(sealed.envelope), sealed.leaf);
  assert.deepEqual(decodePayload(sealed.envelope), body);
});

test('optional fields are omitted rather than serialised as null', () => {
  const body = buildEvent({ type: 'session.start', session: 's', seq: 0, parent: null });
  assert.equal('action' in body, false);
  assert.equal('decision' in body, false);
  assert.equal(body.parent, null);
});

test('rejects unknown event types and bad sequence numbers', () => {
  assert.throws(() => buildEvent({ type: 'nope', session: 's', seq: 0 }), /unknown event type/);
  assert.throws(() => buildEvent({ type: 'prompt', session: 's', seq: -1 }), /integer seq/);
  assert.throws(() => buildEvent({ type: 'prompt', session: '', seq: 0 }), /session id/);
});

/* --------------------------------------------------------------------- ids */

test('ULIDs are 26 chars and sort in time order', () => {
  const early = ulid(1_700_000_000_000);
  const late = ulid(1_800_000_000_000);
  assert.equal(early.length, 26);
  assert.ok(early < late);
});

test('a harness session id maps to a stable Provenant session id', () => {
  assert.equal(sessionId('abc-123'), sessionId('abc-123'));
  assert.notEqual(sessionId('abc-123'), sessionId('abc-124'));
  assert.match(sessionId('abc-123'), /^sess-[0-9a-f]{12}$/);
  assert.notEqual(sessionId(null), sessionId(null));
});
