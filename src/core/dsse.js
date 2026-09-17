/**
 * DSSE (Dead Simple Signing Envelope).
 *
 * The signature covers the payload *and* its type, using Pre-Authentication
 * Encoding, so a payload can never be reinterpreted as a different type:
 *
 *   PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
 *
 * Same envelope shape as in-toto and Sigstore, so existing tooling can read it.
 */

const PREFIX = 'DSSEv1';

/**
 * @param {string} payloadType
 * @param {Buffer|Uint8Array} payload
 * @returns {Buffer}
 */
export function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  const body = Buffer.from(payload);
  return Buffer.concat([
    Buffer.from(`${PREFIX} ${type.length} `, 'utf8'),
    type,
    Buffer.from(` ${body.length} `, 'utf8'),
    body,
  ]);
}

/**
 * @param {object} args
 * @param {string} args.payloadType
 * @param {Buffer} args.payload canonical bytes
 * @param {{keyid: string, sign: (data: Buffer) => Buffer}} args.signer
 * @returns {{payloadType: string, payload: string, signatures: {keyid: string, sig: string}[]}}
 */
export function signEnvelope({ payloadType, payload, signer }) {
  const sig = signer.sign(pae(payloadType, payload));
  return {
    payloadType,
    payload: Buffer.from(payload).toString('base64'),
    signatures: [{ keyid: signer.keyid, sig: Buffer.from(sig).toString('base64') }],
  };
}

/**
 * Verify every signature on an envelope against a key resolver.
 *
 * @param {object} envelope
 * @param {(keyid: string) => ({verify: (data: Buffer, sig: Buffer) => boolean}|null)} resolveKey
 * @returns {{ok: boolean, reason?: string, payload?: Buffer}}
 */
export function verifyEnvelope(envelope, resolveKey) {
  if (!envelope || typeof envelope !== 'object') {
    return { ok: false, reason: 'envelope is not an object' };
  }
  const { payloadType, payload, signatures } = envelope;
  if (typeof payloadType !== 'string' || typeof payload !== 'string') {
    return { ok: false, reason: 'envelope missing payloadType or payload' };
  }
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return { ok: false, reason: 'envelope has no signatures' };
  }

  const body = Buffer.from(payload, 'base64');
  const data = pae(payloadType, body);

  for (const [i, s] of signatures.entries()) {
    if (!s || typeof s.keyid !== 'string' || typeof s.sig !== 'string') {
      return { ok: false, reason: `signature ${i} is malformed` };
    }
    const key = resolveKey(s.keyid);
    if (!key) return { ok: false, reason: `unknown keyid ${s.keyid}` };
    let valid = false;
    try {
      valid = key.verify(data, Buffer.from(s.sig, 'base64'));
    } catch {
      valid = false;
    }
    if (!valid) return { ok: false, reason: `bad signature from ${s.keyid}` };
  }

  return { ok: true, payload: body };
}

/** Decode an envelope payload without verifying it. For display only. */
export function decodePayload(envelope) {
  return JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
}
