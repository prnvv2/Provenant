/**
 * Ed25519 key handling.
 *
 * Two keys in v0.1:
 *
 *   machine key  long-lived, on disk (0600), signs checkpoints and session keys
 *   session key  generated per agent session, signs that session's events
 *
 * v0.1 keeps the machine key in a file because the CLI runs as the developer's
 * own user, so an OS keychain would not keep it away from the agent either.
 * See docs/adr/0003-key-custody-v01.md. Hardware-backed custody arrives with
 * the daemon in v0.2.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

export const KEY_ALG = 'ed25519';

/** @returns {{privatePem: string, publicRaw: Buffer, keyid: string}} */
export function generateKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicRaw = rawPublicKey(publicKey);
  return { privatePem, publicRaw, keyid: keyidFor(publicRaw) };
}

/** Raw 32-byte Ed25519 public key from a KeyObject. */
export function rawPublicKey(keyObject) {
  const jwk = keyObject.export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url');
}

/** Key id: base64url(SHA-256(raw public key)), truncated to 24 chars. */
export function keyidFor(publicRaw) {
  const d = createHash('sha256').update(publicRaw).digest('base64url');
  return `ed25519:${d.slice(0, 24)}`;
}

/** Build a signer from a PKCS#8 PEM private key. */
export function signerFromPem(privatePem) {
  const privateKey = createPrivateKey(privatePem);
  const publicRaw = rawPublicKey(createPublicKey(privateKey));
  const keyid = keyidFor(publicRaw);
  return {
    keyid,
    publicRaw,
    publicKeyB64: publicRaw.toString('base64'),
    /** @param {Buffer} data */
    sign(data) {
      return sign(null, data, privateKey);
    },
  };
}

/** Build a verifier from a raw 32-byte public key. */
export function verifierFromRaw(publicRaw) {
  const raw = Buffer.from(publicRaw);
  if (raw.length !== 32) throw new TypeError('ed25519 public key must be 32 bytes');
  const publicKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
    format: 'jwk',
  });
  return {
    keyid: keyidFor(raw),
    publicRaw: raw,
    /** @param {Buffer} data @param {Buffer} sig */
    verify(data, sig) {
      return verify(null, data, publicKey, sig);
    },
  };
}

export function verifierFromB64(publicKeyB64) {
  return verifierFromRaw(Buffer.from(publicKeyB64, 'base64'));
}
