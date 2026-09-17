# Agent Action Protocol (AAP) event, version 1

Status: **draft**, as implemented by Provenant v0.1. Anything marked *reserved* is
defined in `docs/DESIGN.md` but not yet produced by v0.1.

An implementation that can verify a Provenant log needs only this document,
`canonicalisation.md`, and the Merkle rules below.

## 1. Envelope

Events are stored one per line in `sessions/<session>/events.jsonl` as a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope:

```json
{
  "payloadType": "application/vnd.provenant.event.v1+json",
  "payload": "<base64 of the canonical event bytes>",
  "signatures": [{ "keyid": "ed25519:<b64url sha256 of public key, 24 chars>", "sig": "<base64>" }]
}
```

The signature is over the DSSE Pre-Authentication Encoding, which binds the
payload type to the payload:

```
PAE = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
```

`len` is the ASCII decimal byte length. Signature algorithm: Ed25519 (RFC 8032).

## 2. Event body

```jsonc
{
  "v": 1,                        // integer, this spec version
  "alg": "ed25519",              // signature algorithm of the envelope
  "type": "tool.intent",         // see §3
  "session": "sess-<12 hex>",    // session identifier
  "id": "01JAB3…",               // ULID, 26 chars: idempotency key and time order
  "seq": 5,                      // 0-based, contiguous within a session
  "ts": "2026-09-17T18:11:36.793Z",  // RFC 3339, UTC, millisecond precision
  "parent": "sha256:<hex>",      // leaf hash of the previous event, null for seq 0

  // present depending on type:
  "action":  { "class": "secret.read", "tool": "Bash", "resource": "cat .env" },
  "input":   "sha256:<hex>",     // digest of canonical tool input
  "taint":   "external",         // trusted | internal | external | untrusted-exec
  "decision":{ "effect": "deny", "policy": "deny-secret-read",
               "reason": "…", "bundle": "sha256:<hex>" },
  "outcome": { "ok": true, "output": "sha256:<hex>", "bytes": 1234 },
  "context": { "harness": "claude-code", "cwd": "…", "policy": "sha256:…" },
  "cites":   ["sha256:<hex>"]    // reserved: approvals or evidence relied upon
}
```

Rules:

- Absent optional fields are **omitted**, never `null`. `parent` is the one field
  that is explicitly `null` (at `seq` 0).
- No field carries content. `input`, `outcome.output` and every `context` digest
  are hashes. `action.resource` carries the command or path, which is the one
  human-readable field and is what an auditor reads.
- `decision.bundle` is the digest of the policy that produced the decision, so a
  verifier can tell which rules were in force.
- Unknown fields must be preserved byte-for-byte when re-serialising, because the
  leaf hash covers them. Verifiers must not reject unknown fields.

## 3. Event types

| Type | Meaning | Required fields beyond the common set |
|---|---|---|
| `session.start` | first event of a session | `context` |
| `prompt` | a human prompt entered the context (trusted input) | `input` |
| `ctx.add` | content the agent did not author entered the context | `action`, `context.label` |
| `tool.intent` | a tool call was allowed and is about to run | `action`, `input`, `decision` |
| `tool.outcome` | a tool call finished | `action`, `outcome` |
| `tool.denied` | a tool call was refused | `action`, `input`, `decision` |
| `tool.ask` | a tool call was escalated to a human | `action`, `input`, `decision` |
| `session.end` | session closed | `context.reason` |

## 4. Merkle commitment

Per RFC 6962, with domain separation:

```
leaf = SHA-256(0x00 ‖ canonical(envelope))
node = SHA-256(0x01 ‖ left ‖ right)
MTH([])   = SHA-256("")
MTH([d])  = d
MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n])),  k = largest power of two < n
```

The leaf is hashed over the **canonical form of the whole envelope**, not the
payload, so the signature is inside the commitment. The `0x00` / `0x01` prefixes
are mandatory: without them an internal node can be replayed as a leaf.

## 5. Checkpoint

```json
{
  "origin": "provenant/local/m-<16 hex>",
  "session": "sess-…",
  "size": 10,
  "root": "<base64 of the 32-byte root>",
  "ts": "2026-09-17T18:11:37.204Z",
  "keyid": "ed25519:…",
  "sig": "<base64 over canonical({origin, session, size, root, ts})>"
}
```

Signed by the **machine key**. Every checkpoint is also appended to
`checkpoints/roots.jsonl`; a copy kept outside the machine is what makes
tamper detection meaningful in v0.1.

## 6. Session key certificate

Stored in the session state and signed by the machine key:

```json
{ "type": "session.key", "session": "sess-…", "keyid": "ed25519:…",
  "publicKey": "<base64 raw 32 bytes>", "machine": "m-…", "createdAt": "…" }
```

## 7. Verification

A conforming verifier must check, and report failures for, all of:

1. each envelope signature, under the session key named by `keyid`;
2. the session key certificate, under the machine key;
3. `seq` contiguous from 0, and each `parent` equal to the previous leaf hash
   (`null` at `seq` 0);
4. the checkpoint signature, and that `MTH` over the first `size` leaves equals
   the checkpoint root — a `size` larger than the number of stored events means
   entries were removed;
5. an inclusion proof for every leaf against the current root;
6. where an external root is supplied, that it matches the recomputed root.

Failing any check means the log is not trustworthy. A verifier should name the
first event at which the chain breaks, since that locates the tampering.

## 8. Reserved for later versions

`cites` (approval references), receipts, anchors in a shared log, witness
cosignatures, key event logs and key-state proofs. See `docs/DESIGN.md`. All are
additive: a v1 verifier ignores fields it does not know, but must include them in
the canonical bytes it hashes.
