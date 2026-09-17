# Provenant

> **This is the full system design, not what v0.1 implements.** It covers the whole
> target architecture: daemon, shared log, witnesses, key rotation, credential
> brokering and federation. What actually ships today is in [MVP.md](MVP.md) and the
> repository [README](../README.md); where v0.1 departs from this design, the reason
> is recorded in [adr/](adr/).

**Identity, authorization and verifiable lineage for AI agents.**

Provenant is an open-source trust layer for coding and autonomous agents such as Claude Code, OpenCode, Codex, MCP servers and A2A agents. It gives every agent session a key-bound identity, checks each action against policy *before* it runs, tracks what entered the model's context, and records everything in a tamper-evident Merkle log that anyone can verify offline.

> **Status:** design stage (pre-v0.1). This README is the build input for the project: the source of truth for scope, architecture and conventions until `spec/` and `docs/adr/` exist.
> "Provenant" is a working name.

---

## Contents

1. [Why](#why)
2. [Research basis](#research-basis)
3. [What Provenant does](#what-provenant-does)
4. [Design principles](#design-principles)
5. [Architecture](#architecture)
6. [Core concepts](#core-concepts)
7. [Data formats](#data-formats)
8. [Harness integration](#harness-integration)
9. [Security model](#security-model)
10. [Tech stack](#tech-stack)
11. [Repository layout](#repository-layout)
12. [Engineering conventions](#engineering-conventions)
13. [Roadmap](#roadmap)
14. [Getting started (target UX)](#getting-started-target-ux)
15. [Contributing & governance](#contributing--governance)
16. [Open questions](#open-questions)
17. [References](#references)

---

## Why

Coding agents run as the developer. They use the developer's shell, SSH keys, cloud credentials and git identity. Today:

- A prompt injection in a README, issue or web page can make an agent exfiltrate `.env` or push to `main`.
- Subagents and MCP servers inherit the same ambient authority as the parent.
- Nobody can prove afterwards which actions were the agent's, or under which prompt, model and policy.
- Long-lived tokens sit in environment variables that the agent can read.
- Audit trails are local, mutable transcript files.

Provenant treats every agent, session, subagent and tool server as a **Non-Human Identity (NHI)** with its own keys, narrowly scoped authority, and a verifiable history.

---

## Research basis

Provenant builds on **Malkapuram, Gangavarapu, Gangavarapu & Kavalakuntla, *Context Lineage Assurance for Non-Human Identities in Critical Multi-Agent Systems*, arXiv:2509.18415 (2025)**.

### What the paper contributes

- **Extended A2A Agent Card:** an `identity` block with `agent_id = SHA-256(public_key ‖ domain ‖ timestamp)`, an Ed25519 public key, `identity_proof = Sign(agent_id ‖ skills)`, and `lineage_support` flags (Merkle proofs, DPoP).
- **Action lineage:** each agent action is a small signed event appended to a Certificate-Transparency-style Merkle log (Lineage Store). Leaves are `H(0x00 ‖ event)`, nodes are `H(0x01 ‖ L ‖ R)`, and the log signs periodic Signed Tree Heads.
- **Proof Server:** returns inclusion, consistency and multi-proofs in O(log n), and signs proof packages as a federated auditor.
- **Call-chain verification:** for each event, check the actor's signature, the proof package, and the Proof Server's signature, then follow `prev` links back to a human approval.
- **Human-in-the-loop use case:** a FedRAMP workflow where agent events and signed human approvals alternate in one chain.
- **Future work:** checkpointed log compaction with BLS aggregate signatures, purpose-based access control, multi-domain federation.

### Where Provenant differs

| Concern | Paper | Provenant |
|---|---|---|
| Authorization | Out of scope: log only | Cedar policy gate **before** execution; signed allow/deny/ask decisions |
| Context | Opaque `context_hash` | **Context ledger** with source labels and taint-aware policy |
| Identifier | Changes on key rotation | **Key Event Log with pre-rotation**; stable id |
| Revocation | Not specified | **Key-state transparency map** + 30 s session leases (kill switch ≤ 60 s) |
| Log granularity | One global leaf per event | **Two-tier**: per-session segment trees anchored as one global leaf per segment |
| Proof trust | Proof Server signs packages | Proof server is **untrusted**; checkpoints cosigned by k-of-n **witnesses** |
| Cross-hop verification | Query the Proof Server for each upstream event | Compact signed **lineage receipt** travels with the call |
| Human approval | Signature over event | **WebAuthn passkey assertion over the intent hash**, single-use |
| Privacy | Abstract ZKPs | Salted per-field commitments + encrypted vault with crypto-shredding; ZK deferred |
| Crypto agility | Fixed algorithms | Algorithm ids in envelopes; hybrid Ed25519 + ML-DSA profile |
| Assurance | Valid / invalid | Explicit levels **L0–L4** |

We also correct two inconsistencies in the paper:

- Its per-step root formula `R_t = H(R_{t-1} ‖ E_t)` describes a linear hash chain, not a Merkle tree. Provenant keeps `prev` as a causal link inside events and computes roots with RFC 6962.
- Leaves always use the `0x00` prefix over canonical bytes. The paper also gives the unprefixed form `H(encode(event))`.

---

## What Provenant does

1. **Identifies** every human, host, agent, session, subagent and tool server with its own keys.
2. **Delegates** authority from a human to agents through attenuable capability tokens that can only narrow.
3. **Decides** whether each tool call may run, using deterministic policy that sees what the agent has read.
4. **Brokers** short-lived, scoped, proof-of-possession credentials instead of exposing long-lived secrets.
5. **Records** every intent, decision, approval and outcome as signed events in a two-tier Merkle log.
6. **Proves** any action's provenance with offline-verifiable receipts and evidence capsules.
7. **Revokes** compromised identities across all hosts within 60 seconds.

### Goals

- Every agent action traces to a key-bound NHI and a human grant.
- Risky actions are blocked or escalated before execution.
- Anyone holding a receipt or capsule verifies it offline without trusting operators.
- Revocation takes effect within 60 s.
- Works with Claude Code, OpenCode and Codex without forking them.
- Useful for a single developer with no server.

### Non-goals

- Replacing harness sandboxes or permission modes. Provenant complements them.
- Detecting prompt injection with classifiers. Provenant contains its effects through data-flow policy.
- Blockchain, consensus or tokens.
- Defending a fully root-compromised host, beyond hardware keys and detection.

---

## Design principles

Earlier principles win when two conflict.

1. **Decide, then record.** A signed log of a harmful action is still harmful.
2. **Verify math, not operators.** Log, proof and console servers are untrusted caches.
3. **Authority only narrows.** Human → agent → subagent → tool can only drop rights.
4. **Context is an authorization input.** What the model read determines what it may do.
5. **Nothing slow on the hot path.** Local decisions take < 5 ms; network work is async and batched.
6. **Digests travel, data stays.** Logs hold commitments; content stays with its owner.
7. **Standards over invention.** Reuse C2SP, IETF OAuth, WebAuthn, Cedar and OpenTelemetry.
8. **Useful at one developer.** Every tier adds assurance but none is required.

---

## Architecture

Three planes:

```
┌──────────────────────── EDGE PLANE (per laptop / CI job / pod) ─────────────────────────┐
│  Claude Code hooks   OpenCode plugin   Codex (MCP proxy + exec shim)                     │
│            │                │                    │                                       │
│            └────────────────┴──── local socket ──┘                                       │
│                                   ▼                                                      │
│  agentd ─ Gate (PEP + Cedar PDP) ─ Context ledger/taint ─ Key custody (TPM/keychain)     │
│         ─ Session segment trees ─ Credential broker client ─ MCP/A2A proxy               │
└───────────────┬──────────────────────┬───────────────────────┬──────────────────────────┘
                │ anchors (batched)    │ key events            │ token exchange / approvals
┌───────────────▼──────────── TRUST PLANE (self-hosted or federated) ──────────────────────┐
│  Anchor log (C2SP tlog-tiles)   Key-state map   Witness network   Token service (8693+DPoP)│
│  Approval relay (WebAuthn)      Content vault (encrypted, crypto-shreddable)              │
└───────────────┬──────────────────────────────────────────────────────────────────────────┘
                │ tiles, checkpoints, proofs (all self-verifying)
┌───────────────▼──────────── VERIFICATION PLANE (anyone) ─────────────────────────────────┐
│  verify lib (native + WASM)   CI merge gate   Auditor console   Monitors                  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Plane | State | Responsibility |
|---|---|---|---|
| `agentd` | edge | SQLite (WAL) | Local daemon: intercept, decide, sign, build segment trees, sync anchors. Reachable only via a Unix socket or named pipe with peer-credential checks. Runs as a separate OS user. |
| Gate | edge | compiled policy | Policy enforcement point + Cedar decision + signed decision receipt |
| Context ledger | edge | per session | Records context items (source, digest, label) and computes session taint |
| Harness adapters | edge | stateless | Map native hook payloads to the Agent Action Protocol (AAP) |
| MCP / A2A proxy | edge | pins | Interposes on tool servers and peer agents; attaches and verifies receipts |
| Anchor log | trust | Postgres + object store | Append-only Merkle log of segment anchors and grants; serves static tiles |
| Key-state map | trust | verifiable map | Per-NHI key state per epoch, with inclusion and non-inclusion proofs |
| Witnesses | trust | last size per log | Cosign checkpoints only if they are consistent with the last seen size |
| Token service | trust | provider config | RFC 8693 exchange for short-lived, scoped, DPoP-bound credentials |
| Approval relay | trust | pending approvals | Delivers "ask" decisions to a human device; returns WebAuthn assertions; cannot forge them |
| Content vault | trust | ciphertext | Optional encrypted content for selective disclosure |
| `verify` | verification | none | The **only** code that decides validity; used by CLI, CI, browser and peers |
| Monitors | verification | projections | Detect equivocation, unknown keys, sequence gaps, anomalies |

### Deployment modes

- **Solo:** `agentd` only. The local log is an RFC 6962 tree with machine-signed checkpoints, verifiable offline. Assurance up to L1/L2.
- **Team:** one `docker compose` / Helm deployment of the log, key map, token service and approval relay, with Postgres and S3-compatible storage.
- **Federated:** per-org trust planes, independent witnesses, cross-org receipts. Assurance up to L3/L4.
- **CI:** `agentd --ephemeral` with identity from the CI OIDC token, so no stored secrets.

---

## Core concepts

### Non-Human Identities

| Kind | Example | Lifetime | Key custody |
|---|---|---|---|
| `human` | alice@acme | years | Passkey |
| `host` | laptop, CI runner | months / one job | TPM, Secure Enclave, CI OIDC |
| `agent` | claude-code profile "backend" | months | Host key hierarchy, KEL |
| `session` | one agent run | minutes–hours | In-memory, leased |
| `delegate` | subagent | ≤ parent | In-memory |
| `tool` | MCP server `github@1.4.2` | per version | Publisher key / pinned artifact digest |

### Identifiers and the Key Event Log (ADR-001)

Long-lived NHIs have a **Key Event Log** with **pre-rotation**, following KERI. The inception event commits to the current key and to `H(next_key)`. A rotation must reveal that pre-committed key, so stealing the current key alone does not allow a takeover.

```
id       = "nhi:" + kind + ":" + base32(sha256(JCS(inception_event)))[0:26]
agent_id = "aid://" + hex(sha256(inception_pubkey ‖ domain ‖ created_ts))   # paper-compatible
kid      = base64url(sha256(JCS(jwk)))                                      # RFC 7638 thumbprint
```

### Revocation (ADR-002)

- **Key-state map:** a sparse Merkle tree keyed by `H(nhi_id)`, published per epoch in the style of IETF KEYTRANS and Meta's AKD. It proves current state (active, rotated, revoked) and non-existence.
- **Session leases:** `agentd` renews each session every 30 s. Revoking an agent or human stops renewal, and the session keys are zeroised within 60 s.

### Grants (capabilities)

A human grant is a **Biscuit** token signed by the human. It names the agent, repositories, allowed action classes, expiry and policy bundle hash. Delegating to a subagent appends a block that can only add checks. Verification is offline and uses public keys.

```datalog
// block 0 — human
agent("nhi:agent:q2m…"); repo("acme/api"); policy_bundle("sha256:7c1…");
allow_class(["read","edit","exec.test","git.commit","git.push.branch"]);
check if time($t), $t <= 2026-09-17T18:00:00Z;
// block 1 — session → explore subagent
check if class($c), ["read"].contains($c);
```

### Decision pipeline

```
intent → normalise + classify → grant check (Biscuit) → lease + key state (cached)
       → taint lookup (context ledger) → Cedar evaluate → allow | ask | deny
```

Every stage is local. Budget: **p99 < 5 ms**, excluding human wait time for "ask".

- **allow:** sign `tool.intent`, broker credentials, run, sign `tool.outcome`.
- **ask:** WebAuthn approval bound to the intent hash (ADR-003), then allow or deny.
- **deny:** sign `tool.denied` and return the reason to the harness. Denied attempts are evidence.

### Action classes

Policies target harness-independent classes. Classifiers are plugins; the shell classifier uses **tree-sitter-bash**, not regex, and classifies pipelines and `eval` by their most dangerous part.

| Class | Examples | Default |
|---|---|---|
| `read` | Read, Grep, Glob, `git log` | allow |
| `edit` | Write/Edit inside workspace | allow |
| `edit.outside` | dotfiles, `~/.ssh`, outside workspace | deny |
| `edit.policy` | `.provenant/**` | deny |
| `exec.test` | project-allowlisted build/test commands | allow |
| `exec.other` | arbitrary shell | ask if tainted |
| `net.egress` | curl, WebFetch, installs to unlisted hosts | ask |
| `secret.read` | `.env`, credential files | deny (use the broker) |
| `git.push.branch` | push to non-protected branch | allow |
| `git.push.protected` | push to main/release, force-push | ask (fresh approval) |
| `deploy`, `cloud.mutate` | kubectl/terraform apply, cloud CLIs | ask |

### Policy (Cedar)

```cedar
forbid(principal, action == Action::"net.egress", resource)
when { context.taint == "untrusted-exec" };

permit(principal is Agent, action == Action::"git.push.branch", resource is Branch)
when { !resource.protected };

permit(principal is Agent, action == Action::"git.push.protected", resource is Branch)
when { context.approval.valid && context.approval.age_seconds < 300 };
```

The policy bundle hash is pinned in the grant, so an agent that edits policy files cannot change its own permissions.

### Human approvals (ADR-003)

```
challenge = H("provenant/approve/v1" ‖ intent_digest ‖ decision_nonce ‖ expiry)
```

The human reviews the rendered intent on a trusted surface (a browser, a phone, or the OS passkey prompt) and signs with their passkey. The assertion is single-use, expires within 5 minutes, and is recorded as a cited event. Harness-native confirmation is allowed only for low-risk classes and is recorded at L1 with `approval.method = "harness"`.

### Context integrity and taint (ADR-004)

Every item entering model context is logged as `{source, digest, label}`. Labels form a lattice:

```
trusted          human prompt, grant, policy
  > internal     repo files tracked at the grant commit, org-pinned MCP servers
  > external     web content, issues, third-party MCP output, untracked/downloaded files
  > untrusted-exec  external content that contains instruction-like text
```

**Session taint** is the lowest label seen since the last human checkpoint, and Cedar receives it as `context.taint`. By default, once a session is tainted `external` or lower, `net.egress`, `secret.*`, `git.push.*` and `deploy` require approval. A human approval clears taint for a scoped set of classes. Subagents start with their parent's taint or lower. This follows the capability and information-flow approach of research such as CaMeL and FIDES, simplified to what harness hooks can observe.

Context commitment:

```
context_root = MerkleRoot([
  H("model"‖model_id), H("harness"‖harness@version), H("system"‖system_prompt_digest),
  H("tools"‖tool_schema_digest), H("policy"‖policy_bundle_digest), H("grant"‖grant_digest),
  H("ws"‖git_commit‖dirty_tree_digest), ledger_root ])
```

### Credential broker

Agents never see long-lived secrets. On an allowed decision that needs credentials, `agentd` asks the token service for an **RFC 8693 token exchange**:

- subject = human grant, actor = session NHI, scope derived from the decision
- lifetime ≤ 10 minutes, single resource, DPoP-bound (**RFC 9449**) where supported
- injected only into the one child process

Provider plugins: GitHub App installation tokens, AWS STS with session tags, GCP/Azure workload identity federation, Vault dynamic secrets, short-lived database users.

### Two-tier lineage (ADR-005)

- `agentd` builds an RFC 6962 Merkle tree per **segment** of up to `S` events in a session (default `S = 128`). A segment closes when it's full, after 2 s idle, or at session end.
- Each closed segment emits one **anchor** leaf, `{session, segment_no, size, root, prev_anchor, lease_epoch, sig_session}`, batched to the global anchor log.
- Event inclusion proof = local path (`⌈log₂S⌉` hashes) + anchor inclusion (`⌈log₂A⌉` hashes). The total length is about the same as a single global proof.
- The gains are `S`× fewer global writes, less metadata visible to the log operator, and full offline operation.
- Trade-off: events stay at L1 until their segment is anchored, which takes ≤ 2 s when online.

### Witnessed checkpoints (ADR-006)

Proofs are self-verifying, so the proof and tile server is an untrusted cache and signs nothing. Checkpoints use the C2SP signed-note format and are cosigned by k-of-n witnesses (C2SP tlog-witness), each of which verified consistency with the previous size it saw. A verifier requires k cosignatures from its configured witness set. Compromising the log operator, proof server and console together still cannot forge or fork history.

### Assurance levels

| Level | Name | Meaning |
|---|---|---|
| L0 | Observed | Recorded by an adapter, unsigned (fail-open reads while `agentd` is down) |
| L1 | Signed | Signed by a session key whose chain reaches a human grant; not yet anchored |
| L2 | Anchored | Segment root included in a log-signed checkpoint |
| L3 | Witnessed | Checkpoint k-of-n cosigned; key state proven at event time |
| L4 | Attested | L3 plus hardware attestation of the signing key (and optionally a TEE-attested `agentd`) |

Policies and CI gates require a minimum level, for example `verify-pr --require L3`.

---

## Data formats

### Agent Action Protocol (AAP) event, v1

This extends the paper's canonical event. Field names align with OpenTelemetry GenAI semantic conventions where they exist.

```jsonc
{
  "v": 1, "alg": "ed25519", "type": "tool.intent",
  // session.start | ctx.add | tool.intent | tool.outcome | tool.denied | approval
  // | delegate | key.rotate | revoke | commit.link | segment.close
  "nhi": "nhi:session:9p3…",
  "agent": "nhi:agent:q2m…",
  "grant": "sha256:…",
  "id": "01JAB3…",                 // ULID: idempotency key + time order
  "seq": 311,                      // per-session monotonic
  "ts": "2026-09-17T09:14:03.221Z",
  "lease": 88121,
  "parent": "sha256:…",            // causal predecessor (paper: prev)
  "cites": ["sha256:…"],           // approvals / evidence relied on
  "action": { "class": "git.push.branch", "tool": "Bash", "resource": "repo:acme/api@feat/x" },
  "input": "sha256:…",             // digest of JCS(tool input)
  "context_root": "sha256:…",
  "taint": "external",
  "decision": { "effect": "allow", "policies": ["push-nonprotected"], "bundle": "sha256:…" },
  "disclose": { "command": "sd:sha256:…" }   // salted per-field commitment
}
```

- **Envelope:** DSSE (`payloadType` = `application/vnd.provenant.event+json`), with the signature over the PAE encoding.
- **Canonical form:** RFC 8785 JCS for JSON, deterministic CBOR (RFC 8949 §4.2) on the wire.
- **Leaf:** `SHA-256(0x00 ‖ DSSE_PAE(envelope))`. **Node:** `SHA-256(0x01 ‖ left ‖ right)`. Split at the largest power of two below `n` (RFC 6962).

### Anchor leaf

```jsonc
{ "v": 1, "type": "anchor", "session": "nhi:session:9p3…", "segment_no": 4,
  "size": 128, "root": "sha256:…", "prev_anchor": "sha256:…",
  "seq_range": [256, 383], "lease_epoch": 88121, "sig": "ed25519:…" }
```

### Checkpoint (C2SP signed-note)

```
provenant.dev/log/acme-prod
18231
<base64 root>

— provenant.dev/log/acme-prod <sig>
— witness.example.org <cosig>
```

### Lineage receipt

Carried in the `Provenant-Receipt` HTTP header, A2A message metadata or MCP `_meta`. Size is about 300–600 bytes.

```
base64url(CBOR{
  v: 1, caller: nhi_id, grant: sha256, event: sha256,
  aud: nhi_id_of_callee, nonce: 96-bit, exp: ts + 60,
  taint: label, level: "L1" | "L3",
  anchor?: { log: origin, size, index, path[] },
  key_state?: { epoch, proof },
  sig: ed25519(session key)
})
```

The callee verifies the signature, `aud`, nonce freshness, `exp` and the grant chain offline (L1), plus the anchor, witnesses and key state if its policy requires L3. The callee's own events cite `receipt.event`, so call chains form across organisations with no central query.

### Evidence capsule

```jsonc
{ "spec": "provenant-capsule/1",
  "events": [], "segment_proofs": [], "anchors": [], "checkpoints": [],
  "kel": [], "key_state": [], "grants": [], "approvals": [],
  "disclosures": [ { "event": "sha256:…", "field": "command", "salt": "…", "value": "…" } ],
  "policy_bundles": {} }
```

### Agent Card extension (A2A, paper-compatible)

```jsonc
"identity": {
  "agent_id": "aid://…",
  "public_key": "ed25519:…",
  "identity_proof": "ed25519:sig(agent_id ‖ JCS(skills) ‖ card_version)",
  "lineage_support": { "merkle_proof_generation": true, "dpop_binding": true },
  "provenant": {
    "nhi_id": "nhi:agent:q2m…",
    "kel_uri": "https://keys.acme.dev/kel/q2m…",
    "key_state": { "map": "keys.acme.dev/map", "epoch": 88121, "proof": "…" },
    "receipts": ["application/provenant-receipt+cbor"],
    "min_assurance": "L2"
  }
}
```

### Git linkage

Agent-authored commits carry trailers and can optionally be signed with a session-scoped SSH key:

```
Provenant-Session: nhi:session:9p3…
Provenant-Event: sha256:c0ffee…
Provenant-Log: provenant.dev/log/acme-prod@18231
```

`provenant verify-pr` checks that every commit links to lineage that traces back to a human grant at the required assurance level.

---

## Harness integration

Adapters follow the ports-and-adapters pattern. Each maps its native events to one internal port, `Gate.decide(ActionIntent) → Decision`, and stays under about 300 lines.

> ⚠️ Harness extension APIs change quickly. Verify hook names and payloads against each tool's current documentation, pin tested versions, and keep the compatibility matrix in CI green.

| Harness | Interception | Adapter approach | Coverage |
|---|---|---|---|
| **Claude Code** | Hooks in `settings.json`: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SubagentStop`, `Stop`; plugins; MCP | Each hook calls `provenant hook claude <event>` (static binary: stdin JSON → stdout decision). `PreToolUse` returns an allow/deny/ask permission decision. Distributed as a Claude Code plugin. | pre + post gate |
| **OpenCode** | JS/TS plugins (`.opencode/plugin/`) with `tool.execute.before` / `tool.execute.after` and session events; MCP | `@provenant/opencode` talks to `agentd` over the socket; throwing in `before` blocks the tool | pre + post gate |
| **Codex CLI** | `config.toml`: MCP servers, sandbox/approval policy, `notify`; native hooks where the installed version provides them | (1) route MCP tools through the Provenant MCP proxy; (2) PATH-prepended exec shim for `git`, `gh`, `curl`, package managers, cloud CLIs; (3) `notify` for turn events. Switch to native hooks when available. | proxy + shim |
| **Any MCP client** | MCP stdio / Streamable HTTP | `provenant mcp-proxy` pins servers (artifact digest or publisher key), gates each tool, labels outputs, attaches receipts | MCP tools |
| **A2A agents** | Agent Cards + JSON-RPC | Publishes the extended card; verifies inbound receipts | cross-org |

Claude Code wiring (illustrative):

```json
{
  "hooks": {
    "SessionStart":     [{ "hooks": [{ "type": "command", "command": "provenant hook claude session-start" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "provenant hook claude prompt" }] }],
    "PreToolUse":       [{ "matcher": "*", "hooks": [{ "type": "command", "command": "provenant hook claude pre-tool" }] }],
    "PostToolUse":      [{ "matcher": "*", "hooks": [{ "type": "command", "command": "provenant hook claude post-tool" }] }],
    "Stop":             [{ "hooks": [{ "type": "command", "command": "provenant hook claude stop" }] }]
  }
}
```

OpenCode plugin (illustrative):

```ts
import { connect } from "@provenant/client";

export const Provenant = async ({ directory }) => {
  const gate = await connect({ harness: "opencode", cwd: directory });
  return {
    "tool.execute.before": async (input, output) => {
      const d = await gate.decide({ tool: input.tool, args: output.args });
      if (d.effect !== "allow") throw new Error(`Provenant: ${d.reason}`);
    },
    "tool.execute.after": async (input, output) => gate.outcome(input, output),
  };
};
```

**Failure mode:** if `agentd` is unreachable, mutating classes (`edit.outside`, `exec.*`, `net.egress`, `git.push.*`, `deploy`) **fail closed**, and reads fail open at L0. This is configurable per repository.

---

## Security model

### Trust boundaries

| Boundary | Channel | Controls |
|---|---|---|
| TB1 model/harness → TB2 `agentd` | Unix socket / named pipe | Peer UID/PID + process-ancestry check, schema validation, size limits. The harness is assumed hostile once tainted. |
| TB2 → TB3 hardware | Key API | Non-exportable keys, session keys wrapped by host key, per-session signing rate limits |
| TB2 → TB4 shared services | mTLS (host identity) | Every response verified as a proof, never trusted outright |
| TB4 ↔ TB5 witnesses | HTTPS | Witnesses need only checkpoints and consistency proofs |

`agentd` runs as a separate OS user or service account, so an agent with shell access cannot read its memory, keys or database.

### Threat model (summary)

| # | Threat | Controls | Residual |
|---|---|---|---|
| T1 | Indirect prompt injection → exfiltration or destructive commands | Taint-aware policy, egress classes, passkey approval, broker-only secrets | Approval fatigue |
| T2 | Agent bypasses hooks | Exec shim, OS egress profile, harness sandbox, CI rejects commits without receipts, seq-gap monitors | Defence in depth |
| T3 | Agent reads `agentd` keys/DB | Separate OS user, non-exportable keys, DB holds digests only | Low |
| T4 | Session key theft → forged events | In-memory keys, 30 s lease, seq ranges bound in anchors | Low |
| T5 | Agent key stolen, attacker rotates | KEL pre-rotation | Low |
| T6 | Log operator forks history (split view) | k-of-n witnesses, consistency proofs, cached checkpoints, gossip | Low |
| T7 | Proof server returns bogus proofs | Verifier recomputes all proofs | None |
| T8 | Receipt replay | `aud`, nonce cache, short `exp`, DPoP | Low |
| T9 | Approval phishing | Challenge = intent hash, trusted render surface, single-use | User attention |
| T10 | Malicious or updated MCP server | Digest/publisher pinning, outputs labelled external, re-pin needs approval | Trust on first pin |
| T11 | Agent edits its own policy | Bundle hash pinned in grant, `edit.policy` denied | Low |
| T12 | Metadata leakage via log | Two-tier anchoring, salted commitments, per-tenant logs | Low |
| T13 | Event/approval flooding | Per-NHI quotas, backpressure, approval rate limits | Low |
| T14 | Compromised Provenant release | Reproducible builds, Sigstore, SLSA provenance, two-maintainer release | Ecosystem |
| T15 | Root-compromised host | Hardware keys, monitors, L4 attestation | Out of scope |

### Cryptography

| Purpose | Profile `pv1` (default) | Profile `pv1-hq` |
|---|---|---|
| Event / receipt signatures | Ed25519 | Ed25519 + ML-DSA-65 hybrid |
| Checkpoints / witnesses | Ed25519 signed-note | Ed25519 + ML-DSA-65 |
| Hashing | SHA-256, RFC 6962 domain separation | SHA-256 (FIPS) / SHA-384 option |
| Human approval | WebAuthn ES256 / EdDSA | + attestation required |
| Content vault | XChaCha20-Poly1305, per-session data key | AES-256-GCM (FIPS), KMS-wrapped |
| Transport | TLS 1.3, mTLS host → service | + hybrid X25519MLKEM768 |
| Commitments | `SHA-256(salt₁₂₈ ‖ field ‖ value)` | same |

Rules:

- Algorithm ids appear in every envelope, and verifiers enforce an allowlist. There is no `none`.
- Only audited crates, constant-time comparisons, zeroise on drop, no custom primitives.
- Org root keys are offline with threshold 2-of-3. Log keys are in KMS/HSM and rotate yearly with log sharding.

### Privacy and data handling

- **Log:** anchors only (roots, sizes, signatures).
- **Edge store:** event envelopes (digests, classes, decisions), with configurable retention.
- **Vault (opt-in):** encrypted content for disclosure.
- **Never stored:** secrets, brokered tokens, raw transcripts (unless opted in).
- **Erasure:** destroying a vault data key plus its salts makes commitments unlinkable. Proofs still verify, and the content is unrecoverable (GDPR Art. 17).
- **Selective disclosure:** reveal `{field, salt, value}` for only the fields an auditor needs.
- **Compliance evidence** (not certification): NIST 800-53 AU-2/3/6/9/10, AC-6, IA-2/IA-9, CA-7; SOC 2 CC6.1–6.3, CC7.2; ISO 27001:2022 A.5.15–5.18, A.8.15; EU AI Act Art. 12, Art. 14.

---

## Tech stack

| Area | Choice | Reason |
|---|---|---|
| Core, daemon, services | **Rust**: tokio, axum, tonic / ConnectRPC | Memory safety on the security boundary, no GC latency, static binaries, WASM verifier |
| Crypto | `ed25519-dalek`, `sha2`, `aws-lc-rs` (FIPS, ML-DSA) | Audited, FIPS path |
| Transparency log | C2SP tlog-tiles + signed-note + tlog-witness (Rust impl, vector-tested against Trillian-Tessera) | Works with existing witnesses and tooling |
| Verifiable map | Sparse Merkle tree; evaluate `akd` | Existing Rust key-transparency implementation |
| Policy | Cedar (`cedar-policy`) | Fast, schema-validated, analyzable |
| Capabilities | Biscuit v3 (`biscuit-auth`) | Offline public-key attenuation |
| Shell parsing | tree-sitter-bash | Real grammar for classification |
| Serialization | Deterministic CBOR (`ciborium`), JCS JSON (`serde_jcs`), DSSE | Compact; in-toto/Sigstore compatible |
| Edge storage | SQLite WAL (`rusqlite`), SQLCipher optional | Zero-ops, crash-safe |
| Service storage | Postgres, S3-compatible object storage, Redis (optional nonce cache) | Portable |
| Approvals | `webauthn-rs`, Web Push | Passkeys everywhere |
| Key stores | OS keychain (`keyring`), TPM 2.0, Secure Enclave, PKCS#11, AWS/GCP KMS, Vault Transit | Non-exportable keys |
| Adapters / SDKs | TypeScript (OpenCode, Node), Python, Go (second verifier) | Native plugin languages |
| Console | SvelteKit + `verify` compiled to WASM | Client-side verification |
| Observability | OpenTelemetry (GenAI semconv + `provenant.*`), Prometheus, OCSF export | Vendor-neutral |
| Packaging | `cargo-dist` (Homebrew, winget/Scoop, npm, deb/rpm), OCI, Helm, Nix | Easy install on every platform |

---

## Repository layout

```
provenant/
├── spec/                     # AAP, receipts, capsules, keymap — normative text, CDDL, JSON Schema, vectors (CC-BY-4.0)
├── docs/
│   ├── adr/                  # ADR-001 … (identity, revocation, approvals, taint, two-tier, witnesses)
│   └── security/             # threat model, trust boundaries
├── crates/
│   ├── aap-types/            # L0: events, receipts, capsules
│   ├── canon/                # L0: JCS, DSSE PAE, deterministic CBOR
│   ├── merkle/               # L0: RFC 6962 tree, inclusion/consistency/multiproof, tiles, sparse map
│   ├── crypto-api/           # L0: Signer / Verifier traits, algorithm registry
│   ├── verify/               # L1: assurance levels L0–L4 (native + wasm32)
│   ├── policy/               # L1: Cedar schema/eval, action classifiers, taint lattice
│   ├── grants/               # L1: Biscuit grants and attenuation
│   ├── kel/                  # L1: key event log, pre-rotation
│   ├── context/              # L1: context ledger, context_root
│   ├── agentd/               # L2: local daemon
│   ├── anchor-log/           # L2: sequencer, checkpoints, tile writer
│   ├── key-map/              # L2: verifiable key-state map
│   ├── witness/              # L2: witness server/client
│   ├── token-service/        # L2: RFC 8693 + DPoP
│   ├── approval-relay/       # L2: WebAuthn approvals
│   ├── keystore-*/           # L3: keychain, tpm, kms, pkcs11
│   ├── storage-*/            # L3: sqlite, postgres, s3
│   ├── creds-*/              # L3: github, aws, gcp, azure, vault
│   └── cli/                  # `provenant` binary
├── adapters/
│   ├── claude-code/          # plugin manifest, hooks config, commands
│   ├── opencode/             # @provenant/opencode
│   ├── codex/                # config snippets, exec shim, notify handler
│   ├── mcp-proxy/
│   └── a2a/
├── sdks/                     # ts/, python/, go-verify/
├── policies/                 # baseline/, strict/, examples/
├── conformance/              # cross-implementation test runner
├── console/
├── deploy/                   # compose/, helm/, terraform-examples/
├── SECURITY.md  GOVERNANCE.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  LICENSE
└── README.md
```

---

## Engineering conventions

### Layering (enforced in CI)

- **Layer 0** (`aap-types`, `canon`, `merkle`, `crypto-api`): pure, no I/O, no async, `#![no_std]`-friendly, WASM-safe, minimal dependencies.
- **Layer 1** (`verify`, `policy`, `grants`, `kel`, `context`): domain logic that depends only on layer 0.
- **Layer 2**: async services that orchestrate I/O.
- **Layer 3**: port implementations (key stores, storage, credential providers, adapters).
- Dependencies point inward only. `verify` depends only on layer 0, so the same verifier runs everywhere.

### Patterns

| Pattern | Applied to |
|---|---|
| Functional core, imperative shell | All security logic is pure and deterministic |
| Hexagonal architecture | Harness adapters, key stores, storage, credential providers |
| Event sourcing | Sessions, KELs, approvals; state is a projection |
| CQRS | Anchor-log writer vs tile/proof readers (CDN-served) |
| PEP / PDP / PIP | Adapters / Cedar / context ledger + key map |
| Transactional outbox | Segment close → anchor upload survives crashes and offline periods |
| Group commit + batching | ~1 checkpoint per second covering many anchors |
| Idempotent writes | ULID ids; unique `(session, segment_no)` |
| Bulkheads + backpressure | Per-session bounded queues; per-tenant sequencers |
| Explicit degradation | Degrade to L1 with a visible flag; never skip checks silently |
| Plugin registry | Classifiers, credential providers, adapters; WASM plugins sandboxed |
| Content addressing | Policy bundles, context items, events |
| ADRs | Every significant decision recorded in `docs/adr/` |

### Testing and quality

- **Property tests** (`proptest`): proof round-trips, consistency over random appends, Biscuit attenuation monotonicity.
- **Fuzzing** (`cargo-fuzz`, OSS-Fuzz): CBOR, signed-notes, hook payloads, shell classifier.
- **Differential tests** against Go sumdb / Trillian-Tessera using shared vectors.
- **Model checking:** TLA+ for leases, revocation and the witness protocol.
- **Policy tests:** Cedar validation and analysis on every bundle change.
- **Harness compatibility matrix:** pinned and latest Claude Code, OpenCode and Codex in containers, driven by scripted sessions.
- **Adversarial suite:** a prompt-injection scenario corpus with expected decisions.
- **Chaos tests:** kill `agentd` mid-segment, network partition, clock skew, witness disagreement.
- **Benchmarks** (Criterion): sign, hash, Cedar eval and segment close, with a ±10% regression gate.

### Performance budgets

| Operation | Target |
|---|---|
| Hook decision, end to end (warm) | p99 < 5 ms |
| Hook binary cold start | < 25 ms |
| Cedar evaluation | < 1 ms |
| Segment anchoring (online) | ≤ 2 s |
| Anchor log sequencer | ≥ 10k anchors/s on commodity VM |
| Revocation propagation | ≤ 60 s |
| Proof for 10⁹ entries | ~30 hashes (~1 KB) |

These are design targets, not measurements, until benchmarks exist.

### Code and release hygiene

- Rust 2021+, `clippy -D warnings`, `rustfmt`, `cargo-deny`, `cargo-vet`. `unsafe` is forbidden outside audited key-store FFI.
- Conventional Commits; SemVer for crates; spec versioned separately (`aap/1`).
- Reproducible builds, Sigstore-signed artifacts, SLSA Build L3 provenance, CycloneDX SBOM.
- Two-maintainer review for `crates/crypto*`, `crates/merkle`, `crates/verify`, `spec/`.
- OpenSSF Scorecard ≥ 8 before 1.0.

---

## Roadmap

Planning estimates, assuming 3–4 core contributors starting Q4 2026.

### Phase 0: Spec & foundations (months 0–2)
- [ ] AAP v1 draft; ADR-001…006
- [ ] `canon`, `merkle`, `crypto-api`, `aap-types`
- [ ] Test vectors; `provenant verify` for segment trees
- [ ] Threat model v1
- **Exit:** vectors match Tessera tile/proof output; fuzzers in CI; public design review held

### Phase 1: v0.1 local guard (months 2–4)
- [ ] `agentd` with Cedar gate, action classes, signed decisions
- [ ] Claude Code adapter (session, prompt, pre/post tool hooks)
- [ ] Local segment trees, L1 lineage, `provenant log`
- [ ] Baseline and strict policy packs
- **Exit:** hook p99 < 5 ms; adversarial suite blocks known exfiltration chains; Windows/macOS/Linux installers

### Phase 2: v0.2 three harnesses + context integrity (months 4–6)
- [ ] OpenCode plugin; Codex MCP proxy + exec shim
- [ ] Context ledger, taint lattice, taint-aware default policy
- [ ] Harness compatibility matrix in CI; OTel GenAI export
- **Exit:** one policy file enforced identically across three harnesses; < 1 false ask per session-hour on dogfood repos

### Phase 3: v0.3 team trust plane (months 6–9)
- [ ] Anchor log (tiles), witness server, L2/L3 verification
- [ ] Biscuit human grants; WebAuthn approval relay
- [ ] Evidence capsules; `verify-pr` GitHub Action / GitLab job
- [ ] docker compose + Helm
- **Exit:** 10k anchors/s; chaos suite green; 3 external design partners

### Phase 4: v0.4 identity lifecycle & credentials (months 9–12)
- [ ] KEL with pre-rotation; key-state map; session leases; kill switch
- [ ] Token service with GitHub App, AWS, GCP and Vault providers; DPoP
- [ ] CI OIDC host identities; console
- **Exit:** revocation ≤ 60 s across hosts; zero long-lived secrets in agent env; TLA+ model checked

### Phase 5: v0.5 federation & A2A (months 12–15)
- [ ] Receipts in A2A metadata and MCP `_meta`; peer verification
- [ ] Paper-compatible Agent Card extension; card transparency
- [ ] Public witness pilot; monitors; OCSF SIEM export; compliance evidence reports
- **Exit:** cross-org chain verified at L3 between two independent deployments; Go verifier passes conformance

### v1.0: stable, audited (months 15–18)
- [ ] AAP 1.0 frozen; LTS branch
- [ ] External security audit, findings published
- [ ] `pv1-hq` profile (hybrid ML-DSA, FIPS build)
- [ ] Foundation application (OpenSSF / CNCF)
- **Exit:** no open critical/high findings; ≥ 2 independent verifiers; Scorecard ≥ 8

### Research track (post-1.0, demand-driven)
- L4: TEE-attested `agentd`
- ZK predicates for selective disclosure
- Checkpointed compaction for decade-scale logs (the paper's future work)
- Model-provider-signed context attestations

---

## Getting started (target UX)

> Not yet implemented. This section defines the experience the project is aiming for.

```bash
# install + wire up harnesses found on this machine
npx provenant init --harness claude-code,opencode,codex

provenant status                       # identity, grant, policy bundle, taint, assurance level
provenant grant --repo acme/api --ttl 2h --classes default
provenant log --session current        # human-readable lineage
provenant approve                      # pending approvals (or approve on phone/passkey)
provenant revoke nhi:agent:q2m…        # kill switch

provenant verify-pr 128 --require L3   # CI merge gate
provenant export capsule --since main --out evidence.json
provenant verify evidence.json --witnesses acme,public --require L3
```

Target: **< 5 minutes** from install to first protected session.

---

## Contributing & governance

- **License:** Apache-2.0 for code, CC-BY-4.0 for `spec/`.
- **Governance:** maintainer council of 3–5 people, with at least two organisations represented before 1.0.
- **Spec changes:** RFC issue → 14-day comment period → ADR → test vectors → implementation.
- **Security reports:** private GitHub Security Advisories with 90-day coordinated disclosure (see `SECURITY.md`). Do not open public issues for vulnerabilities.
- **New harness adapters:** use `adapters/_template`, target < 300 lines, and pass `conformance/`.
- **Releases:** minor every 6 weeks; LTS with 12-month support after 1.0; support the two latest minor versions of each harness.

### Project health targets (v1.0)

| Metric | Target |
|---|---|
| Hook latency p99 (warm) | < 5 ms |
| False-ask rate | < 1 per session-hour |
| Time to first protected session | < 5 min |
| Independent verifier implementations | ≥ 2 |
| Organisations with maintainers | ≥ 2 |

---

## Open questions

1. What default segment size `S` should we use, and should it adapt to event rate?
2. Should receipts carry the full grant chain (fully offline) or a digest plus fetch URI (smaller)?
3. What is the smallest taint lattice that policy authors still find understandable?
4. Can model providers sign `(model_id, system_prompt_digest)` so context elements become attested rather than claimed?
5. How should human identities federate across org IdPs without a central registry?
6. When should Codex integration move from proxy + shim to native hooks?

---

## References

- S. Malkapuram, S. Gangavarapu, A. Gangavarapu, K. R. Kavalakuntla. *Context Lineage Assurance for Non-Human Identities in Critical Multi-Agent Systems.* arXiv:2509.18415, 2025.
- Agent2Agent (A2A) Protocol Specification: https://a2a-protocol.org
- B. Laurie, A. Langley, E. Kasper. *Certificate Transparency.* RFC 6962; RFC 9162 (CT v2.0).
- R. Merkle. *A Digital Signature Based on a Conventional Encryption Function.* CRYPTO '87.
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8785: JSON Canonicalization Scheme (JCS)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7638: JSON Web Key Thumbprint
- W3C Web Authentication (WebAuthn) Level 3
- C2SP specifications: tlog-tiles, signed-note, tlog-checkpoint, tlog-witness (https://c2sp.org)
- KERI: Key Event Receipt Infrastructure (pre-rotation)
- IETF KEYTRANS working group; Meta `akd` (Auditable Key Directory)
- Cedar policy language: https://www.cedarpolicy.com
- Biscuit authorization tokens: https://www.biscuitsec.org
- DSSE (Dead Simple Signing Envelope), in-toto / Sigstore
- OpenTelemetry Semantic Conventions for Generative AI
- FIPS 204 (ML-DSA)
- Prompt-injection containment research: CaMeL (Google DeepMind, 2025); FIDES (Microsoft Research, 2025)

