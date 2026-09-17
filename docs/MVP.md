# Provenant v0.1 MVP

> **Two decisions changed after this was written, while building v0.1:** the
> implementation is Node.js with a JSONL store rather than Rust with SQLite
> ([ADR-0002](adr/0002-nodejs-and-jsonl.md)), and the policy engine is declarative
> JSON rather than Cedar ([ADR-0005](adr/0005-policy-engine.md)). Both ADRs give the
> reasoning and the measured costs. The scope and acceptance criteria below held.

> **Status:** planned, not implemented.
> The [README](../README.md) describes the full system. This document defines the first usable release: the smallest version that proves the core ideas.

---

## In one sentence

**v0.1 is a Claude Code plugin that checks every tool call against a policy before it runs, signs a record of each decision, and stores it in a local tamper-evident Merkle log that `provenant verify` can check.**

- One machine
- One harness (Claude Code)
- No server

---

## Why this scope

The full design has many parts: key-rotation logs, revocation, witnesses, credential brokering, cross-agent receipts. None of them matter unless three core ideas work first:

1. **Decide before acting.** Policy is checked *before* a tool runs, not only logged afterwards.
2. **Context changes authority.** An agent that has read outside content gets less trust.
3. **History is tamper-evident.** Any change to the record is detected and pinpointed.

v0.1 proves those three ideas and nothing more.

---

## Demo scenario (definition of done)

If this works end to end on Windows, macOS and Linux, v0.1 is done.

```text
$ provenant init
  ✓ created machine key
  ✓ installed default policy  (.provenant/policy.cedar)
  ✓ wired Claude Code hooks

$ claude
  > "read the issue at https://github.com/acme/api/issues/42 and fix it"

  WebFetch https://github.com/...        → allow   (session taint: external)
  Read src/auth.rs                       → allow
  Edit src/auth.rs                       → allow
  Bash: cat ~/.ssh/id_ed25519            → DENY    secret.read is not allowed
  Bash: cargo test                       → allow
  Bash: git push origin main             → ASK     protected push after external content

$ provenant log
  sess-7f3a  09:14:03  ctx.add      WebFetch            taint=external
  sess-7f3a  09:14:09  tool.intent  Edit src/auth.rs    allow
  sess-7f3a  09:14:21  tool.denied  Bash                secret.read
  ...

$ provenant verify
  ✓ 23 events · signatures valid · Merkle root matches checkpoint #4

# tamper with the log
$ sqlite3 ~/.provenant/lineage.db "UPDATE events SET body = '...' WHERE seq = 7"

$ provenant verify
  ✗ event 7: leaf hash mismatch (log modified after checkpoint #4)
```

---

## Scope

| In v0.1 | Deferred |
|---|---|
| Claude Code hooks: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop` | OpenCode, Codex (v0.2) |
| Cedar policy with **allow / deny / ask** | Biscuit grants, delegation to subagents |
| ~8 action classes: `read`, `edit`, `edit.outside`, `secret.read`, `exec`, `net.egress`, `git.push`, `git.push.protected` | Full tree-sitter shell classifier (v0.1 uses a simple tokenizer) |
| Minimal taint: WebFetch / WebSearch / `curl` output marks the session `external` | Full context ledger and `context_root` |
| One Ed25519 machine key + per-session key signed by it | Key rotation history, key-status registry, revocation, leases |
| Signed events in DSSE envelopes, RFC 8785 canonical JSON | CBOR, lineage receipts, evidence capsules |
| Local RFC 6962 Merkle tree in SQLite + locally signed checkpoints | Two-tier anchoring, shared log server, witnesses |
| CLI: `init`, `hook`, `log`, `verify`, `status` | `grant`, `approve`, `revoke`, `verify-pr`, console |
| "ask" uses Claude Code's own permission prompt | Passkey (WebAuthn) approvals |
| *Stretch:* git commit trailers linking commits to events | Credential broker, DPoP |

---

## Key design decision: no daemon yet

The full architecture has a separate daemon (`agentd`) running as its own OS user. **v0.1 skips it.**

Each hook runs a short-lived process:

```text
Claude Code hook
  └─ provenant hook claude <event>
       1. read hook JSON from stdin
       2. open SQLite (WAL mode)
       3. load policy
       4. classify action → evaluate Cedar → allow | deny | ask
       5. sign event, append leaf to Merkle tree
       6. print decision JSON to stdout, exit
```

**Why:** it avoids IPC, service installation on three operating systems, and daemon lifecycle bugs. A Rust binary doing this should be fast enough; the target is under ~25 ms per hook, measured and not assumed.

**Trade-off:** without a separate OS user, the agent runs as the developer and *could* read the key or edit the database.
- Tampering is still **detected**, provided the checkpoint root is kept somewhere the agent can't rewrite (printed by `verify`, stored by CI, or noted by the user).
- Real **isolation** arrives with the daemon in v0.2.
- The core crates stay I/O-free, so adding the daemon later doesn't require rewriting them.

This trade-off is recorded in `docs/adr/0001-mvp-scope.md` and stated plainly in the README.

---

## Codebase

v0.1 has 5 crates, not the ~25 in the full layout:

```text
provenant/
├── Cargo.toml                  # workspace
├── crates/
│   ├── core/                   # event types, JCS, DSSE, ids: no I/O
│   ├── merkle/                 # RFC 6962: leaf/node hash, root, inclusion proof, verify
│   ├── policy/                 # action classifier + Cedar evaluation + taint rule
│   ├── store/                  # SQLite: events, tree, checkpoints; key file / OS keychain
│   └── cli/                    # `provenant` binary: init, hook, log, verify, status
├── adapters/
│   └── claude-code/            # plugin manifest + hooks config
├── policies/
│   └── default.cedar
├── spec/
│   └── vectors/                # event → canonical bytes → leaf hash → root
└── tests/                      # recorded hook payloads → expected decisions
```

Dependency rule: `core` and `merkle` have **no I/O**. `policy` depends only on `core`. `store` and `cli` do the I/O.

---

## Data shapes

### Event

```jsonc
{
  "v": 1,
  "alg": "ed25519",
  "type": "tool.intent",            // session.start | ctx.add | tool.intent | tool.outcome | tool.denied | session.end
  "session": "sess-7f3a",
  "id": "01JAB3…",                  // ULID
  "seq": 7,
  "ts": "2026-09-17T09:14:21.004Z",
  "parent": "sha256:…",             // leaf hash of previous event in session
  "action": { "class": "secret.read", "tool": "Bash", "resource": "~/.ssh/id_ed25519" },
  "input": "sha256:…",              // digest of canonical tool input
  "taint": "external",
  "decision": { "effect": "deny", "policy": "deny-secret-read" }
}
```

### Hashing

```text
canonical = JCS(DSSE envelope)
leaf      = SHA-256(0x00 ‖ canonical)
node      = SHA-256(0x01 ‖ left ‖ right)
root      = RFC 6962 Merkle Tree Hash over all leaves
```

### Checkpoint

```text
provenant/local/<machine-id>
<tree size>
<base64 root>
<timestamp>
— <machine key signature>
```

### Default policy (sketch)

```cedar
// secrets are never readable by agents
forbid(principal, action == Action::"secret.read", resource);

// writes outside the workspace are denied
forbid(principal, action == Action::"edit.outside", resource);

// reading and editing inside the workspace is fine
permit(principal, action in [Action::"read", Action::"edit"], resource);

// pushing to non-protected branches is fine
permit(principal, action == Action::"git.push", resource);

// network egress and protected pushes → ask when tainted
@effect("ask")
permit(principal, action in [Action::"net.egress", Action::"git.push.protected"], resource)
when { context.taint == "external" };
```

> Cedar has no native "ask" effect. v0.1 represents it with a policy annotation that the `policy` crate reads after evaluation.

---

## Build order

| # | Step | Why this order |
|---|---|---|
| 1 | `merkle` + RFC 6962 test vectors | Pure logic, easiest to get exactly right, everything depends on it |
| 2 | `core`: event struct, JCS, DSSE sign/verify | Defines the data everything else stores |
| 3 | `store`: append event, compute root, write checkpoint | Persistence |
| 4 | `cli verify` and `cli log` | Log can be checked without any harness |
| 5 | `policy`: classifier + Cedar + taint rule, tested on recorded hook payloads | Decision logic, fully testable offline |
| 6 | `cli hook claude` + plugin wiring → run the demo | End-to-end integration |
| 7 | `cli init`: key generation, default policy, hook installation | Makes it installable |

---

## Acceptance criteria

- [ ] The demo scenario above works on Windows, macOS and Linux
- [ ] `merkle` matches RFC 6962 test vectors and passes property tests (random appends → proofs verify)
- [ ] Any modification to the log database makes `verify` fail and name the bad event
- [ ] Policy decisions have tests built from recorded Claude Code hook payloads
- [ ] Fail-closed: if `provenant hook` crashes, mutating actions are blocked
- [ ] Hook latency is measured and written in the README, whatever the number is
- [ ] Install to first protected session takes under 5 minutes

---

## What v0.1 does not protect against

Stated up front so nobody over-trusts the MVP:

- **An agent that deliberately tampers with its own key or database.** This is detected by `verify` against an externally kept checkpoint, but not prevented. Isolation comes in v0.2.
- **Actions that bypass Claude Code's hooks**, such as a process spawned outside the harness.
- **Other harnesses.** OpenCode and Codex come in v0.2.
- **Prompt injection itself.** v0.1 limits what a tainted session may do. It doesn't detect the injection.

---

## First commit contents

```text
README.md                       # full design; notes that v0.1 = local Claude Code guard
LICENSE                         # Apache-2.0
SECURITY.md                     # private vulnerability reporting
CONTRIBUTING.md                 # ADR process, commit style
.gitignore                      # target/, *.db, .provenant/
Cargo.toml                      # workspace with 5 empty crates
docs/MVP.md                     # this file
docs/adr/0001-mvp-scope.md      # scope table + "no daemon yet" decision
```

Notes:
- **Don't commit the research PDF.** Link to [arXiv:2509.18415](https://arxiv.org/abs/2509.18415) instead.
- Add one line near the top of the README: *"v0.1 implements the local Claude Code guard; everything else is roadmap."*

---

## After v0.1

| Release | Adds |
|---|---|
| v0.2 | `agentd` daemon with OS-user isolation · OpenCode plugin · Codex MCP proxy + exec shim · context ledger |
| v0.3 | Shared anchor log · witnesses · human grants · passkey approvals · `verify-pr` CI gate |
| v0.4 | Key rotation history · revocation · credential broker |
| v0.5 | Cross-agent receipts · A2A agent cards · federation |

See the [README roadmap](../README.md#roadmap) for details.
