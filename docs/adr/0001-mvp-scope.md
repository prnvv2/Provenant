# ADR-0001: v0.1 scope is a local Claude Code gate

- **Status:** accepted
- **Date:** 2026-09-17

## Context

The full design (`docs/DESIGN.md`) has an edge daemon, a shared anchor log, witnesses, key rotation, revocation, credential brokering and cross-agent receipts. Building all of it before anything is usable would mean months with no feedback, and most of those parts only earn their complexity once the core ideas are proven.

Three ideas carry the value:

1. Authorization happens **before** the action, not only in a log afterwards.
2. What the agent has **read** changes what it may **do**.
3. The record is **tamper-evident**.

## Decision

v0.1 ships exactly those three, for one harness, on one machine, with no server.

**In:** Claude Code hooks (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`); a declarative policy with allow/ask/deny; ~16 action classes; minimal taint (network reads drop the session to `external`); a machine key certifying per-session keys; DSSE-signed events in an RFC 6962 Merkle tree; signed checkpoints; `init`, `status`, `log`, `verify`, `checkpoint`, `policy`, `explain`, `doctor`.

**Out, with the release that adds it:** daemon isolation and other harnesses (v0.2); shared log, witnesses, human grants, passkey approvals (v0.3); key rotation, revocation, credential broker (v0.4); receipts and federation (v0.5).

## Consequences

- Someone can adopt it in five minutes with no infrastructure, which is the only way to get real feedback on the policy defaults.
- The honest limitation is that v0.1 **detects** log tampering rather than preventing it, and only if a root is kept where the agent cannot write. This is stated in the README rather than glossed over.
- The class set and the event schema are the parts hardest to change later, so they get the most care now; the policy engine and store are deliberately swappable.
