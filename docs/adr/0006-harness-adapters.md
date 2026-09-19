# ADR-0006: Codex and OpenCode adapters, and approvals the agent cannot give itself

- **Status:** accepted
- **Date:** 2026-09-19

## Context

v0.1 gated Claude Code only. Codex and OpenCode expose different extension points, and checking them against their current documentation surfaced one hard constraint:

| | Claude Code | Codex | OpenCode |
|---|---|---|---|
| Mechanism | hook commands in `.claude/settings.json` | hook commands in `.codex/hooks.json` | in-process JS plugins in `.opencode/plugins/` |
| Payload | JSON on stdin | same fields as Claude Code | `tool.execute.before(input, output)` with `input.tool`, `output.args` |
| Block | `permissionDecision: "deny"` or exit 2 | same | throw from `tool.execute.before` |
| **Ask** | `permissionDecision: "ask"` | **parsed but unsupported: Codex marks the hook failed, and a failed hook does not block** | **no way to pause for a human** |
| Turn end | `Stop` | `Stop` (per turn), `SessionEnd` | `session.idle` event |

Codex's behaviour is the dangerous one. Returning `ask`, the natural mapping, would let the action run. The same was already true of Claude Code's exit-code fallback, where `ask` exited 0 — a fail-open that v0.1 shipped and documented rather than fixed.

## Decisions

### 1. One gate, thin adapters

Each harness gets an adapter that maps its payload into the shared normaliser (`src/adapters/common.js`) and maps the decision back into its reply format. Classification, policy, taint, redaction and signing stay in `src/gate.js`. Tool names are canonicalised in the classifier (`bash`→`Bash`, `exec_command`→`Shell`, `apply_patch`→`ApplyPatch`, …) so one policy governs all three.

### 2. `ask` without a native prompt becomes a Provenant approval

When a harness cannot pause for a human (Codex, OpenCode, Claude Code in exit-code mode), `ask` is resolved by Provenant:

1. The action is **blocked** and a pending request is recorded with an id derived from `(session, input digest, class)` — so the id names one exact action.
2. The agent is told to ask the user to run `provenant approve <id>` and to retry the same action.
3. The human runs it in their own terminal. It shows the class, the (redacted) command and the reason, and requires the id to be typed back.
4. The retry of the **identical** input is allowed once, within 10 minutes. The log holds `tool.ask` → `approval` (citing the ask) → `tool.intent` (citing the approval).

A changed command is a different id. An approval is consumed by its first use.

### 3. The agent cannot approve itself

Two independent barriers:

- **Classifier:** `provenant approve`, `provenant init`, `checkpoint` and `hook` run through an agent's shell are `edit.policy`, denied by default. So are writes — by tool, by patch, or by shell redirection — to any harness's hook configuration (`.claude/settings.json`, `.codex/hooks.json`, `.codex/config.toml`, `.opencode/plugins/`, `opencode.json`), whichever harness is running.
- **Terminal:** `provenant approve <id>` refuses unless both stdin and stdout are a TTY. Agent shell tools pipe both.

### 4. Codex: silence means allow

For an allowed action the Codex adapter returns nothing rather than `permissionDecision: "allow"`. An explicit allow could bypass Codex's own approval policy and sandbox; silence leaves them in force. Provenant narrows what Codex permits and never widens it.

### 5. OpenCode: a generated plugin that shells out to Node

The plugin forwards each event to `provenant hook opencode <event>` as a subprocess and throws on deny, rather than importing the gate into OpenCode's process. OpenCode runs plugins in Bun, and the signing path depends on `node:crypto` Ed25519 behaving exactly as in Node; one tested runtime for every harness was worth more than the saved process start. `init` bakes absolute paths to Node and to Provenant into the plugin, so it works whatever PATH OpenCode inherited, and `doctor` reports if either path has moved.

If the subprocess cannot run, the plugin fails closed for everything except a fixed list of read-only tools, so a broken install degrades to a read-only editor rather than an open one.

### 6. Turn end is a checkpoint, not a session end

Codex's `Stop` and OpenCode's `session.idle` fire after every turn. They write a signed checkpoint and leave the session open; `SessionEnd` and `session.deleted` end it.

## Consequences

- `ask` is now safe in every harness and every mode. The Claude Code exit-code fail-open is closed.
- **Approvals prove the chain, not the person.** The `approval` event is signed by the session key, not a human key, so the log shows *that* an approval happened between the ask and the action, and that the agent's own shell could not have issued it — not *who* approved. Passkey-signed approvals (v0.3) close this.
- The TTY check is a strong practical barrier, not a cryptographic one: a determined agent with arbitrary code execution could allocate a pseudo-terminal. That is the same trust boundary as ADR-0003 — the agent runs as the user — and the same fix, the v0.2 daemon under a separate OS user.
- Approval is a round-trip through the user's terminal, which is slower than Claude Code's inline prompt. OpenCode's `permission.ask` hook could route Provenant's `ask` into OpenCode's native prompt; that is deferred until it can be tested against a live OpenCode rather than inferred from type definitions.
- **Neither adapter has been run against a live Codex or OpenCode yet.** Both are built against the published hook and plugin documentation (September 2026) and tested with recorded payloads in `test/fixtures/{codex,opencode}/`; the OpenCode plugin is additionally exercised end to end under Node with real subprocesses. The first live-run discrepancy should become a fixture.
