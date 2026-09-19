# Codex adapter

```bash
provenant init --harness codex            # this repo:  .codex/hooks.json
provenant init --harness codex --global   # every repo: ~/.codex/hooks.json
```

Codex runs lifecycle hooks with the same JSON protocol as Claude Code, and current Codex releases enable hooks by default. If yours doesn't, add this to `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

## What gets installed

Merged into `.codex/hooks.json`. Your own hooks are kept, and the original file is backed up to `hooks.json.provenant-backup` first:

```json
{
  "hooks": {
    "SessionStart":     [{ "hooks": [{ "type": "command", "command": "provenant hook codex session-start", "commandWindows": "provenant hook codex session-start", "timeout": 30 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "provenant hook codex prompt", "…": "…" }] }],
    "PreToolUse":       [{ "matcher": "*", "hooks": [{ "type": "command", "command": "provenant hook codex pre-tool", "…": "…" }] }],
    "PostToolUse":      [{ "matcher": "*", "hooks": [{ "type": "command", "command": "provenant hook codex post-tool", "…": "…" }] }],
    "Stop":             [{ "hooks": [{ "type": "command", "command": "provenant hook codex stop", "…": "…" }] }],
    "SessionEnd":       [{ "hooks": [{ "type": "command", "command": "provenant hook codex session-end", "…": "…" }] }]
  }
}
```

## How decisions reach Codex

| Provenant decides | Codex receives | Why |
|---|---|---|
| **allow** | nothing (exit 0) | Silence leaves Codex's own approval policy and sandbox in force. An explicit `allow` could skip them. Provenant only ever narrows. |
| **deny** | `permissionDecision: "deny"` with the reason | The agent sees why and adapts. |
| **ask** | `permissionDecision: "deny"` with an approval id | Codex parses `"ask"` in PreToolUse but doesn't support it: the hook counts as failed, and a failed hook doesn't block. Returning `ask` would let the action run. |

## Approving an action

When Provenant needs you, the agent is blocked with a message like:

```
Provenant: this action needs human approval [git.push.protected]: Pushing to a protected
branch or force-pushing needs a human decision. Ask the user to review it and run
`provenant approve apr-4aca31fde9` in their own terminal, then retry exactly the same action.
```

In **your own terminal**:

```console
$ provenant approve                  # see what's waiting
1 action(s) waiting for approval:
  apr-4aca31fde9  git.push.protected  git push origin main
                  ↳ Pushing to a protected branch or force-pushing needs a human decision.

$ provenant approve apr-4aca31fde9
Approve this action?
  class     git.push.protected
  action    git push origin main
  …
Type the id (apr-4aca31fde9) to approve, anything else to cancel: apr-4aca31fde9
✓ approved apr-4aca31fde9 — the agent can retry now
```

Then tell Codex to go ahead. The approval covers **that exact command, once, for 10 minutes**. A changed command needs a new approval.

The agent can't approve itself. `provenant approve` run through its shell is denied as a policy edit, and approval refuses to run without an interactive terminal. See [ADR-0006](../../docs/adr/0006-harness-adapters.md) for what this does and doesn't prove.

## Tools covered

Codex fires PreToolUse for `Bash`, `exec_command` (including `["bash","-lc","…"]` argv forms), `apply_patch`, and MCP tools. `apply_patch` is classified by the most dangerous file it names, so a patch that edits `src/app.ts` and `.codex/hooks.json` together counts as a policy edit.

Codex's hosted `WebSearch` tool doesn't fire hooks, so Provenant can't see those searches and doesn't taint the session for them. Pages fetched through the shell (`curl`, `wget`) are seen and do taint it.

## Status

Built against Codex's published hooks documentation (September 2026) and tested with recorded payloads in [`test/fixtures/codex/`](../../test/fixtures/codex/). **It hasn't been run against a live Codex yet.** If a hook misbehaves, run `provenant doctor` and open an issue with the payload (redacted) — that's exactly the fixture the test suite needs.
