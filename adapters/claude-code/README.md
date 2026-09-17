# Claude Code adapter

`provenant init` writes this configuration for you. This directory documents what
it writes, so you can install it by hand, adapt it, or review it before trusting it.

## What gets installed

`provenant init` merges the hooks below into `.claude/settings.json` in the
current repository, or `~/.claude/settings.json` with `--global`. An existing
file is copied to `settings.json.provenant-backup` first, and any hooks you
already have are kept.

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

`hooks.json` in this directory is the same snippet, ready to copy.

## What each hook does

| Hook | Provenant event | Effect on the session |
|---|---|---|
| `SessionStart` | `session.start` | Creates the session and its signing key; records harness, cwd, model and policy digest |
| `UserPromptSubmit` | `prompt` | Records a trusted context item (digest only, never the prompt text) |
| `PreToolUse` | `tool.intent` / `tool.ask` / `tool.denied` | **Decides.** Returns `allow`, `ask` or `deny` to Claude Code |
| `PostToolUse` | `tool.outcome`, plus `ctx.add` when tainting | Records the result digest; drops session trust after network reads |
| `Stop` | `session.end` | Closes the session and writes a signed checkpoint |

## The decision Claude Code receives

For `PreToolUse`, Provenant writes a permission decision to stdout and exits 0:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by Provenant [secret.read]: Credential files are off limits…"
  },
  "provenant": { "session": "sess-…", "event": "sha256:…", "class": "secret.read", "policy": "deny-secret-read", "taint": "external" }
}
```

The `provenant` block is informational; Claude Code ignores it, and it makes the
transcript self-explaining when you read it back.

If your Claude Code version does not honour that response shape, set
`PROVENANT_HOOK_MODE=exitcode` to use the exit-code protocol instead: exit 2 with
the reason on stderr blocks the call. In that mode Provenant cannot express
`ask`, so escalations are allowed through and recorded as `tool.ask`.

## Verifying the wiring

```bash
provenant doctor      # checks the store, key, policy and that hooks are wired
provenant status      # shows the session once the agent has run
```

To test a hook by hand, without an agent:

```bash
echo '{"session_id":"manual","cwd":"'"$PWD"'","tool_name":"Bash","tool_input":{"command":"cat .env"}}' \
  | provenant hook claude pre-tool
```

## Version compatibility

Hook names, payload fields and the response shape belong to Claude Code and change
between versions. Everything version-specific lives in
[`src/adapters/claude.js`](../../src/adapters/claude.js) and is pinned by recorded
payloads in [`test/fixtures/claude/`](../../test/fixtures/claude/).

The adapter reads `session_id`, `cwd`, `tool_name`, `tool_input`, `tool_response`,
`prompt` and `model`, and tolerates the camelCase spellings. If a payload arrives
without a tool name, the hook is a no-op rather than an error.

**If a hook payload cannot be parsed, `PreToolUse` fails closed and denies.** The
same applies if the gate itself throws for a mutating action; read-only actions
are allowed through with the failure reported on stderr.

If you hit a version mismatch, please open an issue with the payload (paths and
prompts redacted) — that is exactly the fixture the test suite needs.
