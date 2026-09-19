# OpenCode adapter

```bash
provenant init --harness opencode            # this repo:  .opencode/plugins/provenant.js
provenant init --harness opencode --global   # every repo: ~/.config/opencode/plugins/provenant.js
```

OpenCode loads every plugin in those directories at startup. Restart OpenCode after installing.

## What gets installed

A generated plugin file. It doesn't make any decisions itself. It forwards each event to Provenant and blocks when told to:

| OpenCode hook | Provenant event | Effect |
|---|---|---|
| `tool.execute.before` | `pre-tool` | **Decides.** Throws to block on deny or ask |
| `tool.execute.after` | `post-tool` | Records the result digest. A web fetch drops session trust |
| `chat.message` | `prompt` | Records your message as trusted input (digest only) |
| `event: session.idle` | `idle` | Signs a checkpoint at the end of each turn |
| `event: session.deleted` | `session-end` | Closes the session |

The plugin runs `node <provenant>/bin/provenant.js hook opencode <event>` as a subprocess, with absolute paths written in by `init`. It works regardless of the PATH OpenCode inherited. If you move your Node install or your Provenant checkout, re-run `init`. `provenant doctor` tells you when the paths have gone stale.

**Why a subprocess?** OpenCode runs plugins in Bun. Running the gate under Node keeps one tested code path for signing and verification across every harness. The cost is a process start per tool call. See [ADR-0006](../../docs/adr/0006-harness-adapters.md).

## Approving an action

OpenCode's `tool.execute.before` can block, but it can't pause to ask you. When Provenant decides **ask**, the plugin blocks with an approval id:

```
Provenant: this action needs human approval [net.egress]: This session has read untrusted
content, so outbound network access needs approval. Ask the user to review it and run
`provenant approve apr-8d02c1b7aa` in their own terminal, then retry exactly the same action.
```

In **your own terminal**, run `provenant approve` to list what's waiting, then `provenant approve <id>` and type the id back. Then tell OpenCode to retry. The approval covers **that exact action, once, for 10 minutes**.

The agent can't approve itself. `provenant approve` from its shell is denied, and approval needs an interactive terminal.

## If Provenant can't be reached

If the subprocess fails (moved paths, broken install, a 15 s timeout), the plugin **fails closed**. Every tool is blocked except read-only ones (`read`, `grep`, `glob`, `list`, `lsp`, and todo/question/skill). A broken install leaves you with a read-only editor, not an unguarded one. The error names the cause in one line and suggests `provenant doctor`.

## Tool names

OpenCode's tools map onto Provenant's classes like this:

| OpenCode | Provenant treats it as |
|---|---|
| `bash` | shell command, classified by content |
| `read`, `grep`, `glob`, `list`, `lsp` | read (or `secret.read` for credential paths) |
| `edit`, `write` | edit, or `edit.outside` / `edit.policy` / `secret.read` by path |
| `apply_patch`, `patch` | classified by the most dangerous file in the patch |
| `webfetch`, `websearch` | `net.egress`, which also taints the session |
| `task` | `delegate` |

The plugin file, `opencode.json` and `.opencode/plugins/` are all protected. An agent that tries to edit them is denied, which stops it switching the guard off.

## Status

Built against OpenCode's published plugin API (September 2026). Tested with recorded payloads in [`test/fixtures/opencode/`](../../test/fixtures/opencode/), and by running the generated plugin under Node with real subprocesses, including the fail-closed path. **It hasn't been run inside a live OpenCode (Bun) yet.** If the plugin doesn't load or a hook misbehaves, please open an issue with the OpenCode version and the error.
