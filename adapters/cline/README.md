# Cline adapter

```bash
provenant init --harness cline            # this repo:  .clinerules/hooks/
provenant init --harness cline --global   # every repo: ~/Documents/Cline/Rules/Hooks/
```

Then enable hooks in Cline: **Settings → Features → Hooks**.

> **Platform:** Cline documents hooks as **macOS and Linux only**. Provenant writes the hook scripts on Windows too, and `init` warns you, but Cline may not run them there.

## What gets installed

One small executable per Cline hook event, each forwarding to Provenant:

| Cline hook file | Provenant event | Effect |
|---|---|---|
| `TaskStart`, `TaskResume` | `task-start`, `task-resume` | Opens or resumes the session for this task |
| `UserPromptSubmit` | `prompt` | Records your message as trusted input (digest only) |
| `PreToolUse` | `pre-tool` | **Decides.** Replies `{"cancel": true}` to block |
| `PostToolUse` | `post-tool` | Records the result. A web fetch lowers the session's trust level |
| `TaskComplete` | `task-complete` | Signs a checkpoint |
| `TaskCancel` | `task-cancel` | Closes the session |

Each script is two lines of shell with absolute paths to Node and Provenant written in, so it doesn't depend on the PATH that Cline's extension host inherited:

```sh
#!/bin/sh
exec '/usr/local/bin/node' '/home/you/Provenant/bin/provenant.js' hook cline pre-tool
```

If you already have your own `PreToolUse` hook, `init` **leaves it alone**. It also reports that Cline is **not gated**, and exits non-zero. Provenant can't gate an event it isn't hooked into, and saying it could would be dishonest.

## How decisions reach Cline

| Provenant decides | Cline receives |
|---|---|
| **allow** | `{"cancel": false}` |
| **deny** | `{"cancel": true, "errorMessage": "…", "contextModification": "…"}` |
| **ask** | a cancel that carries an approval id |

`contextModification` keeps the reason in the conversation, so the model adapts instead of retrying blindly.

Cline's `PreToolUse` can cancel, but it can't pause to ask you. So when Provenant decides **ask**, the call is cancelled with an approval id. Approve it with `provenant approve <id>` in your own terminal, or with **Approve once** in the dashboard (`provenant dashboard`). Then let Cline retry. The approval covers that exact action, once, for 10 minutes.

## Tool names

| Cline | Provenant treats it as |
|---|---|
| `execute_command` | shell command, classified by content |
| `read_file`, `search_files`, `list_files`, `list_code_definition_names` | read (or `secret.read` for credential paths) |
| `write_to_file`, `replace_in_file` | edit, or `edit.outside` / `edit.policy` / `secret.read` by path |
| `web_fetch`, `browser_action` | `net.egress`, which also lowers the session's trust level |
| `use_mcp_tool`, `access_mcp_resource` | `mcp`, recorded as `server/tool` |
| `new_task` | `delegate` |
| `ask_followup_question`, `attempt_completion`, `plan_mode_respond` | read (no side effects) |

`.clinerules/hooks/` and the global hooks folder are protected. An agent that tries to write there is denied, which stops it switching the guard off. Other `.clinerules/` files are ordinary rules and can be edited.

## Status

Built from Cline's published hook descriptions: the [v3.36 hooks announcement](https://cline.bot/blog/cline-v3-36-hooks) and the [plugins and hooks post](https://cline.bot/blog/extend-cline-with-plugins-and-hooks). Cline's reference page now points to its SDK plugin docs, so the stdin field names come from those posts and from third-party integrations. Tested with recorded payloads in [`test/fixtures/cline/`](../../test/fixtures/cline/), and on macOS and Linux by running the generated scripts under `/bin/sh`.

**This adapter hasn't been run inside a live Cline yet.** If a hook misbehaves, open an issue with Cline's version and the (redacted) stdin payload. That payload becomes a test fixture.
