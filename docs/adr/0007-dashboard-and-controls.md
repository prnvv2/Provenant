# ADR-0007: A local control dashboard, and the pause and deny controls behind it

- **Status:** accepted
- **Date:** 2026-09-19

## Context

With four harnesses (Claude Code, Codex, OpenCode, Cline) a user can have several agents running at once, each asking for approvals in its own way. The CLI answers one question at a time. Users asked for one place to **see** every agent and **act** on it: approve or deny what is waiting, stop an agent that is going wrong, and check that a log is intact.

A control surface is also attack surface, and this one is aimed at the thing Provenant exists to constrain: an agent running as the user, with a shell, able to make HTTP requests to localhost and to read the user's files.

## Decisions

### 1. Controls live in the gate, not the dashboard

The dashboard is a view over three primitives that also exist on the CLI, so a dashboard bug cannot create a capability the CLI lacks:

| Control | Effect | Recorded as |
|---|---|---|
| **Approve once** | the identical action may run once within 10 minutes | `approval` event, `decision.effect: allow`, `context.method: dashboard` |
| **Deny** | the identical action is refused for 10 minutes; a retry cites the denial | `approval` event, `decision.effect: deny` |
| **Pause session** | every action except reads is refused in that session | `control` event in the session's log |
| **Pause all** | the same, for every session in every harness | `control.json` + machine-signed line in `control.jsonl` |

A pause does not kill a process; Provenant cannot. It makes the gate answer *deny* to everything but reads, with a reason that tells the agent to stop and wait. Because every harness already asks the gate, one switch covers all of them. An unreadable `control.json` is read as **paused**: failing closed is the safe reading of "someone may have asked for a stop".

### 2. Threat model for the server

Assume the agent can reach 127.0.0.1, read any file the user can, and run `curl`.

| Threat | Mitigation |
|---|---|
| Agent calls the API with curl | Every `/api` request needs a 256-bit token. It is generated per run, **held only in the server's memory**, never written to disk, and compared in constant time. |
| Agent reads the token from disk | It is never on disk. It reaches the browser in the URL **fragment**, which browsers do not send to servers or in `Referer`; the page moves it into `sessionStorage` and strips it from the address bar. |
| Agent starts its own dashboard to obtain a token | `provenant dashboard`, `pause` and `resume` from an agent's shell are `edit.policy`, denied. |
| Agent targets the port anyway | Requests from agent tools to `127.0.0.1`/`localhost` on port 7717 are `edit.policy`, denied and logged, before the token is even checked. |
| Hostile web page, CSRF | Writes are `POST` with a custom header, which a cross-origin page cannot send without a CORS preflight the server never approves. A present `Origin` must be this server. |
| DNS rebinding | `Host` must be this loopback address and port, so a rebinding hostname is refused. |
| XSS via agent output | Commands and paths are attacker-controlled text. The client builds the DOM with `textContent` only — a test fails the build if `innerHTML` appears — and the CSP (`default-src 'none'; script-src 'self'`, no `unsafe-inline`) blocks inline script, inline styles and every other origin. |
| Remote access | The server binds `127.0.0.1` and has no option to bind anywhere else. |

### 3. No dependencies, no build

`node:http` and three static files. A framework would bring a dependency tree onto the most privileged surface in the project, and a build step would mean shipping code nobody reads. The UI polls every two seconds; server-side it re-reads a session's log only when the file's size or mtime changes.

## Consequences

- One screen shows every agent's activity, pending approvals, and sessions; every control is also available on the CLI and recorded in a verifiable log.
- **The token is a bearer credential.** Anyone who sees the printed link controls the user's agents until the dashboard stops. The CLI says so when it prints it. On Windows the link is briefly visible in the command line of the process that opens the browser; `--no-open` avoids that.
- **Same-user limits still apply.** An agent with arbitrary code execution as the user could, in principle, read the dashboard process's memory or the browser's session storage. That is the ADR-0003 boundary, and the fix is the same: run the daemon and dashboard under a separate OS user.
- The port-based classifier rule protects the default port only. Other ports rely on the token, which is the primary control anyway.
- Pause is cooperative at the harness level: an agent that ignores denials can keep asking, and each attempt is refused and logged. It cannot act.
- The UI has been exercised through its API with a real browser-less client and by static checks on the page (no inline script, no `innerHTML`); it has not yet had a visual review across browsers.
