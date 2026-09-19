# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting (Security → Report a vulnerability) on this repository. If that is unavailable, contact a maintainer listed in `GOVERNANCE.md` and ask for a private channel before sending details.

Please include what you were running (`provenant --version`, OS, Node version), the policy in force, and the smallest sequence of steps that reproduces the problem. A failing test case is the most useful thing you can send.

**What to expect:** acknowledgement within 3 working days, an assessment within 10, and coordinated disclosure within 90 days of the report or on the day a fix ships, whichever is earlier. Credit is given unless you ask otherwise.

## Scope

Provenant is pre-1.0 and has not been externally audited.

### In scope

- Bypassing a `deny` or `ask` decision through a tool call the classifier mishandles, including shell composition, quoting, encoding or path traversal that hides intent.
- Forging, altering, reordering or deleting log entries in a way `provenant verify` reports as valid.
- Signature verification that accepts a bad signature, a wrong key, an uncertified session key, or an event whose payload type was changed.
- Merkle proof code that accepts a false inclusion or consistency proof, including second-preimage tricks against leaf and node hashing.
- Causing the gate to fail **open** for a mutating action — for example a crafted hook payload that produces `allow` or `continue` where the guard should have blocked.
- Reading secret material out of the store, log or `provenant` output: private keys, tool inputs, file contents, tokens.
- A credential shape that survives redaction into a recorded event — for example a token form the pattern list misses, or an encoding that evades it. Send the command line (with the secret replaced by an obviously fake value of the same shape).
- Privilege escalation through `provenant init`, such as the settings-file merge writing somewhere unintended.
- An agent obtaining an approval it should not have: approving its own request, reusing an approval for a different or repeated action, using one after it expires, or disabling the guard by writing any harness's hook configuration.
- A Codex, OpenCode or Cline path where an action Provenant denies or escalates still runs.
- **The dashboard:** any way to reach its API without the token, to obtain the token (from disk, logs, headers, or the page), to get the server to act on a cross-origin or rebinding request, to inject script through agent-supplied text, to make it listen beyond loopback, or to lift a pause without the token or an interactive CLI.

### Known limitations, not vulnerabilities

These are documented design limits of v0.1 (see the README and `docs/adr/0003-key-custody-v01.md`). Reports describing them are welcome as issues, but they are not treated as vulnerabilities:

- The agent runs as the same OS user as Provenant, so it can read `~/.provenant`, including the machine key and session keys. v0.1 **detects** tampering rather than preventing it; detection is reliable only against a checkpoint root kept where the agent cannot write. Isolation arrives with the v0.2 daemon.
- Actions taken outside the harness's hooks are not gated.
- An `approval` event is signed by the session key, not a human key: it proves an approval sat between the ask and the action and did not come from the agent's shell, not which person gave it. The interactive-terminal requirement is a practical barrier; an agent with arbitrary code execution as the same user could allocate a pseudo-terminal. Both close with the daemon and passkey approvals.
- `ask` decisions rely on the harness's own prompt and are not cryptographically bound to the action; passkey approvals are v0.3.
- The shell classifier is a tokeniser, not a shell. A *specific* misclassification is in scope and valuable; "a tokeniser is not a parser" is a known limitation.
- The dashboard link is a bearer credential while the dashboard runs. An agent with arbitrary code execution as the same user could read it from the dashboard process's memory or the browser's session storage; that is the same-user boundary as the keys, closed by the planned daemon under a separate OS user.
- Root-compromised hosts are out of scope.

## Supported versions

Only the latest release of the `0.x` line receives security fixes. Until 1.0, a security fix may ship as a minor release with a behavioural change if that is the safer option.

## Practices

Recorded text passes through redaction (`src/core/redact.js`) before it is written or displayed: credential flags, URL userinfo, sensitive query parameters, vendor token prefixes, JWTs and PEM blocks are replaced with a marker. This is defence in depth, not a guarantee — the reliable fix is not putting secrets on a command line, which is what the credential broker in a later release is for. Redaction fires on structure rather than entropy, so digests, commit SHAs and paths stay readable for auditing.

Provenant makes **no network calls** and collects no telemetry. Events store digests of tool inputs and outputs, never their content.

Provenant has **no runtime dependencies** — only Node's built-in modules — so a compromised transitive package cannot reach the security boundary. Cryptography uses `node:crypto` (Ed25519, SHA-256) and the Merkle implementation is tested against test vectors generated by an independent Python implementation. We do not write our own primitives.
