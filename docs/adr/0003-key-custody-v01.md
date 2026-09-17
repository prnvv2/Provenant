# ADR-0003: v0.1 keeps the machine key in a file, and says so

- **Status:** accepted
- **Date:** 2026-09-17

## Context

Provenant signs events so that a log cannot be rewritten undetectably. That guarantee depends on where the signing key lives. In v0.1 the CLI runs **as the developer's own user**, in the same session as the agent it is gating. An agent with shell access has the same file access the CLI has.

Options considered:

1. **File under `~/.provenant/keys/`, mode 0600.** Simple; readable by the agent.
2. **OS keychain** (macOS Keychain, Windows DPAPI, Secret Service). Needs a native module, and still unlocks for any process running as that user — so it raises the effort, not the guarantee.
3. **TPM / Secure Enclave.** A real improvement, and non-exportable, but needs native code, and the *signing oracle* is still reachable by anything running as the user.
4. **Separate daemon as another OS user, hardware-backed keys.** The actual answer, and too much for v0.1.

## Decision

Use option 1 for v0.1, with a two-key structure so the design does not have to change later:

- a **machine key** (PKCS#8 PEM, mode 0600) that signs checkpoints and certifies session keys;
- a **session key** per agent run, generated at session start, which signs that session's events; its certificate (machine-signed) is stored in the session state.

`provenant verify` checks the certification, so a log re-signed with a freshly generated key fails at `key.binding` even though every event signature is internally consistent.

## Consequences

- The threat model is stated plainly in the README: v0.1 **detects** tampering, it does not prevent it. Detection is only reliable against an off-box root, which is why `checkpoint` appends every root to `roots.jsonl` and tells the user to copy it.
- `0600` has no effect on Windows ACLs. The code notes this rather than implying protection it does not provide.
- The two-key structure is what v0.2 needs anyway: the daemon takes over the machine key under its own user, and nothing about the event or verification format changes.
- Session keys are kept in the session state file, which means a session's key is readable for the session's lifetime. v0.2 keeps them in daemon memory instead.
