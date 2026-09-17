---
name: Harness payload mismatch
about: A hook failed, was ignored, or the decision did not reach the agent
labels: adapter
---

**What you saw**

For example: the hook errored, the agent proceeded anyway, or `provenant log` recorded nothing.

**The payload**

Paste the hook JSON with paths, prompts and any tokens redacted. This becomes a test fixture.

```json
{ }
```

**Versions**

```
provenant --version
node --version
```

Claude Code version:
OS:

**Output of**

```
provenant doctor
```
