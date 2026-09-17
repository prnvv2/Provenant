---
name: Classifier or policy problem
about: A tool call was blocked when it should have been allowed, or allowed when it should have been blocked
labels: policy
---

**What happened**

Which decision did you get, and which did you expect?

**The action**

Run this and paste the output. It reports the classification and rule, not file contents:

```
provenant explain --tool <ToolName> --input '<tool input as JSON>' --json
```

**Versions**

```
provenant --version
node --version
```

OS:
Claude Code version:

**Policy**

The default policy, or the rule you think should have matched.
