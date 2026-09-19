# Contributing to Provenant

Thanks for looking. Provenant is early, so the most valuable contributions right now are **real sessions that went wrong**: a command the classifier got wrong, an approval prompt that fired when it should not have, a harness payload we mishandled.

## Getting set up

```bash
git clone https://github.com/prnvv2/provenant && cd provenant
node --version         # needs >= 22
node --test            # runs everything; no install step, no dependencies
npm link               # puts `provenant` on your PATH for manual testing
```

There is nothing to build and nothing to install. If a change needs a dependency, that is a discussion first (see below).

```bash
node --test                        # full suite
node --test test/policy.test.js    # one file
npm run bench                      # latency measurements
npm run vectors                    # regenerate Merkle vectors (needs python3)
```

## Ground rules

**No runtime dependencies.** Provenant is a security tool; every package in `dependencies` is attack surface on the boundary it defends. If you believe a dependency is genuinely necessary, open an issue arguing the case before writing code. Dev-only tooling is a smaller question but still needs a reason.

**Layer 0 stays pure.** `src/core/` and `src/merkle/` must not do I/O, use `async`, or read the environment. They are the parts that will be ported to Rust and compiled to WASM, and the parts most worth testing in isolation.

**Fail closed.** If the gate cannot decide, mutating actions must be blocked. Any new code path on the decision route needs a test proving it does not fail open — see `test/adapter.test.js` for the pattern.

**Never commit a realistic secret, even a fake one.** Test fixtures that look like real tokens are blocked by GitHub push protection and by contributors' own scanners — this happened to `test/redact.test.js` once. Assemble sample secrets at runtime from fragments, as that file now does; the pattern under test is identical and the repository stays pushable.

**Never log content.** Events carry digests, classes and decisions. Tool inputs, file contents, prompts and outputs must not be written to the log. `test/lineage.test.js` asserts this; keep it true.

**Don't change the event format casually.** The leaf hash is computed over canonical bytes, so any change to `buildEvent`, the canonicaliser or the envelope invalidates existing logs. Such a change needs an ADR, a `v` field bump and a note in `CHANGELOG.md`.

## Tests are the specification

- **Classifier and policy:** add a row to the tables in `test/policy.test.js`. That table is the normative description of what each class means, so a new class or command family belongs there first.
- **Merkle code:** add a vector to `scripts/gen_vectors.py`, regenerate, and let the JS be checked against the Python. Do not write expected hashes by hand.
- **Harness payloads:** add a real (redacted) payload to `test/fixtures/<claude|codex|opencode>/` and a case in `test/adapter.test.js` or `test/harnesses.test.js`. Redact paths, prompts and tokens. The Codex and OpenCode adapters were built from documentation, so **a payload captured from a live run is the single most useful contribution right now**.
- **Security behaviour:** a test that tampering is detected, or that a bypass is blocked, is worth more than three tests of happy paths.

A bug fix should come with the test that would have caught it. Several bugs found while building v0.1 — a path-with-spaces failure and a BOM on piped stdin — came from exactly these suites.

## Decisions get recorded

Anything that closes off an alternative gets an ADR in `docs/adr/`, numbered, in the existing format: context, decision, consequences — including the consequences you do not like. Read `docs/adr/0002-nodejs-and-jsonl.md` for the tone: it states the measured cost of its own choice.

Open an issue before starting on: a new harness adapter, a change to the event schema or hashing, a new action class, a dependency, or anything in `src/core/`.

## Pull requests

- One concern per PR; a refactor and a behaviour change should be two.
- `node --test` passes on your platform. CI covers Linux, macOS and Windows — path handling and file locking genuinely differ, so expect Windows to catch things.
- Explain *why* in the description. The what is in the diff.
- Comments should say why a thing is done, not restate the code. Match the surrounding style.
- Adapters stay thin: mapping only, with all logic in `src/gate.js`. Target under 300 lines.

## Reporting issues

For a classifier or policy problem, the fastest useful report is:

```bash
provenant explain --tool Bash --input '{"command":"<the command>"}' --json
provenant --version && node --version
```

plus what you expected instead. For security issues, read [SECURITY.md](SECURITY.md) first — do not open a public issue.

By contributing you agree your work is licensed under Apache-2.0, and that you have the right to submit it.
