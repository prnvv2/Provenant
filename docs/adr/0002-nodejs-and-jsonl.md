# ADR-0002: v0.1 is Node.js with a JSONL store, not Rust with SQLite

- **Status:** accepted
- **Date:** 2026-09-17
- **Supersedes:** the stack described in `docs/MVP.md` (Rust + SQLite), for v0.1 only

## Context

`docs/DESIGN.md` specifies a Rust core for good reasons: memory safety on a security boundary, predictable latency, single static binaries, and a verifier that compiles to WASM. That remains the target for the daemon.

For v0.1, three practical facts pointed elsewhere:

1. **A hook is a process spawn.** Claude Code runs a command per tool call, so start-up time, not throughput, dominates.
2. **Install friction decides adoption.** v0.1's audience already has Node; `npx provenant init` needs no toolchain, and a Rust build asks for cargo or a platform binary pipeline before anyone can try it.
3. **SQLite in Node means a native module** (or Node 22's built-in `node:sqlite`, still marked experimental). A native build step on Windows, macOS and Linux is a large cost for what v0.1 stores.

## Decision

- **Runtime:** Node.js ≥ 22, ESM, **zero dependencies** — only `node:` built-ins. Ed25519 and SHA-256 come from `node:crypto`, tests from `node:test`.
- **Store:** one append-only JSONL file per session, plus a small JSON state file and signed checkpoint files.
- **Concurrency:** sequence allocation and appends take a lock directory (atomic `mkdir`), with a 5 s staleness reclaim, because hooks are separate processes and a harness may run tools in parallel.
- Layer 0 (`core/`, `merkle/`) stays free of I/O so it ports to Rust or runs in a browser unchanged.

## Consequences

- **Measured cost:** the in-process gate is p50 3.6 ms / p99 7.4 ms, but the full hook is p50 84 ms on Windows, of which ~80 ms is Node's start-up. That misses the design target of 5 ms end to end.
- Therefore v0.2 keeps the daemon in Rust *and* moves the hook client to a compiled binary; the Node implementation stays as the reference and the library for JS-based harness plugins.
- JSONL has real upsides here: the log is greppable and diffable, corruption is local to a line, and appends need no transaction. Reading a session is O(n), which is fine for thousands of events and is the reason v0.2 revisits storage.
- Zero dependencies means no supply-chain surface for a security tool, and `npm audit` has nothing to report.
