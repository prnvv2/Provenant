# Governance

Provenant is at the stage where one person can still hold the whole design in
their head. This document says how decisions get made now and what changes as
the project grows.

## Today (pre-1.0)

- **Maintainers:** listed in `MAINTAINERS` once there is more than one. Until
  then, the repository owner is the sole maintainer and reviewer.
- **Decisions:** anything that closes off an alternative is recorded as an ADR in
  `docs/adr/`. Disagreement with a decision is raised as an issue referencing the
  ADR; a superseding ADR is how a decision gets reversed.
- **Spec changes** (event schema, hashing, canonicalisation, receipts) follow:
  issue → 14-day comment period → ADR → test vectors → implementation. The event
  format determines whether old logs stay verifiable, so it moves slowly.
- **Review:** changes to `src/core/`, `src/merkle/` or `src/policy/` need a second
  reviewer once a second maintainer exists. Until then they get the most test
  coverage and the slowest merges.

## Growing up

The project asks for a second maintainer from a different organisation before
1.0, because a single-vendor security tool is hard to trust. Two maintainers from
two organisations is also the precondition for applying to a neutral foundation
(OpenSSF or CNCF sandbox), which is the intended long-term home.

Becoming a maintainer: sustained, reviewed contributions, and judgement shown in
issue discussion — particularly a demonstrated instinct for failing closed.
Nomination is by an existing maintainer, with lazy consensus over 7 days.

## Releases

Releases are cut by a maintainer, tagged, and described in `CHANGELOG.md`. After
1.0 a release needs two maintainer approvals. Security releases may skip the
normal cadence.
