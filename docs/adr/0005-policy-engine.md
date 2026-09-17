# ADR-0005: declarative JSON rules in v0.1, Cedar later

- **Status:** accepted
- **Date:** 2026-09-17
- **Amends:** `docs/DESIGN.md`, which names Cedar as the policy engine

## Context

Cedar is the right long-term choice: fast, schema-validated, formally analysable, and already used for authorization at scale. Two things make it wrong for v0.1:

1. **Cedar has no `ask` effect.** It answers allow or deny. Provenant's central move is the third outcome, escalate to a human, so Cedar needs an annotation convention (`@effect("ask")`) plus glue that reads annotations off the matched policy.
2. **Cedar needs an entity and schema model** — principals, resources, attributes — and the class set is still moving. Freezing a schema now would mean rewriting it repeatedly.

Cedar is also a substantial dependency, which v0.1 avoids by design (ADR-0002).

## Decision

v0.1 uses ordered declarative rules in JSON. First match wins; no match falls back to `defaultEffect` (`ask` in the shipped policy).

```json
{ "id": "ask-egress-when-tainted", "effect": "ask", "classes": ["net.egress"],
  "whenTaintAtOrBelow": "external", "reason": "…" }
```

Conditions: `classes`, `whenTaintAtOrBelow`, `whenTaintAbove`, `resourceMatches`, `resourceNotMatches`. Taint conditions are **lattice comparisons**, not equality, so a rule written for `external` also fires for anything less trusted.

Rules are validated on load: an unknown effect, a missing id or a malformed file **throws** rather than being skipped, so a broken policy cannot silently widen permissions. Every decision returns the rule id and reason, and the policy digest is recorded in each event.

## Consequences

- Policies are readable and editable by anyone, with no new language to learn, which matters while defaults are being tuned.
- No analysis tooling: nothing detects that one rule shadows another. Ordering bugs are caught only by tests.
- The engine surface is two functions (`evaluate`, `decide`) over plain data, so swapping in Cedar is a contained change; rule ids move into policy annotations and the event schema is unaffected.
- Conditions are deliberately limited. Anything needing arithmetic, set logic or entity attributes is a signal to make the Cedar move rather than to grow this format.
