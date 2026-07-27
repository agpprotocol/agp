# Go TPE Phase 3A Provenance Leaf Evaluation

## Scope

This increment:

- promotes the bounded decision-context, participant, evidence, and policy
  binding representations into `internal/model`;
- extracts the three TPE 2.6 evidence-provenance leaf evaluators into
  `internal/primitives/provenance`;
- preserves the bounded CLI function names as compatibility delegates.

Composition, recursive policy references, failure projection, and complete
policy evaluation remain in the CLI for Phase 3B.
