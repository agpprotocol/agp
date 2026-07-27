# Go TPE Phase 2C Policy-Reference Graph Validation

## Scope

This increment:

- promotes the bounded policy representation into `internal/model.Policy`;
- extracts policy-reference graph traversal and limits into
  `internal/validation`;
- preserves the controlled fixture-only identity-digest override;
- keeps CLI-local compatibility delegates and receipt behavior.

Evaluation remains in the bounded CLI for the next phase.
