# Go TPE Phase 3B Recursive Evaluation

## Scope

This increment extracts into `internal/engine`:

- recursive `all_of`, `any_of`, and `not` evaluation;
- recursive `policy_reference` evaluation;
- deterministic recursive failure-code projection;
- complete policy requirement evaluation.

The bounded CLI retains a thin compatibility delegate. Signer projection and
final reproduction-object assembly remain CLI-local for the next phase.
