# Changelog

## Trust Primitive Engine 2.3
- Deterministic `policy_reference` requirements bound by policy identifier,
  version, and canonical SHA-256 digest.
- Explicit immutable policy-set indexing with insertion-order-independent
  resolution.
- Complete reachable-graph validation before evaluation, including cycle,
  depth, referenced-policy-count, and expanded-node limits.
- Recursive referenced-policy evaluation with independent `eligible_roles`
  filtering for every policy.
- Visible `referenced_policy` result boundaries preserving the complete
  recursive result tree.
- Recursive deterministic failure projection across policy-reference
  boundaries, including suppression and failure multiplicity rules.
- Optional `--policy-set` CLI input containing a JSON array of referenced
  Trust Policy objects.
- End-to-end TPE 2.3 golden conformance corpus covering direct, nested,
  shared, composed, satisfied, and unsatisfied references.
- Trust Policy 2.2 compatibility preserved with the existing 22-case golden
  corpus.

## Trust Primitive Engine 2.2
- Deterministic recursive policy composition with `all_of`, `any_of`, and `not`.
- Complete-tree evaluation without short-circuiting.
- Recursive result trees with deterministic failure projection.
- Global requirement identifier uniqueness and canonical child ordering.
- Normative limits of depth 8 and 256 total nodes.
- Recursive JSON Schema and schema/runtime parity coverage.
- Golden compatibility corpus expanded to 22 cases.
- Property hardening expanded to 8 properties and 2,000 generated examples.
- Complete reference validation: 353/353 checks passing.

## 0.5
- Append-only transparency log.
- Cross-language verification.
- Detection of deletion, reorder, truncation, replacement and forks.
- Deployment approval demonstration.

## 0.4
- Ed25519 signed envelopes.
- Replay, expiration and key-revocation tests.

## 0.3
- Independent Python and Go semantic resolvers.
- 260 byte-identical conformance vectors.
