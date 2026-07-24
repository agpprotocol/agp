# Changelog

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
