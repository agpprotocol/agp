# Changelog

## Trust Primitive Engine 2.5.0
- Added `context_value_in` for deterministic scalar membership checks with
  canonical homogeneous value sets and strict JSON type semantics.
- Added `context_path_equals` for deterministic strict comparison between two
  approved Decision Context paths.
- Added `evidence_count_at_least` with optional exact media-type filtering,
  unique evidence-identifier counting, and canonical contributing identifiers.
- Added formal integration coverage across composition, direct and nested
  policy references, recursive failure projection, failure suppression,
  deterministic replay, and result serialization.
- Expanded the stable public Python API coverage with signed TPE 2.5 satisfied
  and unsatisfied evaluations.
- Added a deterministic five-case TPE 2.5 golden corpus with compact sorted-key
  JSON SHA-256 result hashes.
- Added executable TPE 2.5 contextual-predicate examples and CI verification.
- Preserved valid TPE 2.0 through TPE 2.4 policy behavior and existing frozen
  compatibility corpora.
- Expanded complete development validation to 637/637 checks.

## Trust Primitive Engine 2.4.0
- Added deterministic projection and immutable resolution of approved Decision
  Context data under `/proposal/payload/...`.
- Added the `context_value_present` and `context_value_equals` primitives.
- Added the `context_integer_at_least` and `context_integer_at_most`
  primitives with strict integer semantics and safe-integer bounds.
- Added the `evidence_present` primitive with optional digest and media-type
  binding and deterministic mismatch classification.
- Added Decision Context conformance coverage for duplicate and unsorted
  evidence identifiers.
- Propagated the same verified Decision Context through direct, nested, shared,
  and composed policy references.
- Added deterministic recursive failure projection and suppression coverage for
  all TPE 2.4 context and evidence requirements.
- Hardened the stable public Python API with signed end-to-end TPE 2.4
  satisfied and unsatisfied evaluations.
- Preserved TPE 2.3 policy-reference behavior and legacy byte-stable outputs.
- Expanded complete development validation to 541/541 checks.

## Trust Primitive Engine 2.3.4
- Published the `agp-tpe` Python distribution for installation from PyPI.
- Added a public quick start for package installation, schema verification,
  and the stable `trust_primitive_engine` API.
- Added Trusted Publishing through GitHub Actions without persistent PyPI
  credentials.
- Hardened releases by requiring an exact `tpe-vX.Y.Z` tag and package-version
  match, checking out the released tag, and refusing versions already present
  on PyPI.
- No Trust Policy evaluation semantics, schemas, or conformance expectations
  changed from TPE 2.3.3.

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
