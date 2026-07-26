# TPE-2.6-001: Deterministic Evidence Provenance Predicates

- Status: Draft
- Category: Standards Track
- Target: Trust Primitive Engine 2.6
- Created: 2026-07-26
- Depends on:
  - Trust Policy 2
  - AGP Canonicalization 0.7
  - AGP Decision Context 3
  - AGP Signature Statement 3
  - AGP Signed Decision Context 3
  - DC-3-001 Context-Attested Evidence Provenance
  - TPE-2.2-001 Deterministic Policy Composition
  - TPE-2.3-001 Deterministic Policy References
  - TPE-2.4-001 Deterministic Context Requirements
  - TPE-2.5-001 Deterministic Contextual Predicates

## 1. Abstract

This document defines three deterministic Trust Policy predicates over the
context-attested evidence provenance fields introduced by Decision Context 3:

- `evidence_issuer_in`;
- `evidence_type_in`;
- `evidence_distinct_issuers_at_least`.

Evaluation uses only the already-verified `signed_context.context.evidence`
manifest. It does not fetch evidence content, authenticate an external issuer,
verify an external artifact, infer truth, execute code, or consult mutable
external state.

## 2. Security boundary

Decision Context 3 records context-attested provenance. A valid Signed Decision
Context 3 proves that its signer attested to the declared `issuer_id` and
`evidence_type`. It does not prove that the named issuer created, signed,
approved, or observed the external evidence.

Implementations and user interfaces MUST NOT represent TPE 2.6 predicates as
independent issuer authentication.

## 3. Input generation

TPE 2.6 provenance predicates require:

```text
agp.decision-context/3
agp.signature-statement/3
agp.signed-decision-context/3
```

A valid Decision Context 1 or 2 contains no normative provenance fields. When
a TPE 2.6 predicate is evaluated against generation 1 or 2:

- policy validation succeeds;
- the predicate is unsatisfied;
- `observed.provenance_status` is `unavailable`;
- no older field is reinterpreted as provenance;
- the predicate contributes its normal failure code.

This behavior is fail-closed and deterministic.

## 4. Reused DC3 semantics

Every valid Decision Context 3 evidence entry contains exactly:

```text
id
digest
media_type
evidence_type
issuer_id
```

TPE 2.6 reuses the DC3 identifier, evidence type, uniqueness, and canonical
ordering rules without modification.

The evidence type grammar is:

```text
^[a-z0-9][a-z0-9._:/-]{1,123}[a-z0-9]/[1-9][0-9]*$
```

The maximum evidence type length is 128 Unicode scalar values.

## 5. Canonical finite sets

`issuer_ids` and `evidence_types` are JSON arrays representing finite sets.

Each array MUST:

1. contain between 1 and 64 entries inclusive;
2. contain only valid strings for the corresponding DC3 field;
3. contain no duplicates;
4. be sorted in ascending Unicode code-point order.

No trimming, case folding, Unicode normalization, or locale collation is
permitted.

Invalid, duplicate, or unordered sets are rejected as:

```text
INVALID_TRUST_POLICY
```

## 6. Same-entry rule

When a predicate contains both an issuer filter and an evidence-type filter,
one evidence entry MUST satisfy both.

An implementation MUST NOT join an issuer from one evidence entry with an
evidence type from another.

Two separate leaves combined through `all_of` remain separate conditions.
Policy authors requiring same-entry binding MUST use the optional cross-filter
inside one predicate.

## 7. `evidence_issuer_in`

Issuer-only form:

```json
{
  "requirement_id": "requirement:approved-issuer",
  "type": "evidence_issuer_in",
  "issuer_ids": [
    "authority:lab-a",
    "authority:lab-b"
  ]
}
```

Same-entry filtered form:

```json
{
  "requirement_id": "requirement:approved-security-issuer",
  "type": "evidence_issuer_in",
  "issuer_ids": [
    "authority:lab-a",
    "authority:lab-b"
  ],
  "evidence_types": [
    "security:assessment/1"
  ]
}
```

Required members:

```text
requirement_id
type
issuer_ids
```

Optional member:

```text
evidence_types
```

Unknown members are rejected.

The predicate is satisfied iff at least one evidence entry has an `issuer_id`
in `issuer_ids` and, when `evidence_types` is present, an `evidence_type` in
that set on the same entry.

Failure code:

```text
EVIDENCE_ISSUER_NOT_ALLOWED
```

Its result reports:

```json
{
  "observed": {
    "provenance_status": "available",
    "evidence_ids": [],
    "issuer_ids": [],
    "evidence_types": []
  },
  "expected": {
    "issuer_ids": [],
    "evidence_types": null
  }
}
```

All observed arrays contain unique contributing values in canonical order.

## 8. `evidence_type_in`

Type-only form:

```json
{
  "requirement_id": "requirement:approved-type",
  "type": "evidence_type_in",
  "evidence_types": [
    "security:assessment/1",
    "security:penetration-test/1"
  ]
}
```

Same-entry filtered form:

```json
{
  "requirement_id": "requirement:approved-lab-assessment",
  "type": "evidence_type_in",
  "evidence_types": [
    "security:assessment/1"
  ],
  "issuer_ids": [
    "authority:lab-a",
    "authority:lab-b"
  ]
}
```

Required members:

```text
requirement_id
type
evidence_types
```

Optional member:

```text
issuer_ids
```

Unknown members are rejected.

The predicate is satisfied iff at least one evidence entry has an
`evidence_type` in `evidence_types` and, when `issuer_ids` is present, an
`issuer_id` in that set on the same entry.

Failure code:

```text
EVIDENCE_TYPE_NOT_ALLOWED
```

Its result uses the same observed arrays as `evidence_issuer_in`. When no
issuer filter is supplied, `expected.issuer_ids` is `null`.

## 9. `evidence_distinct_issuers_at_least`

Unfiltered form:

```json
{
  "requirement_id": "requirement:independent-sources",
  "type": "evidence_distinct_issuers_at_least",
  "minimum": 2
}
```

Filtered form:

```json
{
  "requirement_id": "requirement:independent-security-sources",
  "type": "evidence_distinct_issuers_at_least",
  "minimum": 2,
  "evidence_types": [
    "security:assessment/1"
  ]
}
```

Required members:

```text
requirement_id
type
minimum
```

Optional member:

```text
evidence_types
```

Unknown members are rejected.

`minimum` MUST be a non-Boolean JSON integer between 1 and 256 inclusive.

The evaluator:

1. reads only the verified evidence manifest;
2. applies the optional exact evidence-type filter;
3. derives one candidate per unique `issuer_id`;
4. counts distinct issuer identifiers;
5. performs no external I/O.

The predicate is satisfied iff the count is at least `minimum`.

Failure code:

```text
EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED
```

The result reports:

```json
{
  "observed": {
    "provenance_status": "available",
    "count": 2,
    "issuer_ids": [
      "authority:lab-a",
      "authority:lab-b"
    ],
    "evidence_ids": [
      "evidence.assessment-a",
      "evidence.assessment-b"
    ]
  },
  "expected": {
    "minimum": 2,
    "evidence_types": null
  }
}
```

Observed arrays are unique and canonically sorted.

## 10. Empty evidence

Decision Context 3 permits:

```json
"evidence": []
```

For an empty manifest:

- `evidence_issuer_in` is unsatisfied;
- `evidence_type_in` is unsatisfied;
- `evidence_distinct_issuers_at_least` observes count `0` and is unsatisfied;
- observed identifier arrays are empty;
- `observed.provenance_status` is `available`.

An empty DC3 manifest is different from unavailable provenance in DC1 or DC2.

## 11. Defensive malformed-state behavior

Public evaluation occurs only after Decision Context validation. An evaluator
called below that boundary MUST nevertheless fail closed:

1. non-object evidence entries do not match;
2. entries missing `id`, `issuer_id`, or `evidence_type` do not match;
3. non-string fields do not match;
4. duplicate evidence identifiers contribute at most once;
5. duplicate issuer identifiers count once;
6. malformed values are not copied into results.

This defensive behavior does not make malformed input valid.

## 12. Validation order

A conforming evaluator MUST:

1. parse JSON and reject duplicate members and unsupported numbers;
2. validate the complete Trust Policy tree;
3. validate every TPE 2.6 requirement;
4. validate Signed Decision Context shape and generation;
5. canonicalize and verify the context digest;
6. verify signatures;
7. verify root-policy binding;
8. validate policy references;
9. construct immutable evaluation state;
10. evaluate without short-circuiting;
11. project failures deterministically;
12. produce canonical output.

Invalid sets, identifiers, evidence types, bounds, ordering, duplicates, and
unknown members are fatal policy-validation errors.

Unavailable, absent, disallowed, and insufficient observations are ordinary
unsatisfied results.

## 13. Composition and references

All three predicates are leaf requirements. They may appear directly, inside
`all_of`, `any_of`, or `not`, and inside directly or transitively referenced
policies.

Complete-tree evaluation, suppression, nested results, and failure projection
follow TPE 2.2 and TPE 2.3 unchanged.

## 14. Failure projection

Unsatisfied leaves contribute:

```text
EVIDENCE_ISSUER_NOT_ALLOWED
EVIDENCE_TYPE_NOT_ALLOWED
EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED
```

Ordering follows canonical requirement-tree and policy-reference order.

## 15. Compatibility

TPE 2.6 remains based on:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
```

Older implementations reject the new requirement types as:

```text
UNSUPPORTED_TRUST_PRIMITIVE
```

Policies without TPE 2.6 predicates preserve TPE 2.5 output shape and
byte-stable behavior.

Decision Context 1 and 2 remain valid for policies that contain no TPE 2.6
provenance predicates.

## 16. Resource limits

| Limit | Value |
|---|---:|
| Minimum finite-set entries | 1 |
| Maximum finite-set entries | 64 |
| Maximum evidence type length | 128 Unicode scalar values |
| Minimum distinct issuer bound | 1 |
| Maximum distinct issuer bound | 256 |

Existing policy-tree, reference, JSON-size, canonicalization, and Decision
Context limits also apply.

## 17. Security considerations

Distinct issuer strings do not prove independent legal or operational actors.
One entity may control several identifiers.

A matched provenance declaration does not prove that evidence bytes exist,
match the digest, are retrievable, are current, or support a claim.

Separate issuer and type leaves do not prove same-entry binding. Optional
cross-filters exist specifically to prevent that ambiguity.

## 18. Conformance requirements

The TPE 2.6 corpus MUST cover at least:

1. issuer membership success and failure;
2. evidence-type membership success and failure;
3. same-entry cross-filter success;
4. cross-entry false-positive prevention;
5. 1, 64, and rejected 65-entry sets;
6. duplicate and unordered sets;
7. invalid issuer identifiers;
8. invalid evidence type versions and lengths;
9. empty evidence;
10. DC1 and DC2 provenance unavailable;
11. DC3 provenance available;
12. distinct count below, at, and above minimum;
13. repeated entries from one issuer count once;
14. optional type-filtered distinct counts;
15. invalid minimum values;
16. insertion-order independence;
17. defensive malformed-state behavior;
18. composition and references;
19. deterministic projection and suppression;
20. TPE 2.5 byte compatibility;
21. repeated byte-identical evaluation;
22. schema/runtime parity;
23. property, fuzz, and mutation testing;
24. public API, clean-wheel, and external-package integration.

## 19. Deferred work

Deferred topics include independently signed evidence attestations, issuer-key
binding, trusted issuer registries, delegation, evidence-type registration,
issuer weighting, exact or maximum cardinality, claims, retrieval, rehashing,
freshness, revocation, generic aggregation, and user-defined primitives.

## 20. Acceptance criteria

This RFC is ready for implementation when primitive members, canonical sets,
same-entry semantics, DC1/DC2 behavior, empty evidence behavior, cardinality,
result shapes, failure codes, validation order, resource limits, compatibility,
and security boundaries are fixed without unresolved decisions.
