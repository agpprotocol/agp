# TPE-2.5-001: Deterministic Contextual Predicates

- Status: Draft
- Category: Standards Track
- Target: Trust Primitive Engine 2.5
- Created: 2026-07-25
- Depends on:
  - Trust Policy 2
  - AGP Canonicalization 0.7
  - AGP Decision Context 1 and 2
  - AGP Signed Decision Context 1 and 2
  - TPE-2.2-001 Deterministic Policy Composition
  - TPE-2.3-001 Deterministic Policy References
  - TPE-2.4-001 Deterministic Context Requirements

## 1. Abstract

This document defines three deterministic contextual predicates for Trust
Policy 2:

- scalar membership in an explicit finite set;
- strict equality between two signed context paths;
- minimum cardinality over the signed evidence manifest.

TPE 2.5 evaluates only already-verified, signed Decision Context data. It does
not fetch evidence content, inspect mutable external state, execute code,
perform implicit type conversion, or introduce a general-purpose expression
language.

Given the same Trust Policy, verified Signed Decision Context, keyring, policy
set, and canonical inputs, conforming implementations MUST produce the same
semantic result and canonical output bytes.

## 2. Motivation

TPE 2.4 supports exact scalar equality, scalar presence, integer bounds, and
exact evidence-manifest entry checks. It cannot directly express policies such
as:

- the deployment environment is one of a finite approved set;
- the requested version exactly matches the approved version;
- at least two JSON evidence reports are declared.

Encoding these predicates in application orchestration weakens policy
portability, independent replay, and auditability. TPE 2.5 adds only bounded,
explicit predicates that remain deterministic and implementation-independent.

## 3. Design principles

1. Evaluation uses only verified signed context data.
2. Every predicate is finite, bounded, and exact.
3. No implicit type coercion is permitted.
4. Missing paths and incompatible observed values are ordinary unsatisfied
   results.
5. Invalid policies are rejected before evaluation.
6. No external I/O or evidence-content inspection is permitted.
7. Result observations are complete enough for audit without copying
   unbounded containers.
8. Composition and reference semantics remain unchanged.
9. Existing TPE 2.4 behavior and byte-stable outputs remain unchanged.
10. TPE 2.5 is not an expression language.

## 4. Goals

This specification MUST provide:

1. deterministic scalar membership in a finite policy set;
2. deterministic strict equality between two context paths;
3. deterministic minimum evidence-manifest cardinality;
4. explicit missing and type-mismatch observations;
5. canonical validation and result representation;
6. bounded memory and evaluation cost;
7. schema/runtime parity;
8. compatibility with composition and policy references;
9. equivalent semantics over Decision Context 1 and 2;
10. cross-implementation conformance vectors.

## 5. Non-goals

This specification does not define:

- arbitrary Boolean or arithmetic expressions;
- scripting, CEL, Rego, JSONPath, JMESPath, or user-defined code;
- regex, substring, prefix, suffix, or locale-aware string matching;
- ordering comparisons between two paths;
- decimals, floating-point values, units, or currencies;
- object or array equality;
- set intersection, subset, or superset operators;
- dynamic expected values outside the signed context and policy;
- evidence-content retrieval, parsing, or rehashing;
- evidence issuer, signer, class, claim, or attestation semantics;
- mutable external data sources;
- generic aggregation over proposal arrays;
- context mutation.

## 6. Signed input boundary

TPE 2.5 predicates evaluate only after the Signed Decision Context has passed:

1. structural validation;
2. canonicalization;
3. context-digest verification;
4. signature verification;
5. root-policy binding;
6. policy-reference graph validation, when applicable.

The authoritative context input is `signed_context.context`.

## 7. Reused TPE 2.4 semantics

TPE 2.5 reuses without modification:

- the allowed path root `/proposal/payload/`;
- the restricted canonical JSON Pointer grammar;
- path length and depth limits;
- path resolution statuses `found`, `missing`, and `type_mismatch`;
- comparable scalar types `null`, Boolean, safe integer, and string;
- strict type equality;
- the immutable verified evaluation state;
- Decision Context 1 and 2 evidence-manifest shape;
- complete-tree evaluation;
- composition, reference, suppression, and failure-projection semantics.

Objects and arrays are not comparable scalar values.

## 8. Scalar canonical ordering

`context_value_in.values` requires canonical ordering.

Each value MUST be one of:

```text
null
boolean
integer
string
```

All values in one requirement MUST have the same JSON type.

Canonical comparison within one type is:

1. `null`: only one possible value;
2. Boolean: `false` before `true`;
3. integer: ascending numeric order;
4. string: ascending Unicode code-point order.

Duplicate values are forbidden.

No cross-type ordering is defined because heterogeneous value sets are
forbidden.

## 9. `context_value_in`

Example:

```json
{
  "requirement_id": "requirement:environment-allowed",
  "type": "context_value_in",
  "path": "/proposal/payload/environment",
  "values": [
    "canary",
    "production"
  ]
}
```

Required members:

```text
requirement_id
type
path
values
```

Unknown members are rejected.

`path` MUST satisfy the TPE 2.4 canonical context path grammar.

`values` MUST:

1. be an array;
2. contain between 1 and 64 entries inclusive;
3. contain only supported comparable scalar values;
4. contain values of one identical JSON type;
5. contain no duplicates;
6. be in canonical order;
7. keep every string at or below 4096 Unicode scalar values;
8. keep every integer inside the AGP safe-integer range.

The predicate is satisfied iff:

1. path resolution is `found`;
2. the observed value is a supported scalar;
3. the observed JSON type is identical to the set member type; and
4. the observed value exactly equals one member of `values`.

Failure code:

```text
CONTEXT_VALUE_NOT_IN_SET
```

Missing paths, traversal mismatch, observed containers, type mismatch, and
non-membership are ordinary unsatisfied results.

## 10. `context_value_in` result representation

A logical result has:

```json
{
  "requirement_id": "requirement:environment-allowed",
  "type": "context_value_in",
  "status": "satisfied",
  "matched_signers": [],
  "observed": {
    "path": "/proposal/payload/environment",
    "resolution": "found",
    "value_type": "string",
    "value": "production"
  },
  "expected": {
    "values": [
      "canary",
      "production"
    ]
  },
  "failure_code": null
}
```

Observed object and array values MUST NOT be copied. Their `value_type` is
reported and `value` is `null`.

## 11. `context_path_equals`

Example:

```json
{
  "requirement_id": "requirement:requested-approved-match",
  "type": "context_path_equals",
  "left_path": "/proposal/payload/requested_version",
  "right_path": "/proposal/payload/approved_version"
}
```

Required members:

```text
requirement_id
type
left_path
right_path
```

Unknown members are rejected.

Both paths MUST independently satisfy the TPE 2.4 canonical context path
grammar.

`left_path` and `right_path` MUST be different strings. A policy that compares
one path to itself is invalid because it adds no constraint.

The predicate is satisfied iff:

1. both resolutions are `found`;
2. both observed values are supported comparable scalars;
3. both observed JSON types are identical; and
4. both observed values are exactly equal.

Failure code:

```text
CONTEXT_PATH_VALUES_NOT_EQUAL
```

A missing path, traversal mismatch, observed container, type mismatch, or
unequal value is an ordinary unsatisfied result.

No path is privileged. The names `left_path` and `right_path` define result
placement only, not comparison precedence.

## 12. `context_path_equals` result representation

A logical result has:

```json
{
  "requirement_id": "requirement:requested-approved-match",
  "type": "context_path_equals",
  "status": "satisfied",
  "matched_signers": [],
  "observed": {
    "left": {
      "path": "/proposal/payload/requested_version",
      "resolution": "found",
      "value_type": "string",
      "value": "3.0.0"
    },
    "right": {
      "path": "/proposal/payload/approved_version",
      "resolution": "found",
      "value_type": "string",
      "value": "3.0.0"
    }
  },
  "expected": {
    "relation": "strict_equal"
  },
  "failure_code": null
}
```

Container values are never copied into results.

## 13. Evidence manifest model

TPE 2.5 counts entries from the verified `context.evidence` array.

Decision Context validation already requires every valid evidence entry to
contain exactly:

```text
id
digest
media_type
```

Valid Decision Context input rejects duplicate evidence identifiers. A
conforming TPE implementation MUST nevertheless count by unique evidence
identifier defensively, so malformed duplicate state cannot inflate a count if
an evaluator is called below the public validation boundary.

Evidence array insertion order MUST NOT affect the result.

## 14. `evidence_count_at_least`

Minimal form:

```json
{
  "requirement_id": "requirement:minimum-evidence",
  "type": "evidence_count_at_least",
  "minimum": 2
}
```

Filtered form:

```json
{
  "requirement_id": "requirement:minimum-json-reports",
  "type": "evidence_count_at_least",
  "minimum": 2,
  "media_type": "application/json"
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
media_type
```

Unknown members are rejected.

`minimum` MUST be a non-Boolean JSON integer between 1 and 256 inclusive.

When supplied, `media_type` MUST satisfy the same syntax and length rules used
by Decision Context evidence entries.

The evaluator MUST:

1. read only the verified evidence manifest;
2. derive one candidate per unique evidence identifier;
3. apply the optional exact, case-sensitive `media_type` filter;
4. count matching candidates;
5. avoid fetching or parsing external evidence content.

The predicate is satisfied iff the observed count is greater than or equal to
`minimum`.

Failure code:

```text
EVIDENCE_COUNT_NOT_REACHED
```

## 15. `evidence_count_at_least` result representation

A logical result has:

```json
{
  "requirement_id": "requirement:minimum-json-reports",
  "type": "evidence_count_at_least",
  "status": "satisfied",
  "matched_signers": [],
  "observed": {
    "count": 3,
    "evidence_ids": [
      "evidence.architecture-review",
      "evidence.security-report",
      "evidence.test-report"
    ]
  },
  "expected": {
    "minimum": 2,
    "media_type": "application/json"
  },
  "failure_code": null
}
```

`evidence_ids` MUST:

- include only entries that contributed to the count;
- contain unique identifiers;
- be sorted in ascending Unicode code-point order.

When no `media_type` filter is supplied, `expected.media_type` MUST be `null`.

The result MUST NOT copy evidence digests or external evidence content.

## 16. Validation order

A conforming evaluator MUST:

1. parse JSON and reject duplicate members and unsupported numbers;
2. validate the complete Trust Policy tree;
3. validate every TPE 2.5 requirement;
4. validate Signed Decision Context shape and version;
5. canonicalize and verify the context digest;
6. verify signatures;
7. verify root-policy binding;
8. validate the policy-reference graph, when present;
9. construct immutable state including the verified context;
10. evaluate every requirement without short-circuiting;
11. project failures deterministically;
12. produce canonical output.

Invalid paths, unordered sets, heterogeneous sets, duplicate values, invalid
bounds, and invalid media types are fatal policy-validation errors:

```text
INVALID_TRUST_POLICY
```

Valid but missing, mismatched, or insufficient observations are ordinary
unsatisfied results.

## 17. Composition and policy references

All three TPE 2.5 predicates are leaf requirements.

They may appear:

- directly in a policy requirement list;
- inside `all_of`;
- inside `any_of`;
- inside `not`;
- inside directly or transitively referenced policies.

Root and referenced policies MUST evaluate against the same immutable verified
Decision Context.

Complete-tree evaluation, nested result representation, failure suppression,
and recursive failure projection follow TPE 2.2 and TPE 2.3 unchanged.

## 18. Failure projection

An unsatisfied TPE 2.5 leaf contributes its own failure code:

```text
CONTEXT_VALUE_NOT_IN_SET
CONTEXT_PATH_VALUES_NOT_EQUAL
EVIDENCE_COUNT_NOT_REACHED
```

Failure ordering remains the canonical requirement-tree and policy-reference
ordering already defined by TPE 2.2 and TPE 2.3.

Satisfied branches suppress failures according to existing composition rules.

## 19. Backward compatibility

TPE 2.5 remains based on:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
```

No Decision Context version change is required.

Older implementations reject TPE 2.5 types as:

```text
UNSUPPORTED_TRUST_PRIMITIVE
```

Policies without TPE 2.5 predicates MUST preserve TPE 2.4 output shape and
byte-stable behavior.

Equivalent `proposal.payload` and `evidence` values in verified Decision
Context 1 and 2 objects MUST produce equivalent TPE 2.5 semantic results.

## 20. Resource limits

| Limit | Value |
|---|---:|
| Maximum path length | 512 Unicode scalar values |
| Maximum descendant segments | 16 |
| Maximum `context_value_in` entries | 64 |
| Minimum `context_value_in` entries | 1 |
| Maximum expected string length | 4096 Unicode scalar values |
| Integer range | AGP canonical safe-integer range |
| Minimum evidence count bound | 1 |
| Maximum evidence count bound | 256 |
| Maximum scalar string copied to a result | 4096 Unicode scalar values |

Existing policy-tree, policy-reference, JSON-size, canonicalization, Decision
Context evidence-count, and process limits also apply.

## 21. Determinism requirements

A conforming implementation MUST demonstrate that results are unchanged by:

- policy-set insertion order;
- evidence-manifest insertion order;
- object-member insertion order;
- repeated evaluation;
- equivalent Decision Context 1 and 2 representations.

Implementations MAY build immutable indexes or sets derived solely from verified
input. Optimization MUST remain semantically equivalent to complete
recomputation.

## 22. Security considerations

### 22.1 Membership policy expansion

Large policy sets can increase validation and canonicalization cost. The
64-entry bound is normative.

### 22.2 Type confusion

Booleans and integers are distinct. In particular:

```text
true != 1
false != 0
```

Heterogeneous membership sets are forbidden to reduce cross-language
ambiguity.

### 22.3 Cross-field trust

Equality between two signed fields proves only that the signed values match. It
does not establish that either value is truthful, authorized, current, or
derived from an independent source.

### 22.4 Evidence quantity is not evidence quality

A count proves only the number of declared manifest entries satisfying an
optional media-type filter. It does not prove that external bytes exist, match
their declared digests, are independent, are trustworthy, or support a claim.

### 22.5 Duplicate inflation

Valid Decision Context input rejects duplicate evidence identifiers. Defensive
unique-id counting prevents accidental inflation below the validated boundary.

### 22.6 Unicode and locale behavior

Strings and identifiers use exact code-point comparison. Implementations MUST
NOT normalize Unicode, case-fold, or apply locale-specific collation.

## 23. Conformance requirements

The TPE 2.5 conformance corpus MUST cover at least:

1. scalar membership success for null, Boolean, integer, and string;
2. non-membership for every supported type;
3. strict Boolean/integer distinction;
4. empty membership set rejection;
5. 64-entry membership boundary;
6. 65-entry membership rejection;
7. heterogeneous membership rejection;
8. duplicate membership rejection;
9. unordered Boolean, integer, and string membership rejection;
10. oversized strings and unsafe integers;
11. shallow, nested, escaped, and array-indexed context paths;
12. missing, traversal mismatch, and container observations;
13. equal path values for every scalar type;
14. unequal values of the same type;
15. equal-looking values of different types;
16. one missing path;
17. both missing paths;
18. identical-path policy rejection;
19. minimum evidence count at the boundary;
20. evidence count below and above the boundary;
21. unfiltered and media-type-filtered counts;
22. absent matching media type;
23. Boolean, zero, negative, and oversized minimum rejection;
24. invalid media type rejection;
25. evidence insertion-order independence;
26. defensive duplicate evidence handling;
27. use inside `all_of`, `any_of`, and `not`;
28. use inside direct and nested policy references;
29. complete-tree evaluation;
30. deterministic failure projection and suppression;
31. equivalent Decision Context 1 and 2 evaluation;
32. legacy TPE 2.4 byte compatibility;
33. repeated byte-identical evaluation;
34. schema/runtime parity;
35. property-based generation;
36. fuzz regression;
37. mutation tests for membership, equality, filtering, and count boundaries;
38. public Python API evaluation;
39. clean-wheel schema packaging;
40. external-package integration.

## 24. Performance requirements

Benchmarks MUST compare:

- one-value and 64-value membership sets;
- shallow and 16-segment path-to-path equality;
- unfiltered and filtered evidence counting;
- composition containing all three predicates;
- direct and repeated referenced-policy use;
- legacy TPE 2.4 policies.

Implementations MAY use binary search for canonical membership arrays or
immutable evidence indexes. Observable results MUST remain identical.

## 25. Deferred work

Deferred topics include:

- context ordering comparisons;
- heterogeneous or nested membership sets;
- object and array equality;
- string operations and regex;
- proposal-array quantifiers;
- evidence maximum or exact cardinality;
- evidence identifier-prefix, class, issuer, signer, or claim filters;
- evidence retrieval and rehashing;
- typed attestations;
- generic access to `constraints`;
- decimals, units, and currencies;
- policy parameters;
- trusted external data sources;
- user-defined primitives;
- a general-purpose expression language.

## 26. Acceptance criteria

This RFC is ready for implementation when the following are fixed without
unresolved semantic decisions:

1. primitive names and exact members;
2. canonical membership ordering;
3. strict scalar comparison rules;
4. path validation and resolution reuse;
5. evidence uniqueness and filtering semantics;
6. result shapes;
7. failure codes;
8. validation order;
9. composition and reference behavior;
10. resource limits;
11. compatibility guarantees;
12. security boundaries;
13. conformance coverage.
