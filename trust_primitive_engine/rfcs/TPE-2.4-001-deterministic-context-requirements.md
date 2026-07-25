# TPE-2.4-001: Deterministic Context Requirements

- Status: Draft
- Category: Standards Track
- Target: Trust Primitive Engine 2.4
- Created: 2026-07-25
- Depends on:
  - Trust Policy 2
  - AGP Canonicalization 0.7
  - AGP Decision Context 1 and 2
  - AGP Signed Decision Context 1 and 2
  - TPE-2.2-001 Deterministic Policy Composition
  - TPE-2.3-001 Deterministic Policy References

## 1. Abstract

This document defines deterministic Trust Policy requirements over selected,
already-signed members of an AGP Decision Context 1 or 2.

TPE 2.4 permits a policy to require exact or bounded properties of
`proposal.payload` and exact presence properties of the signed evidence
manifest. Evaluation uses only the verified Decision Context supplied as
explicit input. It does not fetch evidence content, call external services,
execute scripts, inspect local files, or infer missing values.

Given the same Trust Policy, verified signed Decision Context, keyring, policy
set, and canonical inputs, conforming implementations MUST produce the same
semantic result and canonical output bytes.

## 2. Motivation

TPE 2.3 covers signer identity, roles, weights, thresholds, cardinality,
separation of duties, temporal windows, composition, and exact policy
references. It cannot express deterministic rules such as:

- the proposal targets the production environment;
- a rollout integer does not exceed a fixed bound;
- a coverage integer reaches a minimum;
- a named evidence entry with an exact digest is declared.

Moving these checks into application-specific orchestration weakens portable
policy semantics, independent replay, and auditability.

## 3. Design principles

1. Context requirements operate only on verified, signed context data.
2. No ambient or mutable runtime state is consulted.
3. External evidence content is never fetched or parsed.
4. Paths are canonical, bounded, exact, and implementation-independent.
5. Missing paths and type mismatches fail closed as unsatisfied evaluations.
6. Invalid requirements are rejected before evaluation.
7. No implicit type coercion is permitted.
8. Existing TPE 2.3 behavior and byte-stable outputs remain unchanged.
9. Complete-tree evaluation remains mandatory.
10. This is not a general-purpose expression language.

## 4. Goals

This specification MUST provide:

1. deterministic lookup inside `context.proposal.payload`;
2. exact scalar equality;
3. bounded integer comparisons;
4. deterministic evidence-manifest presence checks;
5. explicit missing-value and type-mismatch observations;
6. canonical result representation;
7. schema/runtime parity;
8. compatibility with composition and policy references;
9. bounded resource consumption;
10. cross-implementation testability.

## 5. Non-goals

This specification does not define arbitrary expressions, scripting, CEL,
Rego, JSONPath, JMESPath, regex, wildcards, recursive descent, array filtering,
negative indexes, type coercion, decimals, arithmetic, aggregation,
cross-field comparisons, external I/O, evidence-content parsing, generic
inspection of signatures or participants, inspection of `constraints`, or
context mutation.

## 6. Signed input boundary

Context requirements evaluate only after the Signed Decision Context has
passed structural validation, canonicalization, context-digest verification,
signature verification, and root-policy binding.

The authoritative input is `signed_context.context`. TPE MUST NOT evaluate
these requirements against an unverified context object.

## 7. Allowed data sources

### 7.1 Proposal payload

Path-based requirements may inspect only descendants of:

```text
/context/proposal/payload
```

Policy paths are relative to the Decision Context and MUST begin with:

```text
/proposal/payload
```

Examples:

```text
/proposal/payload/environment
/proposal/payload/rollout/basis_points
/proposal/payload/services/0/name
```

### 7.2 Evidence manifest

Evidence requirements inspect only `context.evidence`. Every entry has exactly:

```text
id
digest
media_type
```

Evidence content itself remains outside TPE 2.4.

## 8. Deferred and forbidden data sources

Generic paths MUST NOT access:

```text
/object_type
/context_id
/created_at
/expires_at
/evaluation_time
/policy
/proposal/type
/participants
/evidence
/constraints
```

Signers, roles, time, and policy binding retain their dedicated semantics.
Evidence uses the dedicated `evidence_present` requirement. `constraints` is
deferred because deterministic selection and kind-specific semantics require a
separate specification.

## 9. Canonical context path

A context path is a restricted JSON Pointer-like string.

A valid path MUST:

1. be a JSON string;
2. begin with the exact prefix `/proposal/payload/`;
3. be between 19 and 512 Unicode scalar values inclusive;
4. contain at least one non-empty segment after `payload`;
5. contain at most 16 descendant segments after `payload`;
6. use only `~0` for `~` and `~1` for `/`;
7. reject every other `~` sequence;
8. resolve object members by exact case-sensitive equality;
9. resolve arrays only through canonical non-negative decimal indexes.

An array index is either `0` or matches `[1-9][0-9]*`. Leading zeroes,
negative values, and `-` are forbidden. An index outside the array resolves as
missing.

Implementations MUST NOT trim, case-fold, rewrite, or independently normalize
paths.

## 10. Deterministic path resolution

Starting from the complete verified Decision Context:

1. decode `~1` and `~0` in each segment;
2. at an object, select the exact decoded member name;
3. at an array, require a canonical array index;
4. at a scalar, stop with `type_mismatch`;
5. when a member or position does not exist, stop with `missing`;
6. otherwise return `found` with the exact value.

Resolution status is one of:

```text
found
missing
type_mismatch
```

Absence and traversal mismatch are evaluation outcomes, not fatal errors.

## 11. Comparable value types

Equality supports only JSON scalars:

```text
null
boolean
integer
string
```

Objects and arrays are not valid expected values. Equality is type-strict:

```text
true != 1
"1" != 1
null != "null"
```

Integers remain inside the AGP safe-integer range. Decimals are not supported.

## 12. `context_value_present`

```json
{
  "requirement_id": "requirement:environment-present",
  "type": "context_value_present",
  "path": "/proposal/payload/environment"
}
```

Required members: `requirement_id`, `type`, and `path`.
Unknown members are rejected.

Satisfied iff resolution is `found`. A found JSON `null` counts as present.

Failure code:

```text
CONTEXT_VALUE_NOT_PRESENT
```

## 13. `context_value_equals`

```json
{
  "requirement_id": "requirement:production-environment",
  "type": "context_value_equals",
  "path": "/proposal/payload/environment",
  "value": "production"
}
```

Required members: `requirement_id`, `type`, `path`, and `value`.
Unknown members are rejected. `value` MUST be a supported scalar.

Satisfied iff resolution is `found`, the observed value is a scalar, types are
identical, and values are equal.

Failure code:

```text
CONTEXT_VALUE_NOT_EQUAL
```

Missing, traversal mismatch, container values, type mismatch, and unequal
values are ordinary unsatisfied results.

## 14. `context_integer_at_least`

```json
{
  "requirement_id": "requirement:minimum-coverage",
  "type": "context_integer_at_least",
  "path": "/proposal/payload/test_report/coverage_basis_points",
  "minimum": 9000
}
```

Required members: `requirement_id`, `type`, `path`, and `minimum`.
Unknown members are rejected.

`minimum` MUST be a non-Boolean JSON integer between
-9007199254740991 and 9007199254740991 inclusive.

Satisfied iff the observed value is a non-Boolean JSON integer greater than or
equal to `minimum`.

Failure code:

```text
CONTEXT_INTEGER_MINIMUM_NOT_REACHED
```

## 15. `context_integer_at_most`

```json
{
  "requirement_id": "requirement:maximum-rollout",
  "type": "context_integer_at_most",
  "path": "/proposal/payload/rollout/basis_points",
  "maximum": 2500
}
```

Required members: `requirement_id`, `type`, `path`, and `maximum`.
Unknown members are rejected.

`maximum` follows the same integer rules as `minimum`.

Satisfied iff the observed value is a non-Boolean JSON integer less than or
equal to `maximum`.

Failure code:

```text
CONTEXT_INTEGER_MAXIMUM_EXCEEDED
```

## 16. `evidence_present`

Minimal form:

```json
{
  "requirement_id": "requirement:security-report",
  "type": "evidence_present",
  "evidence_id": "evidence.security-report"
}
```

Fully bound form:

```json
{
  "requirement_id": "requirement:approved-security-report",
  "type": "evidence_present",
  "evidence_id": "evidence.security-report",
  "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "media_type": "application/json"
}
```

Required members: `requirement_id`, `type`, and `evidence_id`.
Optional members: `digest` and `media_type`.
Unknown members are rejected.

The identifier, digest, and media type follow Decision Context 1 and 2
validation.

Satisfied iff exactly one evidence entry has the requested identifier and all
optional bindings match.

The deterministic match status is one of:

```text
matched
absent
digest_mismatch
media_type_mismatch
digest_and_media_type_mismatch
```

Status derivation MUST follow this order:

1. If no entry has `evidence_id`, status is `absent`.
2. Otherwise compare every optional binding supplied by the requirement.
3. If both supplied bindings differ, status is
   `digest_and_media_type_mismatch`.
4. If only the supplied digest differs, status is `digest_mismatch`.
5. If only the supplied media type differs, status is
   `media_type_mismatch`.
6. Otherwise status is `matched`.

An omitted optional binding cannot mismatch.

Every status except `matched` uses the single failure code:

```text
EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED
```

This proves only that the signed context declares the manifest entry. It does
not prove the external bytes exist, are retrievable, match the digest, are
safe, or support a factual claim.

## 17. Primitive result semantics

All TPE 2.4 context requirements emit:

```json
"matched_signers": []
```

Path observations report `path`, `resolution`, `value_type`, and scalar
`value`. Objects and arrays are never copied into results; their type is
reported and value is `null`.

Evidence observations report:

```json
{
  "evidence_id": "evidence.security-report",
  "match_status": "matched",
  "present": true,
  "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "media_type": "application/json"
}
```

`digest` and `media_type` report the observed manifest entry, not the expected
bindings. Expected optional bindings are reported separately in `expected`.

When status is `absent`, `present` is `false`, while observed `digest` and
`media_type` are `null`. For every other status, `present` is `true`.

## 18. Validation order

A conforming evaluator MUST:

1. parse JSON and reject duplicate members and unsupported numbers;
2. validate the complete Trust Policy tree;
3. validate every TPE 2.4 requirement;
4. validate Signed Decision Context shape and version;
5. canonicalize and verify the context digest;
6. verify signatures;
7. verify root-policy binding;
8. validate the policy-reference graph, when present;
9. construct immutable state including the verified context;
10. evaluate every requirement without short-circuiting;
11. project failures deterministically;
12. produce canonical output.

Invalid paths and invalid expected values are fatal policy-validation errors:

```text
INVALID_TRUST_POLICY
```

Valid but missing, mismatched, or unsatisfied lookups are ordinary results.

## 19. Evaluation state extension

TPE 2.4 extends immutable evaluation state conceptually with:

```python
decision_context: Mapping[str, Any]
```

The state MUST be detached from caller-owned mutable input. Referenced policies
use the same immutable verified context as the root policy.

## 20. Composition and references

All five TPE 2.4 types are leaf requirements. They may appear at the top level,
inside `all_of`, `any_of`, or `not`, and inside referenced policies.

Complete-tree evaluation, result nesting, suppression, and failure projection
follow TPE 2.2 and TPE 2.3 unchanged.

## 21. Backward compatibility

TPE 2.4 remains based on:

```text
agp.trust-policy/2
```

Older implementations reject the new types as
`UNSUPPORTED_TRUST_PRIMITIVE`.

Policies without TPE 2.4 requirements preserve TPE 2.3 output shape and bytes.
No Decision Context version change is required because the required members
already exist and are signed in both `agp.decision-context/1` and
`agp.decision-context/2`.

TPE 2.4 context requirements MUST produce equivalent semantic results for
equivalent `proposal.payload` and `evidence` values in verified Decision
Context 1 and Decision Context 2 objects. They MUST NOT depend on the
version-2-only `evaluation_time` member.

## 22. Resource limits

| Limit | Value |
|---|---:|
| Maximum path length | 512 Unicode scalar values |
| Maximum descendant segments | 16 |
| Maximum expected string length | 4096 Unicode scalar values |
| Maximum scalar string copied to a result | 4096 Unicode scalar values |
| Integer range | AGP canonical safe-integer range |

Existing policy-tree, policy-reference, JSON-size, and canonicalization limits
also apply.

## 23. Security considerations

Signed data is tamper-evident, not necessarily truthful. A signed assertion
that a scan passed does not prove a scanner ran or that the result was honest.

`evidence_present` proves only manifest declaration. Policy authors SHOULD bind
an exact evidence digest when a particular reviewed artifact is required.

Implementations MUST deep-copy or immutably wrap input to prevent mutation.
They MUST NOT include complete object or array values in results.

## 24. Conformance requirements

The TPE 2.4 corpus MUST cover at least:

1. shallow and nested valid paths;
2. escaped `~` and `/` member names;
3. canonical array indexes;
4. leading-zero, negative, `-`, oversized, empty, malformed, overlong, and
   overdeep paths;
5. forbidden prefixes;
6. present null, Boolean, integer, string, object, and array values;
7. exact type-strict equality;
8. string/integer and Boolean/integer mismatches;
9. minimum and maximum boundaries;
10. negative safe integers;
11. Boolean, decimal, and oversized bounds;
12. missing paths and traversal mismatch;
13. evidence identifier presence;
14. media-type match and mismatch;
15. digest match and mismatch;
16. combined digest and media-type mismatch;
17. absent evidence;
18. deterministic lookup regardless of insertion order;
19. use inside composition;
20. use inside direct and nested policy references;
21. complete-tree evaluation;
22. deterministic failure projection;
23. equivalent evaluation over Decision Context 1 and 2;
24. legacy TPE 2.3 byte compatibility;
25. repeated byte-identical evaluation;
26. schema/runtime parity;
27. property-based generation;
28. fuzz regression;
29. mutation tests for comparison operators;
30. clean-wheel schema packaging;
31. public Python API evaluation.

## 25. Performance requirements

Benchmarks MUST compare a legacy signer-only policy, shallow equality, a
16-segment lookup, integer comparisons, evidence lookup, composed context
requirements, and repeated referenced-policy use.

Implementations MAY construct immutable evidence indexes derived only from the
verified input.

## 26. Deferred work

Deferred topics include generic access to `constraints`, constraint selection
by identifier or kind, proposal-type requirements, evidence retrieval and
rehashing, typed claims, externally signed attestations, cross-field
comparisons, set membership, string operations, regex, array quantifiers,
object subset matching, decimals, units, currencies, trusted data sources,
policy parameters, and user-defined primitives.

## 27. Acceptance criteria

This RFC is accepted when allowed sources, path grammar, traversal, missing and
type behavior, scalar comparisons, evidence semantics, failure codes, resource
limits, compatibility, and security boundaries are fixed sufficiently for
implementation without unresolved semantic decisions.
