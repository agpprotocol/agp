# TPE-2.1-001: Deterministic Temporal Evaluation

- Status: Draft
- Target release: AGP Trust Primitive Engine 2.1
- Created: 2026-07-24
- Compatibility baseline: TPE 2.0
- Authors: AGP Project

## 1. Abstract

This RFC defines deterministic temporal evaluation for the AGP Trust Primitive Engine.

Temporal policy decisions MUST NOT depend on the evaluator's local clock. Instead, the effective evaluation time is supplied as explicit, canonical, signed input.

Given the same trust policy, signed decision context, verified signatures, keyring, and evaluation time, all conforming implementations MUST produce the same semantic result and the same canonical output bytes.

## 2. Motivation

TPE 2.0 evaluates signer identity, role, weight, threshold, cardinality, separation-of-duties, prohibition, and mutual-exclusion requirements.

It cannot currently express rules such as:

- a change is not valid before a particular instant;
- an authorization expires after a particular instant;
- a deployment is permitted only during an approved window;
- a signed approval is valid only for a bounded period.

Reading the evaluator's local system clock would make these rules non-deterministic. Therefore, time MUST be treated as input data rather than ambient state.

## 3. Design principles

1. No primitive may call the operating-system clock.
2. No primitive may call `time.time()`, `datetime.now()`, or an equivalent.
3. Evaluation time must be covered by the signed context digest.
4. Evaluation time must have one canonical representation.
5. Existing non-temporal TPE 2.0 policies must remain evaluable.
6. Missing temporal input must never be silently inferred.
7. Boundary semantics must be explicit and implementation-independent.
8. Invalid temporal values must be rejected before primitive evaluation.

## 4. Terminology

### 4.1 Creation time

`created_at` records when a decision context was created. It does not define when the trust policy is evaluated.

### 4.2 Signature time

`signed_at` records the time asserted by an individual signature statement. It does not define the effective policy evaluation time.

### 4.3 Context expiration

`expires_at` defines expiration semantics for the signed decision context itself. It does not replace a policy-defined temporal requirement.

### 4.4 Evaluation time

`evaluation_time` is the explicit instant against which temporal trust primitives are evaluated. It is consensus input, not local runtime state.

## 5. Canonical representation

`evaluation_time` MUST be represented as a non-negative JSON integer containing Unix epoch seconds in UTC.

```json
{
  "evaluation_time": 1784894400
}
```

The value MUST be a JSON integer, MUST NOT be a JSON boolean, MUST be between zero and 9007199254740991 inclusive, and MUST represent whole seconds.

## 6. Signed Decision Context versioning

Existing object types remain unchanged:

```text
agp.decision-context/1
agp.signed-decision-context/1
```

Temporal evaluation introduces:

```text
agp.decision-context/2
agp.signed-decision-context/2
```

A version 2 decision context includes the required member `evaluation_time`. That member is covered by canonicalization, `context_digest`, and signatures over that digest.

## 7. Backward compatibility

TPE 2.1 MUST support non-temporal TPE 2.0 policies evaluated against valid version 1 signed decision contexts.

For a version 1 context:

```text
EvaluationState.evaluation_time = None
```

A temporal primitive evaluated without `evaluation_time` MUST fail closed. It MUST NOT use `created_at`, `signed_at`, `expires_at`, the local clock, zero, or an inferred current time.

## 8. EvaluationState extension

TPE 2.1 extends the immutable state with:

```python
evaluation_time: int | None
```

`EvaluationState.create()` accepts the same optional value and validates any present value as a non-boolean safe non-negative integer.

## 9. Initial temporal primitive

TPE 2.1 introduces:

```text
time_window
```

Canonical requirement:

```json
{
  "requirement_id": "requirement:deployment-window",
  "type": "time_window",
  "not_before": 1784894400,
  "not_after": 1784980800
}
```

Both bounds are required and MUST satisfy:

```text
not_before <= not_after
```

## 10. Boundary semantics

The window is inclusive at both boundaries:

```text
not_before <= evaluation_time <= not_after
```

Evaluation at either boundary is satisfied. Evaluation before or after the interval is unsatisfied.

## 11. Primitive result

The primitive reports:

```text
position = before | inside | after | missing
```

It uses the single failure code:

```text
TIME_WINDOW_NOT_SATISFIED
```

Example satisfied result:

```json
{
  "requirement_id": "requirement:deployment-window",
  "type": "time_window",
  "status": "satisfied",
  "matched_signers": [],
  "observed": {
    "evaluation_time": 1784894400,
    "position": "inside"
  },
  "expected": {
    "not_before": 1784894400,
    "not_after": 1784980800
  },
  "failure_code": null
}
```

## 12. Missing evaluation time

When `EvaluationState.evaluation_time` is `None`, `time_window` returns an unsatisfied result with `position: "missing"` and `TIME_WINDOW_NOT_SATISFIED`.

This is an evaluation failure, not a policy-validation failure.

## 13. Policy compatibility

TPE 2.1 remains based on:

```text
agp.trust-policy/2
```

Adding `time_window` extends the registered primitive set without changing existing primitive semantics. Older implementations must reject it as `UNSUPPORTED_TRUST_PRIMITIVE`.

## 14. Evaluation output compatibility

For version 1 contexts and policies containing only TPE 2.0 primitives, TPE 2.1 MUST preserve the existing output shape and byte representation.

Legacy outputs MUST NOT gain an `evaluation_time` member.

For temporal evaluations, top-level inclusion of `evaluation_time` will be fixed by the TPE 2.1 byte-stability corpus before release.

## 15. Validation order

1. Parse JSON and reject duplicate members and unsupported numeric forms.
2. Validate the trust policy.
3. Validate signed-context version and shape.
4. Canonicalize and verify the context digest.
5. Verify signatures.
6. Normalize `evaluation_time` into `EvaluationState`.
7. Evaluate canonical requirements.
8. Produce deterministic primitive results.
9. Produce deterministic top-level output.

## 16. Security considerations

The evaluator MUST NOT substitute the local clock for missing signed time.

This RFC makes an asserted time tamper-evident, not inherently truthful. Trusted-time evidence and replay prevention are separate protocol concerns.

`expires_at` and policy `time_window` have different purposes and may both apply.

## 17. Conformance requirements

TPE 2.1 tests must cover at least:

1. Version 1 non-temporal byte compatibility.
2. Version 1 plus `time_window` fails closed.
3. Safe integer evaluation time accepted.
4. Boolean, negative, fractional, and oversized evaluation times rejected.
5. Inverted and boolean window bounds rejected.
6. One second before is unsatisfied.
7. Both exact boundaries are satisfied.
8. Inside is satisfied.
9. One second after is unsatisfied.
10. Repeated evaluation produces identical bytes.
11. Schema/runtime structural agreement.
12. Structural fuzzing leaks no unexpected exceptions.
13. Mutation testing detects changed boundary operators.

## 18. Performance requirements

Optional temporal state must not materially degrade non-temporal TPE 2.0 evaluation.

Benchmarks must compare legacy non-temporal evaluation, one `time_window`, and composed temporal plus signer requirements.

## 19. Deferred work

Deferred topics include trusted time authorities, recurring windows, business calendars, cron expressions, time zones, daylight-saving rules, delegation expiration, revocation effective times, replay prevention, nonce expiration, and automatic use of `created_at`, `signed_at`, or `expires_at`.

## 20. Acceptance criteria

This RFC is accepted when the temporal source is explicit and signed; no local-clock dependency exists; version 1 compatibility is preserved; context versioning, integer representation, boundary semantics, missing-time behavior, result semantics, and security limitations are fixed; and implementation can proceed without unresolved semantic decisions.
