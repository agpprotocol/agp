# TPE-2.2-001: Deterministic Policy Composition

- Status: Draft
- Category: Standards Track
- Target: Trust Primitive Engine 2.2
- Depends on:
  - Trust Policy 2
  - Deterministic Evaluation State
  - TPE-2.1-001 Deterministic Temporal Evaluation

## 1. Abstract

This document defines deterministic composition of trust requirements in AGP Trust Policy 2.

Trust Policy 2 currently represents its top-level `requirements` collection as an implicit conjunction: every requirement must be satisfied for the policy to be satisfied.

This specification introduces explicit, recursively composable Boolean operators:

- `all_of`
- `any_of`
- `not`

Composition is represented as a canonical requirement tree. Every conforming implementation MUST validate and evaluate the complete tree according to the same structural limits, ordering rules, truth semantics, failure semantics, and result representation.

This specification does not introduce arbitrary executable expressions, implementation-defined predicates, scripting, or host-language evaluation.

## 2. Motivation

Flat conjunction is sufficient for policies such as:

- legal must sign;
- security must sign;
- the evaluation must occur inside an authorized time window.

It is insufficient for policies such as:

- legal AND either security OR emergency authority must sign;
- a normal approval path OR a break-glass approval path may authorize;
- an operation is allowed only when a prohibited condition is not satisfied.

Without a normative composition model, policy authors must duplicate policies, move logic outside the Trust Primitive Engine, or rely on implementation-specific orchestration.

Those alternatives weaken:

- independent verification;
- policy portability;
- deterministic replay;
- byte-stable results;
- audit completeness;
- cross-implementation compatibility.

## 3. Goals

This specification MUST provide:

1. deterministic Boolean composition;
2. recursive nesting with bounded resource usage;
3. canonical child ordering;
4. globally unique requirement identifiers;
5. complete evaluation evidence;
6. deterministic result trees;
7. deterministic failure-code derivation;
8. fail-closed validation and evaluation;
9. compatibility with existing primitive requirements.

## 4. Non-goals

This specification does not define:

- arbitrary code execution;
- user-defined functions;
- textual expression languages;
- dynamic policy loading;
- policy references;
- external data fetching;
- runtime mutation of policies;
- host clock access;
- probabilistic evaluation;
- short-circuit evaluation;
- weighted Boolean operators;
- threshold composition over child requirements.

Policy references are reserved for a separate specification.

## 5. Terminology

### 5.1 Leaf requirement

A primitive requirement that does not contain child requirements.

Examples include:

- `required_signer`
- `signer_threshold`
- `time_window`

### 5.2 Composition requirement

A requirement whose satisfaction is derived from one or more child requirements.

The composition types defined by this specification are:

- `all_of`
- `any_of`
- `not`

### 5.3 Requirement tree

The complete recursive structure formed by top-level requirements, composition requirements, and leaf requirements.

### 5.4 Node

Any requirement in the requirement tree, including both composition and leaf requirements.

### 5.5 Depth

The depth of a top-level requirement is 1.

The depth of each child is its parent's depth plus 1.

### 5.6 Complete evaluation

Evaluation in which every structurally valid child requirement is evaluated, regardless of whether the parent result could be determined earlier.

## 6. Policy structure

The existing top-level `requirements` array remains an implicit `all_of`.

For example:

```json
{
  "requirements": [
    {
      "requirement_id": "requirement:legal",
      "type": "required_signer",
      "signer_id": "authority:legal"
    },
    {
      "requirement_id": "requirement:window",
      "type": "time_window",
      "not_before": 1784894400,
      "not_after": 1784980800
    }
  ]
}
```

is semantically equivalent to a conjunction of both requirements.

This specification does not wrap the top-level array in a synthetic result node. Top-level compatibility remains unchanged.

## 7. Composition requirements

### 7.1 `all_of`

```json
{
  "requirement_id": "requirement:deployment-authorization",
  "type": "all_of",
  "requirements": [
    {
      "requirement_id": "requirement:legal",
      "type": "required_signer",
      "signer_id": "authority:legal"
    },
    {
      "requirement_id": "requirement:window",
      "type": "time_window",
      "not_before": 1784894400,
      "not_after": 1784980800
    }
  ]
}
```

Required members:

- `requirement_id`
- `type`
- `requirements`

The `requirements` array MUST contain at least 2 children.

An `all_of` requirement is satisfied if and only if every child is satisfied.

```text
satisfied(all_of(c1 ... cn)) =
    satisfied(c1) AND ... AND satisfied(cn)
```

### 7.2 `any_of`

```json
{
  "requirement_id": "requirement:approval-path",
  "type": "any_of",
  "requirements": [
    {
      "requirement_id": "requirement:security",
      "type": "required_signer",
      "signer_id": "authority:security"
    },
    {
      "requirement_id": "requirement:emergency",
      "type": "required_signer",
      "signer_id": "authority:emergency"
    }
  ]
}
```

Required members:

- `requirement_id`
- `type`
- `requirements`

The `requirements` array MUST contain at least 2 children.

An `any_of` requirement is satisfied if and only if at least one child is satisfied.

```text
satisfied(any_of(c1 ... cn)) =
    satisfied(c1) OR ... OR satisfied(cn)
```

### 7.3 `not`

```json
{
  "requirement_id": "requirement:not-blocked",
  "type": "not",
  "requirement": {
    "requirement_id": "requirement:blocking-authority-present",
    "type": "required_signer",
    "signer_id": "authority:blocking"
  }
}
```

Required members:

- `requirement_id`
- `type`
- `requirement`

A `not` requirement MUST contain exactly one child in the singular `requirement` member.

A `not` requirement is satisfied if and only if its child is unsatisfied.

```text
satisfied(not(c)) = NOT satisfied(c)
```

`not` reverses only the satisfaction state. It does not erase, replace, or reinterpret the child's evidence.

## 8. Closed object model

Composition requirements MUST reject unknown members.

The permitted member sets are:

```text
all_of:
    requirement_id
    type
    requirements

any_of:
    requirement_id
    type
    requirements

not:
    requirement_id
    type
    requirement
```

A composition object containing any additional member MUST be rejected as an invalid trust policy.

## 9. Canonical ordering

### 9.1 Top-level requirements

Existing canonical ordering rules remain unchanged.

Top-level requirements MUST be sorted in ascending Unicode code-point order by `requirement_id`.

### 9.2 Children of `all_of` and `any_of`

Children of `all_of` and `any_of` MUST be sorted in ascending Unicode code-point order by `requirement_id`.

The runtime MUST reject an otherwise valid policy whose children are not in canonical order.

Implementations MUST NOT silently reorder a supplied policy during validation or evaluation.

### 9.3 Child of `not`

Because `not` has exactly one child, no sibling-ordering rule applies.

## 10. Requirement identifier uniqueness

Every `requirement_id` MUST be unique across the complete requirement tree.

Uniqueness is global, not local to a sibling array.

A duplicate identifier MUST cause policy validation to fail before evaluation begins.

## 11. Structural limits

### 11.1 Maximum depth

The maximum permitted requirement-tree depth is 8.

Top-level requirements have depth 1.

A policy containing any node at depth 9 or greater MUST be rejected.

### 11.2 Maximum node count

The complete requirement tree MUST contain no more than 256 nodes.

Every composition requirement and every leaf requirement counts as one node.

The implicit conjunction represented by the top-level `requirements` array does not count as a node.

A policy containing 257 or more nodes MUST be rejected.

### 11.3 Purpose

These limits are normative protections against:

- stack exhaustion;
- memory exhaustion;
- pathological recursion;
- denial-of-service policies;
- implementation-dependent resource behavior.

Implementations MAY impose lower external input-size limits, but MUST support every structurally valid policy within the normative depth and node limits.

## 12. Validation order

Validation MUST occur before primitive evaluation.

A conforming implementation MUST perform the following logical phases:

1. validate the Trust Policy root object;
2. traverse the complete requirement tree;
3. validate each node's closed member set;
4. validate every `requirement_id`;
5. validate composition arity;
6. validate canonical sibling ordering;
7. validate global identifier uniqueness;
8. validate maximum depth;
9. validate maximum node count;
10. validate each leaf primitive;
11. evaluate only after the complete policy is valid.

An implementation MAY combine phases internally, provided externally observable behavior remains equivalent.

A structurally invalid child MUST invalidate the complete policy even when another child would make an `any_of` requirement satisfied.

## 13. Evaluation model

### 13.1 No short-circuit evaluation

Every child of every valid composition requirement MUST be evaluated.

Implementations MUST NOT skip later children after:

- an unsatisfied child determines an `all_of` result;
- a satisfied child determines an `any_of` result;
- any other parent truth value becomes known.

This requirement preserves:

- complete audit evidence;
- deterministic observability;
- stable failure information;
- equivalent results across implementations.

### 13.2 Evaluation order

Children MUST be evaluated in their canonical serialized order.

For `all_of` and `any_of`, this is ascending order by `requirement_id`.

For `not`, the single child is evaluated directly.

### 13.3 Shared state

Every node in one policy evaluation MUST receive the same immutable `EvaluationState`.

Composition MUST NOT mutate:

- matched signers;
- participants;
- weights;
- evaluation time;
- primitive registry state;
- sibling results.

### 13.4 Parent satisfaction

After all children are evaluated:

```text
all_of:
    satisfied when all children are satisfied

any_of:
    satisfied when one or more children are satisfied

not:
    satisfied when its child is unsatisfied
```

No third truth state is introduced.

Primitive errors and invalid policies are not interpreted as `unsatisfied`. They remain evaluation errors or policy-validation errors.

## 14. Result representation

### 14.1 Tree preservation

Composition results MUST preserve the requirement tree.

A composition result MUST contain its direct child results in canonical order.

Child results MUST NOT be flattened into the parent's result.

### 14.2 Composition result shape

An `all_of` or `any_of` result has the following logical structure:

```json
{
  "requirement_id": "requirement:approval-path",
  "primitive_type": "any_of",
  "status": "satisfied",
  "matched_signers": [
    "authority:security"
  ],
  "observed": {
    "satisfied_children": 1,
    "total_children": 2
  },
  "expected": {
    "minimum_satisfied_children": 1
  },
  "failure_code": null,
  "children": [
    {
      "requirement_id": "requirement:emergency",
      "primitive_type": "required_signer",
      "status": "unsatisfied"
    },
    {
      "requirement_id": "requirement:security",
      "primitive_type": "required_signer",
      "status": "satisfied"
    }
  ]
}
```

A `not` result has the following logical structure:

```json
{
  "requirement_id": "requirement:not-blocked",
  "primitive_type": "not",
  "status": "satisfied",
  "matched_signers": [],
  "observed": {
    "child_status": "unsatisfied"
  },
  "expected": {
    "child_status": "unsatisfied"
  },
  "failure_code": null,
  "children": [
    {
      "requirement_id": "requirement:blocking-authority-present",
      "primitive_type": "required_signer",
      "status": "unsatisfied"
    }
  ]
}
```

The following properties are normative:

- composition results contain `children`;
- child order is canonical;
- every valid child produces one child result;
- the result tree mirrors the policy tree;
- repeated evaluation produces byte-identical output.

## 15. Matched signer aggregation

For `all_of` and `any_of`, the parent's `matched_signers` value MUST be the sorted set union of all direct and indirect child `matched_signers`.

For `not`, the parent's `matched_signers` MUST be an empty array.

The child result retains its original matched signers even when negated.

This prevents a satisfied `not` result from claiming a signer as affirmative authorization evidence.

All aggregated signer identifiers MUST be:

- unique;
- sorted in ascending Unicode code-point order.

## 16. Observed and expected values

### 16.1 `all_of`

`observed`:

```json
{
  "satisfied_children": 2,
  "total_children": 3
}
```

`expected`:

```json
{
  "required_satisfied_children": 3
}
```

### 16.2 `any_of`

`observed`:

```json
{
  "satisfied_children": 1,
  "total_children": 3
}
```

`expected`:

```json
{
  "minimum_satisfied_children": 1
}
```

### 16.3 `not`

`observed`:

```json
{
  "child_status": "satisfied"
}
```

`expected`:

```json
{
  "child_status": "unsatisfied"
}
```

Counts MUST be JSON integers and MUST NOT be booleans.

## 17. Composition failure codes

An unsatisfied composition requirement MUST emit exactly one parent failure code:

```text
ALL_OF_NOT_SATISFIED
ANY_OF_NOT_SATISFIED
NOT_NOT_SATISFIED
```

The parent failure code describes the failed composition rule.

Child failure codes remain present in child results.

### 17.1 Policy-level failure projection

The policy-level `failure_codes` array is a deterministic summary of the
failures that contribute to the policy being unsatisfied.

Failure projection MUST be derived recursively from each top-level
requirement result.

A satisfied top-level requirement contributes no failure codes.

An unsatisfied top-level requirement is projected according to the following
rules.

#### 17.1.1 Unsatisfied leaf requirement

An unsatisfied leaf requirement contributes its own `failure_code`.

#### 17.1.2 Unsatisfied `all_of`

An unsatisfied `all_of` result contributes:

1. its own `ALL_OF_NOT_SATISFIED` failure code; and
2. the recursively projected failure codes of each unsatisfied child.

Satisfied children contribute no failure codes.

#### 17.1.3 Unsatisfied `any_of`

An unsatisfied `any_of` result contributes:

1. its own `ANY_OF_NOT_SATISFIED` failure code; and
2. the recursively projected failure codes of every child.

Because an `any_of` result is unsatisfied only when no child is satisfied,
every child will be unsatisfied.

#### 17.1.4 Unsatisfied `not`

An unsatisfied `not` result contributes only its own
`NOT_NOT_SATISFIED` failure code.

Its child is satisfied and therefore contributes no failure code.

### 17.2 Satisfied composition requirements

A satisfied composition requirement contributes no failure codes to the
policy-level summary.

This rule applies even when the result tree contains unsatisfied
descendants.

For example, an `any_of` result may be satisfied while one or more
alternative children are unsatisfied. Those child results and their failure
codes remain present in the result tree for auditability, but they MUST NOT
be projected into the policy-level `failure_codes` array.

### 17.3 Negation and child evidence

When `not` is satisfied because its child is unsatisfied:

- the child result remains unsatisfied;
- the child evidence remains visible;
- the child's original failure code remains inside the child result;
- neither the child failure nor a parent failure is projected to the
  policy-level summary.

When `not` is unsatisfied because its child is satisfied:

- the parent emits `NOT_NOT_SATISFIED`;
- the parent failure is projected to the policy-level summary;
- the satisfied child emits no failure code.

### 17.4 Ordering and multiplicity

After projection, entries MUST be ordered by the corresponding node's
`requirement_id` in ascending Unicode code-point order.

If multiple nodes emit the same failure-code string, each node contributes
one entry. The policy-level array is not a set.

The result tree is authoritative for associating each projected failure code
with its originating requirement.

## 18. Determinism requirements

Given identical:

- signed decision context;
- trust policy;
- keyring;
- primitive registry;
- deterministic evaluation state;
- implementation version;

a conforming implementation MUST produce byte-identical canonical JSON results.

Composition MUST NOT depend on:

- wall-clock time;
- dictionary insertion order;
- hash iteration order;
- recursion implementation details;
- operating system;
- process scheduling;
- short-circuit behavior;
- network access;
- locale.

## 19. Error handling

The complete policy MUST be rejected as invalid when any of the following is true:

- unknown composition type;
- unknown composition member;
- missing required member;
- invalid `requirement_id`;
- duplicate `requirement_id`;
- unsorted children;
- incorrect arity;
- wrong child container type;
- depth limit exceeded;
- node limit exceeded;
- invalid descendant;
- unsupported leaf primitive.

Malformed composition MUST NOT be converted into an unsatisfied result.

## 20. Security considerations

### 20.1 Resource exhaustion

Depth and node-count limits prevent adversarially nested policies from causing unbounded recursion or evaluation cost.

### 20.2 Hidden invalid branches

Complete validation prevents an invalid branch from being hidden behind a satisfied `any_of` child.

### 20.3 Audit suppression

The prohibition on short-circuit evaluation prevents implementations from omitting relevant child evidence.

### 20.4 Identifier ambiguity

Global requirement-ID uniqueness prevents ambiguous result lookup, failure association, or branch substitution.

### 20.5 Negation misuse

`not` negates only deterministic child satisfaction.

It MUST NOT:

- suppress the child result;
- treat evaluation errors as false;
- turn malformed requirements into satisfied results;
- claim child signers as affirmative matched signers.

### 20.6 Policy complexity attacks

Implementations MUST calculate limits over the decoded policy tree before evaluation.

An implementation MUST NOT rely only on transport byte size as a substitute for structural validation.

## 21. Compatibility

Existing Trust Policy 2 policies containing only leaf requirements preserve their existing meaning and result ordering.

The top-level `requirements` array remains conjunctive.

No existing primitive changes its validation or evaluation semantics.

Implementations that do not support TPE 2.2 composition MUST reject the new composition types as unsupported primitives rather than attempting partial evaluation.

## 22. Conformance requirements

A conforming implementation MUST include tests covering at least:

### 22.1 `all_of`

- all children satisfied;
- one child unsatisfied;
- multiple children unsatisfied;
- nested `all_of`;
- complete child evaluation;
- deterministic child order.

### 22.2 `any_of`

- first child satisfied;
- last child satisfied;
- multiple children satisfied;
- no children satisfied;
- unsatisfied alternatives retained in the tree;
- satisfied parent suppresses descendant failure projection;
- complete child evaluation.

### 22.3 `not`

- satisfied child produces unsatisfied parent;
- unsatisfied child produces satisfied parent;
- child evidence retained;
- child matched signers not aggregated into parent;
- child failure suppressed from policy-level summary when negation succeeds.

### 22.4 Validation

- fewer than two children in `all_of`;
- fewer than two children in `any_of`;
- missing child in `not`;
- array supplied to `not`;
- unknown member;
- unsorted children;
- duplicate sibling identifier;
- duplicate identifier across branches;
- depth exactly 8 accepted;
- depth 9 rejected;
- exactly 256 nodes accepted;
- 257 nodes rejected;
- invalid hidden branch rejected;
- unsupported nested primitive rejected.

### 22.5 Determinism

- repeated evaluation produces byte-identical output;
- semantically equivalent but non-canonical ordering is rejected;
- nested failure projection order is deterministic;
- matched signer aggregation is sorted and duplicate-free.

## 23. Example

```json
{
  "object_type": "agp.trust-policy/2",
  "policy_id": "policy:deployment",
  "version": 2,
  "eligible_roles": [
    "approver",
    "emergency",
    "reviewer"
  ],
  "requirements": [
    {
      "requirement_id": "requirement:deployment-authorization",
      "type": "all_of",
      "requirements": [
        {
          "requirement_id": "requirement:approval-path",
          "type": "any_of",
          "requirements": [
            {
              "requirement_id": "requirement:emergency",
              "type": "required_signer",
              "signer_id": "authority:emergency"
            },
            {
              "requirement_id": "requirement:security",
              "type": "required_signer",
              "signer_id": "authority:security"
            }
          ]
        },
        {
          "requirement_id": "requirement:legal",
          "type": "required_signer",
          "signer_id": "authority:legal"
        },
        {
          "requirement_id": "requirement:window",
          "type": "time_window",
          "not_before": 1784894400,
          "not_after": 1784980800
        }
      ]
    }
  ]
}
```

The policy is satisfied when:

1. legal signed;
2. the deterministic evaluation time is inside the inclusive window;
3. either security or emergency authority signed.

Every branch is still evaluated and represented in the result tree.

## 24. Implementation plan

Implementation is divided into separate commits.

### Phase 1: Engine result model

- extend `PrimitiveResult` with immutable child results;
- define recursive canonical serialization;
- preserve compatibility for leaf results;
- add engine-core tests.

### Phase 2: Composition validator

- add recursive traversal;
- enforce global identifier uniqueness;
- enforce canonical sibling ordering;
- enforce arity;
- enforce depth and node limits;
- validate nested leaf primitives through the registry.

### Phase 3: Composition evaluator

- implement `all_of`;
- implement `any_of`;
- implement `not`;
- prohibit short-circuit evaluation;
- aggregate matched signers;
- generate tree results;
- derive deterministic failure projection.

### Phase 4: Schema

- add recursive composition definitions;
- preserve closed object validation;
- add schema/runtime parity cases.

### Phase 5: Conformance and compatibility

- add composition conformance corpus;
- add malformed nested-policy corpus;
- add byte-stability fixtures;
- add fuzz-regression seeds;
- integrate all checks into the aggregate runner.

## 25. Open implementation note

JSON Schema can express recursive composition structure and local arity, but the following constraints remain runtime requirements:

- global `requirement_id` uniqueness;
- canonical sibling ordering;
- maximum complete-tree node count;
- potentially maximum depth, depending on schema strategy.

Schema acceptance alone is not sufficient to establish Trust Policy validity.

## 26. Decision

TPE 2.2 adopts a bounded canonical requirement tree with:

- `all_of`;
- `any_of`;
- `not`;
- complete evaluation;
- no short-circuiting;
- globally unique requirement identifiers;
- maximum depth 8;
- maximum node count 256;
- canonical child ordering;
- tree-preserving deterministic results;
- fail-closed validation.
