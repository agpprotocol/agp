# TPE-2.3-001: Deterministic Policy References

- Status: Draft
- Category: Standards Track
- Target: Trust Primitive Engine 2.3
- Depends on:
  - Trust Policy 2
  - AGP Canonicalization 0.7
  - Decision Context policy binding
  - TPE-2.2-001 Deterministic Policy Composition

## 1. Abstract

This document defines deterministic references from one AGP Trust Policy 2
requirement tree to another Trust Policy 2 object.

A policy reference identifies an exact referenced policy by:

- policy identifier;
- policy version;
- canonical SHA-256 digest.

Referenced policies are supplied through an explicit immutable policy set.
Evaluation MUST NOT fetch policies from the network, filesystem, database,
environment, or another implementation-defined source.

Every referenced policy MUST be fully validated, cryptographically bound to its
declared digest, resolved without ambiguity, checked for cycles, and evaluated
against the same immutable evaluation state as the root policy.

This specification preserves deterministic replay, fail-closed behavior,
complete audit evidence, and byte-stable results.

## 2. Motivation

Trust Policy 2.2 permits recursive Boolean composition inside one policy. It
does not permit reuse of an independently versioned policy module.

Without deterministic policy references, policy authors must:

- duplicate common controls in many policies;
- manually synchronize shared requirements;
- expand every reusable baseline into the root policy;
- move policy selection into implementation-specific orchestration.

Those approaches weaken content binding, reviewability, portability, and
independent replay.

A deterministic reference model permits policies such as:

- deployment authorization AND an exact security baseline;
- payment authorization AND an exact fraud-control policy;
- emergency authorization OR a referenced normal approval policy;
- jurisdiction-specific policy reuse without mutable aliases.

## 3. Goals

This specification MUST provide:

1. exact content-addressed policy references;
2. explicit and immutable reference inputs;
3. deterministic reference resolution;
4. policy identifier, version, and digest verification;
5. cycle detection;
6. bounded transitive expansion;
7. complete referenced-policy validation before evaluation;
8. shared immutable evaluation state;
9. recursive result evidence;
10. byte-stable repeated evaluation;
11. compatibility with existing Trust Policy 2 objects.

## 4. Non-goals

This specification does not define:

- network retrieval;
- URL references;
- filesystem discovery;
- database queries;
- mutable aliases such as `latest`;
- semantic version ranges;
- implementation-selected policy versions;
- fallback policies;
- optional unresolved references;
- partial policy imports;
- policy templates or parameters;
- cross-object-type references;
- remote trust establishment;
- signature formats for policy distribution.

Policy distribution and registry synchronization are separate concerns.

## 5. Terminology

### 5.1 Root policy

The Trust Policy directly bound by the Decision Context and supplied as the
primary evaluation input.

### 5.2 Referenced policy

A Trust Policy 2 object selected by a `policy_reference` requirement.

### 5.3 Policy set

The explicit finite collection of referenced Trust Policy 2 objects supplied
to one evaluation.

### 5.4 Reference key

The tuple:

```text
(policy_id, policy_version, policy_digest)
```

### 5.5 Reference graph

The directed graph whose vertices are the root policy and all transitively
referenced policies, and whose edges are `policy_reference` requirements.

### 5.6 Active reference path

The ordered policy sequence currently being traversed during validation or
evaluation.

## 6. Deterministic reference identity

The complete tuple:

```text
(policy_id, policy_version, policy_digest)
```

is the deterministic identity of a referenced policy.

This tuple is not merely a lookup hint. It is the authoritative identity used
for:

- equality;
- cycle detection;
- memoization;
- canonical result paths;
- referenced-policy counting;
- receipt construction;
- cache keys.

Two policy objects with the same identifier and version but different digests
are different policy identities and MUST NOT be treated as interchangeable.

Two byte-different policy objects that canonicalize to the same canonical bytes
and therefore have the same digest represent the same policy identity.

## 7. Reference requirement

A policy reference is a structural requirement with this exact shape:

```json
{
  "requirement_id": "requirement:security-baseline",
  "type": "policy_reference",
  "policy_id": "policy:security-baseline",
  "policy_version": 3,
  "policy_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Required members:

- `requirement_id`
- `type`
- `policy_id`
- `policy_version`
- `policy_digest`

Unknown members MUST be rejected.

`policy_reference` is a structural node, not a primitive registered in the
primitive registry.

## 8. Reference field validation

### 8.1 `policy_id`

`policy_id` MUST satisfy the Trust Policy identifier syntax.

### 8.2 `policy_version`

`policy_version` MUST be a JSON integer from 1 through
9007199254740991 inclusive.

A JSON boolean MUST be rejected.

### 8.3 `policy_digest`

`policy_digest` MUST have the form:

```text
sha256:<64 lowercase hexadecimal digits>
```

No other digest algorithm is defined by this specification.

## 9. Policy-set input

Evaluation that permits references MUST receive the complete referenced policy
set as an explicit input.

A conforming implementation MUST NOT resolve a reference by consulting:

- the network;
- the local filesystem;
- a database;
- environment variables;
- process-global mutable state;
- a cache not included in the evaluation input;
- a callback whose result is not deterministically bound to the input.

The policy set MAY be represented internally as a map, sequence, or immutable
resolver object, provided externally observable behavior is equivalent.

## 10. Policy-set uniqueness

The policy set MUST NOT contain two entries with the same `policy_id` and
`version`.

The policy set MUST NOT contain duplicate canonical policy objects.

Every supplied policy MUST be a valid `agp.trust-policy/2` object.

Unreferenced policies MAY be rejected by a stricter profile. The reference
implementation SHOULD accept them but MUST NOT allow them to affect results.

## 11. Canonical digest binding

For every referenced policy:

```text
computed_digest =
    "sha256:" + SHA256(AGP-C14N-0.7(referenced_policy))
```

The computed digest MUST equal the `policy_digest` in the reference node.

The referenced object's:

- `policy_id` MUST equal the reference `policy_id`;
- `version` MUST equal the reference `policy_version`.

Identifier or version equality without digest equality is insufficient.

A referenced policy does not contain its own digest because that would create
a self-referential representation.

## 12. Resolution algorithm

For each `policy_reference` node, a conforming implementation MUST:

1. validate the reference node;
2. locate exactly one supplied policy matching `policy_id` and
   `policy_version`;
3. validate the referenced policy root and complete requirement tree;
4. recompute its canonical digest;
5. compare identifier, version, and digest;
6. reject a cycle before descending;
7. enforce transitive structural limits;
8. recursively resolve every nested reference;
9. evaluate only after the complete reachable graph is valid.

Resolution MUST be deterministic and independent of policy-set insertion order.

## 13. Missing and ambiguous references

If no supplied policy matches the declared identifier and version, evaluation
MUST fail with:

```text
POLICY_REFERENCE_NOT_FOUND
```

If more than one supplied policy matches the same identifier and version,
evaluation MUST fail with:

```text
AMBIGUOUS_POLICY_REFERENCE
```

A missing or ambiguous reference is an evaluation error, not an unsatisfied
requirement.

## 14. Binding errors

The following errors are fatal:

```text
POLICY_REFERENCE_ID_MISMATCH
POLICY_REFERENCE_VERSION_MISMATCH
POLICY_REFERENCE_DIGEST_MISMATCH
```

Implementations MAY detect a mismatch while indexing the policy set or while
resolving a node, but emitted behavior MUST remain deterministic.

## 15. Cycle detection

The reference graph MUST be acyclic.

Before descending into a referenced policy, the implementation MUST determine
whether that exact policy identity is already present on the active reference
path.

Policy identity for cycle detection is the complete reference key:

```text
(policy_id, policy_version, policy_digest)
```

A cycle MUST fail with:

```text
POLICY_REFERENCE_CYCLE
```

Examples include:

```text
A -> A
A -> B -> A
A -> B -> C -> B
```

Sharing a referenced policy across separate completed branches is not a cycle.

## 16. Transitive limits

The limits in TPE 2.2 apply across the fully expanded reachable reference
graph.

### 16.1 Maximum reference depth

The root policy has reference depth 0.

A directly referenced policy has reference depth 1.

The maximum permitted reference depth is 8.

Reference depth and the TPE 2.2 requirement-tree depth are independent
counters. Entering a referenced policy increments reference depth but does not
inherit the parent policy's requirement-tree depth. Each policy object must
independently satisfy the TPE 2.2 maximum requirement-tree depth of 8.

A policy at reference depth 9 MUST be rejected with:

```text
POLICY_REFERENCE_DEPTH_EXCEEDED
```

### 16.2 Maximum referenced policy count

At most 32 distinct referenced policy identities may be reachable from one
root evaluation.

The root policy does not count toward this limit.

A 33rd distinct referenced policy MUST be rejected with:

```text
POLICY_REFERENCE_COUNT_EXCEEDED
```

### 16.3 Maximum expanded requirement count

Implementations MUST impose a deterministic maximum expanded requirement count
across the root policy and all reachable referenced policies.

The configured limit MUST be at least 2048 nodes. The reference implementation
uses 2048 nodes by default.

Every composition node, primitive leaf, and `policy_reference` node counts as
one requirement node.

A reference edge does not duplicate the referenced policy's node count when
the same exact referenced policy is reused by multiple non-cyclic branches.

The effective limit MUST be an explicit immutable evaluation configuration
value. It MUST NOT depend on available memory, process load, environment
variables, or another mutable runtime condition.

Exceeding the effective limit MUST fail with:

```text
POLICY_REFERENCE_NODE_LIMIT_EXCEEDED
```

## 17. Requirement identifier scope

TPE 2.2 global `requirement_id` uniqueness remains scoped to one policy object.

Different policies MAY contain the same `requirement_id`.

Result paths MUST therefore identify referenced nodes using both policy identity
and requirement identity.

Implementations MUST NOT flatten all requirement identifiers into one global
namespace across the reference graph.

## 18. Evaluation semantics

A `policy_reference` requirement is satisfied if and only if the referenced
policy evaluation is satisfied.

The referenced policy is evaluated using:

- the same verified signatures;
- the same normalized participants;
- the same matched signer derivation;
- the same immutable `EvaluationState`;
- the same primitive registry;
- the same implementation version.

The referenced policy's own `eligible_roles` controls which verified signers
are eligible inside that referenced policy.

A root policy MUST NOT overwrite or inherit the referenced policy's
`eligible_roles`.

## 19. No short-circuit behavior

Reference resolution and validation MUST NOT be skipped because another branch
already determines a parent Boolean result.

After complete graph validation, evaluation follows TPE 2.2 complete-tree
semantics.

A referenced policy inside a non-selected-looking `any_of` branch MUST still be
resolved, validated, and evaluated.

## 20. Result representation

A successful `policy_reference` evaluation MUST preserve the reference
boundary.

Logical result shape:

```json
{
  "requirement_id": "requirement:security-baseline",
  "primitive_type": "policy_reference",
  "status": "satisfied",
  "matched_signers": [
    "authority:security"
  ],
  "observed": {
    "policy_id": "policy:security-baseline",
    "policy_version": 3,
    "policy_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "policy_status": "satisfied"
  },
  "expected": {
    "policy_status": "satisfied"
  },
  "failure_code": null,
  "referenced_policy": {
    "policy_id": "policy:security-baseline",
    "policy_version": 3,
    "policy_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "status": "satisfied",
    "requirement_results": []
  }
}
```

`referenced_policy` MUST contain the complete referenced policy result tree.

It MUST NOT contain the original policy source object.

## 21. Matched signer aggregation

The `policy_reference` result's `matched_signers` MUST be the sorted set union
of the referenced policy's top-level requirement results.

This value represents affirmative signer evidence used by the referenced
policy.

Duplicate identifiers MUST be removed and output order MUST be ascending
Unicode code-point order.

## 22. Failure semantics

An unsatisfied referenced policy produces an unsatisfied `policy_reference`
requirement with:

```text
POLICY_REFERENCE_NOT_SATISFIED
```

The referenced policy's own projected failure codes remain present inside
`referenced_policy`.

At the parent policy level, projection contributes:

1. `POLICY_REFERENCE_NOT_SATISFIED`; and
2. the recursively projected failures from the referenced policy.

A satisfied reference contributes no policy-level failures, even if its result
tree contains suppressed unsatisfied alternatives.

Resolution, validation, cycle, limit, or binding errors remain fatal and MUST
NOT be converted into unsatisfied results.

## 23. Result path ordering

Failure projection across reference boundaries MUST be ordered by a canonical
node path.

A canonical node path is the ordered sequence of:

```text
(policy_id, policy_version, policy_digest, requirement_id)
```

from the root reference edge to the emitting node.

Canonical comparison uses ascending Unicode code-point order for strings and
ascending numeric order for versions.

Repeated failure-code strings are retained once per emitting node.

## 24. Memoization

An implementation MAY memoize validation or evaluation of an exact referenced
policy identity within one evaluation.

Memoization MUST NOT change:

- result content;
- result ordering;
- failure multiplicity;
- matched signer aggregation;
- cycle detection;
- observable evaluation completeness.

Cached state MUST NOT persist across evaluations unless it is keyed by every
input that affects the result.

Any cache, whether within one evaluation or across evaluations, MUST be
semantically equivalent to complete recomputation.

The reference implementation SHOULD initially avoid cross-evaluation caching.

## 25. Root policy binding

Only the root policy is directly bound by the Decision Context policy tuple.

Referenced policy identity is transitively bound because each reference node is
part of the canonical root policy or another transitively bound referenced
policy.

Changing any referenced policy requires changing its digest in the parent
reference, which changes the parent's digest transitively up to the root.

Therefore a complete reference graph is cryptographically committed by the root
policy digest when all references are exact digest bindings.

## 26. Security considerations

### 26.1 Mutable-reference attack

References without a digest permit content substitution. Such references are
forbidden.

### 26.2 Version-only substitution

Identifier and version matching alone are insufficient. Digest equality is
mandatory.

### 26.3 Resolver equivocation

A resolver that selects different bytes for the same reference breaks
determinism. The complete policy set is therefore an explicit evaluation input.

### 26.4 Cycle denial of service

Cycles MUST be detected before unbounded recursive descent.

### 26.5 Expansion denial of service

Reference depth, referenced-policy count, and expanded-node limits are
normative.

### 26.6 Hidden invalid policy

Every reachable referenced policy MUST be fully validated even when Boolean
short-circuiting could appear to make it unnecessary.

### 26.7 Policy-set injection

Unreferenced policy-set entries MUST NOT affect resolution or evaluation.

## 27. Compatibility

This specification does not change:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
```

Policies without `policy_reference` retain their existing semantics and require
no policy-set input.

A conforming 2.3 implementation MUST evaluate every valid 2.2 policy
identically.

An older implementation that does not support `policy_reference` will reject it
as an unsupported requirement type.

## 28. Required conformance coverage

### 28.1 Valid resolution

- direct reference satisfied;
- direct reference unsatisfied;
- nested references;
- one referenced policy reused by separate branches;
- reference inside `all_of`;
- reference inside `any_of`;
- reference inside `not`;
- referenced policy with its own composition tree.

### 28.2 Binding

- identifier mismatch;
- version mismatch;
- digest mismatch;
- malformed digest;
- boolean version;
- missing referenced policy;
- duplicate identifier/version entries;
- policy-set order independence.

### 28.3 Cycles and limits

- direct self-cycle;
- two-policy cycle;
- longer cycle;
- shared non-cyclic dependency accepted;
- depth 8 accepted;
- depth 9 rejected;
- 32 referenced policies accepted;
- 33 rejected;
- configured expanded-node boundary accepted and exceeded;
- implementation rejects an expanded-node limit below 2048.

### 28.4 Evaluation

- shared immutable evaluation time;
- referenced `eligible_roles` enforced independently;
- no short-circuit resolution;
- deterministic matched signer aggregation;
- recursive failure projection;
- deterministic canonical paths;
- byte-identical replay.

### 28.5 Compatibility

- every existing Trust Policy 2.2 vector remains unchanged;
- policies without references require no policy set;
- unsupported older runtime fails closed.

## 29. Open implementation questions

The normative model is fixed by this RFC draft, but implementation work should
confirm:

1. whether the CLI accepts a policy-set JSON array or a directory-independent
   manifest file;
2. whether referenced-policy results reuse the existing policy evaluation
   shape internally or introduce a dedicated immutable result type;
3. whether within-evaluation memoization is needed in the first implementation;
4. whether policy-set validation is exposed as a separate public function.

These choices MUST NOT change the externally observable semantics defined here.

## 30. Acceptance criteria

This RFC may move from Draft to Implemented when:

- the runtime resolves only explicit policy-set inputs;
- identifier, version, and canonical digest are all enforced;
- cycles and transitive limits are covered;
- reference boundaries remain visible in result trees;
- complete evaluation does not short-circuit;
- existing 2.2 outputs remain byte-identical;
- schema/runtime parity covers the reference node;
- golden vectors cover valid and invalid reference graphs;
- property tests generate bounded acyclic and cyclic policy graphs;
- the complete reference suite passes deterministically.
