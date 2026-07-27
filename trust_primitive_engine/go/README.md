# TPE 2.6 Go reproduction profile

This directory contains a deliberately bounded Go reproduction of the frozen
TPE 2.6 evidence-provenance corpus.

It independently implements:

- `evidence_issuer_in`;
- `evidence_type_in`;
- `evidence_distinct_issuers_at_least`;
- the recursive `policy_reference` projection exercised by the corpus;
- deterministic TPE 2.6 evaluation-result construction.

The Go program reads only `evaluation-input.json`, `root-policy.json`, and
`policy-set.json`. It does not read `expected-evaluation.json` while producing
a result.

Run:

```bash
python trust_primitive_engine/tools/test_tpe26_go_reproduction.py
```

Expected marker:

```text
TPE 2.6 Python/Go frozen-profile reproduction: 7/7 passed
```

## Policy-reference graph preflight

Before evaluation, the reproducer resolves the complete reachable reference
graph and enforces canonical digests, cycle rejection, maximum reference depth
8, maximum 32 reachable policies, and maximum 2048 expanded requirement nodes.

`--validate-policy-graph` returns a compact acceptance receipt. A separate
fixture-only mode permits controlled identity digests for otherwise
unrepresentable cycle conformance vectors.

## Composition with policy references

The reproduction binary evaluates policy references nested under `all_of`,
`any_of`, and `not`, including transitive references and repeated shared-policy
branches.

The 8-vector suite compares complete Python and Go evaluation objects,
including nested `referenced_policy` results and failure-code ordering.

## Composition evaluation

The reproduction binary evaluates bounded `all_of`, `any_of`, and `not`
trees recursively. It emits Python-compatible child evidence and deterministic
failure-code projection without short-circuiting.

The 12-vector suite compares complete evaluation objects for policies without
policy references.

## Composition validation mode

`--validate-policy` now accepts bounded `all_of`, `any_of`, and `not` trees
with TPE 2.6 leaves. The structural profile enforces depth, node-count,
canonical ordering, arity, exact-member, and global-ID constraints.

Composition evaluation and policy-reference validation are still excluded.

## Leaf-policy validation mode

The binary also validates bounded TPE 2.6 leaf policies:

```bash
agp-tpe26-reproduce --validate-policy policy.json
```

The 22-vector parity matrix compares complete-policy acceptance with Python
while deliberately excluding composition and policy-reference semantics.

## Requirement validation mode

The same binary exposes a bounded validation mode:

```bash
agp-tpe26-reproduce --validate-requirement requirement.json
```

The 27-vector Python/Go parity suite verifies common acceptance and rejection
semantics for the three TPE 2.6 predicates.

## Reusable engine successor

The bounded reproducer is not the target architecture for a complete Go
implementation. The successor design is specified in:

```text
trust_primitive_engine/rfcs/TPE-GO-001-reusable-engine-architecture.md
```

Implementation proceeds incrementally while this command remains the frozen
compatibility shell.

## Closure status

The bounded TPE 2.6 Go reproduction line is formally closed by:

```text
trust_primitive_engine/TPE-2.6-GO-IMPLEMENTATION-STATEMENT.md
```

That statement records the demonstrated guarantees, production and fixture
boundaries, explicit non-scope, and the separation from the successor
full-Go-engine workstream.

## Scope limitation

This is not yet a complete second implementation of the Trust Primitive
Engine. It does not implement every Trust Policy 2 primitive, composition
form, validation rule, signature-verification path, or arbitrary reference
graph.
