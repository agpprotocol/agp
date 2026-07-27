# TPE 2.6 Go Implementation Statement

## 1. Status

This document closes the bounded Go reproduction line for TPE 2.6.

The implementation is intentionally narrower than the authoritative Python
Trust Primitive Engine. It is considered complete only for the cross-language
boundaries and evidence listed here.

This statement does not create a new TPE release, object version, package
version, or Git tag.

## 2. Implementation identity

| Field | Value |
|---|---|
| TPE release line | `2.6.0` |
| Release tag | `tpe-v2.6.0` |
| Go module | `trust_primitive_engine/go` |
| Executable | `cmd/agp-tpe26-reproduce` |
| Trust Policy object | `agp.trust-policy/2` |
| Evaluation object | `agp.trust-policy-evaluation/2` |

The Go program is built independently from the Python package and does not read
frozen expected evaluations while producing results.

## 3. Closed implementation scope

The bounded Go implementation covers:

- `evidence_issuer_in`;
- `evidence_type_in`;
- `evidence_distinct_issuers_at_least`;
- optional same-entry issuer and evidence-type filters;
- Decision Context 3 provenance availability;
- unavailable provenance for Decision Context 1 and 2;
- deterministic `all_of`, `any_of`, and `not` evaluation;
- recursive child-result construction;
- deterministic failure projection and suppression;
- direct, transitive, shared, and composed `policy_reference` evaluation;
- recursive `referenced_policy` result evidence;
- canonical policy-digest verification;
- complete reachable policy-reference graph preflight;
- cycle rejection;
- maximum reference depth 8;
- maximum 32 reachable referenced policies;
- maximum 2048 expanded requirement nodes;
- bounded requirement, policy, and composition validation;
- compact deterministic evaluation serialization.

## 4. Demonstrated cross-language guarantees

The following guarantees are demonstrated by executable Python/Go matrices:

| Boundary | Evidence |
|---|---:|
| Frozen-profile byte and SHA-256 reproduction | 7/7 |
| Requirement-validation parity | 27/27 |
| Leaf-policy validation parity | 22/22 |
| Composition-validation parity | 20/20 |
| Composition-evaluation object parity | 12/12 |
| Composition plus policy-reference object parity | 8/8 |
| Policy-reference graph-validation parity | 13/13 |

These suites contribute 109 checks to the complete TPE development validation.

The authoritative aggregate result at closure is:

```text
AGP TPE 2.6 development validation: 796/796 passed
```

The package installation and schema audit independently reports:

```text
AGP TPE package installation and schema audit: 4/4 passed
```

## 5. Production and fixture boundaries

Production graph validation always computes canonical SHA-256 policy digests
from the decoded policy documents.

A fixture-only CLI mode permits controlled identity digests solely to reproduce
self and indirect cycle cases whose digest identities cannot be represented as
ordinary self-consistent policy documents.

The fixture mode is test infrastructure. It is not part of the production
evaluation contract and must not be treated as an alternative policy-resolution
mechanism.

## 6. Resource and determinism guarantees

Within the bounded profile:

- composition depth is at most 8;
- one policy contains at most 256 requirement-tree nodes;
- policy-reference depth is at most 8;
- at most 32 distinct referenced policies are reachable;
- at most 2048 requirement nodes are expanded across the reachable graph;
- policy-set input order does not change graph acceptance;
- child and top-level requirement ordering is canonical;
- requirement IDs are globally unique within one policy;
- invalid reference graphs are rejected before recursive evaluation;
- no partial evaluation object is emitted after graph-preflight failure.

## 7. Explicit non-scope

This closed implementation is not:

- a complete Go implementation of every Trust Policy 2 primitive;
- a Go implementation of the complete Python public API;
- a reusable Go engine package with stable exported APIs;
- a full Signed Decision Context verifier;
- a full JSON Schema runtime;
- a complete raw-JSON parser parity implementation;
- a replacement for the authoritative Python package;
- a third-party certification, formal proof, or security audit.

The executable remains a bounded reproduction and conformance implementation.

## 8. Closure criterion

The bounded Go TPE 2.6 line is closed when all of the following remain true:

1. every registered Python/Go suite passes;
2. all seven frozen evaluations remain byte-identical and hash-identical;
3. the complete validation reports `796/796`;
4. invalid policy-reference graphs are rejected before evaluation;
5. fixture-controlled identities remain isolated from production validation;
6. documentation continues to describe the implementation as bounded.

Any expansion beyond these boundaries belongs to the separate full-Go-engine
workstream and must not silently broaden this conformance claim.

## 9. Successor workstream

The successor is a reusable, progressively complete Go Trust Primitive Engine.

That work requires a separate architecture and implementation plan covering:

- exported engine APIs;
- typed normative errors;
- complete policy-set and context validation;
- progressive primitive-registry coverage;
- signature and Signed Decision Context verification;
- reusable evaluation APIs;
- full cross-language conformance;
- versioned Go library distribution.

The successor workstream does not modify the closure status of this bounded
TPE 2.6 reproduction profile.

Its architecture and phased implementation plan are defined by:

```text
trust_primitive_engine/rfcs/TPE-GO-001-reusable-engine-architecture.md
```
