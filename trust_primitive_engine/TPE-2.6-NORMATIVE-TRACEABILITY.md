# TPE 2.6 Normative Traceability

## Status

This document records the auditable mapping between TPE 2.6 normative rules,
authoritative JSON Schemas, runtime enforcement, frozen evidence, and installed
wheel verification.

It does not change the object versions:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
agp.decision-context/3
agp.signature-statement/3
agp.signed-decision-context/3
```

## Authoritative sources

| Concern | Authoritative source |
|---|---|
| TPE 2.6 predicate semantics | `trust_primitive_engine/rfcs/TPE-2.6-001-deterministic-evidence-provenance-predicates.md` |
| Decision Context 3 structure and provenance declarations | `decision_context/rfcs/DC-3-001-context-attested-evidence-provenance.md` |
| Trust Policy 2 structure | `spec/AGP-TRUST-POLICY-2.0.md` |
| Trust Policy 2 validation rules | `spec/AGP-TRUST-POLICY-2.0-VALIDATION.md` |
| Registry object activation | `registry/registry.json` |
| JSON Schemas | `registry/schemas/` |

## Rule traceability

| Rule | Schema boundary | Runtime boundary | Primary evidence |
|---|---|---|---|
| `evidence_issuer_in` accepts a canonical non-empty issuer set and optional evidence-type cross-filter | `agp.trust-policy-2.schema.json` | `primitives/evidence_provenance.py` | `test_evidence_provenance_predicates.py`, TPE 2.6 golden corpus |
| `evidence_type_in` accepts a canonical non-empty evidence-type set and optional issuer cross-filter | `agp.trust-policy-2.schema.json` | `primitives/evidence_provenance.py` | `test_evidence_provenance_predicates.py`, TPE 2.6 golden corpus |
| `evidence_distinct_issuers_at_least` counts unique issuers after optional same-entry evidence-type filtering | `agp.trust-policy-2.schema.json` | `primitives/evidence_provenance.py` | `test_evidence_provenance_predicates.py`, `test_tpe26_integration.py` |
| Cross-filters bind issuer and evidence type on the same evidence entry | policy schema permits the fields; semantic binding is runtime-enforced | `primitives/evidence_provenance.py` | `same_entry_cross_filter`, `tpe26_same_entry_binding` |
| DC3 provenance is `available`, including an empty evidence array | `agp.decision-context-3.schema.json` | context projection and provenance primitive runtime | `empty-dc3-manifest` golden case |
| DC1/DC2 provenance is `unavailable` and predicates are ordinarily unsatisfied | legacy schemas remain unchanged | provenance projection runtime | `dc2-provenance-unavailable` golden case |
| `issuer_id` and `evidence_type` are context-attested declarations, not independently authenticated issuer claims | DC3 evidence entry requires both fields | signed-context verification authenticates the whole context | DC3 RFC, TPE 2.6 RFC, conformance statement |
| Failure projection remains deterministic through composition and policy references | Trust Policy 2 schema | recursive evaluator | `test_tpe26_integration.py`, recursive golden case |
| Evaluation output is deterministic under compact sorted-key JSON serialization | evaluation object contract | evaluator serialization | TPE 2.6 golden manifest and external reproduction package |

## Schema/runtime boundary

JSON Schema validates structural constraints expressible in Draft 2020-12.
Runtime validation additionally enforces canonical and relational constraints,
including:

- canonical ordering;
- duplicate rejection where uniqueness depends on semantic identifiers;
- safe relational bounds;
- policy-reference digest binding;
- same-entry provenance filtering;
- deterministic failure ordering.

A schema acceptance followed by a runtime rejection is conformant only when the
runtime-only rule is explicitly documented and covered by the schema/runtime
parity or primitive validation matrix.

## Installed-wheel guarantees

`trust_primitive_engine/tools/test_package_install.py` proves that the wheel
built from the repository:

1. contains the complete 13-schema registry inventory;
2. contains byte-identical copies of the authoritative registry schemas;
3. exposes the stable public API and `DEFAULT_SCHEMA_DIR`;
4. validates a frozen Signed Decision Context 3 fixture using only schemas from
   the clean installed wheel.

This prevents a stale local environment from being mistaken for the contents
of the newly built distribution.

## Bounded Go implementation closure

The complete bounded cross-language claim and its non-scope are recorded in
`TPE-2.6-GO-IMPLEMENTATION-STATEMENT.md`.

The closure statement aggregates seven registered Python/Go suites totaling
109 checks and separates the existing reproducer from the successor reusable
Go-engine workstream.

## Cross-language policy-reference graph boundary

`trust_primitive_engine/tools/test_tpe26_go_policy_reference_graph_validation.py`
covers 13 bounded graph-validation cases. Production validation computes
canonical policy digests and runs before recursive evaluation. Controlled
identity digests are accepted only through the fixture-specific conformance
mode used to reproduce self and indirect cycles.

## Cross-language composition plus policy-reference boundary

`trust_primitive_engine/tools/test_tpe26_go_composition_policy_reference_evaluation.py`
compares complete Python and Go evaluation objects across 8 bounded vectors.

The claim covers policy references inside all three composition operators,
transitive references, repeated references to a shared policy, recursive
`referenced_policy` evidence, outer-composition failure suppression, and
deterministic failure projection by full requirement path.

The matrix remains restricted to the three TPE 2.6 evidence-provenance leaves.

## Cross-language composition-evaluation boundary

`trust_primitive_engine/tools/test_tpe26_go_composition_evaluation.py`
compares complete Python and Go evaluation objects across 12 bounded vectors.

The claim covers recursive result trees, `all_of`, `any_of`, and `not` truth
semantics, complete branch evaluation, deterministic failure projection, and
failure suppression beneath satisfied compositions.

The matrix uses only the three TPE 2.6 evidence-provenance leaves and excludes
policy references so that the composition claim remains independently bounded.

## Cross-language composition-validation boundary

`trust_primitive_engine/tools/test_tpe26_go_composition_validation.py` applies
a shared 20-vector matrix to Python and Go.

The bounded claim covers structural validation of `all_of`, `any_of`, and
`not`, including exact members, arity, canonical child order, globally unique
requirement IDs, depth 8, 256 nodes, and validation of every branch.

The bounded Go profile admits only the three TPE 2.6 evidence-provenance
leaves. The shared parity matrix uses genuinely unknown primitives and malformed
policy references for common rejection cases; it does not claim that Python rejects
its other valid primitives or well-formed policy references. Composition evaluation
remains outside this boundary.

## Cross-language leaf-policy validation boundary

`trust_primitive_engine/tools/test_tpe26_go_policy_validation.py` applies a
shared 22-vector matrix to the Python policy validator and the independent Go
validator.

The bounded profile covers exact root members, policy identity and version,
eligible-role constraints, the requirements array, TPE 2.6 leaf validation,
canonical top-level requirement ordering, and duplicate requirement IDs.

Composition trees, policy references, non-TPE-2.6 leaves, and strict raw-JSON
parser parity remain outside this conformance claim.

## Cross-language requirement-validation boundary

`trust_primitive_engine/tools/test_tpe26_go_validation.py` exercises a shared
27-vector matrix against the Python primitive validators and the independent
Go requirement validator.

The matrix covers the exact-member boundary, identifier and evidence-type
syntax, canonical set ordering, duplicate rejection, cardinality limits, JSON
type strictness, and the inclusive `minimum` range from 1 through 256.

The conformance claim is acceptance/rejection parity. Human-readable validation
messages are not standardized by this profile.

## Cross-language frozen-profile boundary

`trust_primitive_engine/tools/test_tpe26_go_reproduction.py` builds a separate
Go program and requires it to reproduce all seven frozen TPE 2.6 evaluations
byte-for-byte and hash-for-hash.

The Go program independently implements the three evidence-provenance
predicates and the policy-reference projection used by the corpus. It derives
the evaluation envelope from the input context and policy rather than reading
the expected evaluation.

This establishes cross-language consistency for the frozen TPE 2.6 profile. It
does not claim a complete second implementation of all Trust Policy 2
validation and evaluation semantics.

## Independent reproduction boundary

`trust_primitive_engine/tools/test_tpe26_external_reproduction.py` separately
proves deterministic public-API evaluation from installed wheels outside the
repository checkout. It freezes one satisfied and one unsatisfied signed DC3
case and verifies their SHA-256 evaluation digests.

## Non-claims

These checks do not establish:

- independent authenticity of an external evidence issuer;
- production security;
- a completed independent security audit;
- third-party adoption;
- semantic equivalence of an implementation that does not pass the frozen
  corpora and validation matrices.
