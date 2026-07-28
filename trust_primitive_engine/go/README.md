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

## Phase 4.1B signer-set primitives

The reusable engine evaluates `prohibited_signer`, `any_of_signers`,
`all_of_signers`, and `exactly_one_of_signers` against the deterministic
matched-signer projection.

See `PHASE-4.1B.md`.

## Phase 4.1A basic signer primitives

The reusable engine evaluates `required_signer` and `signer_threshold` against
the deterministic authorized and role-eligible signer projection.

See `PHASE-4.1A.md`.

## Phase 5B-2C verified signed evaluation

External callers can verify a Signed Decision Context and evaluate its authenticated context through tpe.EvaluateSigned.

See PHASE-5B-2C.md.

## Phase 4B public evaluation API

External Go callers can evaluate policies through the stable `tpe.Evaluate`
facade without importing internal packages.

See `PHASE-4B.md`.

## Phase 4A final evaluation assembly

Signature/input models, signer projection, and complete deterministic
evaluation-object assembly are reusable through `internal/model` and
`internal/engine`.

See `PHASE-4A.md`.

## Phase 3B recursive evaluation

Composition, policy-reference recursion, deterministic failure projection,
and complete requirement evaluation are reusable through `internal/engine`.

See `PHASE-3B.md`.

## Phase 3A provenance leaf evaluation

Decision-context models and TPE 2.6 provenance leaf evaluators are reusable
through `internal/model` and `internal/primitives/provenance`.

See `PHASE-3A.md`.

## Phase 2C policy-reference graph validation

The shared policy model and bounded graph validation are reusable through
`internal/model` and `internal/validation`.

See `PHASE-2C.md`.

## Phase 2B structural validation

Requirement, composition-tree, and policy validation are reusable through
`internal/validation`, while graph validation remains bounded to the CLI.

See `PHASE-2B.md`.

## Phase 2A strict JSON parsing

Strict JSON loading and conversion helpers are reusable through
`internal/parser`, while the bounded CLI preserves its existing surface.

See `PHASE-2A.md`.

## Phase 1 core types

Typed fatal errors, internal policy/result invariants, and canonical JSON
helpers are introduced without changing the bounded reproducer.

See `PHASE-1.md`.

## Go module identity

The reusable engine module is:

```text
agpprotocol.org/agp/trust-primitive-engine
```

Phase 0 package boundaries and compatibility constraints are recorded in
`PHASE-0.md`.

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

## Phase 4.1C signer cardinality primitives

The reusable engine evaluates `at_least_n_signers`, `at_most_n_signers`, and
`exactly_n_signers` with Python-compatible validation and result shapes.

See `PHASE-4.1C.md`.

## Phase 4.1D role threshold primitives

The reusable engine evaluates `role_threshold` and `role_weight_threshold`
against the verified participant projection.

See `PHASE-4.1D.md`.

## Phase 4.1E global threshold primitives

The reusable engine evaluates `global_signature_threshold` and
`global_weight_threshold` over distinct matched signer identities.

See `PHASE-4.1E.md`.

## Phase 4.1F duty separation and mutual exclusion

The reusable engine evaluates `separation_of_duties` and
`mutual_exclusion` with Python-compatible validation and result shapes.

See `PHASE-4.1F.md`.

## Phase 4.1G-1 evidence manifest projection

The public and internal Go context models preserve evidence `digest` and
`media_type` through JSON decoding and public-to-internal conversion.

See `PHASE-4.1G-1.md`.

## Phase 4.1G-2 evidence presence and count primitives

The reusable Go evaluator supports `evidence_present` and
`evidence_count_at_least`, including deterministic validation,
observations, filters, and failure projection.

See `PHASE-4.1G-2.md`.

## Phase 4.1H-1 context projection and path resolution

The Go TPE preserves `proposal.payload` and provides deterministic
restricted context-path parsing and resolution for later contextual
predicate phases.

See `PHASE-4.1H-1.md`.

## Phase 4.1H-2 basic context predicates

The reusable Go evaluator supports context presence, strict scalar
equality, and safe-integer lower and upper bounds.

See `PHASE-4.1H-2.md`.

## Phase 4.1H-3 context set and path predicates

The reusable Go evaluator supports canonical scalar-set membership
and strict equality between two resolved context paths.

See `PHASE-4.1H-3.md`.

## Phase 4.1I-1 evaluation time projection

The Go TPE preserves authenticated Decision Context `evaluation_time`
while distinguishing absence from Unix epoch zero.

See `PHASE-4.1I-1.md`.

## Phase 4.1I-2 deterministic temporal evaluation

The Go TPE implements inclusive `time_window` evaluation using only
the authenticated Decision Context `evaluation_time`, fails closed when
that consensus input is absent, and preserves the stable top-level
evaluation shape.

See `PHASE-4.1I-2.md`.
