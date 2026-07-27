# RFC: Go Trust Primitive Engine Architecture

Status: Draft
Target: post-TPE 2.6 successor workstream
Audience: implementers, reviewers, conformance maintainers

## 1. Summary

This RFC defines the architecture for a reusable and progressively complete Go
implementation of the AGP Trust Primitive Engine.

The existing Go program under `trust_primitive_engine/go/cmd/agp-tpe26-reproduce`
is a deliberately bounded conformance implementation. It remains closed under
`TPE-2.6-GO-IMPLEMENTATION-STATEMENT.md`.

The new workstream must not expand that closure claim implicitly. Instead, it
introduces a separate reusable Go engine with exported APIs, typed errors,
modular validation, primitive registration, signed-context verification, and
incremental Python/Go conformance.

## 2. Goals

The Go engine must eventually provide:

- a reusable library independent of any CLI;
- deterministic policy validation and evaluation;
- typed normative errors with stable machine-readable codes;
- complete Trust Policy 2 composition and policy-reference support;
- a deterministic primitive registry;
- Signed Decision Context verification;
- public evaluation APIs comparable to the Python package;
- reproducible cross-language conformance;
- versioned Go-module distribution.

The migration must preserve the existing complete validation result and all
frozen outputs throughout implementation.

## 3. Non-goals

This RFC does not:

- redefine Trust Policy 2 semantics;
- create TPE 2.7;
- change any object version;
- replace the Python implementation as authoritative during migration;
- require a one-shot rewrite;
- make the current bounded reproducer a stable public library;
- standardize human-readable error text.

## 4. Architectural principles

### 4.1 Library first

All normative behavior must live in importable packages. CLI commands are thin
adapters responsible only for input/output, argument parsing, and exit status.

### 4.2 Deterministic by construction

Public APIs must return deterministic values for the same normalized inputs.
Maps exposed in normative result objects must not influence ordering.

### 4.3 Validation before evaluation

Parsing, structural validation, policy-set indexing, graph validation,
signature verification, and evaluation are distinct phases.

Fatal defects must not be converted into ordinary unsatisfied requirements.

### 4.4 Typed normative errors

Every fatal failure must have a stable code and optional structured detail.
Callers must be able to inspect errors with `errors.Is` or `errors.As`.

Human-readable messages are diagnostic only.

### 4.5 Incremental conformance

Each implementation phase must add bounded cross-language tests before adding
the next capability.

The existing frozen Go profile remains unchanged until equivalent library APIs
are proven.

## 5. Proposed Go module layout

The module identity selected in Phase 0 is:

```text
module agpprotocol.org/agp/trust-primitive-engine
```

The decision and package-visibility boundary are recorded in
`trust_primitive_engine/go/PHASE-0.md`.

Proposed package layout:

```text
trust_primitive_engine/go/
  cmd/
    agp-tpe/
    agp-tpe26-reproduce/
  tpe/
    api.go
    errors.go
    options.go
  canonical/
    json.go
    digest.go
  model/
    policy.go
    context.go
    result.go
    signatures.go
  parser/
    json.go
  validation/
    identifiers.go
    policy.go
    context.go
    policy_set.go
    graph.go
  engine/
    state.go
    dispatcher.go
    composition.go
    policy.go
    projection.go
  primitive/
    primitive.go
    registry.go
  primitives/
    signer/
    role/
    temporal/
    context/
    evidence/
    provenance/
  signedcontext/
    keyring.go
    verify.go
```

Package cycles are prohibited.

The `tpe` package is the stable public facade. Lower-level packages may remain
internal until their contracts are ready.

## 6. Public API

The first stable facade should expose a small API:

```go
package tpe

type EvaluateRequest struct {
    SignedContext any
    Policy        any
    Keyring       any
    PolicySet     any
}

type Evaluation struct {
    ObjectType             string
    Status                 string
    PolicyID               string
    PolicyVersion          int64
    PolicyDigest           string
    ContextID              string
    ContextDigest          string
    VerifiedSignatureIDs   []string
    VerifiedSigners        []string
    MatchedSigners         []string
    UnauthorizedSigners    []string
    IneligibleRoleSigners  []string
    SignatureCount         int64
    Weight                 int64
    RequirementResults     []RequirementResult
    FailureCodes           []string
}

func Evaluate(ctx context.Context, request EvaluateRequest) (Evaluation, error)
```

The initial public facade may accept decoded JSON-compatible values while model
types stabilize.

File paths, stdin, and stdout must not appear in the core API.

## 7. Error model

The engine must define:

```go
type Error struct {
    Code   Code
    Detail string
    Path   []string
    Cause  error
}

func (e *Error) Error() string
func (e *Error) Unwrap() error
```

`Code` is a string-backed type containing normative codes such as:

```text
INVALID_JSON
INVALID_TRUST_POLICY
INVALID_TRUST_POLICY_SET
UNSUPPORTED_TRUST_PRIMITIVE
POLICY_REFERENCE_NOT_FOUND
POLICY_REFERENCE_DIGEST_MISMATCH
POLICY_REFERENCE_CYCLE
POLICY_REFERENCE_DEPTH_EXCEEDED
POLICY_REFERENCE_COUNT_EXCEEDED
POLICY_REFERENCE_NODE_LIMIT_EXCEEDED
INVALID_SIGNED_DECISION_CONTEXT
INVALID_SIGNATURE
UNKNOWN_KEY
UNSUPPORTED_ALGORITHM
POLICY_ID_MISMATCH
POLICY_VERSION_MISMATCH
POLICY_DIGEST_MISMATCH
```

The exact set must be derived from normative documents and existing executable
Python behavior.

## 8. Parsing and canonicalization

Raw JSON parsing must be isolated from validation.

The parser must eventually enforce:

- UTF-8 without BOM;
- no duplicate members;
- no trailing data;
- integers only where required;
- no non-finite numbers;
- safe-integer bounds;
- deterministic decoding behavior.

Canonical serialization and SHA-256 digest calculation belong in a dedicated
package shared by policy, context, signature, and evaluation code.

## 9. Model and immutability

Validated model values must be immutable by convention:

- constructors validate and copy inputs;
- exported slices are copied on construction and return;
- maps are avoided in public normative types where ordering matters;
- internal maps may be used only as indexes;
- normalization occurs once before evaluation.

The Go result model must preserve the Python invariants:

- satisfied results have no failure code;
- unsatisfied results have one failure code;
- matched signers are sorted and unique;
- children preserve canonical requirement order;
- referenced-policy evidence is explicit;
- satisfied policies contain no projected failures;
- unsatisfied policies contain at least one projected failure.

## 10. Primitive contract and registry

The primitive interface should separate validation from evaluation:

```go
type Primitive interface {
    Type() string
    Validate(raw map[string]any) (ValidatedRequirement, error)
    Evaluate(requirement ValidatedRequirement, state State) (Result, error)
}
```

The registry must:

- reject empty type identifiers;
- reject duplicate registration;
- resolve deterministically;
- expose sorted registered types;
- distinguish unsupported primitives from invalid definitions.

Composition and `policy_reference` are structural requirement categories, not
ordinary primitive plugins.

## 11. Evaluation pipeline

The public `Evaluate` call must execute these phases in order:

1. parse and normalize request inputs;
2. validate root policy;
3. validate and index policy set;
4. validate root policy binding in the context;
5. validate Signed Decision Context structure;
6. verify signatures and keyring bindings;
7. validate the complete reachable policy-reference graph;
8. construct immutable evaluation context;
9. evaluate every requirement without short-circuiting;
10. project failures deterministically;
11. construct the final evaluation object;
12. return a value suitable for canonical serialization.

A failure in phases 1 through 8 returns an error and no evaluation object.

## 12. Signed Decision Context integration

The repository already contains an independent Go Signed Decision Context
verifier and persistent Ed25519 vectors.

The TPE engine should not copy that CLI implementation directly into the new
engine package.

Instead, signed-context verification must first be extracted into a reusable Go
library with:

```go
type VerificationResult struct {
    VerifiedSignatureIDs []string
    VerifiedSigners      []string
}

func Verify(
    ctx context.Context,
    signedContext any,
    keyring any,
) (VerificationResult, error)
```

The TPE engine then consumes this library.

Only Ed25519 is currently required. Algorithm agility must remain explicit and
fail closed.

## 13. Compatibility strategy

Python remains the behavioral oracle during migration.

Each phase must compare one or more of:

- acceptance and rejection;
- normative error code;
- normalized policy or context representation;
- complete logical evaluation object;
- canonical JSON bytes;
- SHA-256 digest.

No phase may update frozen expected outputs merely to make Go pass.

Differences require either:

- a Go defect;
- a Python defect fixed in both implementations with normative justification;
- a documented non-overlapping boundary.

## 14. Implementation phases

### Phase 0 — Architecture and module identity

- merge this RFC;
- choose the stable Go module path;
- create package skeletons;
- preserve the bounded reproducer unchanged.

Exit criterion: package layout builds and existing 796/796 validation passes.

### Phase 1 — Core types and typed errors

- add public error model;
- add result and policy identity types;
- add canonical JSON and digest helpers;
- add unit tests for invariants.

Exit criterion: no CLI behavior change; deterministic type tests pass.

### Phase 2 — Validation library extraction

- move identifier, integer, set, requirement-tree, policy, and graph validation
  from the reproducer into packages;
- keep CLI wrappers as compatibility adapters;
- compare all existing Go validation matrices through library APIs.

Exit criterion: existing Go validation suites pass without invoking duplicated
validation logic.

### Phase 3 — Evaluation library extraction

- extract state, primitive evaluation, composition, recursive references, and
  failure projection;
- make the reproducer call the library;
- preserve byte-identical frozen outputs.

Exit criterion: all 109 bounded Python/Go checks remain green through the new
library.

### Phase 4 — Primitive-registry expansion

Port remaining Trust Policy 2 primitives by families:

1. signer-count and required-signer primitives;
2. role and weight primitives;
3. separation and mutual-exclusion primitives;
4. temporal primitives;
5. context and evidence primitives;
6. provenance primitives.

Every family requires shared Python/Go validation and evaluation matrices.

### Phase 5 — Signed-context library

- extract reusable Go validation and Ed25519 verification;
- consume persistent cross-language crypto vectors;
- integrate verified signatures into TPE evaluation.

Exit criterion: signed public API evaluations match Python.

### Phase 6 — Public Go API

- expose `tpe.Evaluate`;
- expose typed request and result values;
- add examples and compatibility tests;
- keep CLI as a thin wrapper.

### Phase 7 — Full conformance and distribution

- reach complete implemented primitive coverage;
- add complete public API conformance;
- publish versioning policy;
- tag the first reusable Go library release only after all declared guarantees
  pass in CI.

## 15. CI requirements

The full-Go workstream must preserve:

```text
AGP TPE 2.6 development validation: 796/796 passed
```

until new tests intentionally increase the total.

Every PR must run:

- existing repository conformance;
- bounded Go reproduction suites;
- new package unit tests;
- cross-language tests for the capability introduced;
- `go test ./...`;
- `go vet ./...` once packages exist;
- formatting and diff checks.

## 16. Migration rule for the bounded reproducer

The existing command remains the frozen compatibility shell during extraction.

Allowed changes:

- replacing local implementation with calls into proven library packages;
- retaining output and error behavior;
- deleting duplicated code only after parity tests pass.

Disallowed changes:

- silently broadening its documented conformance scope;
- changing frozen output bytes;
- exposing fixture-only identity overrides through production APIs;
- using expected-evaluation files at runtime.

## 17. Security considerations

The architecture must fail closed for:

- malformed JSON;
- unknown algorithms;
- invalid key lengths;
- unknown keys;
- invalid signatures;
- policy-binding mismatches;
- unresolved or digest-mismatched references;
- cyclic or over-limit reference graphs;
- unsupported primitives.

Resource limits must be enforced before unbounded recursion or large
allocations.

This RFC is not a security audit.

## 18. Phase 0 decisions

Phase 0 resolves the initial architecture decisions as follows:

1. module path: `agpprotocol.org/agp/trust-primitive-engine`;
2. initial facade inputs may use decoded JSON-compatible values while typed
   models stabilize;
3. initial schema parity uses equivalent native validators;
4. only `tpe` is public; implementation packages begin under `internal`;
5. semantic versioning starts only when the public facade is stabilized;
6. Signed Decision Context remains a sibling module and must expose a reusable
   verification package before integration.

These decisions are recorded in `trust_primitive_engine/go/PHASE-0.md`.

## 19. Acceptance

This RFC is accepted when:

- the architecture is reviewed;
- the bounded TPE 2.6 Go closure statement remains unchanged;
- the module and package boundaries are approved;
- implementation phases have explicit exit criteria;
- no normative object or release version is changed.
