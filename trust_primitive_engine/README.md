# AGP Trust Primitive Engine

The AGP Trust Primitive Engine (TPE) deterministically evaluates Trust Policy
2 objects over cryptographically verified signer identities from an AGP Signed
Decision Context.

The current implementation supports:

- Trust Policy 2 primitive requirements;
- deterministic temporal evaluation;
- recursive Boolean composition;
- deterministic policy references;
- deterministic Decision Context projection and resolution;
- deterministic context-value and evidence requirements;
- complete recursive result evidence;
- deterministic policy-level failure projection.

## Requirement categories

### Primitive requirements

The engine currently includes:

- `required_signer`
- `signer_threshold`
- `global_signature_threshold`
- `global_weight_threshold`
- `role_threshold`
- `role_weight_threshold`
- `separation_of_duties`
- `mutual_exclusion`
- `prohibited_signer`
- `any_of_signers`
- `all_of_signers`
- `exactly_one_of_signers`
- `at_least_n_signers`
- `at_most_n_signers`
- `exactly_n_signers`
- `time_window`
- `context_value_present`
- `context_value_equals`
- `context_integer_at_least`
- `context_integer_at_most`
- `evidence_present`

### Context and evidence requirements

Trust Primitive Engine 2.4 adds deterministic requirements over the verified
Decision Context.

Context paths are restricted to `/proposal/payload/...` and use JSON Pointer
escaping. A found JSON `null` value counts as present. Missing paths and
traversal mismatches are ordinary unsatisfied results.

Example context requirements:

```json
[
  {
    "requirement_id": "requirement:environment-present",
    "type": "context_value_present",
    "path": "/proposal/payload/environment"
  },
  {
    "requirement_id": "requirement:production-environment",
    "type": "context_value_equals",
    "path": "/proposal/payload/environment",
    "value": "production"
  },
  {
    "requirement_id": "requirement:minimum-coverage",
    "type": "context_integer_at_least",
    "path": "/proposal/payload/test_report/coverage_basis_points",
    "minimum": 9000
  },
  {
    "requirement_id": "requirement:maximum-rollout",
    "type": "context_integer_at_most",
    "path": "/proposal/payload/rollout/basis_points",
    "maximum": 2500
  }
]
```

Scalar equality is type-strict. Integer comparisons reject Booleans, decimals,
and values outside the AGP safe-integer range.

Example evidence requirement:

```json
{
  "requirement_id": "requirement:approved-security-report",
  "type": "evidence_present",
  "evidence_id": "evidence.security-report",
  "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "media_type": "application/json"
}
```

The evidence match status is deterministically classified as `matched`,
`absent`, `digest_mismatch`, `media_type_mismatch`, or
`digest_and_media_type_mismatch`.

Context and evidence requirements can appear directly, inside composition
requirements, and inside referenced policies. Root and referenced policies use
the same verified Decision Context.

Primitive implementations are registered through `PrimitiveRegistry`.

### Composition requirements

Trust Primitive Engine 2.2 supports:

- `all_of`
- `any_of`
- `not`

Composition evaluates the complete requirement tree without short-circuiting.
Child results remain visible even when the parent result is already logically
determined.

### Policy references

Trust Primitive Engine 2.3 adds the structural requirement type:

```json
{
  "requirement_id": "requirement:security-policy",
  "type": "policy_reference",
  "policy_id": "policy:security",
  "policy_version": 1,
  "policy_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

A reference is resolved only from the explicit policy set supplied for the
evaluation.

The tuple below is an exact binding:

- `policy_id`
- `policy_version`
- `policy_digest`

The digest is the lowercase hexadecimal SHA-256 digest of the canonical
referenced Trust Policy object. Algorithm prefixes such as `sha256:` are not
accepted.

## Policy-set format

The policy set is a JSON array of complete Trust Policy 2 objects:

```json
[
  {
    "object_type": "agp.trust-policy/2",
    "policy_id": "policy:security",
    "version": 1,
    "eligible_roles": [
      "reviewer"
    ],
    "requirements": [
      {
        "requirement_id": "requirement:security-reviewer",
        "type": "required_signer",
        "signer_id": "authority:security"
      }
    ]
  }
]
```

Policy-set order does not affect resolution or evaluation.

Each `policy_id` and `version` pair must be unique. Every reachable referenced
policy is validated before evaluation begins.

The root policy does not need to appear in the policy set.

Unreferenced policy-set entries do not affect the result.

## CLI usage

Evaluate a policy without references:

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --keyring keyring.json
```

Evaluate a policy containing `policy_reference` requirements:

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --policy-set policy-set.json \
  --keyring keyring.json
```

The optional schema directory remains available:

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --policy-set policy-set.json \
  --keyring keyring.json \
  --schema-dir registry/schemas
```

The CLI exits with:

- `0` when the policy is satisfied;
- `2` when evaluation completes and the policy is unsatisfied;
- `1` for validation, verification, binding, policy-set, or reference errors.

## Referenced-policy semantics

A `policy_reference` is satisfied if and only if its referenced policy is
satisfied.

Each referenced policy applies its own `eligible_roles`. Verified signer
identity, participant data, and evaluation time are shared across the complete
evaluation, but these values are recalculated for every policy:

- `matched_signers`
- `signature_count`
- `weight`

The result contains a visible `referenced_policy` boundary:

```json
{
  "requirement_id": "requirement:security-policy",
  "type": "policy_reference",
  "status": "satisfied",
  "matched_signers": [
    "authority:security"
  ],
  "observed": {
    "policy_id": "policy:security",
    "policy_version": 1,
    "policy_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "policy_status": "satisfied"
  },
  "expected": {
    "policy_status": "satisfied"
  },
  "failure_code": null,
  "referenced_policy": {
    "policy_id": "policy:security",
    "policy_version": 1,
    "policy_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "status": "satisfied",
    "requirement_results": [],
    "failure_codes": []
  }
}
```

`referenced_policy` contains result evidence only. It does not contain the
original source policy object.

## Failure behavior

An unsatisfied reference emits:

```text
POLICY_REFERENCE_NOT_SATISFIED
```

Its referenced policy retains its own recursive `failure_codes`.

At the containing policy level, an unsatisfied reference contributes:

1. `POLICY_REFERENCE_NOT_SATISFIED`;
2. recursively projected failures from the referenced policy.

Satisfied requirements suppress descendant failures from policy-level
projection according to the same composition rules used by TPE 2.2.

Repeated failure-code strings remain present once per emitting result node.

## Fatal reference errors

Reference-graph defects are fatal evaluation errors. They are not converted
into ordinary unsatisfied results.

The implementation may emit errors including:

- `POLICY_REFERENCE_SET_REQUIRED`
- `INVALID_TRUST_POLICY_SET`
- `POLICY_REFERENCE_NOT_FOUND`
- `POLICY_REFERENCE_ID_MISMATCH`
- `POLICY_REFERENCE_VERSION_MISMATCH`
- `POLICY_REFERENCE_DIGEST_MISMATCH`
- `POLICY_REFERENCE_CYCLE`
- `POLICY_REFERENCE_DEPTH_EXCEEDED`
- `POLICY_REFERENCE_COUNT_EXCEEDED`
- `POLICY_REFERENCE_NODE_LIMIT_EXCEEDED`

Normative limits are:

- maximum reference depth: 8;
- maximum reachable referenced policies: 32;
- maximum expanded requirement nodes: 2048.

## Compatibility

Trust Policy 1 remains unchanged.

Trust Policy 2 continues to use:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
```

Policies without `policy_reference` retain their existing TPE 2.2 semantics and
do not require a policy set.

Policies without TPE 2.4 context or evidence requirements preserve their TPE
2.3 output shape and byte-stable behavior.

The TPE 2.2 golden compatibility corpus remains authoritative for legacy
behavior.

## Conformance tests

Run the Trust Policy 2 compatibility corpus:

```bash
python trust_primitive_engine/tools/test_golden_policy_corpus.py
```

Run the TPE 2.3 policy-reference corpus:

```bash
python \
  trust_primitive_engine/tools/test_policy_reference_conformance_corpus.py
```

The TPE 2.3 fixtures are stored under:

```text
trust_primitive_engine/fixtures/golden/v2.3
```

The corpus covers:

- direct satisfied references;
- direct unsatisfied references;
- nested references;
- shared references;
- independent referenced-policy roles;
- references inside `all_of`;
- references inside `any_of`;
- references inside `not`;
- deterministic replay and compact serialization.

Run the complete TPE 2.4 development validation:

```bash
python trust_primitive_engine/tools/run_all_tests.py
```

The expected final line is:

```text
AGP TPE 2.6 development validation: 684/684 passed
```

TPE 2.4 coverage includes:

- context projection and immutable resolution;
- all four context-value primitives;
- evidence presence and optional binding mismatches;
- Decision Context 1 and 2 equivalence;
- composition integration;
- direct, nested, shared, and composed policy references;
- recursive failure projection and suppression;
- signed public Python API evaluations;
- clean wheel installation and packaged schemas.

Run the TPE 2.4 context and evidence golden corpus independently:

```bash
python \
  trust_primitive_engine/tools/test_tpe24_context_evidence_golden_corpus.py
```

The fixtures are stored under:

```text
trust_primitive_engine/fixtures/golden/v2.4
```

Each case freezes the logical evaluation, compact sorted-key JSON
serialization, deterministic replay, and SHA-256 result digest.

Run the TPE 2.5 golden corpus independently:

```bash
python trust_primitive_engine/tools/test_tpe25_golden_corpus.py
```

The fixtures are stored under `trust_primitive_engine/fixtures/golden/v2.5`.

Run the executable TPE 2.5 examples:

```bash
bash trust_primitive_engine/examples/contextual-predicates/run_examples.sh
```

## Release conformance

- `TPE-2.4-CONFORMANCE-STATEMENT.md`
- `TPE-2.5-CONFORMANCE-STATEMENT.md`
- `TPE-2.6-CONFORMANCE-STATEMENT.md`

### Independent TPE 2.6 external reproduction

Build and install the TPE wheel and a standalone consumer package in a clean
temporary environment, then reproduce two frozen signed Decision Context 3
results outside the repository:

```bash
python trust_primitive_engine/tools/test_tpe26_external_reproduction.py
```

Expected final marker:

```text
TPE 2.6 external reproduction: 2/2 passed
```

The consumer imports only the stable `trust_primitive_engine` public API and
verifies both deterministic result hashes from an installed wheel.

## Normative specifications

- `rfcs/TPE-2.1-001-deterministic-temporal-evaluation.md`
- `rfcs/TPE-2.2-001-deterministic-policy-composition.md`
- `rfcs/TPE-2.3-001-deterministic-policy-references.md`
- `rfcs/TPE-2.4-001-deterministic-context-requirements.md`
- `rfcs/TPE-2.5-001-deterministic-contextual-predicates.md`
