# TPE 2.4 Integration Guide

This guide explains how an external system can integrate with the AGP Trust
Primitive Engine (TPE) 2.4 through its command-line interface and stable public
Python API.

For normative semantics, see:

- `README.md`
- `rfcs/TPE-2.1-001-deterministic-temporal-evaluation.md`
- `rfcs/TPE-2.2-001-deterministic-policy-composition.md`
- `rfcs/TPE-2.3-001-deterministic-policy-references.md`
- `rfcs/TPE-2.4-001-deterministic-context-requirements.md`

## 1. Integration inputs

A complete TPE 2.4 evaluation can require four JSON inputs:

1. a Signed Decision Context;
2. a root Trust Policy 2 object;
3. an external verification keyring;
4. an optional policy set when the root policy or any reachable policy uses
   `policy_reference`.

The root policy is always supplied separately with `--policy`.

The root policy does not need to appear in the policy set.

## 2. Runtime requirements

Install the repository dependencies from the repository root:

```bash
python -m pip install -r requirements-v0.4.txt
```

The implementation currently expects Python 3.12 in CI.

## 3. Signed Decision Context

TPE evaluates verified signer identities, not unverified participant claims.

The input file must be an AGP Signed Decision Context accepted by the repository
implementation. It contains:

- the Decision Context;
- the canonical Decision Context digest;
- one or more signature statements;
- Ed25519 signatures over canonical signature statements.

A Decision Context 2 contains, among other fields:

- `context_id`;
- `created_at`;
- `expires_at`;
- `evaluation_time`;
- the root policy identity and digest;
- proposal data;
- participants and their roles;
- evidence;
- constraints.

The policy binding inside the context must exactly match the supplied root
policy:

```json
{
  "policy": {
    "id": "policy:production-change",
    "version": 1,
    "digest": "64-lowercase-hexadecimal-characters"
  }
}
```

A mismatching root-policy digest is a fatal evaluation error.

## 4. Signing a Decision Context

Use the repository signer:

```bash
python signed_decision_context/python/sign_decision_context.py \
  decision-context.json \
  --private-key authority-private-key.json \
  --signer-id authority:operations \
  --key-id key:operations:2026 \
  --signature-id signature:operations:0001 \
  --signed-at 2026-07-24T20:01:00Z \
  --output signed-context.json
```

Append another signature with `--append`:

```bash
python signed_decision_context/python/sign_decision_context.py \
  signed-context.json \
  --append \
  --private-key reviewer-private-key.json \
  --signer-id authority:security \
  --key-id key:security:2026 \
  --signature-id signature:security:0001 \
  --signed-at 2026-07-24T20:02:00Z \
  --output signed-context.json
```

The signing utility signs the AGP canonical form of the signature statement.
It does not sign ordinary JSON serialization.

## 5. Verification keyring

TPE resolves verification keys from an external keyring:

```json
{
  "keys": [
    {
      "signer_id": "authority:operations",
      "key_id": "key:operations:2026",
      "algorithm": "ed25519",
      "public_key": "unpadded-base64url-public-key"
    },
    {
      "signer_id": "authority:security",
      "key_id": "key:security:2026",
      "algorithm": "ed25519",
      "public_key": "unpadded-base64url-public-key"
    }
  ]
}
```

The keyring is an integration trust input. Production systems must define their
own procedures for:

- trust-root management;
- key issuance;
- key rotation;
- key revocation;
- key distribution;
- protection against unauthorized keyring modification.

TPE 2.4 verifies signatures against the supplied keyring. The keyring itself is
not automatically authenticated by TPE.

## 6. Root Trust Policy

A Trust Policy 2 object uses:

```json
{
  "object_type": "agp.trust-policy/2",
  "policy_id": "policy:production-change",
  "version": 1,
  "eligible_roles": [
    "approver"
  ],
  "requirements": [
    {
      "requirement_id": "requirement:operations",
      "type": "required_signer",
      "signer_id": "authority:operations"
    }
  ]
}
```

`eligible_roles` is evaluated independently for each policy.

A verified signer whose participant role is not eligible for the current policy
does not contribute to that policy's:

- `matched_signers`;
- `signature_count`;
- `weight`.

The same signer may still contribute to a referenced policy whose
`eligible_roles` includes that signer's role.

## 7. Policy references

A policy reference binds exactly to:

- `policy_id`;
- `policy_version`;
- `policy_digest`.

Example:

```json
{
  "requirement_id": "requirement:security-policy",
  "type": "policy_reference",
  "policy_id": "policy:security-review",
  "policy_version": 1,
  "policy_digest": "64-lowercase-hexadecimal-characters"
}
```

The digest is the SHA-256 digest of the canonical complete referenced Trust
Policy object.

A reference is satisfied only when the referenced policy is satisfied.

## 8. Decision Context projection and TPE 2.4 requirements

TPE 2.4 evaluates selected proposal values and evidence only from the verified
Decision Context supplied for the evaluation.

Context-value requirements may access paths beneath:

```text
/proposal/payload/
```

The path uses JSON Pointer escaping:

- `~0` represents `~`;
- `~1` represents `/`;
- array indices use canonical decimal form;
- leading-zero indices such as `/01` are rejected.

The projection is immutable and detached from the caller's input. Requirements
cannot read arbitrary root-level Decision Context fields.

Resolution produces one of these deterministic internal outcomes:

| Resolution | Meaning |
|---|---|
| `found` | The complete path exists. A JSON `null` value still counts as found. |
| `missing` | A requested member or array index does not exist. |
| `type_mismatch` | Traversal attempted to continue through a scalar or incompatible container. |

Missing values and traversal mismatches produce ordinary `unsatisfied`
requirement results. They are not fatal evaluation errors.

### `context_value_present`

```json
{
  "requirement_id": "requirement:environment-present",
  "type": "context_value_present",
  "path": "/proposal/payload/environment"
}
```

The requirement is satisfied when resolution is `found`. A found JSON `null`
counts as present.

Failure code:

```text
CONTEXT_VALUE_NOT_PRESENT
```

### `context_value_equals`

```json
{
  "requirement_id": "requirement:production-environment",
  "type": "context_value_equals",
  "path": "/proposal/payload/environment",
  "value": "production"
}
```

The expected value must be a supported JSON scalar. Equality is type-strict:

```text
true != 1
"1" != 1
null != "null"
```

Objects and arrays are not valid expected values.

Failure code:

```text
CONTEXT_VALUE_NOT_EQUAL
```

### `context_integer_at_least`

```json
{
  "requirement_id": "requirement:minimum-coverage",
  "type": "context_integer_at_least",
  "path": "/proposal/payload/test_report/coverage_basis_points",
  "minimum": 9000
}
```

The observed value and `minimum` must be non-Boolean JSON integers inside the
AGP safe-integer range.

Failure code:

```text
CONTEXT_INTEGER_MINIMUM_NOT_REACHED
```

### `context_integer_at_most`

```json
{
  "requirement_id": "requirement:maximum-rollout",
  "type": "context_integer_at_most",
  "path": "/proposal/payload/rollout/basis_points",
  "maximum": 2500
}
```

The observed value and `maximum` follow the same strict integer rules.

Failure code:

```text
CONTEXT_INTEGER_MAXIMUM_EXCEEDED
```

### `evidence_present`

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

`digest` and `media_type` are optional bindings. The requirement is satisfied
only when exactly one evidence entry has the requested identifier and every
supplied binding matches.

The deterministic observed match status is one of:

```text
matched
absent
digest_mismatch
media_type_mismatch
digest_and_media_type_mismatch
```

Every non-`matched` status produces the ordinary failure code:

```text
EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED
```

The same verified Decision Context is propagated through root and referenced
policies. Therefore, context and evidence requirements behave identically when
nested inside `all_of`, `any_of`, `not`, or `policy_reference`.

## 9. Policy-set format

The policy set is a JSON array of complete Trust Policy 2 objects:

```json
[
  {
    "object_type": "agp.trust-policy/2",
    "policy_id": "policy:security-review",
    "version": 1,
    "eligible_roles": [
      "reviewer"
    ],
    "requirements": [
      {
        "requirement_id": "requirement:security",
        "type": "required_signer",
        "signer_id": "authority:security"
      }
    ]
  }
]
```

Integration rules:

- each `policy_id` and `version` pair must be unique;
- policy-set order does not affect the result;
- every reachable referenced policy is validated before evaluation;
- unreferenced entries do not affect evaluation;
- policies containing references require `--policy-set`;
- the root policy remains external to the policy set.

## 10. CLI evaluation

### Policy without references

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --keyring keyring.json
```

### Policy with references

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --policy-set policy-set.json \
  --keyring keyring.json
```

### Explicit schema directory

```bash
python trust_primitive_engine/python/evaluate_trust_policy_v2.py \
  signed-context.json \
  --policy root-policy.json \
  --policy-set policy-set.json \
  --keyring keyring.json \
  --schema-dir registry/schemas
```

The CLI writes one compact JSON object to standard output.

## 11. Exit codes

The CLI contract is:

| Exit code | Meaning |
|---:|---|
| `0` | Verification and evaluation completed; policy is `satisfied`. |
| `1` | Fatal input, validation, verification, binding, policy-set, or reference error. |
| `2` | Verification and evaluation completed; policy is `unsatisfied`. |

Integrations must inspect both the process exit code and the emitted JSON.

Do not treat exit code `2` as an infrastructure failure. It is a completed,
deterministic policy decision.

## 12. Satisfied result

A successful evaluation emits:

```json
{
  "object_type": "agp.trust-policy-evaluation/2",
  "status": "satisfied",
  "failure_codes": []
}
```

The complete result also includes:

- root policy identity and digest;
- context identity and digest;
- verified signatures and signers;
- root-policy matched signers;
- unauthorized and ineligible-role signers;
- signature count and weight;
- complete requirement results;
- recursive referenced-policy evidence.

## 13. Unsatisfied result

An ordinary policy failure emits exit code `2` and:

```json
{
  "object_type": "agp.trust-policy-evaluation/2",
  "status": "unsatisfied",
  "failure_codes": [
    "POLICY_REFERENCE_NOT_SATISFIED",
    "REQUIRED_SIGNER_MISSING"
  ]
}
```

For a failed policy reference:

- the boundary requirement emits `POLICY_REFERENCE_NOT_SATISFIED`;
- `referenced_policy.status` is `unsatisfied`;
- the referenced policy retains its own recursive requirement results;
- referenced failure codes are projected into the containing policy result.

Context and evidence requirement failures are also ordinary unsatisfied
decisions. Their failure codes include:

```text
CONTEXT_VALUE_NOT_PRESENT
CONTEXT_VALUE_NOT_EQUAL
CONTEXT_INTEGER_MINIMUM_NOT_REACHED
CONTEXT_INTEGER_MAXIMUM_EXCEEDED
EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED
```

The requirement result preserves deterministic `observed` and `expected`
evidence, including context resolution or evidence match status.

## 14. Fatal error result

Fatal errors emit exit code `1` and:

```json
{
  "status": "error",
  "error_code": "POLICY_REFERENCE_DIGEST_MISMATCH",
  "detail": "deterministic diagnostic detail"
}
```

Fatal reference errors include:

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

Fatal graph defects are not converted into ordinary unsatisfied decisions.

## 15. Reference graph limits

TPE 2.3 enforces:

| Limit | Value |
|---|---:|
| Maximum reference depth | `8` |
| Maximum reachable referenced policies | `32` |
| Maximum expanded requirement nodes | `2048` |

External systems should reject or constrain oversized policy packages before
submission when possible.

## 16. Determinism expectations

For identical valid inputs and the same implementation version, integrations
should expect deterministic:

- canonical digests;
- reference resolution;
- complete graph validation;
- requirement evaluation;
- failure projection;
- compact JSON serialization;
- exit status.

Policy-set ordering must not change the result.

## 17. Security requirements for integrators

Production integrations should:

- authenticate and authorize the source of every policy;
- protect root policies and policy sets against substitution;
- independently protect the keyring;
- separate private-key custody from evaluation infrastructure;
- reject unexpected algorithms and non-canonical encodings;
- preserve the exact signed context used for each decision;
- log the complete evaluation result and implementation version;
- avoid reusing the deterministic private keys contained in examples;
- define key-revocation and policy-revocation procedures outside TPE 2.3;
- apply operating-system and process-level resource limits around the CLI.

TPE determines whether supplied cryptographic and policy inputs satisfy the
defined policy. It does not determine whether the surrounding system supplied
the correct trusted policy package or keyring.

## 18. Executable examples

### Positive example

```bash
bash trust_primitive_engine/examples/policy-references/run_example.sh
```

Expected marker:

```text
POLICY_REFERENCE_EXAMPLE_PASS
```

### Negative examples

```bash
bash trust_primitive_engine/examples/policy-reference-failures/run_examples.sh
```

Expected markers include:

```text
PASS  digest_mismatch      POLICY_REFERENCE_DIGEST_MISMATCH
PASS  missing_policy       POLICY_REFERENCE_NOT_FOUND
PASS  ineligible_role      POLICY_REFERENCE_NOT_SATISFIED
PASS  cycle_detected       POLICY_REFERENCE_CYCLE
POLICY_REFERENCE_FAILURE_EXAMPLES_PASS
```

### TPE 2.4 context and evidence examples

```bash
bash trust_primitive_engine/examples/context-and-evidence/run_examples.sh
```

The runner covers satisfied context and evidence, a context equality failure,
absent evidence, digest mismatch, and recursive failure projection through a
policy reference.

Expected final marker:

```text
TPE_2_4_CONTEXT_EVIDENCE_EXAMPLES_PASS
```

### TPE 2.4 golden corpus

```bash
python \
  trust_primitive_engine/tools/test_tpe24_context_evidence_golden_corpus.py
```

The versioned corpus under `fixtures/golden/v2.4` freezes ten end-to-end
context and evidence evaluations. Each case includes its authoritative result
and the SHA-256 digest of compact sorted-key UTF-8 JSON serialization.

Expected final line:

```text
TPE 2.4 context/evidence golden corpus: 10/10 passed
```

## 19. Recommended integration workflow

A production caller should:

1. obtain the signed context, root policy, policy set, and keyring from trusted
   sources;
2. validate file size and resource limits;
3. invoke the TPE CLI without shell interpolation of untrusted values;
4. capture standard output and the exit code;
5. parse the JSON output;
6. distinguish `satisfied`, `unsatisfied`, and fatal `error`;
7. persist the exact inputs and result for audit;
8. apply the organization's business action only after mapping the result to an
   explicit local decision rule.

## 20. Package installation

Install the published package from PyPI:

```bash
python -m pip install agp-tpe
```

To install from a repository checkout instead:

```bash
python -m pip install .
```

After installation:

```python
from trust_primitive_engine import evaluate_trust_policy
```

The distribution name is `agp-tpe`. The import package is
`trust_primitive_engine`. TPE 2.4 requires Python 3.12 or newer.

The repository includes a clean-wheel installation test:

```bash
python trust_primitive_engine/tools/test_package_install.py
```

This test builds a wheel, installs it into a temporary isolated virtual
environment, imports the public API, and verifies that packaged schemas are
available.

## 21. Public Python API

Add the TPE Python directory to the interpreter path or package it within the
integrating application, then import the stable facade:

```python
from trust_primitive_engine import (
    TrustPolicyEvaluationError,
    evaluate_trust_policy,
)

try:
    result = evaluate_trust_policy(
        signed_context=signed_context,
        policy=root_policy,
        keyring=keyring,
        policy_set=policy_set,
    )
except TrustPolicyEvaluationError as exc:
    print(exc.code, exc.detail)
else:
    print(result["status"])
```

The public API accepts Python mappings and sequences. It returns ordinary
`satisfied` and `unsatisfied` evaluation objects and raises
`TrustPolicyEvaluationError` only for fatal errors.

Callers should import only from `trust_primitive_engine`, not from internal
`engine`, `primitives`, or `evaluate_trust_policy_v2` modules.

## 22. Stability boundary

TPE 2.4 uses:

```text
agp.trust-policy/2
agp.trust-policy-evaluation/2
```

Policies without `policy_reference` preserve TPE 2.2 behavior and do not require
a policy set.

Policies without TPE 2.4 context or evidence requirements preserve their
existing TPE 2.3 result shape and byte-stable behavior.

Integrators should depend on documented CLI inputs, exit codes, object types,
and result fields rather than importing internal Python modules directly.
Internal package organization may evolve independently of the public
integration contract.
