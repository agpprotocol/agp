# TPE 2.4 Conformance Statement

## 1. Release identification

This document records the implementation and validation status of the AGP
Trust Primitive Engine release identified as:

| Field | Value |
|---|---|
| Distribution | `agp-tpe` |
| Release | `2.4.0` |
| Git tag | `tpe-v2.4.0` |
| Python | `>=3.12` |
| Normative RFC | `rfcs/TPE-2.4-001-deterministic-context-requirements.md` |
| Complete validation | `552/552 passed` |

This statement applies to the source tree, package metadata, fixtures, and
tests present in the release line represented by `tpe-v2.4.0` and the
subsequent conformance-only additions documented here.

## 2. Normative scope

TPE 2.4 implements deterministic requirements over the signed Decision
Context boundary defined by TPE-2.4-001.

The release permits policy evaluation against:

- canonical paths rooted below `/proposal/payload/`;
- the signed evidence manifest;
- Decision Context 1 and Decision Context 2 inputs;
- recursively referenced Trust Policy 2 objects;
- existing deterministic composition nodes.

The release does not permit policy requirements to read arbitrary runtime
state, environment variables, network state, mutable external databases,
unsigned metadata, or other data outside the signed evaluation input.

## 3. Implemented primitives

TPE 2.4 adds the following primitive types:

| Primitive | Purpose |
|---|---|
| `context_value_present` | Requires a canonical context path to resolve. |
| `context_value_equals` | Requires a scalar context value to equal a policy value using strict type semantics. |
| `context_integer_at_least` | Requires an observed safe integer to meet a lower bound. |
| `context_integer_at_most` | Requires an observed safe integer to meet an upper bound. |
| `evidence_present` | Requires an evidence identifier and optionally binds its digest and media type. |

The implementation distinguishes ordinary policy failure from fatal
validation, verification, policy-set, binding, and reference errors.

## 4. Deterministic evaluation guarantees

For identical valid inputs and the same implementation release, TPE 2.4
provides deterministic:

- context projection;
- JSON Pointer validation and resolution;
- policy normalization;
- primitive evaluation;
- evidence matching status;
- recursive policy-reference evaluation;
- failure-code projection and suppression;
- matched-signer aggregation;
- result object structure;
- compact sorted-key UTF-8 JSON serialization;
- SHA-256 result digests used by the golden corpus.

Policy-set insertion order and evidence insertion order do not change the
logical result.

## 5. Normative requirement traceability

| RFC area | Implementation evidence | Primary conformance evidence |
|---|---|---|
| Signed input boundary and allowed sources | Decision Context projection in evaluation state | `test_context_resolution.py` |
| Canonical context path | Restricted JSON Pointer parser and resolver | `test_context_resolution.py` |
| `context_value_present` | Context primitive registry and evaluator | `test_context_value_primitives.py` |
| `context_value_equals` | Strict scalar comparison | `test_context_value_primitives.py` |
| `context_integer_at_least` | Safe-integer lower-bound evaluation | `test_context_value_primitives.py` |
| `context_integer_at_most` | Safe-integer upper-bound evaluation | `test_context_value_primitives.py` |
| `evidence_present` | Evidence lookup and optional binding evaluation | `test_evidence_present_primitive.py` |
| Primitive result semantics | Stable requirement results and failure codes | primitive suites and golden corpus |
| Validation order | Schema/runtime validation and deterministic rejection | validation matrix and parity suites |
| Composition | Existing structural dispatcher with TPE 2.4 leaves | composition and primitive suites |
| Policy references | Recursive evaluation and failure projection | recursive reference suites |
| Backward compatibility | Existing TPE 2.0–2.3 corpora remain green | complete validation runner |
| Resource limits | Existing tree and reference graph limits | graph and tree validation suites |
| Public integration | `evaluate_trust_policy` public API | `test_public_api.py` |
| Installed distribution | wheel build and clean installation | `test_package_install.py` |
| Independent consumer | external package installed outside checkout | `test_external_package_integration.py` |

## 6. Complete validation inventory

The authoritative development runner is:

```bash
python trust_primitive_engine/tools/run_all_tests.py
```

The expected final line is:

```text
AGP TPE 2.4 development validation: 552/552 passed
```

The complete runner covers:

- engine core;
- context projection and resolution;
- all four context-value primitives;
- `evidence_present`;
- policy-tree validation;
- composition evaluation;
- legacy conformance;
- time-window conformance;
- schema/runtime parity;
- primitive validation matrix;
- property hardening;
- compatibility and byte-stability corpora;
- fuzz regression seeds;
- policy-set indexing;
- policy-reference validation, resolution, graph limits, recursive evaluation,
  and recursive failure projection;
- verified policy-set evaluation;
- CLI behavior;
- TPE 2.3 and TPE 2.4 golden corpora;
- public Python API;
- external package integration;
- clean wheel installation.

## 7. TPE 2.4 golden corpus

The versioned corpus is stored at:

```text
trust_primitive_engine/fixtures/golden/v2.4
```

Its manifest identifies the corpus as:

```text
agp.tpe-context-evidence-conformance/2.4
```

The corpus freezes ten end-to-end cases using compact sorted-key UTF-8 JSON
and SHA-256:

| Case | Expected status | Expected SHA-256 |
|---|---|---|
| `satisfied-all` | `satisfied` | `effb0595f5f77313d0f58277f7e7b931ceb98b74598e4d23041539147e46182a` |
| `context-value-not-equal` | `unsatisfied` | `eb203bc1c84830f5d3ccb9e19f5c8022bcaee4c400da31e00bc8db43259d6afd` |
| `context-value-not-present` | `unsatisfied` | `71439990fa3c686bd2e3f0ad5e75c96ec3be46666ef28a831a6619aeb63be59a` |
| `integer-minimum-not-reached` | `unsatisfied` | `6b395d0b7c873d675edc0d4a8c3560738485a146f8943615bd9b4222d13b3766` |
| `integer-maximum-exceeded` | `unsatisfied` | `1c457c0df83b18b87cc8cf8bc2447a309f8080b2c893379e8bb245a4db468066` |
| `evidence-absent` | `unsatisfied` | `13c4c18cdab0e237684c14472d401dfe033ef583ec31f2b18d5d183280f1c0b4` |
| `evidence-digest-mismatch` | `unsatisfied` | `d770b8b1e0cdde6bdd1d06eae742dbf4d1e10eb9a1195e5a53a969d051f00b52` |
| `evidence-media-type-mismatch` | `unsatisfied` | `338ae522bb21236929ca458a05566a51a7c73aec65f1b04b1527eed8e7bb5c43` |
| `evidence-both-mismatch` | `unsatisfied` | `e7b6b53d7dff2f87684e5838d18fa6b4ac56eb42b5f30df87b811a3a7e48521e` |
| `recursive-reference-projection` | `unsatisfied` | `c7438aba6f567ac11d82c064bf22c1260c2acc71d1093f529d66ff1846c46a06` |

Run it independently with:

```bash
python \
  trust_primitive_engine/tools/test_tpe24_context_evidence_golden_corpus.py
```

Expected final line:

```text
TPE 2.4 context/evidence golden corpus: 10/10 passed
```

## 8. Public API and package distribution

The public Python API is exported by:

```python
from trust_primitive_engine import (
    DEFAULT_SCHEMA_DIR,
    TrustPolicyEvaluationError,
    evaluate_trust_policy,
)
```

The public evaluator accepts:

- a signed context;
- a root policy;
- a keyring;
- an optional policy set;
- an optional schema directory override.

Ordinary policy failure returns an `unsatisfied` evaluation. Fatal input,
cryptographic verification, policy binding, policy-set, and reference errors
raise `TrustPolicyEvaluationError`.

The release is packaged as `agp-tpe==2.4.0`. The wheel includes the public
package, evaluator dependencies, primitive and engine modules, canonicalization
support, signed-context validation and verification support, and packaged
schemas.

## 9. External integration evidence

The standalone consumer package is located at:

```text
trust_primitive_engine/examples/external-package
```

The integration test:

1. builds the `agp-tpe` wheel;
2. builds the separate external consumer wheel;
3. creates a clean temporary virtual environment;
4. installs both distributions independently;
5. removes `PYTHONPATH`;
6. runs from outside the repository checkout;
7. verifies that `trust_primitive_engine` was imported from `site-packages`;
8. evaluates a cryptographically signed Decision Context 2;
9. validates the frozen compact-result SHA-256.

The expected external result digest is:

```text
2a02b927800fad3722e19512cde03dca38ce0ae787b8de0b0972411d9a3d6865
```

Run it with:

```bash
python \
  trust_primitive_engine/tools/test_external_package_integration.py
```

Expected final line:

```text
TPE 2.4 external package integration: 1/1 passed
```

## 10. Backward compatibility

TPE 2.4 preserves the behavior of valid TPE 2.0, 2.1, 2.2, and 2.3 policies.

Policies that do not use TPE 2.4 primitives retain their prior evaluation
semantics. Existing composition, time-window, signer, cardinality, policy-set,
and policy-reference suites remain part of the complete validation.

The TPE 2.4 context projection is additive to evaluation state and does not
change legacy policy output.

## 11. Security properties

TPE 2.4 verifies and evaluates supplied cryptographic and policy inputs. It
does not establish that the surrounding system selected the correct trusted
policy package, keyring, revocation state, or business action.

Production integrators remain responsible for:

- trusted policy and keyring distribution;
- private-key custody;
- policy and key revocation;
- authenticated input transport;
- durable audit storage;
- operating-system and process isolation;
- resource limits around evaluation;
- authorization of the business action taken after evaluation.

The deterministic keys and signatures in examples are public test material and
must never be used in production.

## 12. Explicit limits and deferred work

TPE 2.4 does not provide:

- comparisons between two context paths;
- generic set-membership predicates;
- regular-expression or substring matching;
- arithmetic expressions;
- floating-point or decimal comparison;
- mutable external-data lookups;
- network retrieval during evaluation;
- evidence cardinality rules;
- evidence issuer or class constraints;
- policy or key revocation protocols;
- domain-specific business authorization.

These areas require separate normative work and are candidates for later TPE
releases.

## 13. Reproducible verification procedure

From a clean repository checkout with Python 3.12 or later:

```bash
python trust_primitive_engine/tools/run_all_tests.py

python \
  trust_primitive_engine/tools/test_tpe24_context_evidence_golden_corpus.py

python \
  trust_primitive_engine/tools/test_external_package_integration.py

python trust_primitive_engine/tools/test_package_install.py
```

A conformant verification run must produce all of the following markers:

```text
AGP TPE 2.4 development validation: 552/552 passed
TPE 2.4 context/evidence golden corpus: 10/10 passed
TPE 2.4 external package integration: 1/1 passed
AGP TPE package installation: 1/1 passed
```

## 14. Conformance declaration

The AGP Trust Primitive Engine implementation identified in Section 1 is
declared conformant with the implemented scope of
TPE-2.4-001: Deterministic Context Requirements when all authoritative suites
listed in this document pass without modification to their expected outputs,
case manifests, or frozen digests.

This declaration covers deterministic implementation behavior and release
evidence. It is not a third-party certification, formal proof, security audit,
or representation that every surrounding deployment is secure.
