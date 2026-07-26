# TPE 2.6 Conformance Statement

## 1. Release identification

| Field | Value |
|---|---|
| Release | `2.6.0` |
| Git tag | `tpe-v2.6.0` |
| Python distribution | `agp-tpe==2.6.0` |
| Trust Policy object | `agp.trust-policy/2` |
| Evaluation object | `agp.trust-policy-evaluation/2` |

This statement records deterministic implementation evidence for the TPE 2.6
release line. The release tag is created only after the release pull request is
merged into `main`.

## 2. Implemented scope

TPE 2.6 implements:

- `evidence_issuer_in`;
- `evidence_type_in`;
- `evidence_distinct_issuers_at_least`;
- optional same-entry issuer and evidence-type cross-filters;
- deterministic distinct-issuer counting;
- Decision Context 3 provenance availability;
- fail-closed unavailable provenance for Decision Context 1 and 2;
- composition, policy references, recursive failure projection, and failure
  suppression;
- deterministic serialization and replay.

The provenance fields are context-attested declarations. This implementation
does not independently authenticate external evidence issuers.

## 3. Normative source

The implemented scope is defined by:

```text
trust_primitive_engine/rfcs/
TPE-2.6-001-deterministic-evidence-provenance-predicates.md
```

TPE 2.6 also relies on the Decision Context 3 object family:

```text
agp.decision-context/3
agp.signature-statement/3
agp.signed-decision-context/3
```

## 4. Authoritative implementation evidence

Primary implementation and validation files include:

```text
trust_primitive_engine/python/primitives/evidence_provenance.py
trust_primitive_engine/tools/test_evidence_provenance_predicates.py
trust_primitive_engine/tools/test_tpe26_integration.py
trust_primitive_engine/tools/test_tpe26_golden_corpus.py
trust_primitive_engine/tools/test_public_api.py
trust_primitive_engine/tools/run_all_tests.py
```

## 5. Complete validation

The authoritative complete validation command is:

```bash
python trust_primitive_engine/tools/run_all_tests.py
```

Expected release result:

```text
AGP TPE 2.6 development validation: 682/682 passed
```

The complete suite includes schema/runtime parity, primitive validation,
property hardening, legacy golden and byte-stability corpora, policy-reference
evaluation, signed Decision Context verification, public API tests, external
package integration, and isolated wheel installation.

## 6. TPE 2.6 focused and integration suites

Expected focused results include:

```text
TPE 2.6 evidence provenance predicates: 9/9 passed
TPE 2.6 formal integration: 14/14 passed
AGP TPE public Python API: 9/9 passed
```

The integration suite covers composition, direct and nested references,
same-entry binding, failure projection, suppression, empty DC3 evidence,
unavailable DC2 provenance, deterministic replay, referenced serialization, and
DC3 inheritance of `evaluation_time`.

## 7. Golden corpus

Corpus identifier:

```text
agp.tpe-evidence-provenance-conformance/2.6
```

Hash serialization:

```text
json-sort-keys-compact-utf8
```

Hash algorithm:

```text
sha-256
```

| Case | Status | Expected SHA-256 |
|---|---|---|
| `satisfied-all` | `satisfied` | `1fe753204836f7da662c9789a87c3d66a5310ac3e0c34ab385e613d0b90affe0` |
| `issuer-not-allowed` | `unsatisfied` | `30d3395a6a0957a22a96738ba597a9c2478aaa7975b5ff8b8f9c57ed35ca66c3` |
| `type-not-allowed` | `unsatisfied` | `617978dfaa115c6998a3599f88922dc8aa3af4cd76213a5588ad7266f3ca7b97` |
| `distinct-minimum-not-reached` | `unsatisfied` | `30312992e91b65dd872818ebd9f1de01211ed409353ac3653e23c186c1cd8fe6` |
| `empty-dc3-manifest` | `unsatisfied` | `884d03cfaf936c9af786ecf4c6ba93f7c1f3eecc7830ff3eb3d3c98c15493c7d` |
| `dc2-provenance-unavailable` | `unsatisfied` | `e1c8c2968718c79927dbd5fb362d5fcdf85eb18b934152ca2b324afdf84397c4` |
| `recursive-reference-projection` | `unsatisfied` | `1341f5775d34fb795d03843e0991a5674f0b510f3c0f77ceb65f3e10b9bfe980` |

Expected corpus result:

```text
TPE 2.6 evidence provenance golden corpus: 7/7 passed
```

## 8. Compatibility boundary

TPE 2.6 preserves:

- valid TPE 2.0 through TPE 2.5 policy behavior;
- `agp.trust-policy/2`;
- `agp.trust-policy-evaluation/2`;
- existing frozen golden-corpus results;
- existing byte-stability results;
- policies that do not use TPE 2.6 provenance predicates.

Older Decision Context generations are not reinterpreted as carrying provenance.
Their provenance status is `unavailable`, and TPE 2.6 predicates fail as
ordinary unsatisfied requirements.

## 9. Packaging evidence

The release package is:

```text
agp-tpe==2.6.0
```

The wheel includes the public API, evaluator, engine, primitive modules,
canonicalization and signed-context verification dependencies, and registry
schemas. The complete validation builds and installs the wheel in isolated
temporary environments.

## 10. Security boundary

This conformance statement demonstrates deterministic implementation behavior
for the implemented scope. It is not:

- a third-party certification;
- a formal proof;
- an independent security audit;
- evidence that context-attested issuer declarations are externally authentic;
- a representation that every deployment using TPE is secure.

## 11. Conformance declaration

The AGP Trust Primitive Engine implementation identified in Section 1 is
declared conformant with the implemented scope of TPE-2.6-001 when all
authoritative suites listed in this document pass without modification to their
expected outputs, case manifests, or frozen digests.

This declaration covers deterministic implementation behavior and release
evidence only.
