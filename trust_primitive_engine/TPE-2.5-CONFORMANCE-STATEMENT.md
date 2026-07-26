# TPE 2.5 Conformance Statement

## 1. Release identification

| Field | Value |
|---|---|
| Distribution | `agp-tpe` |
| Release | `2.5.0` |
| Git tag | `tpe-v2.5.0` |
| Python | `>=3.12` |
| Normative RFC | `rfcs/TPE-2.5-001-deterministic-contextual-predicates.md` |
| Complete validation | `637/637 passed` |

This statement applies to the source tree, package metadata, fixtures, and
tests represented by the release tag `tpe-v2.5.0`.

## 2. Implemented scope

TPE 2.5 adds:

- `context_value_in`;
- `context_path_equals`;
- `evidence_count_at_least`.

Their primary failure codes are:

```text
CONTEXT_VALUE_NOT_IN_SET
CONTEXT_PATH_VALUES_NOT_EQUAL
EVIDENCE_COUNT_NOT_REACHED
```

## 3. Deterministic guarantees

TPE 2.5 provides deterministic validation, strict scalar comparison,
context-path resolution, evidence filtering and unique-identifier counting,
composition, recursive references, failure projection and suppression,
replay, result serialization, and frozen SHA-256 hashes.

## 4. Authoritative evidence

| Area | Evidence |
|---|---|
| Context predicates | `test_contextual_predicates.py` |
| Evidence count | `test_evidence_count_at_least.py` |
| Composition and references | `test_tpe25_integration.py` |
| Public API | `test_public_api.py` |
| Golden corpus | `test_tpe25_golden_corpus.py` |
| Clean wheel | `test_package_install.py` |
| Installed legacy consumer | `test_external_package_integration.py` |

## 5. Complete validation

```bash
python trust_primitive_engine/tools/run_all_tests.py
```

Required final line:

```text
AGP TPE 2.5 development validation: 637/637 passed
```

## 6. Golden corpus

The corpus is stored under:

```text
trust_primitive_engine/fixtures/golden/v2.5
```

Its five frozen hashes are recorded in `manifest.json`.

Independent verification:

```bash
python trust_primitive_engine/tools/test_tpe25_golden_corpus.py
```

Required final line:

```text
TPE 2.5 contextual predicates golden corpus: 5/5 passed
```

## 7. Package and compatibility

The release package is `agp-tpe==2.5.0`.

TPE 2.5 preserves valid TPE 2.0 through TPE 2.4 policy behavior. The
external-package test intentionally runs the existing TPE 2.4 consumer
against the TPE 2.5 wheel.

## 8. Security boundary

TPE evaluates supplied cryptographic and policy inputs. Integrators remain
responsible for trusted policy and key distribution, revocation, key
custody, authenticated transport, audit storage, process isolation,
resource controls, and authorization of the resulting business action.

This statement is not a third-party certification, formal proof, or
independent security audit.

## 9. Reproducible verification

```bash
python trust_primitive_engine/tools/run_all_tests.py
python trust_primitive_engine/tools/test_tpe25_golden_corpus.py
bash trust_primitive_engine/examples/contextual-predicates/run_examples.sh
python trust_primitive_engine/tools/test_external_package_integration.py
python trust_primitive_engine/tools/test_package_install.py
```

Required markers include:

```text
AGP TPE 2.5 development validation: 637/637 passed
TPE 2.5 contextual predicates golden corpus: 5/5 passed
TPE_2_5_CONTEXTUAL_PREDICATES_EXAMPLES_PASS
TPE 2.4 external package integration: 1/1 passed
AGP TPE package installation: 1/1 passed
```
