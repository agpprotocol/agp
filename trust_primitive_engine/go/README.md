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

## Requirement validation mode

The same binary exposes a bounded validation mode:

```bash
agp-tpe26-reproduce --validate-requirement requirement.json
```

The 27-vector Python/Go parity suite verifies common acceptance and rejection
semantics for the three TPE 2.6 predicates.

## Scope limitation

This is not yet a complete second implementation of the Trust Primitive
Engine. It does not implement every Trust Policy 2 primitive, composition
form, validation rule, signature-verification path, or arbitrary reference
graph.
