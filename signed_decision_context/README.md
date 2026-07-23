# Signed Decision Context

Stage 1 provides:

- normative draft specification;
- Signature Statement JSON Schema;
- Signed Decision Context JSON Schema;
- Python structural validator;
- ephemeral conformance runner.

## Requirements

```bash
python -m pip install jsonschema
```

## Run conformance

From the repository root:

```bash
python signed_decision_context/tools/run_conformance.py
```

## Canonicalization

The validator and conformance runner import the repository's normative
implementation directly from:

```text
canonicalization/python/canonicalize.py
```

Decision Context digests and Signature Statement bytes therefore use the same
AGP Canonicalization 0.7 implementation already exercised by the canonicalization
conformance suite.
