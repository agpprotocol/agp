# Phase 6D-6B — Reproducible Python dependency inputs

Phase 6D-6B separates public package compatibility from CI
reproducibility.

## Compatibility declarations

`requirements-v0.4.txt` and project runtime dependencies keep supported
version ranges. These declarations remain suitable for package users.

## Reviewed CI inputs

`constraints-ci.txt` pins the direct Python inputs used by CI:

- pip 26.1.2
- build 1.5.0
- twine 6.2.0
- hatchling 1.27.0
- cryptography 49.0.0
- jsonschema 4.26.0
- hypothesis 6.161.1

Historical conformance and TPE validation install runtime requirements
through these constraints. Publishing uses exact build and validation
tool versions, and `PIP_CONSTRAINT` also constrains the isolated PEP 517
build environment.

The root package build backend is pinned to hatchling 1.27.0.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_python_dependency_reproducibility_contract.py
```

Expected marker:

```text
AGP Python dependency reproducibility contract: 12/12 passed
```

The contract contributes twelve checks to complete TPE development
validation, increasing its expected total from 1001 to 1013.
