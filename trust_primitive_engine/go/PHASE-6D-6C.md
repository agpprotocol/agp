# Phase 6D-6C — Python transitive locks and hash enforcement

Phase 6D-6C locks the complete Python dependency graphs used by CI and
publishing on Ubuntu 24.04 with Python 3.12.

## Runtime lock

`requirements-ci-lock.txt` contains the complete resolved graph for
historical conformance and TPE validation. Every package is pinned and
protected by SHA-256 hashes.

CI installs this graph with:

```text
python -m pip install --require-hashes -r requirements-ci-lock.txt
```

## Release lock

`requirements-release-lock.txt` contains the complete resolved graph for
build and upload tooling, including hatchling, build, and twine.

Publishing installs the release graph with hash enforcement and builds
with `--no-isolation`, preventing an isolated PEP 517 environment from
resolving additional unreviewed dependencies.

## Compatibility declarations

`requirements-v0.4.txt`, project runtime dependency ranges, and
`constraints-ci.txt` remain compatibility and reviewed direct-input
declarations. The lock files are the executable CI and release graphs.

## Permanent contract

```text
trust_primitive_engine/tools/test_python_transitive_lock_contract.py
```

Expected marker:

```text
AGP Python transitive lock contract: 14/14 passed
```

The contract contributes fourteen checks, increasing complete TPE
development validation from 1013 to 1027 checks.
