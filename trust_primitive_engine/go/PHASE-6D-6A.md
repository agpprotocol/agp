# Phase 6D-6A — Reproducible CI runtime inputs

Phase 6D-6A removes moving runner and Go toolchain inputs from
GitHub Actions.

## Changes

All eight workflows now use:

```text
runs-on: ubuntu-24.04
```

The historical conformance workflow uses:

```text
go-version: "1.23.x"
```

The Go release-integrity workflow uses:

```text
go-version: "1.25.x"
```

Go 1.25 is required by the pinned `govulncheck v1.6.0` scanner.

The `check-latest: true` option is removed.

Go 1.23 covers the repository root module and historical suites. Go 1.25
is isolated to release integrity so the pinned scanner can run without
making the historical conformance toolchain unnecessarily newer.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_ci_runtime_reproducibility_contract.py
```

Expected marker:

```text
AGP CI runtime reproducibility contract: 10/10 passed
```

The contract contributes ten checks to complete TPE development
validation, increasing its expected total from 991 to 1001.
