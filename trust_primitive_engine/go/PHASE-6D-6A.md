# Phase 6D-6A — Reproducible CI runtime inputs

Phase 6D-6A removes moving runner and Go toolchain inputs from
GitHub Actions.

## Changes

All eight workflows now use:

```text
runs-on: ubuntu-24.04
```

The two workflows that previously used the moving `stable` Go alias now
use:

```text
go-version: "1.23.x"
```

The `check-latest: true` option is removed.

The selected Go version covers the repository root module, which
requires Go 1.23, while remaining compatible with all modules declaring
Go 1.22 or earlier.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_ci_runtime_reproducibility_contract.py
```

Expected marker:

```text
AGP CI runtime reproducibility contract: 9/9 passed
```

The contract contributes nine checks to complete TPE development
validation, increasing its expected total from 991 to 1000.
