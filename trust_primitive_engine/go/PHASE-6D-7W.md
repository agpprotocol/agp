# Phase 6D-7W — Explicit historical validation baseline binding

The preexisting `tpe-v2.6.0` tag passes its complete historical baseline:

```text
AGP TPE 2.6 development validation: 682/682 passed
```

Current `main` includes later release-governance contracts and passes
`1338/1338`.

Recovery must neither require a future total inside historical source nor
silently accept any historical total. It therefore requires:

1. the expected complete validation total for the exact tag;
2. the SHA-256 of the exact historical `run_all_tests.py`.

The runner bytes are hashed before execution. Recovery rejects a digest
mismatch, executes that exact runner by absolute path, requires full success,
and requires the observed total to equal the explicit baseline.

The recovery report records the observed total, runner SHA-256, and baseline
source `explicit-historical-tag-runner`. No authorization or mutation is
created.
