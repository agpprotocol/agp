# Phase 6D-7C — Release SBOM

Phase 6D-7C adds a deterministic CycloneDX JSON 1.7 SBOM to every Python
release.

The generator uses the final wheel metadata as the authoritative source
for package identity and direct runtime requirements. It walks the
installed, hash-locked release environment to record the active runtime
dependency closure.

No additional SBOM package is added to the release lock.

The SBOM includes the root package, exact runtime dependency versions,
Package URLs, the dependency graph, and SHA-256 hashes for the wheel and
source distribution.

Timestamps and random serial numbers are omitted. JSON keys and
dependency arrays are sorted so identical inputs produce byte-identical
output.

The document is written outside `dist/`:

```text
release-assets/agp-tpe.cdx.json
```

This prevents the PyPI publishing action from treating it as a Python
distribution. After PyPI succeeds, it is attached to the matching GitHub
Release alongside `SHA256SUMS`.

The permanent contract is:

```text
trust_primitive_engine/tools/test_release_sbom_contract.py
```

Expected marker:

```text
AGP release SBOM contract: 12/12 passed
```

The contract increases complete TPE development validation from 1049 to
1061 checks.
