# Phase 6D-7D — Release provenance attestations

Phase 6D-7D adds GitHub Artifact Attestations to the Python release
pipeline.

The workflow uses the immutable commit for `actions/attest` v4.2.1:

```text
508db95dd578ae2727ebd6217d5ba78e4fbda05d
```

One SLSA build-provenance attestation covers:

```text
dist/*.whl
dist/*.tar.gz
dist/SHA256SUMS
release-assets/agp-tpe.cdx.json
```

A second SBOM attestation binds the CycloneDX document to both Python
distributions.

The workflow explicitly grants:

```text
contents: write
id-token: write
attestations: write
artifact-metadata: write
```

Published artifacts can be verified with:

```text
gh attestation verify <artifact> --repo agpprotocol/agp
```

The permanent contract is:

```text
trust_primitive_engine/tools/test_release_attestation_contract.py
```

Expected marker:

```text
AGP release provenance attestation contract: 14/14 passed
```

The contract increases complete TPE development validation from 1061 to
1075 checks.
