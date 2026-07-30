# Phase 6D-7E — Release attestation verification gate

Phase 6D-7E turns release attestations into a fail-closed verification gate.

## Published assets

The GitHub Release contains exactly one artifact of each expected class:

```text
agp_tpe-<version>-py3-none-any.whl
agp_tpe-<version>.tar.gz
SHA256SUMS
agp-tpe.cdx.json
```

The workflow downloads fresh copies from the published GitHub Release rather
than verifying only files that remain in the build workspace.

## Integrity gate

The downloaded wheel and source distribution must pass:

```text
sha256sum --check SHA256SUMS
```

## Provenance policy

Every downloaded release asset must have a valid SLSA provenance attestation
that satisfies all of the following:

```text
repository: agpprotocol/agp
signer workflow: agpprotocol/agp/.github/workflows/publish-pypi.yml
source ref: refs/tags/<release tag>
source digest: commit resolved from the released tag
runner: GitHub-hosted
```

Attestations generated on self-hosted runners are rejected.

## SBOM policy

Both Python distributions must also have a valid CycloneDX SBOM attestation
with predicate type:

```text
https://cyclonedx.org/bom
```

## Failure behavior

Any missing asset, duplicate asset, checksum mismatch, provenance mismatch,
SBOM mismatch, source mismatch, workflow mismatch, or runner-policy mismatch
fails the release workflow.

## Permanent contract

```text
trust_primitive_engine/tools/test_release_attestation_verification_contract.py
```

Expected marker:

```text
AGP release attestation verification contract: 20/20 passed
```

The contract increases complete TPE development validation from 1075 to
1095 checks.
