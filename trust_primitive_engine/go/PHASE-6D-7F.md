# Phase 6D-7F — Release verification observability and recovery

Phase 6D-7F makes release-attestation failures observable and recoverable
without rebuilding or republishing an immutable package version.

## Evidence

Every release verification produces:

- `verification-report.json`;
- `verification-summary.md`;
- one SHA-256 digest per downloaded release asset;
- provenance and CycloneDX SBOM status per applicable asset;
- repository, signer workflow, source tag, and source digest identity;
- an explicit overall pass or fail result.

The Markdown report is appended to the GitHub Actions job summary. Both reports
and the downloaded verification inputs are uploaded as a workflow artifact with
90-day retention.

## Recovery workflow

`.github/workflows/verify-release-attestations.yml` accepts an existing
`tpe-v...` tag through `workflow_dispatch`.

The recovery path is verification-only. It:

1. checks out the existing release tag;
2. downloads the already-published GitHub Release assets;
3. verifies checksums, provenance, and CycloneDX SBOM attestations;
4. writes and retains fresh verification evidence.

It does not build distributions, upload release assets, or publish to PyPI.

## Fail-closed operator procedure

When verification fails after publication:

1. preserve the failed run and its evidence;
2. inspect the JSON and Markdown reports;
3. correct verification policy, tooling, or metadata on a new repository commit;
4. rerun the verification-only workflow for the existing tag;
5. treat the release as unverified until the recovery workflow succeeds.

Do not delete PyPI artifacts or GitHub Release evidence automatically. Do not rebuild or attempt to overwrite the same immutable package version.
