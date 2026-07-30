# Phase 6D-7B — Release artifact checksums

Phase 6D-7B adds a deterministic SHA-256 manifest to the Python release
pipeline.

## Release artifacts

The publishing workflow builds exactly two distributions:

```text
agp_tpe-<version>-py3-none-any.whl
agp_tpe-<version>.tar.gz
```

## Checksum lifecycle

After the build, the workflow:

1. sorts the wheel and source-distribution names under `LC_ALL=C`;
2. generates `dist/SHA256SUMS`;
3. requires exactly two manifest entries;
4. verifies every entry with `sha256sum --check`;
5. publishes the distributions to PyPI through trusted publishing;
6. attaches `SHA256SUMS` to the matching GitHub Release.

The attachment uses the release event's exact tag and `--clobber`, making
reruns deterministic and idempotent.

## Permission change

The publishing job changes `contents: read` to `contents: write` solely
to attach the checksum manifest to the already-created GitHub Release.
`id-token: write` remains dedicated to PyPI trusted publishing.

## Permanent contract

```text
trust_primitive_engine/tools/test_release_artifact_checksum_contract.py
```

Expected marker:

```text
AGP release artifact checksum contract: 10/10 passed
```

The contract adds ten checks, increasing complete TPE development
validation from 1039 to 1049 checks.
