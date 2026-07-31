# Phase 6D-7N — Explicit draft publication authorization

Publishing a draft GitHub Release triggers the repository's
`release: published` workflow and therefore crosses the PyPI publication
boundary.

Phase 6D-7N adds a validation-only command:

```text
trust_primitive_engine/tools/validate_draft_publication_authorization.py
```

It requires three independent evidence documents:

1. the deterministic release candidate;
2. the authorization used for the annotated candidate tag;
3. a separate draft-publication authorization.

The command revalidates repository state, package metadata, remote annotated
tag identity, and the exact draft Release state. It requires the Release to be
a non-prerelease draft with no publication timestamp and zero assets.

The observed draft fields are serialized canonically and hashed with SHA-256.
The publication authorization must bind that digest together with the
candidate digest, repository, release tag, and source commit, and must contain
the exact decision:

```text
authorize-draft-release-publication
```

This phase validates authorization only. It does not edit or publish the
Release, upload assets, run the release workflow, or publish to PyPI.
