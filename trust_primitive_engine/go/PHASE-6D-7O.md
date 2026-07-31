# Phase 6D-7O — Controlled publication of an authorized draft

Publishing a GitHub Release is the irreversible event that triggers the
repository's `release: published` workflow and starts the PyPI publication
path.

Phase 6D-7O adds:

```text
trust_primitive_engine/tools/publish_authorized_draft_release.py
```

Before mutation, the command revalidates:

- the deterministic candidate and its SHA-256;
- the annotated-tag authorization;
- the separate draft-publication authorization;
- clean tracked repository state;
- current HEAD and package metadata;
- the exact annotated remote tag and peeled source commit;
- the exact draft Release state;
- the canonical SHA-256 of the observed draft.

The only Release mutation is:

```text
gh release edit <tag> --repo <repository> --draft=false
```

After mutation, the command requires the Release to be published, non-
prerelease, and timestamped. It then requires a matching `release` event for
the fixed workflow `Publish AGP TPE to PyPI`, bound to the candidate tag and
source commit.

The command reports that PyPI publication was triggered. It does not claim
that PyPI publication or final attestation verification succeeded; those
remain observable workflow outcomes.

Repository tests use a simulated `gh` executable. They do not publish a real
Release or package.
