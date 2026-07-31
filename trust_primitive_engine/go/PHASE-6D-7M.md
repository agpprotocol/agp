# Phase 6D-7M — Controlled draft GitHub Release creation

The PyPI workflow is triggered by `release: published`. Creating a published
Release is therefore the publication boundary, not a preparation step.

Phase 6D-7M adds a command that creates only a draft GitHub Release:

```text
trust_primitive_engine/tools/create_authorized_draft_release.py
```

Before mutation it requires:

- deterministic candidate evidence;
- bound authorization evidence;
- clean tracked repository state;
- current HEAD and package metadata matching the candidate;
- the exact annotated tag already present on the remote;
- the remote tag peeling to the candidate source commit;
- non-empty explicit release notes;
- no existing GitHub Release for the tag.

The command invokes `gh release create` with `--verify-tag` and `--draft`.
It then verifies the Release has the exact tag and title, remains a non-
prerelease draft, has no publication timestamp, and contains no assets.

This phase does not publish the Release, upload assets, or publish to PyPI.
Publishing the draft remains a later, separately authorized operation.
