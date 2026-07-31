# Phase 6D-7K — Explicitly authorized local candidate tag

Repository and GitHub inspection found no independent platform authorization
boundary for TPE tags:

- the `pypi` environment has no protection rules or required reviewers;
- no repository tag ruleset exists;
- the inspected public TPE tags are annotated but unsigned;
- branch protection is not available through the inspected endpoint.

Phase 6D-7K therefore does not claim two-person approval or cryptographic
authorizer identity. It introduces an explicit operator-authorization boundary
that is honest about those limits.

The repository-owned command:

```text
trust_primitive_engine/tools/materialize_authorized_candidate_tag.py
```

requires:

- the exact deterministic 6D-7J candidate report;
- a separate JSON authorization document;
- SHA-256 binding from authorization to candidate evidence;
- exact binding to release tag and source commit;
- an explicit authorization decision and statement;
- an authorizer label and RFC3339 UTC authorization time;
- clean tracked repository state;
- current HEAD and package metadata matching the candidate;
- local and remote tag availability rechecked immediately before creation.

A successful operation creates only a local annotated Git tag and verifies its
type and peeled commit. It does not push the tag, create a GitHub Release, or
publish to PyPI.

Independent approval requires future GitHub environment reviewers, tag
rulesets, or cryptographically signed authorization evidence. This phase does
not represent those controls as already present.
