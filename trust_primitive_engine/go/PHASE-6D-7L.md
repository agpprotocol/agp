# Phase 6D-7L — Controlled remote publication of an authorized tag

Workflow inspection confirms that pushing a TPE tag does not itself publish a
package or create a GitHub Release. PyPI publication is triggered only by the
separate `release: published` event.

Phase 6D-7L adds:

```text
trust_primitive_engine/tools/publish_authorized_candidate_tag.py
```

The command requires the same deterministic candidate report and bound
authorization evidence used by Phase 6D-7K. Before any network mutation it:

- recomputes the candidate evidence SHA-256;
- validates candidate and authorization fields;
- requires a clean tracked worktree and index;
- requires current HEAD and package metadata to match the candidate;
- requires the local release reference to be an annotated tag;
- requires the local tag to peel to the candidate source commit;
- rechecks that the remote tag and peeled reference are absent.

The only mutation is an atomic push of one exact refspec:

```text
refs/tags/<tag>:refs/tags/<tag>
```

The command never uses `--tags`, `--mirror`, force, deletion, or a wildcard.
After the push it reads the remote tag and peeled reference and requires both to
match the local annotated tag object and candidate source commit.

This phase does not create a GitHub Release and does not publish to PyPI.
Those remain later, separately authorized operations.
