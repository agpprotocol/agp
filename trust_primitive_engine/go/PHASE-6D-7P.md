# Phase 6D-7P — Terminal publication verification

Phase 6D-7O proves that an exactly authorized draft can be published and that
the release workflow was triggered. Triggered is not the same as successful.

Phase 6D-7P adds a read-only terminal verifier:

```text
trust_primitive_engine/tools/verify_terminal_release_publication.py
```

Success requires all of the following:

1. the GitHub Release is published, non-prerelease, and targets the exact
   source commit;
2. the Release contains exactly four uploaded, nonempty assets:
   wheel, source distribution, `SHA256SUMS`, and `agp-tpe.cdx.json`;
3. the fixed workflow `Publish AGP TPE to PyPI` completed with
   `conclusion=success`;
4. the workflow run is bound to the exact release tag and source commit;
5. PyPI contains exactly one wheel and one source distribution for the exact
   version, both non-yanked and carrying SHA-256 digests;
6. canonical release-verification evidence reports `overall_status=passed`
   and covers all four asset classes with checksum, provenance, and applicable
   CycloneDX SBOM verification.

This phase performs no Release mutation, workflow dispatch, rerun, package
upload, deletion, or recovery action.

Repository tests use simulated GitHub, PyPI, and attestation evidence. They do
not publish or modify any real release.
