# Phase 6D-7H — Canonical successful release verification gate

Phase 6D-7H makes the repository-owned attestation verifier the single post-upload release gate.

The publish workflow already builds the wheel and source distribution, generates `SHA256SUMS` and a CycloneDX SBOM, creates provenance and SBOM attestations, publishes to PyPI, and uploads the four required GitHub Release assets.

Previously, the workflow implemented verification twice: an inline shell path and the canonical `verify_release_attestations.py` evidence path. The inline implementation is removed. The canonical verifier now runs directly after release asset upload as a blocking step.

The summary and JSON/Markdown evidence upload remain `if: always()` so failed verification stays observable and retained for 90 days.

This phase does not add a manual or TestPyPI publication path and does not modify historical releases.
